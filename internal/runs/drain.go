package runs

import (
	"context"
	"errors"
	"fmt"
	"slices"
	"time"

	"github.com/nebarg/sftpit/internal/events"
	"github.com/nebarg/sftpit/internal/sshfront"
)

// drainPoll is how often a drain looks for the last file handle to close.
const drainPoll = 20 * time.Millisecond

// Drained says how a drain ended a run.
type Drained struct {
	// Unfinished are the paths of the files whose handles were still open
	// when the drain ended their connections, sorted.
	Unfinished []string
}

// Drain ends the clients of run, which must be the current run, so that
// nothing can change its files, and leaves it without admission until a
// reset starts the next. It stops the run's timers and closes admission,
// waits for up to wait for every file handle to close, leaving the
// connections open meanwhile, then ends every connection, as a reset does.
// A file handle still open by then is an unfinished transfer, which Drained
// names. Draining a drained run says the same again. Another run fails with
// ErrStaleRun, a run that a failed reset left without admission with
// ErrUnavailable, and a drain once Close has been called with an error
// wrapping sshfront.ErrServerClosed. If the sessions outlast ctx, Status
// reports the run unavailable until a reset succeeds.
func (m *Manager) Drain(ctx context.Context, run string, wait time.Duration) (Drained, error) {
	m.resetting.Lock()
	defer m.resetting.Unlock()
	current, err := m.drainable(run)
	if err != nil {
		return Drained{}, err
	}
	return m.drain(ctx, current, wait)
}

// drainable returns the current run, if it is run and can be drained.
// m.resetting must be held.
func (m *Manager) drainable(run string) (*activeRun, error) {
	if m.closed {
		return nil, fmt.Errorf("runs: drain: %w", sshfront.ErrServerClosed)
	}
	m.mu.Lock()
	defer m.mu.Unlock()
	if run != m.current.run.ID {
		return nil, staleRun(m.current, run)
	}
	if m.failed != nil {
		return nil, fmt.Errorf("runs: drain: %w: %w", ErrUnavailable, m.failed)
	}
	return m.current, nil
}

// drain drains a, the current run. m.resetting must be held.
func (m *Manager) drain(ctx context.Context, a *activeRun, wait time.Duration) (Drained, error) {
	m.mu.Lock()
	if a.drained != nil {
		defer m.mu.Unlock()
		return *a.drained, nil
	}
	a.draining = true
	m.mu.Unlock()

	a.stopTimers()
	m.srv.CloseAdmission()
	awaitClosedFiles(ctx, a, wait)
	// A handle opened from here on is unfinished too, however soon after.
	before := a.events.Last()
	err := m.srv.Pause(ctx)

	m.mu.Lock()
	defer m.mu.Unlock()
	a.draining = false
	if err != nil {
		if !errors.Is(err, sshfront.ErrServerClosed) {
			m.failed = err
			m.logger.Error("drain failed; admission stays closed until a reset succeeds", "run", a.run.ID, "err", err)
		}
		return Drained{}, fmt.Errorf("runs: wait for the run's sessions to finish: %w", err)
	}
	drained := Drained{Unfinished: unfinished(a.events, before)}
	a.drained = &drained
	a.events.Record(events.Event{Kind: events.RunDrained, Unfinished: drained.Unfinished})
	m.logger.Info("run drained", "run", a.run.ID, "unfinished", len(drained.Unfinished))
	return drained, nil
}

// awaitClosedFiles returns once a's clients have closed every file handle,
// wait has passed or ctx is done.
func awaitClosedFiles(ctx context.Context, a *activeRun, wait time.Duration) {
	deadline := time.NewTimer(wait)
	defer deadline.Stop()
	poll := time.NewTicker(drainPoll)
	defer poll.Stop()
	for a.backend.OpenFiles() > 0 {
		select {
		case <-poll.C:
		case <-deadline.C:
			return
		case <-ctx.Done():
			return
		}
	}
}

// unfinished returns the sorted paths of the transfers recorded after the
// event numbered after that their sessions ended.
func unfinished(rec *events.Recorder, after uint64) []string {
	var paths []string
	for {
		page := rec.Events(after, maxEvents, events.Filter{Kinds: []events.Kind{events.Transfer}})
		for _, e := range page.Events {
			if e.Transfer.Closed == "session_ended" {
				paths = append(paths, e.Path)
			}
		}
		if page.Next <= after || len(page.Events) == 0 {
			break
		}
		after = page.Next
	}
	slices.Sort(paths)
	return slices.Compact(paths)
}

// isDrained reports whether a has been drained, or is being drained.
func (m *Manager) isDrained(a *activeRun) bool {
	m.mu.Lock()
	defer m.mu.Unlock()
	return a.draining || a.drained != nil
}
