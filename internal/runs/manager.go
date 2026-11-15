package runs

import (
	"cmp"
	"context"
	"errors"
	"fmt"
	"io"
	"log/slog"
	"os"
	"strconv"
	"sync"
	"time"

	"github.com/nebarg/sftpit/internal/backend"
	"github.com/nebarg/sftpit/internal/config"
	"github.com/nebarg/sftpit/internal/events"
	"github.com/nebarg/sftpit/internal/faults"
	"github.com/nebarg/sftpit/internal/sftpproxy"
	"github.com/nebarg/sftpit/internal/sshfront"
)

// maxEvents bounds the events kept for each run.
const maxEvents = 10000

// Options configure a Manager.
type Options struct {
	// Server configures the SSH server that serves the runs. The Manager
	// sets its Handler and Hooks, and makes each user's home directory in
	// every run.
	Server sshfront.Config

	// SeedDir is the host directory whose files every run starts with, or
	// "" for none.
	SeedDir string

	// Folders are folders to make in every run, as absolute SFTP paths.
	Folders []string

	// Limits bound each run's files and the handles open on them.
	Limits backend.Limits

	// ReplyOrder is the order in which each session's replies reach its
	// client.
	ReplyOrder sftpproxy.ReplyOrder

	// Policy is what clients may do, whatever faults a run injects.
	Policy config.Policy

	// Scenarios are the scenarios that can be turned on in a run.
	Scenarios *config.Scenarios

	// Scenario names the scenario turned on in the first run, or is "" for
	// none.
	Scenario string

	// Logger receives what the runs log. Nil means slog.Default().
	Logger *slog.Logger
}

// Manager serves the runs of a workspace, one at a time, through an SSH
// server of its own. Each connection is served by the current run, and a
// reset ends that run and starts the next. Its methods are safe for
// concurrent use.
type Manager struct {
	workspace *Workspace
	fixtures  *fixtureSnapshot
	opts      Options
	logger    *slog.Logger
	srv       *sshfront.Server

	// resetting serialises each reset, each change of the current run's
	// rules or faults, so that none arms timers on a run that a reset is
	// ending, and Close. It is held for the whole of a reset, so nothing
	// that only reads takes it. It guards activeRun.stops and
	// activeRun.lastFault, and closed, which Close sets so that nothing
	// starts or changes a run after it.
	resetting sync.Mutex
	closed    bool

	// scenarioFiles serialises reading the saved scenarios with saving and
	// deleting them, along with the change each makes to the current run's
	// faults, so that a list of the scenarios is of one moment. Code that
	// holds resetting too takes it after resetting.
	scenarioFiles sync.Mutex

	// mu guards current, inReset and failed, and activeRun.faults, which
	// change along with the run's rules under it, so that code holding mu
	// sees the faults and the counts of their rules as of one moment. It is
	// held only briefly. current and activeRun.faults also change only while
	// resetting is held, so code holding resetting reads them without mu.
	mu      sync.Mutex
	current *activeRun
	// inReset is set while a reset is under way, and failed once one has
	// failed, until another succeeds.
	inReset bool
	failed  error
}

// activeRun is a run that a Manager serves.
type activeRun struct {
	run     *Run
	root    *os.Root
	rules   *faults.Engine
	events  *events.Recorder
	handler sshfront.Handler
	hooks   sshfront.Hooks

	// stops stop the timers armed for the run: those it started with, and
	// those of each change of its rules. They are guarded by the Manager's
	// resetting.
	stops []func()

	// faults are the faults added to the run in plain terms, in the order
	// added. A change replaces the slice, never its elements, since readers
	// keep it once mu is released. lastFault numbers them.
	faults    []plainFault
	lastFault int
}

// stopTimers stops every timer armed for the run.
func (a *activeRun) stopTimers() {
	for _, stop := range a.stops {
		stop()
	}
}

// Start snapshots the seed in the workspace w and starts the first run,
// whose files are restored from the snapshot, and returns a Manager serving
// it. The caller serves the Manager's Server on its listeners, and closes
// the Manager to stop.
func Start(w *Workspace, opts Options) (*Manager, error) {
	logger := cmp.Or(opts.Logger, slog.Default())
	fixtures, err := w.snapshotSeed(opts.SeedDir)
	if err != nil {
		return nil, err
	}
	m := &Manager{workspace: w, fixtures: fixtures, opts: opts, logger: logger}
	cfg := opts.Server
	cfg.Handler, cfg.Hooks = m.handle, m.hooks()
	cfg.Logger = cmp.Or(cfg.Logger, logger)
	if m.srv, err = sshfront.New(cfg); err != nil {
		return nil, err
	}
	if m.current, err = m.begin(); err != nil {
		return nil, err
	}
	if opts.Scenario != "" {
		if _, err := m.SwitchScenario(opts.Scenario, true); err != nil {
			return nil, errors.Join(err, m.Close())
		}
	}
	return m, nil
}

// Server returns the SSH server that serves the runs.
func (m *Manager) Server() *sshfront.Server { return m.srv }

// Close stops the server, as sshfront.Server.Close does, and ends the
// current run.
func (m *Manager) Close() error {
	// Closing the server first ends a reset that waits for sessions.
	err := m.srv.Close()
	m.resetting.Lock()
	defer m.resetting.Unlock()
	m.closed = true
	m.current.stopTimers()
	if closeErr := m.current.root.Close(); closeErr != nil {
		err = errors.Join(err, fmt.Errorf("runs: close the run's files: %w", closeErr))
	}
	return err
}

// Reset ends the current run and starts the next, with no faults. It first
// closes admission and ends every connection, as sshfront.Server.Pause
// does, along with the run's timers, and waits until every session has
// finished, so that no client of the run can still change its files, or
// until ctx is done. The next run's files are restored from the seed
// snapshot. Reset returns the status of the run it started, as Status gives
// it, before another reset can start. If anything fails once admission is
// closed, admission stays closed and Status reports the run unavailable until
// a reset succeeds. A reset that begins after Close has been called, or that
// is still waiting for sessions when it is called, fails with an error
// wrapping sshfront.ErrServerClosed.
func (m *Manager) Reset(ctx context.Context) (Status, error) {
	m.resetting.Lock()
	defer m.resetting.Unlock()
	if m.closed {
		return Status{}, fmt.Errorf("runs: reset: %w", sshfront.ErrServerClosed)
	}
	current := m.active()

	m.mu.Lock()
	m.inReset = true
	m.mu.Unlock()
	next, err := m.restart(ctx, current)
	m.mu.Lock()
	m.inReset = false
	if err != nil {
		m.failed = err
	} else {
		m.current, m.failed = next, nil
	}
	m.mu.Unlock()
	if err != nil {
		// A server closed under the reset is shutting down, not failing.
		if !errors.Is(err, sshfront.ErrServerClosed) {
			m.logger.Error("reset failed; admission stays closed until a reset succeeds", "run", current.run.ID, "err", err)
		}
		return Status{}, err
	}

	if err := current.root.Close(); err != nil {
		m.logger.Warn("closing the files of the previous run failed", "run", current.run.ID, "err", err)
	}
	m.srv.Resume()
	m.logger.Info("reset", "run", next.run.ID)
	return m.Status(), nil
}

// Rules returns the rules of the current run.
func (m *Manager) Rules() faults.RuleSet {
	return m.active().rules.Rules()
}

// replaceRules replaces the rules of current, the current run, with rules,
// as faults.Engine.Replace does if revision is still the current revision,
// and its faults with list, and returns the new rules. It fails with
// faults.ErrStaleRevision for another revision, and whenever it fails it
// leaves the rules and the faults as they were. The run takes the listener
// down at the moments of the rules that start afresh, as it does at those
// of the rules it started with. The caller holds resetting.
func (m *Manager) replaceRules(current *activeRun, revision uint64, rules []faults.Rule, list []plainFault) (faults.RuleSet, error) {
	m.mu.Lock()
	timers, err := current.rules.Replace(revision, rules)
	if err == nil {
		current.faults = list
	}
	m.mu.Unlock()
	if err != nil {
		return faults.RuleSet{}, err
	}
	current.stops = append(current.stops, armTimers(timers, m.srv, m.logger, current.events.Record))
	set := current.rules.Rules()
	current.events.Record(events.Event{Kind: events.RulesChanged, Rules: &events.Rules{Revision: set.Revision, Previous: revision}})
	return set, nil
}

// ReleaseStalls releases the stalls and freezes in progress in the current
// run, as faults.Engine.ReleaseStalls does.
func (m *Manager) ReleaseStalls() {
	m.active().rules.ReleaseStalls()
}

// Events returns the events of the current run.
func (m *Manager) Events() *events.Recorder {
	return m.active().events
}

// restart ends current's timers and connections, and begins the next run
// once every session of current has finished.
func (m *Manager) restart(ctx context.Context, current *activeRun) (*activeRun, error) {
	current.stopTimers()
	if err := m.srv.Pause(ctx); err != nil {
		return nil, fmt.Errorf("runs: wait for the run's sessions to finish: %w", err)
	}
	return m.begin()
}

// State says whether clients can reach the current run.
type State string

const (
	// StateUp is a run that admits clients.
	StateUp State = "up"
	// StateDown is a run whose server is down for an outage.
	StateDown State = "down"
	// StateResetting is a run that a reset is ending.
	StateResetting State = "resetting"
	// StateUnavailable is a run that a failed reset has left without
	// admission.
	StateUnavailable State = "unavailable"
)

// Status describes the current run.
type Status struct {
	Run   Run
	State State

	// Revision is the revision of the run's rules, as faults.Engine.Revision
	// numbers them.
	Revision uint64

	// DownUntil is when an outage ends, in StateDown.
	DownUntil time.Time

	// Err is why the last reset failed, in StateUnavailable.
	Err error

	// Stalled counts the requests or replies that stalls hold now, and
	// Frozen the connections that freezes hold.
	Stalled, Frozen int
}

// Status describes the current run.
func (m *Manager) Status() Status {
	m.mu.Lock()
	s := Status{Run: *m.current.run, State: StateUp, Revision: m.current.rules.Revision()}
	s.Stalled, s.Frozen = m.current.events.Waiting(events.StallFault), m.current.events.Waiting(events.FreezeConnectionFault)
	switch {
	case m.inReset:
		s.State = StateResetting
	case m.failed != nil:
		s.State, s.Err = StateUnavailable, m.failed
	}
	m.mu.Unlock()
	if s.State == StateUp {
		if until, down := m.srv.Outage(); down {
			s.State, s.DownUntil = StateDown, until
		}
	}
	return s
}

// begin starts a run in the workspace, with no faults, its files restored
// from the seed snapshot and a home directory for each user. Each run draws
// a fresh seed for its random decisions.
func (m *Manager) begin() (_ *activeRun, err error) {
	run, err := m.workspace.NewRun(faults.RandomSeed())
	if err != nil {
		return nil, err
	}
	root, err := os.OpenRoot(run.Files)
	if err != nil {
		return nil, fmt.Errorf("runs: open run files: %w", err)
	}
	defer func() {
		if err != nil {
			root.Close()
		}
	}()
	embedded, err := backend.New(root, backend.Options{Limits: m.opts.Limits, Logger: m.logger})
	if err != nil {
		return nil, err
	}
	if m.fixtures != nil {
		if err := m.fixtures.restore(embedded); err != nil {
			return nil, err
		}
	}
	for _, u := range m.opts.Server.Users {
		if err := embedded.MkdirAll(u.Home); err != nil {
			return nil, fmt.Errorf("runs: create home %s for %s: %w", u.Home, u.Name, err)
		}
	}
	for _, folder := range m.opts.Folders {
		if err := embedded.MkdirAll(folder); err != nil {
			return nil, fmt.Errorf("runs: create folder %s: %w", folder, err)
		}
	}

	rec := events.NewRecorder(run.Started, maxEvents)
	rules, err := faults.New(nil, run.Seed, faults.Options{Logger: m.logger, Record: rec.Record})
	if err != nil {
		return nil, err
	}
	rec.Record(events.Event{Kind: events.RunStarted, Run: &events.Run{ID: run.ID, Seed: strconv.FormatUint(uint64(run.Seed), 10)}, Rules: &events.Rules{Revision: rules.Revision()}})
	return &activeRun{
		run:     run,
		root:    root,
		rules:   rules,
		events:  rec,
		handler: Handler(embedded, rules, m.opts.Policy, sftpproxy.Options{ReplyOrder: m.opts.ReplyOrder, Logger: m.logger, Record: rec.Record}),
		hooks:   connectionHooks(rules, m.logger, rec.Record),
	}, nil
}

func (m *Manager) active() *activeRun {
	m.mu.Lock()
	defer m.mu.Unlock()
	return m.current
}

// handle serves a session of the current run. Admission is closed while a
// reset replaces the run, so a connection is served by one run throughout.
func (m *Manager) handle(ctx context.Context, conn *sshfront.Conn, channel io.ReadWriteCloser) error {
	return m.active().handler(ctx, conn, channel)
}

// hooks returns the hooks of the current run.
func (m *Manager) hooks() sshfront.Hooks {
	return sshfront.Hooks{
		Connect: func(ctx context.Context, conn *sshfront.Conn) {
			m.active().hooks.Connect(ctx, conn)
		},
		Authenticate: func(ctx context.Context, conn *sshfront.Conn) {
			m.active().hooks.Authenticate(ctx, conn)
		},
		Disconnect: func(conn *sshfront.Conn) {
			m.active().hooks.Disconnect(conn)
		},
	}
}
