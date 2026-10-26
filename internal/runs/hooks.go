package runs

import (
	"context"
	"errors"
	"log/slog"
	"net"
	"sync"
	"time"

	"github.com/nebarg/sftpit/internal/faults"
	"github.com/nebarg/sftpit/internal/sftpproxy"
	"github.com/nebarg/sftpit/internal/sshfront"
)

// Hooks returns the sshfront.Hooks that inject rules' faults into each
// connection as it is accepted and as its client logs in: a delay, which
// ends early if the connection does or its rule is removed, a close, reset
// or freeze of the connection, or an outage of the server. A frozen
// connection is closed at its limit, when its rule is removed or rules
// releases its stalls, or when the handshake timeout ends the hook. Hooks
// returns no hooks if rules is nil. It logs each fault it injects to
// logger, or to slog.Default() if logger is nil.
func Hooks(rules *faults.Engine, logger *slog.Logger) sshfront.Hooks {
	if rules == nil {
		return sshfront.Hooks{}
	}
	if logger == nil {
		logger = slog.Default()
	}
	return sshfront.Hooks{
		Connect: func(ctx context.Context, conn *sshfront.Conn) {
			inject(ctx, logger, rules, conn, faults.Connect, rules.Connect(faults.Client{Connection: conn.ID()}))
		},
		Authenticate: func(ctx context.Context, conn *sshfront.Conn) {
			client := faults.Client{User: conn.User(), KeyFingerprint: conn.KeyFingerprint(), Connection: conn.ID()}
			inject(ctx, logger, rules, conn, faults.Authenticate, rules.Authenticate(client))
		},
	}
}

func inject(ctx context.Context, logger *slog.Logger, rules *faults.Engine, conn *sshfront.Conn, event faults.Operation, action sftpproxy.Action) {
	attrs := []any{"conn", conn.ID(), "operation", event}
	if conn.User() != "" {
		attrs = append(attrs, "user", conn.User())
	}
	if action == nil {
		return
	}
	attrs = append(attrs, sftpproxy.FaultAttrs(action, "")...)
	logger.Info("injected fault", attrs...)
	var err error
	switch a := action.(type) {
	case sftpproxy.Delay:
		if wait(ctx, a.Duration, a.Release, nil) {
			logger.Info("fault released", attrs...)
		}
	case sftpproxy.Drop:
		if a.Reset {
			err = conn.Reset()
		} else {
			err = conn.Close()
		}
	case sftpproxy.Freeze:
		conn.Freeze()
		if wait(ctx, a.Limit, a.Release, rules.Released()) {
			logger.Info("fault released", attrs...)
		}
		err = conn.Close()
	case sftpproxy.ListenerDown:
		conn.Server().Down(a.Duration, a.CloseExisting)
	}
	// A connection that is already closed, by the server shutting down for
	// one, needs closing no more.
	if err != nil && !errors.Is(err, net.ErrClosed) {
		logger.Warn("injecting a fault failed", append(attrs, "err", err)...)
	}
}

// ArmTimers takes srv down at the moments of the run that rules times,
// whatever the run's sessions are doing then, until stop is called. A
// moment that has already come, such as the start of the run, takes srv
// down before ArmTimers returns. Once stop has returned, no outage begins.
// It logs each outage to logger, or to slog.Default() if logger is nil.
func ArmTimers(rules *faults.Engine, srv *sshfront.Server, logger *slog.Logger) (stop func()) {
	if rules == nil {
		return func() {}
	}
	if logger == nil {
		logger = slog.Default()
	}
	return armTimers(rules.Timers(), srv, logger)
}

// armTimers takes srv down at the moments of timers, as ArmTimers does.
func armTimers(timers []sftpproxy.Timer, srv *sshfront.Server, logger *slog.Logger) (stop func()) {
	var (
		mu      sync.Mutex
		stopped bool
		armed   []*time.Timer
	)
	for _, t := range timers {
		down := t.Action.(sftpproxy.ListenerDown)
		fire := func() {
			mu.Lock()
			defer mu.Unlock()
			if stopped || (t.Reserve != nil && !t.Reserve()) {
				return
			}
			logger.Info("injected fault", sftpproxy.FaultAttrs(down, "timer")...)
			srv.Down(down.Duration, down.CloseExisting)
		}
		if wait := time.Until(t.At); wait > 0 {
			armed = append(armed, time.AfterFunc(wait, fire))
		} else {
			fire()
		}
	}
	return func() {
		mu.Lock()
		defer mu.Unlock()
		stopped = true
		for _, timer := range armed {
			timer.Stop()
		}
	}
}

// wait waits for d, or until ctx is done or release or stalls is closed,
// and reports whether a release ended it.
func wait(ctx context.Context, d time.Duration, release, stalls <-chan struct{}) (released bool) {
	timer := time.NewTimer(d)
	defer timer.Stop()
	select {
	case <-timer.C:
	case <-ctx.Done():
	case <-release:
		return true
	case <-stalls:
		return true
	}
	return false
}
