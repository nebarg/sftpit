package runs

import (
	"context"
	"errors"
	"log/slog"
	"net"
	"time"

	"github.com/nebarg/sftpit/internal/faults"
	"github.com/nebarg/sftpit/internal/sftpproxy"
	"github.com/nebarg/sftpit/internal/sshfront"
)

// Hooks returns the sshfront.Hooks that inject rules' faults into each
// connection as it is accepted and as its client logs in: a delay, which
// ends early if the connection does, a close, reset or freeze of the
// connection, or an outage of the server. A frozen connection is closed at its limit, or when the
// handshake timeout ends the hook. Hooks returns no hooks if rules is nil.
// It logs each fault it injects to logger, or to slog.Default() if logger is
// nil.
func Hooks(rules *faults.Engine, logger *slog.Logger) sshfront.Hooks {
	if rules == nil {
		return sshfront.Hooks{}
	}
	if logger == nil {
		logger = slog.Default()
	}
	return sshfront.Hooks{
		Connect: func(ctx context.Context, conn *sshfront.Conn) {
			inject(ctx, logger, conn, faults.Connect, rules.Connect(faults.Client{Connection: conn.ID()}))
		},
		Authenticate: func(ctx context.Context, conn *sshfront.Conn) {
			client := faults.Client{User: conn.User(), KeyFingerprint: conn.KeyFingerprint(), Connection: conn.ID()}
			inject(ctx, logger, conn, faults.Authenticate, rules.Authenticate(client))
		},
	}
}

func inject(ctx context.Context, logger *slog.Logger, conn *sshfront.Conn, event faults.Operation, action sftpproxy.Action) {
	attrs := []any{"conn", conn.ID(), "request", event}
	if conn.User() != "" {
		attrs = append(attrs, "user", conn.User())
	}
	var err error
	switch a := action.(type) {
	case nil:
		return
	case sftpproxy.Delay:
		logger.Info("injected fault", append(attrs, "fault", "delay", "duration", a.Duration)...)
		wait(ctx, a.Duration)
	case sftpproxy.Drop:
		if a.Reset {
			logger.Info("injected fault", append(attrs, "fault", "close_connection", "mode", "rst")...)
			err = conn.Reset()
		} else {
			logger.Info("injected fault", append(attrs, "fault", "close_connection", "mode", "fin")...)
			err = conn.Close()
		}
	case sftpproxy.Freeze:
		logger.Info("injected fault", append(attrs, "fault", "freeze_connection", "limit", a.Limit)...)
		conn.Freeze()
		wait(ctx, a.Limit)
		err = conn.Close()
	case sftpproxy.ListenerDown:
		logger.Info("injected fault", append(attrs, "fault", "listener_down", "duration", a.Duration, "close_existing", a.CloseExisting)...)
		conn.Server().Down(a.Duration, a.CloseExisting)
	}
	// A connection that is already closed, by the server shutting down for
	// one, needs closing no more.
	if err != nil && !errors.Is(err, net.ErrClosed) {
		logger.Warn("injecting a fault failed", append(attrs, "err", err)...)
	}
}

// ArmTimers takes srv down at the moments of the run that rules times,
// whatever the run's sessions are doing then, until stop is called. It logs
// each outage to logger, or to slog.Default() if logger is nil.
func ArmTimers(rules *faults.Engine, srv *sshfront.Server, logger *slog.Logger) (stop func()) {
	if rules == nil {
		return func() {}
	}
	if logger == nil {
		logger = slog.Default()
	}
	var timers []*time.Timer
	for _, t := range rules.Timers() {
		down := t.Action.(sftpproxy.ListenerDown)
		timers = append(timers, time.AfterFunc(time.Until(t.At), func() {
			if t.Reserve != nil && !t.Reserve() {
				return
			}
			logger.Info("injected fault", "fault", "listener_down", "when", "timer", "duration", down.Duration, "close_existing", down.CloseExisting)
			srv.Down(down.Duration, down.CloseExisting)
		}))
	}
	return func() {
		for _, timer := range timers {
			timer.Stop()
		}
	}
}

// wait waits for d, or until ctx is done.
func wait(ctx context.Context, d time.Duration) {
	timer := time.NewTimer(d)
	defer timer.Stop()
	select {
	case <-timer.C:
	case <-ctx.Done():
	}
}
