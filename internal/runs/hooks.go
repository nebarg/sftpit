package runs

import (
	"context"
	"errors"
	"fmt"
	"log/slog"
	"net"
	"sync"
	"time"

	"github.com/nebarg/sftpit/internal/events"
	"github.com/nebarg/sftpit/internal/faults"
	"github.com/nebarg/sftpit/internal/sftpproxy"
	"github.com/nebarg/sftpit/internal/sshfront"
)

// connectionHooks returns the sshfront.Hooks that inject rules' faults into
// each connection as it is accepted and as its client logs in: a delay,
// which ends early if the connection does or its rule is removed, a close,
// reset or freeze of the connection, or an outage of the server. A frozen
// connection is closed at its limit, when its rule is removed or rules
// releases its stalls, or when the handshake timeout ends the hook. It logs
// each fault it injects to logger, and records each connection, login,
// disconnection and fault, and the end of each fault's wait, with record.
func connectionHooks(rules *faults.Engine, logger *slog.Logger, record func(events.Event)) sshfront.Hooks {
	return sshfront.Hooks{
		Connect: func(ctx context.Context, conn *sshfront.Conn) {
			record(events.Event{Kind: events.Connected, Connection: conn.ID()})
			inject(ctx, logger, record, rules, conn, faults.Connect, rules.Connect(faults.Client{Connection: conn.ID()}))
		},
		Authenticate: func(ctx context.Context, conn *sshfront.Conn) {
			record(events.Event{Kind: events.Authenticated, Connection: conn.ID(), User: conn.User(), KeyFingerprint: conn.KeyFingerprint()})
			client := faults.Client{User: conn.User(), KeyFingerprint: conn.KeyFingerprint(), Connection: conn.ID()}
			inject(ctx, logger, record, rules, conn, faults.Authenticate, rules.Authenticate(client))
		},
		Disconnect: func(conn *sshfront.Conn) {
			record(events.Event{Kind: events.Disconnected, Connection: conn.ID(), User: conn.User(), KeyFingerprint: conn.KeyFingerprint()})
		},
	}
}

func inject(ctx context.Context, logger *slog.Logger, record func(events.Event), rules *faults.Engine, conn *sshfront.Conn, event faults.Operation, fault sftpproxy.Fault) {
	action := fault.Action
	if action == nil {
		return
	}
	// Taken before the fault is announced, so that a release that follows
	// the announcement ends it.
	released := rules.Released()
	attrs := []any{"conn", conn.ID(), "operation", event}
	if conn.User() != "" {
		attrs = append(attrs, "user", conn.User())
	}
	described := sftpproxy.FaultAttrs(action, "")
	attrs = append(attrs, described...)
	logger.Info("injected fault", attrs...)
	injected := events.Event{Kind: events.FaultInjected, Connection: conn.ID(), User: conn.User(), KeyFingerprint: conn.KeyFingerprint(), Request: string(event), Rule: fault.Rule, Fault: describe(described)}
	record(injected)
	ended := func(reason string) {
		if reason == "canceled" || reason == "released" {
			logger.Info("fault released", attrs...)
		}
		e := injected
		e.Kind, e.Reason, e.Fault = events.FaultEnded, reason, &events.Fault{Type: injected.Fault.Type}
		record(e)
	}
	var err error
	switch a := action.(type) {
	case sftpproxy.Delay:
		ended(wait(ctx, a.Duration, a.Release, nil, "elapsed"))
	case sftpproxy.Drop:
		if a.Reset {
			err = conn.Reset()
		} else {
			err = conn.Close()
		}
	case sftpproxy.Freeze:
		conn.Freeze()
		ended(wait(ctx, a.Limit, a.Release, released, "limit"))
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

// describe returns the fault that attrs, from sftpproxy.FaultAttrs,
// describe, as an event gives it.
func describe(attrs []any) *events.Fault {
	f := &events.Fault{}
	for i := 0; i+1 < len(attrs); i += 2 {
		key, value := attrs[i].(string), attrs[i+1]
		switch key {
		case "fault":
			f.Type = value.(string)
		case "when":
			f.When = value.(string)
		default:
			if f.Settings == nil {
				f.Settings = make(map[string]any)
			}
			if v, ok := value.(fmt.Stringer); ok {
				value = v.String()
			}
			f.Settings[key] = value
		}
	}
	return f
}

// armTimers takes srv down at the moments of timers, the ListenerDowns of a
// run, whatever the run's sessions are doing then, until stop is called. A
// moment that has already come, such as the start of the run, takes srv
// down before armTimers returns. Once stop has returned, no outage begins.
// It logs each outage to logger, and records it with record.
func armTimers(timers []sftpproxy.Timer, srv *sshfront.Server, logger *slog.Logger, record func(events.Event)) (stop func()) {
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
			described := sftpproxy.FaultAttrs(down, "timer")
			logger.Info("injected fault", described...)
			record(events.Event{Kind: events.FaultInjected, Rule: t.Rule, Fault: describe(described)})
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
// and returns why it ended: atLimit once d has passed, "canceled" for
// release, which closes when a rule is removed, "released" for stalls, or
// "session_ended" for ctx.
func wait(ctx context.Context, d time.Duration, release, stalls <-chan struct{}, atLimit string) (reason string) {
	timer := time.NewTimer(d)
	defer timer.Stop()
	select {
	case <-timer.C:
		return atLimit
	case <-ctx.Done():
		return "session_ended"
	case <-release:
		return "canceled"
	case <-stalls:
		return "released"
	}
}
