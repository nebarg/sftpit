package runs

import (
	"bufio"
	"context"
	"errors"
	"io"
	"log/slog"
	"net"
	"os"
	"sync/atomic"
	"testing"
	"time"

	"github.com/nebarg/sftpit/internal/faults"
	"github.com/nebarg/sftpit/internal/sftpproxy"
	"github.com/nebarg/sftpit/internal/testutil"
)

func TestReleaseStallsLetsAStalledRequestGoOn(t *testing.T) {
	stuck := faults.Rule{ID: "stuck", Match: faults.Match{Operations: []faults.Operation{faults.Stat}}, Action: sftpproxy.Stall{When: sftpproxy.Before, Limit: time.Minute}}
	m, addr := startManager(t, Options{})
	withRules(t, m, stuck)
	run := m.Status().Run.ID
	c, _ := dialSFTP(t, addr)
	for stat := 1; stat <= 2; stat++ {
		done := make(chan error, 1)
		go func() {
			_, err := c.Stat("/")
			done <- err
		}()
		awaitFired(t, m, "stuck", uint64(stat))
		select {
		case err := <-done:
			t.Fatalf("stat %d returned %v before the release", stat, err)
		case <-time.After(100 * time.Millisecond):
		}
		if err := m.ReleaseStalls(run); err != nil {
			t.Fatalf("ReleaseStalls: %v", err)
		}
		if err := testutil.Receive(t, done); err != nil {
			t.Errorf("stat %d after the release = %v", stat, err)
		}
	}
	if err := m.ReleaseStalls("20261024-101500.123-3f9a"); !errors.Is(err, ErrStaleRun) {
		t.Errorf("ReleaseStalls of another run = %v, want ErrStaleRun", err)
	}
}

func TestReleaseStallsClosesAConnectionFrozenAtConnectButLeavesADelay(t *testing.T) {
	tests := []struct {
		name   string
		action sftpproxy.Action
		// closed is set if the release closes the connection, and
		// otherwise the client sees nothing yet.
		closed bool
	}{
		{"freeze", sftpproxy.Freeze{Limit: time.Minute}, true},
		{"delay", sftpproxy.Delay{Duration: time.Minute}, false},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			logs := make(messages, 64)
			held := connectRule(tt.action)
			m, addr := startManager(t, Options{Logger: slog.New(logs)})
			withRules(t, m, held)
			raw, err := net.Dial("tcp", addr)
			if err != nil {
				t.Fatalf("Dial: %v", err)
			}
			defer raw.Close()
			testutil.ReceiveUntil(t, logs, "injected fault")
			if err := m.ReleaseStalls(m.Status().Run.ID); err != nil {
				t.Fatalf("ReleaseStalls: %v", err)
			}
			wait := waitTimeout
			if !tt.closed {
				wait = 300 * time.Millisecond
			}
			if err := raw.SetDeadline(time.Now().Add(wait)); err != nil {
				t.Fatal(err)
			}
			line, err := bufio.NewReader(raw).ReadString('\n')
			switch {
			case tt.closed && (line != "" || !errors.Is(err, io.EOF)):
				t.Errorf("read %q (%v), want the frozen connection closed once released", line, err)
			case !tt.closed && !errors.Is(err, os.ErrDeadlineExceeded):
				t.Errorf("read %q (%v), want the delay to go on", line, err)
			}
			if tt.closed {
				testutil.ReceiveUntil(t, logs, "fault released")
			}
		})
	}
}

func TestAReleaseAsAFreezeAtConnectIsAnnouncedEndsIt(t *testing.T) {
	var m atomic.Pointer[Manager]
	// A release just after the fault is announced must still end it, as
	// one from the API can.
	release := logHook(func(msg string) {
		if msg != "injected fault" {
			return
		}
		if err := m.Load().ReleaseStalls(m.Load().Status().Run.ID); err != nil {
			t.Errorf("ReleaseStalls: %v", err)
		}
	})
	started, addr := startManager(t, Options{Logger: slog.New(release)})
	withRules(t, started, connectRule(sftpproxy.Freeze{Limit: time.Minute}))
	m.Store(started)
	raw, err := net.Dial("tcp", addr)
	if err != nil {
		t.Fatalf("Dial: %v", err)
	}
	defer raw.Close()
	if err := raw.SetDeadline(time.Now().Add(waitTimeout)); err != nil {
		t.Fatal(err)
	}
	if line, err := bufio.NewReader(raw).ReadString('\n'); line != "" || !errors.Is(err, io.EOF) {
		t.Errorf("read %q (%v), want the frozen connection closed once released", line, err)
	}
}

// logHook is a log handler that calls itself with each message.
type logHook func(msg string)

func (h logHook) Enabled(context.Context, slog.Level) bool { return true }

func (h logHook) Handle(_ context.Context, r slog.Record) error {
	h(r.Message)
	return nil
}

func (h logHook) WithAttrs([]slog.Attr) slog.Handler { return h }
func (h logHook) WithGroup(string) slog.Handler      { return h }

func awaitFired(t *testing.T, m *Manager, id string, n uint64) {
	t.Helper()
	deadline := time.Now().Add(waitTimeout)
	for {
		set, err := m.Rules(m.Status().Run.ID)
		if err != nil {
			t.Fatalf("Rules: %v", err)
		}
		if set.Counts[id].Fired >= n {
			return
		}
		if time.Now().After(deadline) {
			t.Fatalf("rule %s has fired %d times, want %d", id, set.Counts[id].Fired, n)
		}
		time.Sleep(10 * time.Millisecond)
	}
}
