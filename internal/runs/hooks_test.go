package runs

import (
	"context"
	"errors"
	"io"
	"log/slog"
	"net"
	"testing"
	"time"

	"github.com/nebarg/sftpit/internal/faults"
	"github.com/nebarg/sftpit/internal/sftpproxy"
	"github.com/nebarg/sftpit/internal/sshfront"
)

func TestFaultsAtConnectEndWithTheHandshake(t *testing.T) {
	tests := []struct {
		name   string
		action sftpproxy.Action
	}{
		{"delay", sftpproxy.Delay{Duration: time.Minute}},
		{"freeze", sftpproxy.Freeze{Limit: time.Minute}},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			addr, _, _ := serveWithHooks(t, tt.action, 300*time.Millisecond)
			raw, err := net.Dial("tcp", addr)
			if err != nil {
				t.Fatalf("Dial: %v", err)
			}
			defer raw.Close()
			if err := raw.SetDeadline(time.Now().Add(5 * time.Second)); err != nil {
				t.Fatalf("SetDeadline: %v", err)
			}
			if _, err := io.ReadAll(raw); err != nil {
				t.Errorf("the connection was not closed at the handshake timeout: %v", err)
			}
		})
	}
}

func TestShutdownDuringAFreezeIsNoFailure(t *testing.T) {
	addr, srv, logs := serveWithHooks(t, sftpproxy.Freeze{Limit: time.Minute}, time.Minute)
	raw, err := net.Dial("tcp", addr)
	if err != nil {
		t.Fatalf("Dial: %v", err)
	}
	defer raw.Close()
	for msg := ""; msg != "injected fault"; {
		select {
		case msg = <-logs:
		case <-time.After(5 * time.Second):
			t.Fatal("the freeze was not injected")
		}
	}

	closed := make(chan error, 1)
	go func() { closed <- srv.Close() }()
	select {
	case err := <-closed:
		if err != nil {
			t.Errorf("Close: %v", err)
		}
	case <-time.After(5 * time.Second):
		t.Fatal("Close waited for the freeze")
	}
	for len(logs) > 0 {
		if msg := <-logs; msg == "injecting a fault failed" {
			t.Errorf("closing the frozen connection at shutdown was logged as a failure")
		}
	}
}

// serveWithHooks serves connections whose connect gets action, with the
// handshake timeout given, and returns the server's address, the server
// and the messages it logs.
func serveWithHooks(t *testing.T, action sftpproxy.Action, handshakeTimeout time.Duration) (string, *sshfront.Server, messages) {
	t.Helper()
	logs := make(messages, 64)
	logger := slog.New(logs)
	rules, err := faults.New([]faults.Rule{{ID: "connect", Match: faults.Match{Operations: []faults.Operation{faults.Connect}}, Action: action}}, 0, logger)
	if err != nil {
		t.Fatalf("faults.New: %v", err)
	}
	hostKeys, err := sshfront.LoadOrCreateHostKeys(t.TempDir())
	if err != nil {
		t.Fatalf("LoadOrCreateHostKeys: %v", err)
	}
	srv, err := sshfront.New(sshfront.Config{
		HostKeys:         hostKeys,
		Users:            []sshfront.User{{Name: "test", Password: "test"}},
		Handler:          func(context.Context, *sshfront.Conn, io.ReadWriteCloser) error { return nil },
		Hooks:            Hooks(rules, logger),
		HandshakeTimeout: handshakeTimeout,
		Logger:           logger,
	})
	if err != nil {
		t.Fatalf("sshfront.New: %v", err)
	}
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatalf("Listen: %v", err)
	}
	served := make(chan error, 1)
	go func() { served <- srv.Serve(ln) }()
	t.Cleanup(func() {
		srv.Close()
		if err := <-served; !errors.Is(err, sshfront.ErrServerClosed) {
			t.Errorf("Serve: %v", err)
		}
	})
	return ln.Addr().String(), srv, logs
}

// messages is a slog handler that sends the message of each record to it,
// dropping those that do not fit.
type messages chan string

func (m messages) Enabled(context.Context, slog.Level) bool { return true }

func (m messages) Handle(_ context.Context, r slog.Record) error {
	select {
	case m <- r.Message:
	default:
	}
	return nil
}

func (m messages) WithAttrs([]slog.Attr) slog.Handler { return m }
func (m messages) WithGroup(string) slog.Handler      { return m }
