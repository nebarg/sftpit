package sshfront_test

import (
	"errors"
	"io"
	"log/slog"
	"net"
	"syscall"
	"testing"
	"time"

	"golang.org/x/crypto/ssh"

	"github.com/nebarg/sftpit/internal/sshfront"
)

const listeningAgain = "INFO listening again after an outage"

func TestDownRefusesConnectionsUntilItEnds(t *testing.T) {
	handler, conns, _ := connPublisher()
	logs := make(messages, 16)
	addr, srv := startServer(t, sshfront.Config{
		Users:   []sshfront.User{{Name: "test", Password: testPassword}},
		Handler: handler,
		Logger:  slog.New(logs),
	})
	awaitServing(t, addr)

	start := time.Now()
	srv.Down(300*time.Millisecond, false)
	if raw, err := net.Dial("tcp", addr); !errors.Is(err, syscall.ECONNREFUSED) {
		if err == nil {
			raw.Close()
		}
		t.Fatalf("Dial during the outage = %v, want the connection refused", err)
	}
	awaitLog(t, logs, listeningAgain)
	if took := time.Since(start); took < 300*time.Millisecond {
		t.Errorf("the outage lasted %v, want 300ms", took)
	}
	client := mustDial(t, addr, "test", ssh.Password(testPassword))
	openSFTP(t, client, conns)
}

func TestDownClosesExistingConnectionsIfAsked(t *testing.T) {
	for _, closeExisting := range []bool{false, true} {
		handler, conns, returned := connPublisher()
		addr, srv := startServer(t, sshfront.Config{
			Users:   []sshfront.User{{Name: "test", Password: testPassword}},
			Handler: handler,
		})
		client := mustDial(t, addr, "test", ssh.Password(testPassword))
		openSFTP(t, client, conns)

		srv.Down(time.Minute, closeExisting)
		ended := make(chan error, 1)
		go func() { ended <- client.Wait() }()
		select {
		case <-ended:
			if !closeExisting {
				t.Error("without close_existing, the outage closed an existing connection")
			}
		case <-time.After(200 * time.Millisecond):
			if closeExisting {
				t.Error("with close_existing, an existing connection outlasted the outage's start")
			}
		}
		if closeExisting {
			receive(t, returned)
		}
	}
}

func TestDownExtendsAnOutageThatWouldEndSooner(t *testing.T) {
	handler, _, _ := connPublisher()
	logs := make(messages, 16)
	_, srv := startServer(t, sshfront.Config{
		Users:   []sshfront.User{{Name: "test", Password: testPassword}},
		Handler: handler,
		Logger:  slog.New(logs),
	})

	start := time.Now()
	srv.Down(200*time.Millisecond, false)
	srv.Down(600*time.Millisecond, false)
	srv.Down(100*time.Millisecond, false)
	awaitLog(t, logs, listeningAgain)
	if took := time.Since(start); took < 600*time.Millisecond {
		t.Errorf("the outage lasted %v, want the longest one asked for, 600ms", took)
	}
}

func TestCloseEndsAnOutage(t *testing.T) {
	handler, _, _ := connPublisher()
	_, srv := startServer(t, sshfront.Config{
		Users:   []sshfront.User{{Name: "test", Password: testPassword}},
		Handler: handler,
	})
	srv.Down(time.Minute, false)

	closed := make(chan error, 1)
	go func() { closed <- srv.Close() }()
	if err := receive(t, closed); err != nil {
		t.Fatalf("Close: %v", err)
	}
}

func TestServeListensAgainOnceItCan(t *testing.T) {
	handler, conns, _ := connPublisher()
	logs := make(messages, 64)
	addr, srv := startServer(t, sshfront.Config{
		Users:   []sshfront.User{{Name: "test", Password: testPassword}},
		Handler: handler,
		Logger:  slog.New(logs),
	})
	awaitServing(t, addr)

	srv.Down(100*time.Millisecond, false)
	squatter, err := net.Listen("tcp", addr)
	if err != nil {
		t.Fatalf("Listen during the outage: %v", err)
	}
	awaitLog(t, logs, "WARN listening again after an outage failed; retrying")
	squatter.Close()
	awaitLog(t, logs, listeningAgain)
	client := mustDial(t, addr, "test", ssh.Password(testPassword))
	openSFTP(t, client, conns)
}

func TestAConnectionAcceptedAsAnOutageBeginsIsClosed(t *testing.T) {
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatalf("Listen: %v", err)
	}
	held := &heldListener{Listener: ln, accepted: make(chan struct{}), release: make(chan struct{})}
	handler, _, _ := connPublisher()
	srv := serve(t, held, sshfront.Config{
		Users:   []sshfront.User{{Name: "test", Password: testPassword}},
		Handler: handler,
	})
	raw, err := net.Dial("tcp", ln.Addr().String())
	if err != nil {
		t.Fatalf("Dial: %v", err)
	}
	defer raw.Close()
	receive(t, held.accepted)

	srv.Down(time.Minute, false)
	close(held.release)
	if err := raw.SetDeadline(time.Now().Add(waitTimeout)); err != nil {
		t.Fatalf("SetDeadline: %v", err)
	}
	if got, err := io.ReadAll(raw); err != nil || len(got) > 0 {
		t.Errorf("the server sent %q (%v), want the connection closed before its handshake", got, err)
	}
}

// awaitLog waits until the server logs want, whatever it logs before.
func awaitLog(t *testing.T, logs messages, want string) {
	t.Helper()
	for msg := receive(t, logs); msg != want; msg = receive(t, logs) {
	}
}

// awaitServing waits until the server at addr sends its SSH version, which
// it does once it accepts connections.
func awaitServing(t *testing.T, addr string) {
	t.Helper()
	raw, err := net.Dial("tcp", addr)
	if err != nil {
		t.Fatalf("Dial: %v", err)
	}
	defer raw.Close()
	if err := raw.SetDeadline(time.Now().Add(waitTimeout)); err != nil {
		t.Fatalf("SetDeadline: %v", err)
	}
	if _, err := raw.Read(make([]byte, 64)); err != nil {
		t.Fatalf("reading the server's version: %v", err)
	}
}

// heldListener holds the first connection it accepts until release is
// closed.
type heldListener struct {
	net.Listener
	accepted chan struct{}
	release  chan struct{}
	once     bool
}

func (l *heldListener) Accept() (net.Conn, error) {
	c, err := l.Listener.Accept()
	if err != nil || l.once {
		return c, err
	}
	l.once = true
	close(l.accepted)
	<-l.release
	return c, nil
}
