package sshfront_test

import (
	"errors"
	"fmt"
	"io"
	"log/slog"
	"net"
	"syscall"
	"testing"
	"time"

	"golang.org/x/crypto/ssh"

	"github.com/nebarg/sftpit/internal/sshfront"
	"github.com/nebarg/sftpit/internal/testutil"
)

func TestDownRefusesConnectionsUntilItEnds(t *testing.T) {
	handler, conns, _ := connPublisher()
	logs := make(messages, 16)
	addr, srv := startServer(t, sshfront.Config{
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
	testutil.ReceiveUntil(t, logs, listeningAgain)
	if took := time.Since(start); took < 300*time.Millisecond {
		t.Errorf("the outage lasted %v, want 300ms", took)
	}
	client := mustDial(t, addr, "test", ssh.Password(testPassword))
	openSFTP(t, client, conns)
}

func TestDownClosesExistingConnectionsIfAsked(t *testing.T) {
	for _, closeExisting := range []bool{false, true} {
		t.Run(fmt.Sprintf("closeExisting=%v", closeExisting), func(t *testing.T) {
			handler, conns, returned := connPublisher()
			addr, srv := startServer(t, sshfront.Config{Handler: handler})
			client := mustDial(t, addr, "test", ssh.Password(testPassword))
			openSFTP(t, client, conns)

			srv.Down(time.Minute, closeExisting)
			select {
			case err := <-waitForClient(client):
				if !closeExisting {
					t.Errorf("without close_existing, the outage closed an existing connection: %v", err)
				}
			case <-time.After(200 * time.Millisecond):
				if closeExisting {
					t.Error("with close_existing, an existing connection outlasted the outage's start")
				}
			}
			if closeExisting {
				testutil.Receive(t, returned)
			}
		})
	}
}

func TestDownExtendsAnOutageThatWouldEndSooner(t *testing.T) {
	logs := make(messages, 16)
	_, srv := startServer(t, sshfront.Config{
		Logger: slog.New(logs),
	})

	start := time.Now()
	srv.Down(200*time.Millisecond, false)
	srv.Down(600*time.Millisecond, false)
	srv.Down(100*time.Millisecond, false)
	testutil.ReceiveUntil(t, logs, listeningAgain)
	if took := time.Since(start); took < 600*time.Millisecond {
		t.Errorf("the outage lasted %v, want the longest one asked for, 600ms", took)
	}
}

func TestCloseEndsAnOutage(t *testing.T) {
	_, srv := startServer(t, sshfront.Config{})
	srv.Down(time.Minute, false)

	closed := make(chan error, 1)
	go func() { closed <- srv.Close() }()
	if err := testutil.Receive(t, closed); err != nil {
		t.Fatalf("Close: %v", err)
	}
}

func TestServeListensAgainOnceItCan(t *testing.T) {
	handler, conns, _ := connPublisher()
	logs := make(messages, 64)
	addr, srv := startServer(t, sshfront.Config{
		Handler: handler,
		Logger:  slog.New(logs),
	})
	awaitServing(t, addr)

	srv.Down(100*time.Millisecond, false)
	squatter, err := net.Listen("tcp", addr)
	if err != nil {
		t.Fatalf("Listen during the outage: %v", err)
	}
	testutil.ReceiveUntil(t, logs, "WARN listening again after an outage failed; retrying")
	squatter.Close()
	testutil.ReceiveUntil(t, logs, listeningAgain)
	client := mustDial(t, addr, "test", ssh.Password(testPassword))
	openSFTP(t, client, conns)
}

func TestAConnectionAcceptedAsAnOutageBeginsIsClosed(t *testing.T) {
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatalf("Listen: %v", err)
	}
	held := &heldListener{Listener: ln, accepted: make(chan struct{}), release: make(chan struct{})}
	srv := serve(t, held, sshfront.Config{})
	raw, err := net.Dial("tcp", ln.Addr().String())
	if err != nil {
		t.Fatalf("Dial: %v", err)
	}
	defer raw.Close()
	testutil.Receive(t, held.accepted)

	srv.Down(time.Minute, false)
	close(held.release)
	if err := raw.SetDeadline(time.Now().Add(waitTimeout)); err != nil {
		t.Fatalf("SetDeadline: %v", err)
	}
	if got, err := io.ReadAll(raw); err != nil || len(got) > 0 {
		t.Errorf("the server sent %q (%v), want the connection closed before its handshake", got, err)
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
