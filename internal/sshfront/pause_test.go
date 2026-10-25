package sshfront_test

import (
	"context"
	"errors"
	"io"
	"log/slog"
	"net"
	"testing"
	"time"

	"golang.org/x/crypto/ssh"

	"github.com/nebarg/sftpit/internal/sshfront"
)

const admissionClosed = "INFO closed a connection while admission is closed"

func TestPauseEndsEveryConnectionAndAdmitsNoneUntilResume(t *testing.T) {
	handler, conns, returned := connPublisher()
	logs := make(messages, 64)
	addr, srv := startServer(t, sshfront.Config{
		Handler: handler,
		Logger:  slog.New(logs),
	})
	client := mustDial(t, addr, "test", ssh.Password(testPassword))
	openSFTP(t, client, conns)
	ended := waitForClient(client)

	if err := srv.Pause(t.Context()); err != nil {
		t.Fatalf("Pause: %v", err)
	}
	if len(returned) != 1 {
		t.Error("Pause returned before the connection's handler")
	}
	receive(t, ended)
	assertClosedBeforeHandshake(t, addr)
	awaitLog(t, logs, admissionClosed)

	srv.Resume()
	openSFTP(t, mustDial(t, addr, "test", ssh.Password(testPassword)), conns)
}

func TestPauseEndsAnOutage(t *testing.T) {
	handler, conns, _ := connPublisher()
	logs := make(messages, 64)
	addr, srv := startServer(t, sshfront.Config{
		Handler: handler,
		Logger:  slog.New(logs),
	})
	awaitServing(t, addr)
	srv.Down(time.Minute, false)

	if err := srv.Pause(t.Context()); err != nil {
		t.Fatalf("Pause: %v", err)
	}
	if _, down := srv.Outage(); down {
		t.Error("the server is still down after Pause")
	}
	awaitLog(t, logs, listeningAgain)
	srv.Down(time.Minute, true)
	if _, down := srv.Outage(); down {
		t.Error("Down took the server down while admission was closed")
	}
	assertClosedBeforeHandshake(t, addr)

	srv.Resume()
	openSFTP(t, mustDial(t, addr, "test", ssh.Password(testPassword)), conns)
}

func TestPauseStopsWaitingWhenItsContextIsDone(t *testing.T) {
	release := make(chan struct{})
	started := make(chan struct{}, 1)
	addr, srv := startServer(t, sshfront.Config{
		Handler: func(context.Context, *sshfront.Conn, io.ReadWriteCloser) error {
			started <- struct{}{}
			<-release
			return nil
		},
	})
	client := mustDial(t, addr, "test", ssh.Password(testPassword))
	session, err := client.NewSession()
	if err != nil {
		t.Fatalf("NewSession: %v", err)
	}
	defer session.Close()
	if err := session.RequestSubsystem("sftp"); err != nil {
		t.Fatalf("RequestSubsystem(sftp): %v", err)
	}
	receive(t, started)

	ctx, cancel := context.WithTimeout(t.Context(), 100*time.Millisecond)
	defer cancel()
	if err := srv.Pause(ctx); !errors.Is(err, context.DeadlineExceeded) {
		t.Errorf("Pause with a handler that has not returned = %v, want the deadline exceeded", err)
	}
	assertClosedBeforeHandshake(t, addr)

	close(release)
	if err := srv.Pause(t.Context()); err != nil {
		t.Errorf("Pause once the handler has returned: %v", err)
	}
}

func TestPauseEndsAHandshakeHeldByAHook(t *testing.T) {
	entered := make(chan struct{}, 1)
	addr, srv := startServer(t, sshfront.Config{
		Hooks: sshfront.Hooks{Connect: func(ctx context.Context, _ *sshfront.Conn) {
			entered <- struct{}{}
			<-ctx.Done()
		}},
	})
	raw, err := net.Dial("tcp", addr)
	if err != nil {
		t.Fatalf("Dial: %v", err)
	}
	defer raw.Close()
	receive(t, entered)
	// The client closes its end on the server's FIN, as a real one does, so
	// that Pause need not wait out the drain.
	go func() {
		io.Copy(io.Discard, raw)
		raw.Close()
	}()

	paused := make(chan error, 1)
	go func() { paused <- srv.Pause(t.Context()) }()
	if err := receive(t, paused); err != nil {
		t.Errorf("Pause: %v", err)
	}
}

func TestPauseAfterClose(t *testing.T) {
	srv := newServer(t, sshfront.Config{})
	srv.Close()
	if err := srv.Pause(t.Context()); !errors.Is(err, sshfront.ErrServerClosed) {
		t.Errorf("Pause after Close = %v, want ErrServerClosed", err)
	}
}

// assertClosedBeforeHandshake checks that the server at addr accepts a
// connection and closes it without sending its version.
func assertClosedBeforeHandshake(t *testing.T, addr string) {
	t.Helper()
	raw, err := net.Dial("tcp", addr)
	if err != nil {
		t.Fatalf("Dial while admission is closed = %v, want the connection accepted", err)
	}
	defer raw.Close()
	if err := raw.SetDeadline(time.Now().Add(waitTimeout)); err != nil {
		t.Fatalf("SetDeadline: %v", err)
	}
	if got, err := io.ReadAll(raw); err != nil || len(got) > 0 {
		t.Errorf("the server sent %q (%v), want the connection closed before its handshake", got, err)
	}
}
