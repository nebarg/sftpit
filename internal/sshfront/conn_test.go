package sshfront_test

import (
	"errors"
	"io"
	"syscall"
	"testing"
	"time"

	"golang.org/x/crypto/ssh"

	"sftpit/internal/sshfront"
)

func TestConnClose(t *testing.T) {
	client, conn, returned := connectedClient(t)
	clientDone := waitForClient(client)

	if err := conn.Close(); err != nil {
		t.Fatalf("Close: %v", err)
	}

	if err := receive(t, clientDone); !errors.Is(err, io.EOF) {
		t.Errorf("client saw %v, want EOF from a normal close", err)
	}
	receive(t, returned)
}

func TestConnReset(t *testing.T) {
	client, conn, returned := connectedClient(t)
	clientDone := waitForClient(client)

	if err := conn.Reset(); err != nil {
		t.Fatalf("Reset: %v", err)
	}

	if err := receive(t, clientDone); !errors.Is(err, syscall.ECONNRESET) {
		t.Errorf("client saw %v, want a connection reset", err)
	}
	receive(t, returned)
}

func TestConnFreezeWithholdsKeepalivesUntilThaw(t *testing.T) {
	client, conn, _ := connectedClient(t)

	conn.Freeze()
	replied := make(chan error, 1)
	go func() {
		_, _, err := client.SendRequest("keepalive@openssh.com", true, nil)
		replied <- err
	}()

	select {
	case err := <-replied:
		t.Fatalf("keepalive answered while frozen (err %v)", err)
	case <-time.After(300 * time.Millisecond):
	}

	conn.Thaw()
	if err := receive(t, replied); err != nil {
		t.Fatalf("keepalive after thaw: %v", err)
	}
}

func TestConnCloseWhileFrozen(t *testing.T) {
	client, conn, returned := connectedClient(t)
	clientDone := waitForClient(client)

	conn.Freeze()
	closed := make(chan error, 1)
	go func() { closed <- conn.Close() }()

	if err := receive(t, closed); err != nil {
		t.Fatalf("Close: %v", err)
	}
	receive(t, clientDone)
	receive(t, returned)
}

func connectedClient(t *testing.T) (*ssh.Client, *sshfront.Conn, <-chan struct{}) {
	t.Helper()
	handler, conns, returned := connPublisher()
	addr, _ := startServer(t, sshfront.Config{
		Users:   []sshfront.User{{Name: "test", Password: testPassword}},
		Handler: handler,
	})
	client := mustDial(t, addr, "test", ssh.Password(testPassword))
	return client, openSFTP(t, client, conns), returned
}

func waitForClient(client *ssh.Client) <-chan error {
	done := make(chan error, 1)
	go func() { done <- client.Wait() }()
	return done
}
