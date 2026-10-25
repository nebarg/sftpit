package sshfront_test

import (
	"errors"
	"io"
	"net"
	"syscall"
	"testing"
	"time"

	"golang.org/x/crypto/ssh"

	"github.com/nebarg/sftpit/internal/sshfront"
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

// TestConnCloseWithDataUnread checks that a normal close reaches the client
// as a close even when the server has not read everything it sent, which
// would otherwise make the kernel reset the connection.
func TestConnCloseWithDataUnread(t *testing.T) {
	client, conn, returned := connectedClient(t)
	clientDone := waitForClient(client)

	// While the connection is frozen the server reads nothing.
	conn.Freeze()
	for range 100 {
		if _, _, err := client.SendRequest("unread", false, make([]byte, 1024)); err != nil {
			t.Fatalf("SendRequest: %v", err)
		}
	}
	time.Sleep(100 * time.Millisecond)

	start := time.Now()
	if err := conn.Close(); err != nil {
		t.Fatalf("Close: %v", err)
	}
	if err := receive(t, clientDone); !errors.Is(err, io.EOF) {
		t.Errorf("client saw %v, want EOF from a normal close", err)
	}
	if elapsed := time.Since(start); elapsed >= sshfront.DrainTimeout {
		t.Errorf("client saw the close after %v, want it before the server stopped waiting", elapsed)
	}
	receive(t, returned)
}

// TestConnCloseStopsWaitingForTheClient checks that a normal close gives up
// on a client that never closes its end, at its timeout or when the server
// closes, whichever comes first.
func TestConnCloseStopsWaitingForTheClient(t *testing.T) {
	tests := []struct {
		name        string
		closeServer bool
		// wait is how long the connection's handler takes to return, at
		// least or at most.
		wait  time.Duration
		least bool
	}{
		{name: "timeout", wait: sshfront.DrainTimeout, least: true},
		{name: "server closed", closeServer: true, wait: sshfront.DrainTimeout / 2},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			handler, conns, returned := connPublisher()
			addr, srv := startServer(t, sshfront.Config{
				Handler: handler,
			})
			client, _ := lingeringClient(t, addr)
			conn := openSFTP(t, client, conns)

			start := time.Now()
			if err := conn.Close(); err != nil {
				t.Fatalf("Close: %v", err)
			}
			if tt.closeServer {
				if err := srv.Close(); err != nil {
					t.Fatalf("server Close: %v", err)
				}
			}
			receive(t, returned)
			elapsed := time.Since(start)
			if tt.least && elapsed < tt.wait {
				t.Errorf("handler returned after %v, want at least %v", elapsed, tt.wait)
			}
			if !tt.least && elapsed > tt.wait {
				t.Errorf("handler returned after %v, want at most %v", elapsed, tt.wait)
			}
		})
	}
}

func TestConnCloseAfterTheClientResets(t *testing.T) {
	handler, conns, returned := connPublisher()
	addr, _ := startServer(t, sshfront.Config{
		Handler: handler,
	})
	client, raw := lingeringClient(t, addr)
	conn := openSFTP(t, client, conns)

	// Frozen, the server cannot notice the reset before it closes.
	conn.Freeze()
	if err := raw.SetLinger(0); err != nil {
		t.Fatalf("SetLinger: %v", err)
	}
	raw.Close()
	time.Sleep(100 * time.Millisecond)

	if err := conn.Close(); err != nil {
		t.Errorf("Close = %v, want nil", err)
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

func TestConnFreezeWithholdsKeepalives(t *testing.T) {
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

	if err := conn.Close(); err != nil {
		t.Fatalf("Close: %v", err)
	}
	if err := receive(t, replied); err == nil {
		t.Error("keepalive answered once the frozen connection closed")
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
		Handler: handler,
	})
	client := mustDial(t, addr, "test", ssh.Password(testPassword))
	return client, openSFTP(t, client, conns), returned
}

// lingeringClient logs in to addr over a connection that stays open when the
// client closes it, as one does for a client that ignores the server's close,
// and returns the client and its connection.
func lingeringClient(t *testing.T, addr string) (*ssh.Client, *net.TCPConn) {
	t.Helper()
	raw, err := net.Dial("tcp", addr)
	if err != nil {
		t.Fatalf("Dial: %v", err)
	}
	t.Cleanup(func() { raw.Close() })
	c, chans, reqs, err := ssh.NewClientConn(lingeringConn{raw}, addr, &ssh.ClientConfig{
		User:            "test",
		Auth:            []ssh.AuthMethod{ssh.Password(testPassword)},
		HostKeyCallback: trustHostKeys,
	})
	if err != nil {
		t.Fatalf("login: %v", err)
	}
	return ssh.NewClient(c, chans, reqs), raw.(*net.TCPConn)
}

type lingeringConn struct{ net.Conn }

func (lingeringConn) Close() error { return nil }
