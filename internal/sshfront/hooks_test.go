package sshfront_test

import (
	"cmp"
	"context"
	"errors"
	"log/slog"
	"net"
	"testing"
	"time"

	"golang.org/x/crypto/ssh"

	"github.com/nebarg/sftpit/internal/sshfront"
	"github.com/nebarg/sftpit/internal/testutil"
)

// hookCall records what a hook saw of its connection.
type hookCall struct {
	hook        string
	id          uint64
	user        string
	fingerprint string
}

func TestHooksRunBeforeTheHandshakeAndBeforeTheClientIsLoggedIn(t *testing.T) {
	key := newClientKey(t)
	handler, conns, _ := connPublisher()
	calls := make(chan hookCall, 2)
	release := make(chan struct{})
	addr, _ := startServer(t, sshfront.Config{
		Users:   []sshfront.User{{Name: "test", Password: testPassword, AuthorizedKeys: []ssh.PublicKey{key.PublicKey()}}},
		Handler: handler,
		Hooks: sshfront.Hooks{
			Connect: func(_ context.Context, conn *sshfront.Conn) {
				calls <- hookCall{"connect", conn.ID(), conn.User(), conn.KeyFingerprint()}
			},
			Authenticate: func(_ context.Context, conn *sshfront.Conn) {
				calls <- hookCall{"authenticate", conn.ID(), conn.User(), conn.KeyFingerprint()}
				<-release
			},
		},
	})
	keyboardInteractive := ssh.KeyboardInteractive(func(_, _ string, _ []string, _ []bool) ([]string, error) {
		return []string{testPassword}, nil
	})

	tests := []struct {
		name            string
		auth            ssh.AuthMethod
		wantFingerprint string
	}{
		{name: "password", auth: ssh.Password(testPassword)},
		{name: "keyboard-interactive", auth: keyboardInteractive},
		{name: "public key", auth: ssh.PublicKeys(key), wantFingerprint: ssh.FingerprintSHA256(key.PublicKey())},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			dialed := make(chan *ssh.Client, 1)
			go func() {
				client, err := dial(addr, "test", tt.auth)
				if err != nil {
					t.Errorf("login: %v", err)
				}
				dialed <- client
			}()

			connected := testutil.Receive(t, calls)
			if connected.hook != "connect" || connected.user != "" || connected.fingerprint != "" {
				t.Errorf("first hook = %+v, want connect with no user or key", connected)
			}
			authenticated := testutil.Receive(t, calls)
			want := hookCall{"authenticate", connected.id, "test", tt.wantFingerprint}
			if authenticated != want {
				t.Errorf("second hook = %+v, want %+v", authenticated, want)
			}
			select {
			case <-dialed:
				t.Fatal("the client logged in while the Authenticate hook was running")
			case <-time.After(100 * time.Millisecond):
			}
			released := time.Now()
			release <- struct{}{}

			client := testutil.Receive(t, dialed)
			if client == nil {
				return
			}
			defer client.Close()
			conn := openSFTP(t, client, conns)
			if conn.ID() != connected.id {
				t.Errorf("handler's conn.ID() = %d, want %d, the hooks' connection", conn.ID(), connected.id)
			}
			if conn.Authenticated().Before(released) {
				t.Errorf("conn.Authenticated() = %v, want after the hook returned at %v", conn.Authenticated(), released)
			}
		})
	}
}

func TestHooksCanEndTheHandshake(t *testing.T) {
	closeConn := func(_ context.Context, conn *sshfront.Conn) { conn.Close() }
	resetConn := func(_ context.Context, conn *sshfront.Conn) { _ = conn.Reset() }
	tests := []struct {
		name  string
		hooks sshfront.Hooks
	}{
		{name: "close at connect", hooks: sshfront.Hooks{Connect: closeConn}},
		{name: "reset at connect", hooks: sshfront.Hooks{Connect: resetConn}},
		{name: "close at authenticate", hooks: sshfront.Hooks{Authenticate: closeConn}},
		{name: "reset at authenticate", hooks: sshfront.Hooks{Authenticate: resetConn}},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			handler, conns, _ := connPublisher()
			logs := make(messages, 16)
			addr, _ := startServer(t, sshfront.Config{
				Handler: handler,
				Hooks:   tt.hooks,
				Logger:  slog.New(logs),
			})

			if client, err := dial(addr, "test", ssh.Password(testPassword)); err == nil {
				client.Close()
				t.Fatal("login succeeded, want the hook to end it")
			}
			if msg := testutil.Receive(t, logs); msg != "DEBUG ssh handshake ended by the server" {
				t.Errorf("the server logged %q, want the handshake ended, not failed", msg)
			}
			select {
			case conn := <-conns:
				t.Errorf("handler served connection %d, want none", conn.ID())
			default:
			}
		})
	}
}

func TestHandshakeFailureIsLogged(t *testing.T) {
	logs := make(messages, 16)
	addr, _ := startServer(t, sshfront.Config{
		Logger: slog.New(logs),
	})
	raw, err := net.Dial("tcp", addr)
	if err != nil {
		t.Fatalf("Dial: %v", err)
	}
	defer raw.Close()
	// The server fails on reaching the end of the client's version.
	if err := raw.(*net.TCPConn).CloseWrite(); err != nil {
		t.Fatalf("CloseWrite: %v", err)
	}
	if msg := testutil.Receive(t, logs); msg != "INFO ssh handshake failed" {
		t.Errorf("the server logged %q, want the handshake failure", msg)
	}
}

func TestServerCloseEndsHandshakesWithoutFailures(t *testing.T) {
	logs := make(messages, 16)
	entered := make(chan struct{})
	addr, srv := startServer(t, sshfront.Config{
		HandshakeTimeout: time.Minute,
		Logger:           slog.New(logs),
		Hooks:            sshfront.Hooks{Connect: func(context.Context, *sshfront.Conn) { close(entered) }},
	})
	raw, err := net.Dial("tcp", addr)
	if err != nil {
		t.Fatalf("Dial: %v", err)
	}
	defer raw.Close()
	testutil.Receive(t, entered)

	if err := srv.Close(); err != nil {
		t.Fatalf("Close: %v", err)
	}
	if msg := testutil.Receive(t, logs); msg != "DEBUG ssh handshake ended by the server" {
		t.Errorf("the server logged %q, want the handshake ended, not failed", msg)
	}
}

func TestHookContextEnds(t *testing.T) {
	tests := []struct {
		name string
		// connect is the Connect hook, which waits for its ctx.
		connect func(ctx context.Context, conn *sshfront.Conn)
		// end ends the hook's ctx, if the hook does not.
		end     func(t *testing.T, srv *sshfront.Server)
		timeout time.Duration
		want    error
	}{
		{
			name:    "at the handshake timeout",
			connect: func(ctx context.Context, _ *sshfront.Conn) { <-ctx.Done() },
			timeout: 200 * time.Millisecond,
			want:    context.DeadlineExceeded,
		},
		{
			name:    "when the connection closes",
			connect: func(ctx context.Context, conn *sshfront.Conn) { _ = conn.Reset(); <-ctx.Done() },
			want:    context.Canceled,
		},
		{
			name:    "when the server closes",
			connect: func(ctx context.Context, _ *sshfront.Conn) { <-ctx.Done() },
			end: func(t *testing.T, srv *sshfront.Server) {
				t.Helper()
				if err := srv.Close(); err != nil {
					t.Errorf("Close: %v", err)
				}
			},
			want: context.Canceled,
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			entered := make(chan struct{}, 1)
			ended := make(chan error, 1)
			addr, srv := startServer(t, sshfront.Config{
				HandshakeTimeout: cmp.Or(tt.timeout, time.Minute),
				Hooks: sshfront.Hooks{Connect: func(ctx context.Context, conn *sshfront.Conn) {
					entered <- struct{}{}
					tt.connect(ctx, conn)
					ended <- ctx.Err()
				}},
			})
			// A hook that resets the connection at once can make Dial
			// fail, after the server has accepted it.
			if raw, err := net.Dial("tcp", addr); err == nil {
				defer raw.Close()
			}

			testutil.Receive(t, entered)
			if tt.end != nil {
				tt.end(t, srv)
			}
			if err := testutil.Receive(t, ended); !errors.Is(err, tt.want) {
				t.Errorf("hook's ctx.Err() = %v, want %v", err, tt.want)
			}
		})
	}
}
