package sshfront_test

import (
	"bytes"
	"context"
	"crypto/ed25519"
	"crypto/rand"
	"errors"
	"fmt"
	"io"
	"log/slog"
	"net"
	"os"
	"testing"
	"time"

	"github.com/pkg/sftp"
	"golang.org/x/crypto/ssh"

	"github.com/nebarg/sftpit/internal/sshfront"
	"github.com/nebarg/sftpit/internal/testutil"
)

const (
	testPassword   = "test-password"
	waitTimeout    = testutil.WaitTimeout
	listeningAgain = "INFO listening again after an outage"
)

var hostKeys []ssh.Signer

func TestMain(m *testing.M) {
	dir, err := os.MkdirTemp("", "sshfront-hostkeys-")
	if err != nil {
		fmt.Fprintln(os.Stderr, err)
		os.Exit(1)
	}
	code := 1
	hostKeys, err = sshfront.LoadOrCreateHostKeys(dir)
	if err != nil {
		fmt.Fprintln(os.Stderr, err)
	} else {
		code = m.Run()
	}
	os.RemoveAll(dir)
	os.Exit(code)
}

// newServer returns a server with the test host keys. Users default to the
// test user, the handler to inMemorySFTP, and the logger to one that
// discards.
func newServer(t *testing.T, cfg sshfront.Config) *sshfront.Server {
	t.Helper()
	cfg.HostKeys = hostKeys
	if cfg.Users == nil {
		cfg.Users = []sshfront.User{{Name: "test", Password: testPassword}}
	}
	if cfg.Handler == nil {
		cfg.Handler = inMemorySFTP
	}
	if cfg.Logger == nil {
		cfg.Logger = slog.New(slog.DiscardHandler)
	}
	srv, err := sshfront.New(cfg)
	if err != nil {
		t.Fatalf("New: %v", err)
	}
	return srv
}

func startServer(t *testing.T, cfg sshfront.Config) (string, *sshfront.Server) {
	t.Helper()
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatalf("Listen: %v", err)
	}
	srv := serve(t, ln, cfg)
	return ln.Addr().String(), srv
}

func serve(t *testing.T, ln net.Listener, cfg sshfront.Config) *sshfront.Server {
	t.Helper()
	srv := newServer(t, cfg)
	served := make(chan error, 1)
	go func() { served <- srv.Serve(ln) }()
	t.Cleanup(func() {
		if err := srv.Close(); err != nil {
			t.Errorf("Close: %v", err)
		}
		if err := <-served; !errors.Is(err, sshfront.ErrServerClosed) {
			t.Errorf("Serve returned %v, want ErrServerClosed", err)
		}
	})
	return srv
}

func dial(addr, user string, auth ssh.AuthMethod) (*ssh.Client, error) {
	return ssh.Dial("tcp", addr, &ssh.ClientConfig{
		User:            user,
		Auth:            []ssh.AuthMethod{auth},
		HostKeyCallback: trustHostKeys,
		Timeout:         waitTimeout,
	})
}

func mustDial(t *testing.T, addr, user string, auth ssh.AuthMethod) *ssh.Client {
	t.Helper()
	client, err := dial(addr, user, auth)
	if err != nil {
		t.Fatalf("login as %s: %v", user, err)
	}
	t.Cleanup(func() { client.Close() })
	return client
}

func trustHostKeys(_ string, _ net.Addr, key ssh.PublicKey) error {
	for _, hostKey := range hostKeys {
		if bytes.Equal(hostKey.PublicKey().Marshal(), key.Marshal()) {
			return nil
		}
	}
	return errors.New("unknown host key")
}

func newClientKey(t *testing.T) ssh.Signer {
	t.Helper()
	_, key, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatalf("generate client key: %v", err)
	}
	signer, err := ssh.NewSignerFromKey(key)
	if err != nil {
		t.Fatalf("client signer: %v", err)
	}
	return signer
}

// connPublisher returns a handler that publishes each connection it serves
// and holds the channel open until the connection ends, plus channels that
// receive the connections and signal each handler's return.
func connPublisher() (sshfront.Handler, <-chan *sshfront.Conn, <-chan struct{}) {
	conns := make(chan *sshfront.Conn, 16)
	returned := make(chan struct{}, 16)
	handler := func(ctx context.Context, conn *sshfront.Conn, _ io.ReadWriteCloser) error {
		conns <- conn
		<-ctx.Done()
		returned <- struct{}{}
		return nil
	}
	return handler, conns, returned
}

func inMemorySFTP(_ context.Context, _ *sshfront.Conn, channel io.ReadWriteCloser) error {
	err := sftp.NewRequestServer(channel, sftp.InMemHandler()).Serve()
	if errors.Is(err, io.EOF) {
		return nil
	}
	return err
}

func openSFTP(t *testing.T, client *ssh.Client, conns <-chan *sshfront.Conn) *sshfront.Conn {
	t.Helper()
	session, err := client.NewSession()
	if err != nil {
		t.Fatalf("NewSession: %v", err)
	}
	t.Cleanup(func() { session.Close() })
	if err := session.RequestSubsystem("sftp"); err != nil {
		t.Fatalf("RequestSubsystem(sftp): %v", err)
	}
	return testutil.Receive(t, conns)
}

// messages is a slog handler that sends the level and message of each
// record to it.
type messages chan string

func (m messages) Enabled(context.Context, slog.Level) bool { return true }

func (m messages) Handle(_ context.Context, r slog.Record) error {
	m <- r.Level.String() + " " + r.Message
	return nil
}

func (m messages) WithAttrs([]slog.Attr) slog.Handler { return m }
func (m messages) WithGroup(string) slog.Handler      { return m }

func waitForClient(client *ssh.Client) <-chan error {
	done := make(chan error, 1)
	go func() { done <- client.Wait() }()
	return done
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
