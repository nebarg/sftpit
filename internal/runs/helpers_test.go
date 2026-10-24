package runs

import (
	"bytes"
	"context"
	"crypto/ed25519"
	"crypto/rand"
	"errors"
	"log/slog"
	"net"
	"sync"
	"testing"
	"time"

	"github.com/pkg/sftp"
	"golang.org/x/crypto/ssh"

	"github.com/nebarg/sftpit/internal/backend"
	"github.com/nebarg/sftpit/internal/sshfront"
)

const (
	testUser     = "test"
	testPassword = "test-password"
	waitTimeout  = 5 * time.Second
)

// startManager starts runs in a new workspace with opts, for testUser, and
// serves them on a loopback port, returning the manager and the address.
func startManager(t *testing.T, opts Options) (*Manager, string) {
	t.Helper()
	w, err := OpenWorkspace(t.TempDir())
	if err != nil {
		t.Fatalf("OpenWorkspace: %v", err)
	}
	t.Cleanup(func() { w.Close() })
	opts.Server.HostKeys = []ssh.Signer{newHostKey(t)}
	if opts.Server.Users == nil {
		opts.Server.Users = []sshfront.User{{Name: testUser, Password: testPassword, Home: "/"}}
	}
	if opts.Limits == (backend.Limits{}) {
		opts.Limits = backend.Limits{MaxFileBytes: 1 << 30, MaxTotalBytes: 1 << 30, MaxFiles: 1000, MaxOpenFiles: 100}
	}
	if opts.Logger == nil {
		opts.Logger = slog.New(slog.DiscardHandler)
	}
	m, err := Start(w, opts)
	if err != nil {
		t.Fatalf("Start: %v", err)
	}
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatalf("Listen: %v", err)
	}
	served := make(chan error, 1)
	go func() { served <- m.Server().Serve(ln) }()
	t.Cleanup(func() {
		if err := m.Close(); err != nil {
			t.Errorf("Close: %v", err)
		}
		if err := <-served; !errors.Is(err, sshfront.ErrServerClosed) {
			t.Errorf("Serve: %v", err)
		}
	})
	return m, ln.Addr().String()
}

// newHostKey returns a new Ed25519 host key, which is quicker to make than
// the RSA key that sshfront.LoadOrCreateHostKeys makes too.
func newHostKey(t *testing.T) ssh.Signer {
	t.Helper()
	_, key, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	signer, err := ssh.NewSignerFromKey(key)
	if err != nil {
		t.Fatal(err)
	}
	return signer
}

// dialSFTP logs in to the server at addr as testUser and starts an SFTP
// session, returning the client and a channel that receives once the
// connection ends.
func dialSFTP(t *testing.T, addr string) (*sftp.Client, <-chan error) {
	t.Helper()
	conn := dialSSH(t, addr)
	ended := make(chan error, 1)
	go func() { ended <- conn.Wait() }()
	c, err := sftp.NewClient(conn)
	if err != nil {
		t.Fatalf("sftp.NewClient: %v", err)
	}
	t.Cleanup(func() { c.Close() })
	return c, ended
}

// dialSSH logs in to the server at addr as testUser.
func dialSSH(t *testing.T, addr string) *ssh.Client {
	t.Helper()
	conn, err := ssh.Dial("tcp", addr, &ssh.ClientConfig{
		User:            testUser,
		Auth:            []ssh.AuthMethod{ssh.Password(testPassword)},
		HostKeyCallback: ssh.InsecureIgnoreHostKey(),
		Timeout:         waitTimeout,
	})
	if err != nil {
		t.Fatalf("ssh.Dial: %v", err)
	}
	t.Cleanup(func() { conn.Close() })
	return conn
}

func receive[T any](t *testing.T, ch <-chan T) T {
	t.Helper()
	select {
	case v := <-ch:
		return v
	case <-time.After(waitTimeout):
		t.Fatal("timed out waiting")
		var zero T
		return zero
	}
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

// syncBuffer is a bytes.Buffer that is safe for concurrent use, for logs
// that a run's sessions write.
type syncBuffer struct {
	mu  sync.Mutex
	buf bytes.Buffer
}

func (b *syncBuffer) Write(p []byte) (int, error) {
	b.mu.Lock()
	defer b.mu.Unlock()
	return b.buf.Write(p)
}

func (b *syncBuffer) String() string {
	b.mu.Lock()
	defer b.mu.Unlock()
	return b.buf.String()
}
