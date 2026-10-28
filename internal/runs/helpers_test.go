package runs

import (
	"context"
	"crypto/ed25519"
	"crypto/rand"
	"errors"
	"log/slog"
	"net"
	"testing"
	"time"

	"github.com/pkg/sftp"
	"golang.org/x/crypto/ssh"

	"github.com/nebarg/sftpit/internal/backend"
	"github.com/nebarg/sftpit/internal/faults"
	"github.com/nebarg/sftpit/internal/sftpproxy"
	"github.com/nebarg/sftpit/internal/sftpwire"
	"github.com/nebarg/sftpit/internal/sshfront"
	"github.com/nebarg/sftpit/internal/testutil"
)

const (
	testUser     = "test"
	testPassword = "test-password"
	waitTimeout  = testutil.WaitTimeout
)

// newManager starts runs in a new workspace with opts, for testUser, and
// closes them when the test ends. Nothing serves them, so a test of their
// timers alone can run in a synctest bubble.
func newManager(t *testing.T, opts Options) *Manager {
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
	t.Cleanup(func() {
		if err := m.Close(); err != nil {
			t.Errorf("Close: %v", err)
		}
	})
	return m
}

// startManager starts runs as newManager does, and serves them on a
// loopback port, returning the manager and the address.
func startManager(t *testing.T, opts Options) (*Manager, string) {
	t.Helper()
	m := newManager(t, opts)
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatalf("Listen: %v", err)
	}
	served := make(chan error, 1)
	go func() { served <- m.Server().Serve(ln) }()
	// This runs before newManager's cleanup, so the server must close here.
	t.Cleanup(func() {
		m.Server().Close()
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

// connectRule is a rule, held, that gives action to every connection as it
// is accepted.
func connectRule(action sftpproxy.Action) faults.Rule {
	return faults.Rule{ID: "held", Match: faults.Match{Operations: []faults.Operation{faults.Connect}}, Action: action}
}

// outageAt is a rule that takes the server down for a minute, at moment
// into the run.
func outageAt(moment time.Duration) faults.Rule {
	return faults.Rule{
		ID:      "outage",
		Trigger: &faults.Trigger{Anchor: faults.Run, At: &faults.Range[time.Duration]{Min: moment, Max: moment}},
		Action:  sftpproxy.ListenerDown{Duration: time.Minute},
	}
}

var denyStats = faults.Rule{ID: "deny-stats", Match: faults.Match{Operations: []faults.Operation{faults.Stat}}, Action: sftpproxy.Fail{Status: sftpwire.StatusPermissionDenied}}

// awaitRefused waits until nothing listens at addr.
func awaitRefused(t *testing.T, addr string) {
	t.Helper()
	deadline := time.Now().Add(waitTimeout)
	for {
		conn, err := net.Dial("tcp", addr)
		if err != nil {
			return
		}
		conn.Close()
		if time.Now().After(deadline) {
			t.Fatalf("%s still accepts connections", addr)
		}
		time.Sleep(10 * time.Millisecond)
	}
}
