// Package integration runs independent SFTP clients against sftpit over real
// TCP and SSH connections. Each transparency test runs one workload directly
// against the embedded backend and again through the proxy, and requires the
// same client-visible outcomes and the same resulting files.
package integration

import (
	"context"
	"crypto/ed25519"
	"crypto/rand"
	"crypto/sha256"
	"encoding/pem"
	"errors"
	"fmt"
	"io"
	"io/fs"
	"log/slog"
	"net"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"testing"
	"time"

	"golang.org/x/crypto/ssh"

	"github.com/nebarg/sftpit/internal/backend"
	"github.com/nebarg/sftpit/internal/config"
	"github.com/nebarg/sftpit/internal/faults"
	"github.com/nebarg/sftpit/internal/runs"
	"github.com/nebarg/sftpit/internal/sftpproxy"
	"github.com/nebarg/sftpit/internal/sshfront"
)

const (
	testUser      = "test"
	testPassword  = "test-password"
	clientTimeout = 2 * time.Minute
)

var (
	hostKeys  []ssh.Signer
	clientKey ed25519.PrivateKey
)

func TestMain(m *testing.M) {
	dir, err := os.MkdirTemp("", "sftpit-integration-")
	if err != nil {
		fmt.Fprintln(os.Stderr, err)
		os.Exit(1)
	}
	code := 1
	hostKeys, err = sshfront.LoadOrCreateHostKeys(dir)
	if err == nil {
		_, clientKey, err = ed25519.GenerateKey(rand.Reader)
	}
	if err != nil {
		fmt.Fprintln(os.Stderr, err)
	} else {
		code = m.Run()
	}
	os.RemoveAll(dir)
	os.Exit(code)
}

// route is how a server hands each SFTP session to the embedded backend.
type route string

const (
	direct  route = "direct"
	proxied route = "proxied"
)

var routes = []route{direct, proxied}

// server is an SSH server over a run of its own, which starts with no files.
type server struct {
	addr  string
	port  string
	files string
	run   *runs.Run

	sessions sync.WaitGroup
}

// waitForSessions waits until the server has finished every session it has
// started, so that everything they log has been logged.
func (s *server) waitForSessions() { s.sessions.Wait() }

// defaultLimits are the storage limits sftpit serve has by default.
var defaultLimits = backend.Limits{
	MaxFileBytes:  config.DefaultMaxFileBytes,
	MaxTotalBytes: config.DefaultMaxTotalBytes,
	MaxFiles:      config.DefaultMaxFiles,
	MaxOpenFiles:  config.DefaultMaxOpenFiles,
}

// startServer starts a server that routes each session as via says. A
// proxied session goes through the same handler as sftpit serve and runs
// with opts, logging nothing unless opts has a Logger.
func startServer(t testing.TB, via route, opts sftpproxy.Options) *server {
	t.Helper()
	return startLimitedServer(t, via, nil, opts, defaultLimits)
}

// startServerWithRules starts a proxied server whose faults come from rules.
func startServerWithRules(t testing.TB, rules *faults.Engine, opts sftpproxy.Options) *server {
	t.Helper()
	return startLimitedServer(t, proxied, rules, opts, defaultLimits)
}

// startLimitedServer is startServer with limits on the run's files.
func startLimitedServer(t testing.TB, via route, rules *faults.Engine, opts sftpproxy.Options, limits backend.Limits) *server {
	t.Helper()
	workspace, err := runs.OpenWorkspace(t.TempDir())
	if err != nil {
		t.Fatalf("OpenWorkspace: %v", err)
	}
	t.Cleanup(func() { workspace.Close() })
	run, err := workspace.NewRun(runs.Scenario{})
	if err != nil {
		t.Fatalf("NewRun: %v", err)
	}
	root, err := os.OpenRoot(run.Files)
	if err != nil {
		t.Fatalf("OpenRoot: %v", err)
	}
	t.Cleanup(func() { root.Close() })
	logger := slog.New(slog.DiscardHandler)
	embedded, err := backend.New(root, backend.Options{Limits: limits, Logger: logger})
	if err != nil {
		t.Fatalf("backend.New: %v", err)
	}

	handler := func(ctx context.Context, conn *sshfront.Conn, channel io.ReadWriteCloser) error {
		return embedded.Serve(channel, conn.Home())
	}
	var hooks sshfront.Hooks
	if via == proxied {
		if opts.Logger == nil {
			opts.Logger = logger
		}
		handler = runs.Handler(run, embedded, rules, opts)
		hooks = runs.Hooks(rules, opts.Logger)
	}
	s := &server{files: run.Files, run: run}
	serveSession := handler
	handler = func(ctx context.Context, conn *sshfront.Conn, channel io.ReadWriteCloser) error {
		s.sessions.Add(1)
		defer s.sessions.Done()
		return serveSession(ctx, conn, channel)
	}
	signer, err := ssh.NewSignerFromKey(clientKey)
	if err != nil {
		t.Fatalf("client signer: %v", err)
	}
	srv, err := sshfront.New(sshfront.Config{
		HostKeys: hostKeys,
		Users: []sshfront.User{{
			Name:           testUser,
			Password:       testPassword,
			AuthorizedKeys: []ssh.PublicKey{signer.PublicKey()},
		}},
		Handler: handler,
		Hooks:   hooks,
		Logger:  logger,
	})
	if err != nil {
		t.Fatalf("sshfront.New: %v", err)
	}
	t.Cleanup(runs.ArmTimers(rules, srv, opts.Logger))
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

	s.addr = ln.Addr().String()
	_, s.port, err = net.SplitHostPort(s.addr)
	if err != nil {
		t.Fatalf("SplitHostPort: %v", err)
	}
	return s
}

// startRuns starts runs with opts, as sftpit serve does, for the test
// user, and serves them. The server it returns describes the first run.
func startRuns(t testing.TB, opts runs.Options) (*runs.Manager, *server) {
	t.Helper()
	workspace, err := runs.OpenWorkspace(t.TempDir())
	if err != nil {
		t.Fatalf("OpenWorkspace: %v", err)
	}
	t.Cleanup(func() { workspace.Close() })
	signer, err := ssh.NewSignerFromKey(clientKey)
	if err != nil {
		t.Fatalf("client signer: %v", err)
	}
	opts.Server = sshfront.Config{
		HostKeys: hostKeys,
		Users:    []sshfront.User{{Name: testUser, Password: testPassword, AuthorizedKeys: []ssh.PublicKey{signer.PublicKey()}, Home: "/"}},
	}
	opts.Limits = defaultLimits
	if opts.Logger == nil {
		opts.Logger = slog.New(slog.DiscardHandler)
	}
	m, err := runs.Start(workspace, opts)
	if err != nil {
		t.Fatalf("runs.Start: %v", err)
	}
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatalf("Listen: %v", err)
	}
	served := make(chan error, 1)
	go func() { served <- m.Server().Serve(ln) }()
	t.Cleanup(func() {
		m.Close()
		if err := <-served; !errors.Is(err, sshfront.ErrServerClosed) {
			t.Errorf("Serve: %v", err)
		}
	})

	run := m.Status().Run
	s := &server{addr: ln.Addr().String(), files: run.Files, run: &run}
	if _, s.port, err = net.SplitHostPort(s.addr); err != nil {
		t.Fatalf("SplitHostPort: %v", err)
	}
	return m, s
}

// treeEntry describes one file or directory under a backend directory.
type treeEntry struct {
	path   string
	mode   fs.FileMode
	size   int64
	sha256 string
	mtime  string
}

func (e treeEntry) String() string {
	return fmt.Sprintf("%s %v size=%d sha256=%s mtime=%s", e.path, e.mode, e.size, e.sha256, e.mtime)
}

// readTree describes everything under dir. A modification time before since
// was set by the client and is recorded exactly; a later one is recorded as
// "recent", because it differs between runs.
func readTree(t *testing.T, dir string, since time.Time) []treeEntry {
	t.Helper()
	var entries []treeEntry
	err := filepath.WalkDir(dir, func(name string, d fs.DirEntry, err error) error {
		if err != nil || name == dir {
			return err
		}
		info, err := d.Info()
		if err != nil {
			return err
		}
		rel, err := filepath.Rel(dir, name)
		if err != nil {
			return err
		}
		e := treeEntry{path: filepath.ToSlash(rel), mode: info.Mode(), mtime: "recent"}
		if info.ModTime().Before(since) {
			e.mtime = info.ModTime().UTC().Format(time.RFC3339)
		}
		if info.Mode().IsRegular() {
			data, err := os.ReadFile(name)
			if err != nil {
				return err
			}
			e.size = int64(len(data))
			e.sha256 = digest(data)
		}
		entries = append(entries, e)
		return nil
	})
	if err != nil {
		t.Fatalf("read tree %s: %v", dir, err)
	}
	return entries
}

func digest(data []byte) string {
	return fmt.Sprintf("%x", sha256.Sum256(data))
}

// assertSameLines fails with both versions when direct and proxied differ.
func assertSameLines[T fmt.Stringer](t *testing.T, what string, direct, proxied []T) {
	t.Helper()
	d, p := lines(direct), lines(proxied)
	if d == p {
		return
	}
	t.Errorf("%s differs through the proxy\n--- direct\n%s\n--- proxied\n%s", what, d, p)
}

func lines[T fmt.Stringer](items []T) string {
	var b strings.Builder
	for _, item := range items {
		b.WriteString(item.String())
		b.WriteByte('\n')
	}
	return b.String()
}

// assertFiles checks the content of the regular files in tree against want,
// which maps each path to its content, and that no other files exist.
func assertFiles(t *testing.T, tree []treeEntry, want map[string][]byte) {
	t.Helper()
	got := make(map[string]string)
	for _, e := range tree {
		if e.mode.IsRegular() {
			got[e.path] = e.sha256
		}
	}
	for name, content := range want {
		if got[name] != digest(content) {
			t.Errorf("%s: sha256 %q, want %d bytes with sha256 %s", name, got[name], len(content), digest(content))
		}
		delete(got, name)
	}
	for name := range got {
		t.Errorf("unexpected file %s", name)
	}
}

func writeFile(t testing.TB, name string, data []byte) {
	t.Helper()
	if err := os.WriteFile(name, data, 0o600); err != nil {
		t.Fatalf("write %s: %v", name, err)
	}
}

func writeClientKey(t testing.TB, dir string) string {
	t.Helper()
	block, err := ssh.MarshalPrivateKey(clientKey, "")
	if err != nil {
		t.Fatalf("marshal client key: %v", err)
	}
	name := filepath.Join(dir, "id_ed25519")
	writeFile(t, name, pem.EncodeToMemory(block))
	return name
}

func randomBytes(n int) []byte {
	b := make([]byte, n)
	rand.Read(b)
	return b
}

// line is one line of a client's transcript.
type line string

func (l line) String() string { return string(l) }

func splitLines(out []byte) []line {
	var ls []line
	for s := range strings.SplitSeq(strings.TrimRight(string(out), "\n"), "\n") {
		ls = append(ls, line(s))
	}
	return ls
}
