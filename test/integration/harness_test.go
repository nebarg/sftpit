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
	"testing"
	"time"

	"golang.org/x/crypto/ssh"

	"sftpit/internal/backend"
	"sftpit/internal/sftpproxy"
	"sftpit/internal/sshfront"
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

// server is an SSH server over its own empty backend directory.
type server struct {
	addr  string
	port  string
	files string
}

func startServer(t *testing.T, via route) *server {
	t.Helper()
	files := t.TempDir()
	root, err := os.OpenRoot(files)
	if err != nil {
		t.Fatalf("OpenRoot: %v", err)
	}
	t.Cleanup(func() { root.Close() })
	embedded := backend.New(root)
	logger := slog.New(slog.DiscardHandler)

	handler := func(ctx context.Context, conn *sshfront.Conn, channel io.ReadWriteCloser) error {
		return embedded.Serve(channel, conn.Home())
	}
	if via == proxied {
		handler = func(ctx context.Context, conn *sshfront.Conn, channel io.ReadWriteCloser) error {
			return sftpproxy.Serve(ctx, channel, embedded.Open(conn.Home()), logger)
		}
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
		Logger:  logger,
	})
	if err != nil {
		t.Fatalf("sshfront.New: %v", err)
	}
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

	addr := ln.Addr().String()
	_, port, err := net.SplitHostPort(addr)
	if err != nil {
		t.Fatalf("SplitHostPort: %v", err)
	}
	return &server{addr: addr, port: port, files: files}
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

func writeFile(t *testing.T, name string, data []byte) {
	t.Helper()
	if err := os.WriteFile(name, data, 0o600); err != nil {
		t.Fatalf("write %s: %v", name, err)
	}
}

func writeClientKey(t *testing.T, dir string) string {
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
	for _, s := range strings.Split(strings.TrimRight(string(out), "\n"), "\n") {
		ls = append(ls, line(s))
	}
	return ls
}
