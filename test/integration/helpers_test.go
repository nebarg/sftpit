// Package integration runs independent SFTP clients against sftpit over real
// TCP and SSH connections. Each transparency test runs one workload directly
// against the embedded backend and again through the proxy, and requires the
// same client-visible outcomes and the same resulting files.
package integration

import (
	"bytes"
	"context"
	"crypto/ed25519"
	"crypto/rand"
	"crypto/sha256"
	"encoding/json"
	"encoding/pem"
	"errors"
	"fmt"
	"io"
	"io/fs"
	"log/slog"
	"net"
	"os"
	"os/exec"
	"path/filepath"
	"regexp"
	"slices"
	"strings"
	"sync"
	"testing"
	"time"

	"golang.org/x/crypto/ssh"
	"golang.org/x/crypto/ssh/knownhosts"

	"github.com/pkg/sftp"

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
	hostKeys     []ssh.Signer
	clientKey    ed25519.PrivateKey
	clientSigner ssh.Signer
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
	if err == nil {
		clientSigner, err = ssh.NewSignerFromKey(clientKey)
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

	// runs serves the server's runs, unless the test wires its sessions by
	// hand, and wait waits for the sessions it has started to finish.
	runs *runs.Manager
	wait func()
}

// path returns where the server stores the file at the virtual path name,
// whose name the backend encodes.
func (s *server) path(name string) string {
	return filepath.Join(s.files, filepath.FromSlash(backend.StoredName(name)))
}

// waitForSessions waits until the server has finished every session it has
// started, so that everything they log has been logged. A server that serves
// runs ends its sessions first, as a reset does, which also ends an outage.
func (s *server) waitForSessions() { s.wait() }

// counts returns what the rule id has done in the server's run.
func (s *server) counts(t testing.TB, id string) faults.Counts {
	t.Helper()
	set, err := s.runs.Rules(s.run.ID)
	if err != nil {
		t.Errorf("Rules: %v", err)
	}
	return set.Counts[id]
}

// releaseStalls releases the stalls and freezes in progress in the server's
// run.
func (s *server) releaseStalls(t testing.TB) {
	t.Helper()
	if err := s.runs.ReleaseStalls(s.run.ID); err != nil {
		t.Errorf("ReleaseStalls: %v", err)
	}
}

// startServer starts a server that routes each session as via says, wired
// by hand for a test that needs what the configuration cannot give: the
// direct route, or faults chosen by a Go function. A proxied session goes
// through the same handler as sftpit serve and runs with opts, logging
// nothing unless opts has a Logger.
func startServer(t testing.TB, via route, opts sftpproxy.Options) *server {
	t.Helper()
	return startLimitedServer(t, via, opts, config.DefaultLimits())
}

// startLimitedServer is startServer with limits on the run's files.
func startLimitedServer(t testing.TB, via route, opts sftpproxy.Options, limits backend.Limits) *server {
	t.Helper()
	workspace, err := runs.OpenWorkspace(t.TempDir())
	if err != nil {
		t.Fatalf("OpenWorkspace: %v", err)
	}
	t.Cleanup(func() {
		if err := workspace.Close(); err != nil {
			t.Errorf("close the workspace: %v", err)
		}
	})
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
	if via == proxied {
		if opts.Logger == nil {
			opts.Logger = logger
		}
		handler = runs.Handler(run, embedded, nil, opts)
	}
	var sessions sync.WaitGroup
	s := &server{files: run.Files, run: run, wait: sessions.Wait}
	serveSession := handler
	handler = func(ctx context.Context, conn *sshfront.Conn, channel io.ReadWriteCloser) error {
		sessions.Add(1)
		defer sessions.Done()
		return serveSession(ctx, conn, channel)
	}
	srv, err := sshfront.New(sshfront.Config{
		HostKeys: hostKeys,
		Users:    testUsers(),
		Handler:  handler,
		Logger:   logger,
	})
	if err != nil {
		t.Fatalf("sshfront.New: %v", err)
	}
	s.addr = serve(t, srv)
	_, s.port, err = net.SplitHostPort(s.addr)
	if err != nil {
		t.Fatalf("SplitHostPort: %v", err)
	}
	return s
}

// startScenario starts runs, as sftpit serve does, whose first run injects
// the faults of rules, drawing from seed, and logs to logger, or nowhere if
// it is nil.
func startScenario(t testing.TB, rules []faults.Rule, seed faults.Seed, logger *slog.Logger) *server {
	t.Helper()
	_, srv := startRuns(t, runs.Options{
		Scenarios: map[string]config.Scenario{"test": {Rules: rules, Seed: &seed}},
		Scenario:  "test",
		Logger:    logger,
	})
	return srv
}

// startRuns starts runs with opts, as sftpit serve does, and serves them.
// The server is the test user's, with the default storage limits, and logs
// nowhere, unless opts says otherwise. The server it returns describes the
// first run.
func startRuns(t testing.TB, opts runs.Options) (*runs.Manager, *server) {
	t.Helper()
	workspace, err := runs.OpenWorkspace(t.TempDir())
	if err != nil {
		t.Fatalf("OpenWorkspace: %v", err)
	}
	t.Cleanup(func() {
		if err := workspace.Close(); err != nil {
			t.Errorf("close the workspace: %v", err)
		}
	})
	opts.Server.HostKeys = hostKeys
	if opts.Server.Users == nil {
		opts.Server.Users = testUsers()
	}
	if opts.Limits == (backend.Limits{}) {
		opts.Limits = config.DefaultLimits()
	}
	if opts.Logger == nil {
		opts.Logger = slog.New(slog.DiscardHandler)
	}
	m, err := runs.Start(workspace, opts)
	if err != nil {
		t.Fatalf("runs.Start: %v", err)
	}
	t.Cleanup(func() {
		if err := m.Close(); err != nil {
			t.Errorf("close the runs: %v", err)
		}
	})
	run := m.Status().Run
	s := &server{addr: serve(t, m.Server()), files: run.Files, run: &run, runs: m}
	// Pause waits for every connection's sessions to end, and Resume admits
	// clients again.
	s.wait = func() {
		if err := m.Server().Pause(t.Context()); err != nil {
			t.Errorf("wait for the sessions: %v", err)
		}
		m.Server().Resume()
	}
	if _, s.port, err = net.SplitHostPort(s.addr); err != nil {
		t.Fatalf("SplitHostPort: %v", err)
	}
	return m, s
}

// testUsers are the users of a server: the test user, with a password and
// the client key.
func testUsers() []sshfront.User {
	return []sshfront.User{{Name: testUser, Password: testPassword, AuthorizedKeys: []ssh.PublicKey{clientSigner.PublicKey()}, Home: "/"}}
}

// serve serves srv on a loopback port until the test ends, and returns the
// address.
func serve(t testing.TB, srv *sshfront.Server) string {
	t.Helper()
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatalf("Listen: %v", err)
	}
	served := make(chan error, 1)
	go func() { served <- srv.Serve(ln) }()
	t.Cleanup(func() {
		if err := srv.Close(); err != nil {
			t.Errorf("close the server: %v", err)
		}
		if err := <-served; !errors.Is(err, sshfront.ErrServerClosed) {
			t.Errorf("Serve: %v", err)
		}
	})
	return ln.Addr().String()
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

// capturedLog collects what a server and its rules log, for a test to check.
type capturedLog struct {
	mu  sync.Mutex
	buf bytes.Buffer
}

func (l *capturedLog) Write(p []byte) (int, error) {
	l.mu.Lock()
	defer l.mu.Unlock()
	return l.buf.Write(p)
}

func (l *capturedLog) logger() *slog.Logger {
	return slog.New(slog.NewTextHandler(l, nil))
}

func (l *capturedLog) text() string {
	l.mu.Lock()
	defer l.mu.Unlock()
	return l.buf.String()
}

// assertSnapshot checks that srv has logged one snapshot: of the file at the
// virtual path name holding data, closed as one of closedBy says, with a copy
// of data in the run's snapshots directory.
func (l *capturedLog) assertSnapshot(t *testing.T, srv *server, name string, data []byte, closedBy ...string) {
	t.Helper()
	var got []string
	for record := range strings.Lines(l.text()) {
		if strings.Contains(record, "msg=snapshot") {
			// Leave out the time, and the connection, which differ between
			// runs.
			_, rest, _ := strings.Cut(strings.TrimSpace(record), " ")
			got = append(got, connID.ReplaceAllString(rest, "conn=N "))
		}
	}
	stored := backend.StoredName(name)
	var want []string
	for _, by := range closedBy {
		want = append(want, fmt.Sprintf("level=INFO msg=snapshot conn=N user=%s path=%s closed_by=%s size=%d sha256=%s copy=snapshots/1/%s", testUser, name, by, len(data), digest(data), stored))
	}
	if len(got) != 1 || !slices.Contains(want, got[0]) {
		t.Errorf("snapshots logged:\n%s\nwant one of:\n%s", strings.Join(got, "\n"), strings.Join(want, "\n"))
	}
	copied, err := os.ReadFile(filepath.Join(srv.run.Dir, "snapshots", "1", filepath.FromSlash(stored)))
	if err != nil || !bytes.Equal(copied, data) {
		t.Errorf("the snapshot's copy has %d bytes (%v), want the %d snapshotted", len(copied), err, len(data))
	}
}

// connID matches the connection a session's log record names.
var connID = regexp.MustCompile(`conn=\d+ `)

// assertHolds checks that the file at the virtual path name holds want, or
// that there is no file there if want is nil.
func assertHolds(t *testing.T, srv *server, name string, want []byte) {
	t.Helper()
	got, err := os.ReadFile(srv.path(name))
	switch {
	case want == nil && !errors.Is(err, fs.ErrNotExist):
		t.Errorf("%s holds %d bytes (%v), want no file", name, len(got), err)
	case want != nil && (err != nil || !bytes.Equal(got, want)):
		t.Errorf("%s holds %d bytes with SHA-256 %s (%v), want %d with %s", name, len(got), digest(got), err, len(want), digest(want))
	}
}

// pkgSFTPClient logs in to srv over SSH with pkg/sftp's client, using auth.
// Closing the client closes the connection too.
func pkgSFTPClient(tb testing.TB, srv *server, auth ssh.AuthMethod) *sshSFTPClient {
	tb.Helper()
	conn, err := ssh.Dial("tcp", srv.addr, &ssh.ClientConfig{
		User: testUser,
		Auth: []ssh.AuthMethod{auth},
		HostKeyCallback: func(_ string, _ net.Addr, key ssh.PublicKey) error {
			for _, k := range hostKeys {
				if bytes.Equal(k.PublicKey().Marshal(), key.Marshal()) {
					return nil
				}
			}
			return fmt.Errorf("unknown host key %s", key.Type())
		},
	})
	if err != nil {
		tb.Fatalf("ssh.Dial: %v", err)
	}
	c, err := sftp.NewClient(conn, sftp.UseConcurrentWrites(true))
	if err != nil {
		conn.Close()
		tb.Fatalf("sftp.NewClient: %v", err)
	}
	return &sshSFTPClient{Client: c, conn: conn}
}

type sshSFTPClient struct {
	*sftp.Client
	conn *ssh.Client
}

func (c *sshSFTPClient) Close() error {
	return errors.Join(c.Client.Close(), c.conn.Close())
}

func transferWithOpenSSH(t testing.TB, srv *server, work string, upload bool) {
	t.Helper()
	sftpPath := openSSHOrSkip(t)
	batch := "get /orders.csv orders.csv\n"
	if upload {
		batch = "put orders.csv /orders.csv\n"
	}
	if out, err := openSSH(t, sftpPath, srv, work, batch); err != nil {
		t.Fatalf("sftp failed: %v\n%s", err, out)
	}
}

func transferWithPhpseclib(t testing.TB, srv *server, work string, upload bool) {
	t.Helper()
	php := phpseclibOrSkip(t)
	op := "get"
	if upload {
		op = "put"
	}
	transcript := runPhpseclib(t, php, srv, "transfer.php", work, op)
	if phpseclibResults(t, transcript)[op] != true {
		t.Fatalf("phpseclib %s failed: %v", op, transcript)
	}
}

// openSSHOrSkip returns the path of OpenSSH's sftp client, or skips the test
// if it cannot run.
func openSSHOrSkip(t testing.TB) string {
	t.Helper()
	if testing.Short() {
		t.Skip("runs the OpenSSH sftp client")
	}
	sftpPath, err := exec.LookPath("sftp")
	if err != nil {
		t.Skip("OpenSSH sftp client not installed")
	}
	return sftpPath
}

// openSSH runs batch with the OpenSSH sftp client in work, adding options to
// its command line, and returns everything it printed.
func openSSH(t testing.TB, sftpPath string, srv *server, work, batch string, options ...string) ([]byte, error) {
	t.Helper()
	return openSSHCommand(t, sftpPath, srv, work, batch, options...).CombinedOutput()
}

// openSSHCommand returns the command with which openSSH runs batch. Its
// setup can fail the test, so it runs on the test's goroutine, and the
// command can then run on another.
func openSSHCommand(t testing.TB, sftpPath string, srv *server, work, batch string, options ...string) *exec.Cmd {
	t.Helper()
	dir := t.TempDir()
	keyFile := writeClientKey(t, dir)
	var known []string
	for _, key := range hostKeys {
		known = append(known, knownhosts.Line([]string{srv.addr}, key.PublicKey()))
	}
	knownHosts := filepath.Join(dir, "known_hosts")
	writeFile(t, knownHosts, []byte(strings.Join(known, "\n")+"\n"))
	batchFile := filepath.Join(dir, "batch")
	writeFile(t, batchFile, []byte(batch))

	ctx, cancel := context.WithTimeout(t.Context(), clientTimeout)
	t.Cleanup(cancel)
	args := []string{
		"-b", batchFile,
		"-P", srv.port,
		"-F", os.DevNull,
		"-i", keyFile,
		"-o", "IdentitiesOnly=yes",
		"-o", "IdentityAgent=none",
		"-o", "BatchMode=yes",
		"-o", "StrictHostKeyChecking=yes",
		"-o", "UserKnownHostsFile=" + knownHosts,
		"-o", "GlobalKnownHostsFile=" + os.DevNull,
	}
	for _, o := range options {
		args = append(args, "-o", o)
	}
	cmd := exec.CommandContext(ctx, sftpPath, append(args, testUser+"@127.0.0.1")...)
	cmd.Dir = work
	return cmd
}

// phpseclibOrSkip returns the path of php, or skips the test if phpseclib
// cannot run.
func phpseclibOrSkip(t testing.TB) string {
	t.Helper()
	if testing.Short() {
		t.Skip("runs phpseclib")
	}
	php, err := exec.LookPath("php")
	if err != nil {
		t.Skip("php not installed")
	}
	if _, err := os.Stat(filepath.Join(phpDir, "vendor", "autoload.php")); err != nil {
		t.Skip("the PHP clients are not installed; run make integration-deps")
	}
	return php
}

// runPhpseclib runs one of the phpseclib scripts against srv with work as
// its work directory and any further arguments, and returns what it printed.
func runPhpseclib(t testing.TB, php string, srv *server, script, work string, args ...string) []line {
	t.Helper()
	var keys bytes.Buffer
	for _, key := range hostKeys {
		keys.Write(ssh.MarshalAuthorizedKey(key.PublicKey()))
	}
	hostKeysFile := filepath.Join(t.TempDir(), "host_keys")
	writeFile(t, hostKeysFile, keys.Bytes())

	ctx, cancel := context.WithTimeout(t.Context(), clientTimeout)
	defer cancel()
	cmd := exec.CommandContext(ctx, php, append([]string{filepath.Join(phpDir, script),
		"127.0.0.1", srv.port, testUser, testPassword, hostKeysFile, work}, args...)...)
	var stderr bytes.Buffer
	cmd.Stderr = &stderr
	out, err := cmd.Output()
	if err != nil || stderr.Len() > 0 {
		t.Fatalf("phpseclib workload: %v\nstdout:\n%s\nstderr:\n%s", err, out, stderr.Bytes())
	}
	return splitLines(out)
}

// transcriptEntry is one operation in a transcript: its result, and the
// SFTP error for a false one.
type transcriptEntry struct {
	Op     string `json:"op"`
	Result any    `json:"result"`
	Error  string `json:"error"`
}

func decodeTranscript(t testing.TB, transcript []line) []transcriptEntry {
	t.Helper()
	var entries []transcriptEntry
	for _, l := range transcript {
		var entry transcriptEntry
		if err := json.Unmarshal([]byte(l), &entry); err != nil {
			t.Fatalf("transcript line %q: %v", l, err)
		}
		entries = append(entries, entry)
	}
	return entries
}

// phpseclibResults maps each operation in a transcript to its JSON result.
func phpseclibResults(t testing.TB, transcript []line) map[string]any {
	t.Helper()
	byOp := make(map[string]any)
	for _, entry := range decodeTranscript(t, transcript) {
		byOp[entry.Op] = entry.Result
	}
	return byOp
}

// phpseclibFailures maps each operation in a transcript that failed to its
// error: the SFTP error for a false result, or the exception it threw.
func phpseclibFailures(t testing.TB, transcript []line) map[string]string {
	t.Helper()
	byOp := make(map[string]string)
	for _, entry := range decodeTranscript(t, transcript) {
		if entry.Result == false {
			byOp[entry.Op] = entry.Error
		} else if thrown, ok := entry.Result.(map[string]any); ok && thrown["exception"] != nil {
			byOp[entry.Op] = fmt.Sprintf("%v: %v", thrown["exception"], thrown["message"])
		}
	}
	return byOp
}

// phpDir holds the PHP clients: phpseclib, and Laravel's filesystem on top
// of it.
const phpDir = "php"

// uploadCutoff is where partial uploads are cut off. It falls inside a write
// for both clients, so the write that crosses it is trimmed.
const uploadCutoff = 1<<20 + 1000

// phpseclibClosedBy holds how a snapshot may say phpseclib closed a handle
// whose upload failed. phpseclib takes the reply to its first WRITE for its
// CLOSE's, so it disconnects without waiting for its CLOSE to be answered.
// The session can end before then, and the end closes the handle.
var phpseclibClosedBy = []string{"client", `"session end"`}

// snapshotClosedBy returns how a snapshot may say a handle was closed when
// its upload gets result: by the fault, if result drops the connection, or
// else as the client closes it, which byClient holds.
func snapshotClosedBy(byClient []string, result sftpproxy.Action) []string {
	if _, ok := result.(sftpproxy.Drop); ok {
		return []string{"fault"}
	}
	return byClient
}

// The paths publish.php uploads to and then publishes at.
const (
	temporaryPath = "/incoming/orders.csv.part"
	publishedPath = "/incoming/orders.csv"
)
