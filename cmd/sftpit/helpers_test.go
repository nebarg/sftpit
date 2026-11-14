package main

import (
	"context"
	"fmt"
	"io"
	"net"
	"net/http"
	"os"
	"path/filepath"
	"regexp"
	"strings"
	"testing"
	"time"

	"github.com/pkg/sftp"
	"golang.org/x/crypto/ssh"

	"github.com/nebarg/sftpit/internal/testutil"
)

const startTimeout = 10 * time.Second

// TestMain gives the tests a user config directory of their own, so that
// serve never touches the user's own host keys.
func TestMain(m *testing.M) {
	dir, err := os.MkdirTemp("", "sftpit-cmd-config-")
	if err != nil {
		fmt.Fprintln(os.Stderr, err)
		os.Exit(1)
	}
	userConfigDir = func() (string, error) { return dir, nil }
	code := m.Run()
	os.RemoveAll(dir)
	os.Exit(code)
}

// running is a serve command running in the background.
type running struct {
	stdout, stderr *testutil.SyncBuffer
	addr, apiAddr  string
	workspace      string
	run            string
	cancel         context.CancelFunc
	code           chan int
}

var (
	addrLine      = regexp.MustCompile(`serving SFTP on (\S+)`)
	apiLine       = regexp.MustCompile(`API: http://(\S+)/api/`)
	workspaceLine = regexp.MustCompile(`workspace: (.+) \((?:deleted|kept)`)
	runLine       = regexp.MustCompile(`run: (\S+)`)
)

// commandContext returns a context for a command that is meant to return on
// its own, which ends it if a regression keeps it running.
func commandContext(t *testing.T) context.Context {
	t.Helper()
	ctx, cancel := context.WithTimeout(t.Context(), startTimeout)
	t.Cleanup(cancel)
	return ctx
}

// startServe runs serve with args, after flags for free ports for SFTP and
// the control API, which args can override.
func startServe(t *testing.T, args ...string) *running {
	t.Helper()
	ctx, cancel := context.WithCancel(t.Context())
	s := &running{stdout: &testutil.SyncBuffer{}, stderr: &testutil.SyncBuffer{}, cancel: cancel, code: make(chan int, 1)}
	args = append([]string{"serve", "--sftp-listen", "127.0.0.1:0", "--http-listen", "127.0.0.1:0"}, args...)
	go func() { s.code <- run(ctx, args, s.stdout, s.stderr) }()
	t.Cleanup(func() { s.stop(t) })

	deadline := time.Now().Add(startTimeout)
	for !strings.Contains(s.stdout.String(), "Press Ctrl+C to stop.") {
		select {
		case code := <-s.code:
			// stop, in the cleanup, needs the code too.
			s.code <- code
			t.Fatalf("serve exited with %d before starting\nstderr:\n%s", code, s.stderr.String())
		case <-time.After(10 * time.Millisecond):
		}
		if time.Now().After(deadline) {
			t.Fatalf("serve did not start\nstdout:\n%s\nstderr:\n%s", s.stdout.String(), s.stderr.String())
		}
	}
	out := s.stdout.String()
	s.addr = addrLine.FindStringSubmatch(out)[1]
	s.apiAddr = apiLine.FindStringSubmatch(out)[1]
	s.workspace = workspaceLine.FindStringSubmatch(out)[1]
	s.run = runLine.FindStringSubmatch(out)[1]
	return s
}

// files returns the directory of the run's files.
func (s *running) files() string {
	return filepath.Join(s.workspace, "runs", s.run, "fs")
}

// stop cancels the command and returns its exit code. It can be called
// more than once.
func (s *running) stop(t *testing.T) int {
	t.Helper()
	s.cancel()
	select {
	case code := <-s.code:
		s.code <- code
		return code
	case <-time.After(startTimeout):
		t.Fatal("serve did not stop")
		return 0
	}
}

func (s *running) dial(t *testing.T, user, password string) *sftp.Client {
	t.Helper()
	want := fingerprints(s.stdout.String())
	conn, err := ssh.Dial("tcp", s.addr, &ssh.ClientConfig{
		User: user,
		Auth: []ssh.AuthMethod{ssh.Password(password)},
		HostKeyCallback: func(_ string, _ net.Addr, key ssh.PublicKey) error {
			if !strings.Contains(want, ssh.FingerprintSHA256(key)) {
				return fmt.Errorf("host key %s is not in the banner", ssh.FingerprintSHA256(key))
			}
			return nil
		},
		Timeout: startTimeout,
	})
	if err != nil {
		t.Fatalf("ssh.Dial: %v", err)
	}
	c, err := sftp.NewClient(conn)
	if err != nil {
		conn.Close()
		t.Fatalf("sftp.NewClient: %v", err)
	}
	t.Cleanup(func() {
		c.Close()
		conn.Close()
	})
	return c
}

var fingerprintPattern = regexp.MustCompile(`SHA256:\S+`)

// fingerprints returns the host-key fingerprints in a banner, space
// separated.
func fingerprints(banner string) string {
	return strings.Join(fingerprintPattern.FindAllString(banner, -1), " ")
}

// goneReadyFile returns a ready file that a serve listening at httpAddr
// could have written before it stopped.
func goneReadyFile(httpAddr string) string {
	return `{"sftp_address": "127.0.0.1:1", "http_address": "` + httpAddr + `", "workspace": "/gone", "host_keys": [{"type": "ssh-ed25519", "fingerprint": "SHA256:x"}]}`
}

// serveHeldRequests serves HTTP on a loopback port with a handler that
// sends to started as each request arrives and answers done once finish is
// closed. It returns the server, its address, and a channel that receives
// what Serve returns.
func serveHeldRequests(t *testing.T, finish <-chan struct{}) (api *http.Server, addr string, started <-chan struct{}, served <-chan error) {
	t.Helper()
	arrived := make(chan struct{}, 1)
	api = &http.Server{Handler: http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		arrived <- struct{}{}
		<-finish
		fmt.Fprint(w, "done")
	})}
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatalf("Listen: %v", err)
	}
	result := make(chan error, 1)
	go func() { result <- api.Serve(ln) }()
	return api, ln.Addr().String(), arrived, result
}

// getBody gets / from the HTTP server at addr and sends the body, or the
// error, to the channel it returns.
func getBody(addr string) <-chan string {
	body := make(chan string, 1)
	go func() {
		resp, err := http.Get("http://" + addr + "/")
		if err != nil {
			body <- err.Error()
			return
		}
		defer resp.Body.Close()
		data, err := io.ReadAll(resp.Body)
		if err != nil {
			body <- err.Error()
			return
		}
		body <- string(data)
	}()
	return body
}

// awaitRefused waits until nothing listens at addr.
func awaitRefused(t *testing.T, addr string) {
	t.Helper()
	deadline := time.Now().Add(testutil.WaitTimeout)
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
