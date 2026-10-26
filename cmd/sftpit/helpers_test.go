package main

import (
	"bytes"
	"context"
	"fmt"
	"net"
	"os"
	"path/filepath"
	"regexp"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/pkg/sftp"
	"golang.org/x/crypto/ssh"
)

const startTimeout = 10 * time.Second

// running is a serve command running in the background.
type running struct {
	stdout, stderr *syncBuffer
	addr, apiAddr  string
	workspace      string
	run            string
	cancel         context.CancelFunc
	code           chan int
}

var (
	addrLine      = regexp.MustCompile(`serving SFTP on (\S+)`)
	apiLine       = regexp.MustCompile(`control API: http://(\S+)/api/v1/`)
	workspaceLine = regexp.MustCompile(`workspace: (.+) \((?:deleted|kept)`)
	runLine       = regexp.MustCompile(`run: (\S+)`)
)

// commandContext returns a context for a command that is meant to return on
// its own, which ends it if a regression keeps it running.
func commandContext(t *testing.T) context.Context {
	ctx, cancel := context.WithTimeout(t.Context(), startTimeout)
	t.Cleanup(cancel)
	return ctx
}

// startServe runs serve with args, after flags for free ports for SFTP and
// the control API, which args can override.
func startServe(t *testing.T, args ...string) *running {
	t.Helper()
	ctx, cancel := context.WithCancel(t.Context())
	s := &running{stdout: &syncBuffer{}, stderr: &syncBuffer{}, cancel: cancel, code: make(chan int, 1)}
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

func writeTestFile(t *testing.T, name, content string) {
	t.Helper()
	if err := os.WriteFile(name, []byte(content), 0o600); err != nil {
		t.Fatal(err)
	}
}

// goneReadyFile returns a ready file that a serve listening at httpAddr
// could have written before it stopped.
func goneReadyFile(httpAddr string) string {
	return `{"sftp_address": "127.0.0.1:1", "http_address": "` + httpAddr + `", "workspace": "/gone", "host_keys": [{"type": "ssh-ed25519", "fingerprint": "SHA256:x"}]}`
}

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
