package main

import (
	"bytes"
	"context"
	"errors"
	"fmt"
	"io/fs"
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

func TestServeTransfersFilesAndCleansUp(t *testing.T) {
	s := startServe(t, "--sftp-listen", "127.0.0.1:0")
	if !strings.Contains(s.stdout.String(), `login: user "test", password "test"`) {
		t.Errorf("banner does not show the default login:\n%s", s.stdout.String())
	}

	c := s.dial(t, "test", "test")
	want := bytes.Repeat([]byte("orders,"), 100000)
	f, err := c.Create("/orders.csv")
	if err != nil {
		t.Fatalf("Create: %v", err)
	}
	if _, err := f.ReadFrom(bytes.NewReader(want)); err != nil {
		t.Fatalf("upload: %v", err)
	}
	f.Close()
	stored, err := os.ReadFile(filepath.Join(s.workspace, "fs", "orders.csv"))
	if err != nil || !bytes.Equal(stored, want) {
		t.Fatalf("stored file: %d bytes, %v; want the %d uploaded", len(stored), err, len(want))
	}

	if code := s.stop(t); code != exitOK {
		t.Fatalf("exit code = %d, want %d\nstderr:\n%s", code, exitOK, s.stderr.String())
	}
	if stderr := s.stderr.String(); stderr != "" {
		t.Errorf("stopping with a client connected logged:\n%s", stderr)
	}
	if _, err := os.Stat(s.workspace); !errors.Is(err, fs.ErrNotExist) {
		t.Errorf("workspace %s still exists after shutdown (%v)", s.workspace, err)
	}
}

func TestServeUsesConfiguredUsersAndHostKeys(t *testing.T) {
	dir := t.TempDir()
	config := filepath.Join(dir, "sftpit.yaml")
	writeTestFile(t, config, `schema_version: 1
env_file: "test.env"
server:
  host_key: "hostkeys"
users:
  - name: "partner-b"
    password_env: "PARTNER_B_PASSWORD"
    home: "/partner-b"
`)
	writeTestFile(t, filepath.Join(dir, "test.env"), "PARTNER_B_PASSWORD=s3cret-value\n")

	first := startServe(t, "--config", config, "--sftp-listen", "127.0.0.1:0")
	if out := first.stdout.String(); !strings.Contains(out, "users: partner-b (password)") || strings.Contains(out, "s3cret-value") {
		t.Errorf("banner should list the user without the password:\n%s", out)
	}
	c := first.dial(t, "partner-b", "s3cret-value")
	if wd, err := c.Getwd(); err != nil || wd != "/partner-b" {
		t.Errorf("Getwd = %q, %v; want the home directory", wd, err)
	}
	c.Close()
	first.stop(t)

	second := startServe(t, "--config", config, "--sftp-listen", "127.0.0.1:0")
	second.stop(t)
	if a, b := fingerprints(first.stdout.String()), fingerprints(second.stdout.String()); strings.Count(a, "SHA256:") != 2 || a != b {
		t.Errorf("host keys changed between runs: %v then %v", a, b)
	}
	if _, err := os.Stat(filepath.Join(dir, "hostkeys", "ssh_host_ed25519_key")); err != nil {
		t.Errorf("host key not kept in the configured directory: %v", err)
	}
}

func TestServeRejectsInvalidSettings(t *testing.T) {
	missingSecret := filepath.Join(t.TempDir(), "sftpit.yaml")
	writeTestFile(t, missingSecret, "schema_version: 1\nusers:\n  - {name: a, password_env: SFTPIT_SERVE_TEST_UNSET}\n")

	tests := []struct {
		name string
		args []string
		want string
	}{
		{"non-loopback address", []string{"--sftp-listen", "0.0.0.0:2122"}, "not a loopback address"},
		{"unknown flag", []string{"--http-listen", "127.0.0.1:0"}, "flag provided but not defined"},
		{"stray argument", []string{"extra"}, `unexpected arguments ["extra"]`},
		{"missing config", []string{"--config", "missing.yaml"}, "missing.yaml"},
		{"missing secret", []string{"--config", missingSecret}, "SFTPIT_SERVE_TEST_UNSET is not set"},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			var stdout, stderr syncBuffer
			code := run(context.Background(), append([]string{"serve"}, tt.args...), &stdout, &stderr)
			if code != exitUsage {
				t.Errorf("exit code = %d, want %d", code, exitUsage)
			}
			if !strings.Contains(stderr.String(), tt.want) {
				t.Errorf("stderr = %q, want it to contain %q", stderr.String(), tt.want)
			}
		})
	}
}

func TestServeFailsClearlyOnAnOccupiedPort(t *testing.T) {
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	defer ln.Close()

	var stdout, stderr syncBuffer
	code := run(context.Background(), []string{"serve", "--sftp-listen", ln.Addr().String()}, &stdout, &stderr)
	if code != exitFailure {
		t.Errorf("exit code = %d, want %d", code, exitFailure)
	}
	if !strings.Contains(stderr.String(), "address already in use") {
		t.Errorf("stderr = %q, want the listen error", stderr.String())
	}
}

func TestServeHelp(t *testing.T) {
	var stdout, stderr syncBuffer
	if code := run(context.Background(), []string{"serve", "--help"}, &stdout, &stderr); code != exitOK {
		t.Errorf("exit code = %d, want %d", code, exitOK)
	}
	if !strings.Contains(stdout.String(), "Usage: sftpit serve") {
		t.Errorf("stdout = %q, want the serve usage", stdout.String())
	}
}

// running is a serve command running in the background.
type running struct {
	stdout, stderr *syncBuffer
	addr           string
	workspace      string
	cancel         context.CancelFunc
	code           chan int
}

var (
	addrLine      = regexp.MustCompile(`serving SFTP on (\S+)`)
	workspaceLine = regexp.MustCompile(`workspace: (.+) \(deleted`)
)

func startServe(t *testing.T, args ...string) *running {
	t.Helper()
	ctx, cancel := context.WithCancel(context.Background())
	s := &running{stdout: &syncBuffer{}, stderr: &syncBuffer{}, cancel: cancel, code: make(chan int, 1)}
	go func() { s.code <- run(ctx, append([]string{"serve"}, args...), s.stdout, s.stderr) }()
	t.Cleanup(func() { s.stop(t) })

	deadline := time.Now().Add(startTimeout)
	for !strings.Contains(s.stdout.String(), "Press Ctrl+C to stop.") {
		select {
		case code := <-s.code:
			t.Fatalf("serve exited with %d before starting\nstderr:\n%s", code, s.stderr.String())
		case <-time.After(10 * time.Millisecond):
		}
		if time.Now().After(deadline) {
			t.Fatalf("serve did not start\nstdout:\n%s\nstderr:\n%s", s.stdout.String(), s.stderr.String())
		}
	}
	out := s.stdout.String()
	s.addr = addrLine.FindStringSubmatch(out)[1]
	s.workspace = workspaceLine.FindStringSubmatch(out)[1]
	return s
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
