package main

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io/fs"
	"net"
	"os"
	"path/filepath"
	"regexp"
	"runtime"
	"strconv"
	"strings"
	"sync"
	"syscall"
	"testing"
	"time"

	"github.com/pkg/sftp"
	"golang.org/x/crypto/ssh"

	"github.com/nebarg/sftpit/internal/faults"
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
	stored, err := os.ReadFile(filepath.Join(s.files(), "orders.csv"))
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

func TestServeInjectsTheSelectedScenariosFaults(t *testing.T) {
	config := filepath.Join(t.TempDir(), "sftpit.yaml")
	writeTestFile(t, config, `schema_version: 1
scenarios:
  deny-ack:
    faults:
      - id: deny-remove
        match: {user: test, operation: remove, path_glob: "/outgoing/*.csv"}
        action: {type: fail, when: before, status: permission_denied}
`)
	for _, scenario := range []string{"deny-ack", ""} {
		args := []string{"--config", config, "--sftp-listen", "127.0.0.1:0"}
		if scenario != "" {
			args = append(args, "--scenario", scenario)
		}
		s := startServe(t, args...)
		c := s.dial(t, "test", "test")
		if err := c.Mkdir("/outgoing"); err != nil {
			t.Fatalf("Mkdir: %v", err)
		}
		f, err := c.Create("/outgoing/orders.csv")
		if err != nil {
			t.Fatalf("Create: %v", err)
		}
		f.Close()

		err = c.Remove("/outgoing/orders.csv")
		_, statErr := os.Stat(filepath.Join(s.files(), "outgoing", "orders.csv"))
		c.Close()
		s.stop(t)
		if scenario == "" {
			if err != nil || statErr == nil {
				t.Errorf("without a scenario, Remove = %v and the file is still there (%v), want it removed", err, statErr)
			}
			if strings.Contains(s.stdout.String(), "scenario:") || strings.Contains(s.stdout.String(), "  seed:") || strings.Contains(s.stderr.String(), "rule") {
				t.Errorf("without a scenario, sftpit reported one:\n%s%s", s.stdout.String(), s.stderr.String())
			}
			continue
		}
		if !errors.Is(err, fs.ErrPermission) || statErr != nil {
			t.Errorf("Remove = %v and the file is gone (%v), want permission denied and the file kept", err, statErr)
		}
		if out := s.stdout.String(); !strings.Contains(out, "scenario: deny-ack (1 fault rule)") {
			t.Errorf("banner does not name the scenario:\n%s", out)
		}
		if logs := s.stderr.String(); !strings.Contains(logs, `msg="rule fired" rule=deny-remove request=remove path=/outgoing/orders.csv user=test ordinal=1`) {
			t.Errorf("stderr does not log the rule firing:\n%s", logs)
		}
	}
}

func TestServeInjectsFaultsAtLogin(t *testing.T) {
	config := filepath.Join(t.TempDir(), "sftpit.yaml")
	writeTestFile(t, config, `schema_version: 1
scenarios:
  cut-first-login:
    faults:
      - id: first-login
        match: {operation: authenticate, occurrence: [1]}
        action: {type: close_connection}
`)
	s := startServe(t, "--config", config, "--sftp-listen", "127.0.0.1:0", "--scenario", "cut-first-login")
	if conn, err := ssh.Dial("tcp", s.addr, &ssh.ClientConfig{
		User:            "test",
		Auth:            []ssh.AuthMethod{ssh.Password("test")},
		HostKeyCallback: ssh.InsecureIgnoreHostKey(),
		Timeout:         startTimeout,
	}); err == nil {
		conn.Close()
		t.Error("the first login succeeded, want it cut off")
	}
	s.dial(t, "test", "test").Close()
	s.stop(t)
	if logs := s.stderr.String(); !strings.Contains(logs, `msg="injected fault" conn=1 request=authenticate user=test fault=close_connection mode=fin`) {
		t.Errorf("stderr does not log the fault at the first login:\n%s", logs)
	}
}

func TestServeTakesTheListenerDownAtAMomentOfTheRun(t *testing.T) {
	config := filepath.Join(t.TempDir(), "sftpit.yaml")
	writeTestFile(t, config, `schema_version: 1
scenarios:
  outage:
    faults:
      - id: at-the-start
        trigger: {at: 0s, anchor: run}
        action: {type: listener_down, duration: 1m}
`)
	s := startServe(t, "--config", config, "--sftp-listen", "127.0.0.1:0", "--scenario", "outage")
	deadline := time.Now().Add(startTimeout)
	for !strings.Contains(s.stderr.String(), `msg="injected fault" fault=listener_down when=timer duration=1m0s close_existing=false`) {
		if time.Now().After(deadline) {
			t.Fatalf("serve did not take the listener down:\n%s", s.stderr.String())
		}
		time.Sleep(10 * time.Millisecond)
	}
	if conn, err := net.Dial("tcp", s.addr); !errors.Is(err, syscall.ECONNREFUSED) {
		if err == nil {
			conn.Close()
		}
		t.Errorf("Dial during the outage = %v, want the connection refused", err)
	}
}

func TestServeShowsRecordsAndDrawsFromTheScenariosSeed(t *testing.T) {
	config := filepath.Join(t.TempDir(), "sftpit.yaml")
	slowStat := `
      - id: slow-stat
        match: {operation: stat}
        action: {type: delay, when: before, duration: {min: 1ms, max: 20ms}}
`
	writeTestFile(t, config, "schema_version: 1\nscenarios:\n  pinned:\n    seed: 481516\n    faults:"+slowStat+"  fresh:\n    faults:"+slowStat)
	freshLine := regexp.MustCompile(`  seed: (\d+) \(fresh; --seed (\d+) repeats its decisions\)\n`)
	tests := []struct {
		args []string
		// pinned is the seed shown and recorded, or "" for a fresh one.
		pinned string
	}{
		{[]string{"--scenario", "pinned"}, "481516"},
		{[]string{"--scenario", "pinned", "--seed", "7"}, "7"},
		{[]string{"--scenario", "fresh", "--seed", "18446744073709551615"}, "18446744073709551615"},
		{[]string{"--scenario", "fresh"}, ""},
		{[]string{"--scenario", "fresh"}, ""},
	}
	var fresh []string
	for _, tt := range tests {
		s := startServe(t, append([]string{"--config", config, "--sftp-listen", "127.0.0.1:0"}, tt.args...)...)
		var record struct {
			Scenario   string `json:"scenario"`
			Seed       uint64 `json:"seed"`
			SeedPinned bool   `json:"seed_pinned"`
		}
		b, err := os.ReadFile(filepath.Join(s.workspace, "runs", s.run, "run.json"))
		if err == nil {
			err = json.Unmarshal(b, &record)
		}
		c := s.dial(t, "test", "test")
		if _, err := c.Stat("/"); err != nil {
			t.Errorf("%v: Stat: %v", tt.args, err)
		}
		c.Close()
		s.stop(t)
		if err != nil {
			t.Fatalf("%v: run.json: %v", tt.args, err)
		}

		out := s.stdout.String()
		shown := tt.pinned
		if tt.pinned != "" {
			if !strings.Contains(out, "  seed: "+tt.pinned+" (pinned)\n") {
				t.Errorf("%v: banner does not show seed %s as pinned:\n%s", tt.args, tt.pinned, out)
			}
		} else if m := freshLine.FindStringSubmatch(out); m == nil || m[1] != m[2] {
			t.Fatalf("%v: banner does not show a fresh seed and how to repeat it:\n%s", tt.args, out)
		} else {
			shown = m[1]
			fresh = append(fresh, shown)
			if _, err := strconv.ParseUint(shown, 10, 32); err != nil {
				t.Errorf("%v: fresh seed %s does not fit in 32 bits", tt.args, shown)
			}
		}
		if want := tt.args[1]; record.Scenario != want || strconv.FormatUint(record.Seed, 10) != shown || record.SeedPinned != (tt.pinned != "") {
			t.Errorf("%v: run.json records %+v, want scenario %s and seed %s, pinned: %v", tt.args, record, want, shown, tt.pinned != "")
		}
		seed, _ := strconv.ParseUint(shown, 10, 64)
		key := faults.Key{Rule: "slow-stat", Choice: "duration", User: "test", Path: "/", Operation: "stat", Ordinal: 1}
		duration := faults.Between(faults.Seed(seed).Draw(key), time.Millisecond, 20*time.Millisecond)
		if fired := fmt.Sprintf(`msg="rule fired" rule=slow-stat request=stat path=/ user=test ordinal=1 duration=%v`, duration); !strings.Contains(s.stderr.String(), fired) {
			t.Errorf("%v: stderr lacks %s, drawn from seed %s:\n%s", tt.args, fired, shown, s.stderr.String())
		}
	}
	// Two fresh 32-bit seeds coincide with a chance of 1 in 2^32.
	if len(fresh) == 2 && fresh[0] == fresh[1] {
		t.Errorf("two runs drew the same fresh seed %s", fresh[0])
	}
}

func TestServeKeepsADataDirectory(t *testing.T) {
	dataDir := filepath.Join(t.TempDir(), "sandbox-data")

	first := startServe(t, "--sftp-listen", "127.0.0.1:0", "--data-dir", dataDir)
	if !strings.Contains(first.stdout.String(), "workspace: "+dataDir+" (kept, with its last five runs)") {
		t.Errorf("banner does not say the workspace is kept:\n%s", first.stdout.String())
	}
	c := first.dial(t, "test", "test")
	f, err := c.Create("/orders.csv")
	if err != nil {
		t.Fatalf("Create: %v", err)
	}
	if _, err := f.Write([]byte("id,total\n")); err != nil {
		t.Fatalf("upload: %v", err)
	}
	f.Close()
	if code := first.stop(t); code != exitOK {
		t.Fatalf("exit code = %d, want %d\nstderr:\n%s", code, exitOK, first.stderr.String())
	}
	if got, err := os.ReadFile(filepath.Join(first.files(), "orders.csv")); err != nil || string(got) != "id,total\n" {
		t.Errorf("the first run's upload is %q (%v) after it stopped, want it kept", got, err)
	}

	second := startServe(t, "--sftp-listen", "127.0.0.1:0", "--data-dir", dataDir)
	if second.run == first.run {
		t.Errorf("both starts ran %s, want a new run each time", first.run)
	}
	if _, err := second.dial(t, "test", "test").Stat("/orders.csv"); !errors.Is(err, os.ErrNotExist) {
		t.Errorf("the second run sees the first run's upload (%v), want it to start empty", err)
	}
	second.stop(t)
	if a, b := fingerprints(first.stdout.String()), fingerprints(second.stdout.String()); a != b {
		t.Errorf("host keys changed between runs: %v then %v", a, b)
	}
}

func TestServeRefusesUnusableDataDirectories(t *testing.T) {
	notEmpty := t.TempDir()
	writeTestFile(t, filepath.Join(notEmpty, "notes.txt"), "keep me")
	var stdout, stderr syncBuffer
	code := run(context.Background(), []string{"serve", "--sftp-listen", "127.0.0.1:0", "--data-dir", notEmpty}, &stdout, &stderr)
	if code != exitUsage || !strings.Contains(stderr.String(), "is not empty: not an sftpit workspace") {
		t.Errorf("a directory with other files: exit %d, stderr %q", code, stderr.String())
	}

	inUse := t.TempDir()
	startServe(t, "--sftp-listen", "127.0.0.1:0", "--data-dir", inUse)
	stderr = syncBuffer{}
	code = run(context.Background(), []string{"serve", "--sftp-listen", "127.0.0.1:0", "--data-dir", inUse}, &stdout, &stderr)
	if code != exitFailure || !strings.Contains(stderr.String(), "workspace in use by another sftpit process") {
		t.Errorf("a workspace in use: exit %d, stderr %q", code, stderr.String())
	}
}

func TestServeStartsEveryRunFromTheSeed(t *testing.T) {
	seed := t.TempDir()
	if err := os.MkdirAll(filepath.Join(seed, "outgoing"), 0o755); err != nil {
		t.Fatal(err)
	}
	writeTestFile(t, filepath.Join(seed, "outgoing", "orders.csv"), "id,total\n1,9.99\n")

	for run := 1; run <= 2; run++ {
		s := startServe(t, "--sftp-listen", "127.0.0.1:0", "--seed-dir", seed)
		if !strings.Contains(s.stdout.String(), "seeded from: "+seed) {
			t.Errorf("run %d: banner does not name the seed:\n%s", run, s.stdout.String())
		}
		c := s.dial(t, "test", "test")
		f, err := c.Open("/outgoing/orders.csv")
		if err != nil {
			t.Fatalf("run %d: Open a seeded file: %v", run, err)
		}
		var got bytes.Buffer
		if _, err := f.WriteTo(&got); err != nil || got.String() != "id,total\n1,9.99\n" {
			t.Fatalf("run %d: downloaded %q, %v", run, got.String(), err)
		}
		f.Close()
		if _, err := c.Stat("/outgoing/uploaded.csv"); !errors.Is(err, os.ErrNotExist) {
			t.Errorf("run %d: a file uploaded in an earlier run is still there (%v)", run, err)
		}

		if err := c.Remove("/outgoing/orders.csv"); err != nil {
			t.Fatalf("run %d: Remove: %v", run, err)
		}
		up, err := c.Create("/outgoing/uploaded.csv")
		if err != nil {
			t.Fatalf("run %d: Create: %v", run, err)
		}
		up.Close()
		s.stop(t)
	}
	if _, err := os.Stat(filepath.Join(seed, "outgoing", "orders.csv")); err != nil {
		t.Errorf("seed file changed by a client: %v", err)
	}
}

func TestServeRejectsUnusableSeeds(t *testing.T) {
	withLink := t.TempDir()
	writeTestFile(t, filepath.Join(withLink, "orders.csv"), "data")
	if err := os.Symlink("orders.csv", filepath.Join(withLink, "link.csv")); err != nil {
		t.Skipf("cannot create a symlink here: %v", err)
	}
	var stdout, stderr syncBuffer
	code := run(context.Background(), []string{"serve", "--sftp-listen", "127.0.0.1:0", "--seed-dir", withLink}, &stdout, &stderr)
	if code != exitUsage || !strings.Contains(stderr.String(), "link.csv: only regular files and directories") {
		t.Errorf("seed with a symlink: exit %d, stderr %q", code, stderr.String())
	}

	tooBig := t.TempDir()
	writeTestFile(t, filepath.Join(tooBig, "orders.csv"), "data!")
	config := filepath.Join(t.TempDir(), "sftpit.yaml")
	writeTestFile(t, config, "schema_version: 1\nstorage:\n  max_file_bytes: 4\n")
	stderr = syncBuffer{}
	code = run(context.Background(), []string{"serve", "--sftp-listen", "127.0.0.1:0", "--config", config, "--seed-dir", tooBig}, &stdout, &stderr)
	if code != exitUsage || !strings.Contains(stderr.String(), "orders.csv: storage limit reached: max_file_bytes is 4") {
		t.Errorf("seed past a limit: exit %d, stderr %q", code, stderr.String())
	}

	if runtime.GOOS == "windows" {
		return
	}
	holdsWorkspace := t.TempDir()
	tmp := filepath.Join(holdsWorkspace, "tmp")
	if err := os.Mkdir(tmp, 0o700); err != nil {
		t.Fatal(err)
	}
	t.Setenv("TMPDIR", tmp)
	stderr = syncBuffer{}
	code = run(context.Background(), []string{"serve", "--sftp-listen", "127.0.0.1:0", "--seed-dir", holdsWorkspace}, &stdout, &stderr)
	if code != exitUsage || !strings.Contains(stderr.String(), "contains the workspace") {
		t.Errorf("seed holding the workspace: exit %d, stderr %q", code, stderr.String())
	}
	if entries, _ := os.ReadDir(tmp); len(entries) != 0 {
		t.Errorf("workspace left behind in %s: %v", tmp, entries)
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
		{"undefined scenario", []string{"--scenario", "upload-recovery"}, `scenario "upload-recovery" is not defined`},
		{"seed without a scenario", []string{"--seed", "7"}, "--seed needs --scenario, whose random decisions it pins"},
		{"negative seed", []string{"--scenario", "s", "--seed", "-1"}, `invalid value "-1" for flag -seed: a seed is a whole number from 0 to 18446744073709551615`},
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
	run            string
	cancel         context.CancelFunc
	code           chan int
}

var (
	addrLine      = regexp.MustCompile(`serving SFTP on (\S+)`)
	workspaceLine = regexp.MustCompile(`workspace: (.+) \((?:deleted|kept)`)
	runLine       = regexp.MustCompile(`run: (\S+)`)
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
