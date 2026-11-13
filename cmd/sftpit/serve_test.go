package main

import (
	"bytes"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"io/fs"
	"net"
	"net/http"
	"os"
	"path/filepath"
	"regexp"
	"runtime"
	"slices"
	"strings"
	"syscall"
	"testing"

	"golang.org/x/crypto/ssh"

	"github.com/nebarg/sftpit/internal/config"
	"github.com/nebarg/sftpit/internal/control"
	"github.com/nebarg/sftpit/internal/testutil"
)

func TestServeTransfersFilesAndCleansUp(t *testing.T) {
	s := startServe(t)
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
	stderr := s.stderr.String()
	for _, want := range []*regexp.Regexp{
		regexp.MustCompile(`level=INFO msg=connected conn=1 remote=127\.0\.0\.1:\d+\n`),
		regexp.MustCompile(`level=INFO msg="logged in" conn=1 user=test\n`),
		regexp.MustCompile(`level=INFO msg=transfer conn=1 user=test path=/orders.csv mode=read_write bytes_read=0 bytes_written=700000 duration=\S+ closed=close\n`),
		regexp.MustCompile(`level=INFO msg=disconnected conn=1 user=test\n`),
	} {
		if !want.MatchString(stderr) {
			t.Errorf("the log does not match %s:\n%s", want, stderr)
		}
	}
	if strings.Contains(stderr, "level=WARN") || strings.Contains(stderr, "level=ERROR") {
		t.Errorf("stopping with a client connected logged a warning or an error:\n%s", stderr)
	}
	if _, err := os.Stat(s.workspace); !errors.Is(err, fs.ErrNotExist) {
		t.Errorf("workspace %s still exists after shutdown (%v)", s.workspace, err)
	}
}

func TestServeKeepsReadOnlyPathsFromChange(t *testing.T) {
	dir := t.TempDir()
	config := filepath.Join(dir, "sftpit.yaml")
	testutil.WriteFile(t, config, `schema_version: 1
users:
  - name: "test"
    password_env: "TEST_PASSWORD"
  - name: "partner-b"
    password_env: "TEST_PASSWORD"
policy:
  read_only:
    - path_prefix: "/reference"
    - path_prefix: "/outgoing"
      users: ["partner-b"]
`)
	testutil.WriteFile(t, filepath.Join(dir, ".env"), "TEST_PASSWORD=pw\n")

	s := startServe(t, "--config", config, "--env-file", filepath.Join(dir, ".env"))
	if out := s.stdout.String(); !strings.Contains(out, "  read-only: /reference, /outgoing (partner-b)\n") {
		t.Errorf("banner should list the read-only paths:\n%s", out)
	}
	for user, refused := range map[string][]string{
		"test":      {"/reference"},
		"partner-b": {"/reference", "/outgoing"},
	} {
		c := s.dial(t, user, "pw")
		for _, dir := range []string{"/reference", "/outgoing"} {
			err := c.Mkdir(dir)
			if denied := errors.Is(err, fs.ErrPermission); denied != slices.Contains(refused, dir) {
				t.Errorf("%s: Mkdir(%s) = %v, want it refused: %v", user, dir, err, slices.Contains(refused, dir))
			}
		}
	}
}

func TestServeUsesConfiguredUsersAndHostKeys(t *testing.T) {
	dir := t.TempDir()
	config := filepath.Join(dir, "sftpit.yaml")
	testutil.WriteFile(t, config, `schema_version: 1
env_file: "test.env"
server:
  host_key: "hostkeys"
users:
  - name: "partner-b"
    password_env: "PARTNER_B_PASSWORD"
    home: "/partner-b"
`)
	testutil.WriteFile(t, filepath.Join(dir, "test.env"), "PARTNER_B_PASSWORD=s3cret-value\n")

	first := startServe(t, "--config", config)
	if out := first.stdout.String(); !strings.Contains(out, "users: partner-b (password)") || strings.Contains(out, "s3cret-value") {
		t.Errorf("banner should list the user without the password:\n%s", out)
	}
	c := first.dial(t, "partner-b", "s3cret-value")
	if wd, err := c.Getwd(); err != nil || wd != "/partner-b" {
		t.Errorf("Getwd = %q, %v; want the home directory", wd, err)
	}
	c.Close()
	first.stop(t)

	second := startServe(t, "--config", config)
	second.stop(t)
	if a, b := fingerprints(first.stdout.String()), fingerprints(second.stdout.String()); strings.Count(a, "SHA256:") != 2 || a != b {
		t.Errorf("host keys changed between runs: %v then %v", a, b)
	}
	if _, err := os.Stat(filepath.Join(dir, "hostkeys", "ssh_host_ed25519_key")); err != nil {
		t.Errorf("host key not kept in the configured directory: %v", err)
	}
}

func TestServeKeepsTheUsersHostKeysWithoutASetting(t *testing.T) {
	configDir, err := userConfigDir()
	if err != nil {
		t.Fatal(err)
	}
	keyDir := filepath.Join(configDir, "sftpit", "hostkeys")

	first := startServe(t)
	first.stop(t)
	second := startServe(t)
	second.stop(t)
	if out := first.stdout.String(); !strings.Contains(out, "host keys, from "+keyDir+":") {
		t.Errorf("banner does not say the host keys come from %s:\n%s", keyDir, out)
	}
	if a, b := fingerprints(first.stdout.String()), fingerprints(second.stdout.String()); strings.Count(a, "SHA256:") != 2 || a != b {
		t.Errorf("host keys changed between starts: %v then %v", a, b)
	}
	if _, err := os.Stat(filepath.Join(keyDir, "ssh_host_ed25519_key")); err != nil {
		t.Errorf("host key not kept in the user's directory: %v", err)
	}
}

func TestUserHostKeyDir(t *testing.T) {
	found := func() (string, error) { return "/home/me/.config", nil }
	tests := []struct {
		name      string
		profile   config.Profile
		configDir func() (string, error)
		want      string
		warning   string
	}{
		{name: "loopback", profile: config.Loopback, configDir: found, want: filepath.Join("/home/me/.config", "sftpit", "hostkeys")},
		{name: "container", profile: config.Container, configDir: found},
		{
			name: "no user config directory", profile: config.Loopback,
			configDir: func() (string, error) { return "", errors.New("$HOME is not defined") },
			warning:   "sftpit serve: warning: host keys will change at every start: $HOME is not defined\n",
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			var stderr strings.Builder
			if got := userHostKeyDir(tt.profile, tt.configDir, "serve", &stderr); got != tt.want || stderr.String() != tt.warning {
				t.Errorf("userHostKeyDir = %q, warning %q; want %q, %q", got, stderr.String(), tt.want, tt.warning)
			}
		})
	}
}

func TestServeLogsEveryRequestAtTheDebugLevel(t *testing.T) {
	for _, tt := range []struct {
		level string
		debug bool
	}{{"debug", true}, {"info", false}, {"warn", false}} {
		t.Run(tt.level, func(t *testing.T) {
			s := startServe(t, "--log-level", tt.level)
			if _, err := s.dial(t, "test", "test").Stat("/"); err != nil {
				t.Fatalf("Stat: %v", err)
			}
			s.stop(t)
			stderr := s.stderr.String()
			if got := strings.Contains(stderr, `level=DEBUG msg="sftp request"`); got != tt.debug {
				t.Errorf("logs requests: %v, want %v:\n%s", got, tt.debug, stderr)
			}
			if got := strings.Contains(stderr, "level=INFO"); got != (tt.level != "warn") {
				t.Errorf("logs at info: %v, want %v:\n%s", got, tt.level != "warn", stderr)
			}
		})
	}
}

func TestServeTurnsFaultsOnFromATest(t *testing.T) {
	seed := t.TempDir()
	testutil.WriteFile(t, filepath.Join(seed, "outgoing", "report.csv"), "id,total\n")
	s := startServe(t, "--seed-dir", seed)
	api := "http://" + s.apiAddr + "/api"
	do := func(method, path, body string, want int) map[string]any {
		t.Helper()
		req, err := http.NewRequest(method, api+path, strings.NewReader(body))
		if err != nil {
			t.Fatal(err)
		}
		req.Header.Set(control.RequestHeader, "1")
		resp, err := http.DefaultClient.Do(req)
		if err != nil {
			t.Fatalf("%s %s: %v", method, path, err)
		}
		defer resp.Body.Close()
		var decoded map[string]any
		if resp.StatusCode != http.StatusNoContent {
			if err := json.NewDecoder(resp.Body).Decode(&decoded); err != nil {
				t.Fatalf("%s %s: %v", method, path, err)
			}
		}
		if resp.StatusCode != want {
			t.Fatalf("%s %s = %s %v, want %d", method, path, resp.Status, decoded, want)
		}
		return decoded
	}

	fault := do("POST", "/faults", `{"preset": "deletes_fail", "folder": "/outgoing"}`, http.StatusCreated)
	c := s.dial(t, "test", "test")
	if err := c.Remove("/outgoing/report.csv"); !errors.Is(err, os.ErrPermission) {
		t.Errorf("a delete with the fault on = %v, want it refused", err)
	}
	if got := do("GET", "/faults/"+fault["id"].(string), "", http.StatusOK); got["happened"] != 1.0 {
		t.Errorf("the fault = %v, want it to have happened once", got)
	}
	if !strings.Contains(s.stderr.String(), "rule=deletes-fail-1") {
		t.Errorf("the log does not name the fault:\n%s", s.stderr.String())
	}

	do("POST", "/reset", "", http.StatusNoContent)
	c = s.dial(t, "test", "test")
	if err := c.Remove("/outgoing/report.csv"); err != nil {
		t.Errorf("a delete after a reset = %v, want the seed's file back and the fault gone", err)
	}
	if got := do("GET", "/faults", "", http.StatusOK); len(got["faults"].([]any)) != 0 {
		t.Errorf("after a reset, faults = %v, want none", got)
	}
}

func TestServeShowsWhatClientsDidAsActivity(t *testing.T) {
	s := startServe(t)
	api := "http://" + s.apiAddr + "/api"
	c := s.dial(t, "test", "test")
	if err := c.Mkdir("/outgoing"); err != nil {
		t.Fatalf("Mkdir: %v", err)
	}
	f, err := c.Create("/outgoing/report.csv")
	if err != nil {
		t.Fatalf("Create: %v", err)
	}
	if _, err := f.Write(bytes.Repeat([]byte("x"), 100000)); err != nil {
		t.Fatalf("Write: %v", err)
	}
	f.Close()
	if _, err := c.ReadDir("/outgoing"); err != nil {
		t.Fatalf("ReadDir: %v", err)
	}
	for range 2 {
		f, err := c.Open("/outgoing/report.csv")
		if err != nil {
			t.Fatalf("Open: %v", err)
		}
		if _, err := io.ReadAll(f); err != nil {
			t.Fatalf("download: %v", err)
		}
		f.Close()
	}
	requestJSONStatus(t, "POST", api+"/faults", `{"preset": "deletes_fail"}`, http.StatusCreated)
	if err := c.Remove("/outgoing/report.csv"); !errors.Is(err, os.ErrPermission) {
		t.Fatalf("Remove = %v, want it refused", err)
	}
	if _, err := c.Stat("/missing.csv"); !errors.Is(err, os.ErrNotExist) {
		t.Fatalf("Stat = %v, want no such file", err)
	}

	// An event is recorded as its reply is sent, so the client's last
	// reply means the activity holds every line.
	var got []string
	lines := requestJSON(t, api+"/activity")["lines"].([]any)
	for _, l := range lines {
		l := l.(map[string]any)
		var line strings.Builder
		fmt.Fprint(&line, l["kind"], " ", l["outcome"])
		for _, field := range []string{"path", "reason", "bytes"} {
			if v, ok := l[field]; ok {
				fmt.Fprint(&line, " ", field, "=", v)
			}
		}
		if f, ok := l["fault"].(map[string]any); ok {
			fmt.Fprint(&line, " fault=", f["name"])
		}
		if _, ok := l["repeat"]; ok {
			line.WriteString(" repeat")
		}
		got = append(got, line.String())
	}
	want := []string{
		"connected ok",
		"mkdir ok path=/outgoing",
		"upload ok path=/outgoing/report.csv bytes=100000",
		"listing ok path=/outgoing",
		"download ok path=/outgoing/report.csv bytes=100000",
		"download ok path=/outgoing/report.csv bytes=100000 repeat",
		"delete fault path=/outgoing/report.csv reason=permission_denied fault=Deletes fail",
		// The client's own follow-up to a refused delete.
		"rmdir failed path=/outgoing/report.csv reason=no_such_file",
		"check ok path=/outgoing/report.csv",
		"check failed path=/missing.csv reason=no_such_file",
	}
	if strings.Join(got, "\n") != strings.Join(want, "\n") {
		t.Errorf("activity:\n%s\nwant:\n%s", strings.Join(got, "\n"), strings.Join(want, "\n"))
	}
	if first := lines[0].(map[string]any); !strings.HasPrefix(first["client"].(string), "SSH-2.0-") || !strings.HasPrefix(first["remote"].(string), "127.0.0.1:") {
		t.Errorf("the connection line = %v, want the client's version and address", first)
	}
	latest := requestJSON(t, api+"/activity?limit=2")["lines"].([]any)
	if len(latest) != 2 || latest[1].(map[string]any)["path"] != "/missing.csv" {
		t.Errorf("activity?limit=2 = %v, want the latest two lines", latest)
	}
}

// requestJSONStatus makes a request to the control API and checks its
// status.
func requestJSONStatus(t *testing.T, method, url, body string, want int) {
	t.Helper()
	req, err := http.NewRequest(method, url, strings.NewReader(body))
	if err != nil {
		t.Fatal(err)
	}
	req.Header.Set(control.RequestHeader, "1")
	resp, err := http.DefaultClient.Do(req)
	if err != nil {
		t.Fatalf("%s %s: %v", method, url, err)
	}
	resp.Body.Close()
	if resp.StatusCode != want {
		t.Fatalf("%s %s = %s, want %d", method, url, resp.Status, want)
	}
}

func TestServeInjectsTheSelectedScenariosFaults(t *testing.T) {
	config := filepath.Join(t.TempDir(), "sftpit.yaml")
	testutil.WriteFile(t, config, `schema_version: 1
server:
  host_key: keys
scenarios:
  deny-ack:
    faults:
      - {preset: deletes_fail, user: test, names: "*.csv"}
`)
	for _, scenario := range []string{"deny-ack", ""} {
		args := []string{"--config", config}
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
			if strings.Contains(s.stdout.String(), "scenario") || strings.Contains(s.stdout.String(), "  seed:") || strings.Contains(s.stderr.String(), "rule fired") {
				t.Errorf("without a scenario, sftpit reported one:\n%s%s", s.stdout.String(), s.stderr.String())
			}
			continue
		}
		if !errors.Is(err, fs.ErrPermission) || statErr != nil {
			t.Errorf("Remove = %v and the file is gone (%v), want permission denied and the file kept", err, statErr)
		}
		if out := s.stdout.String(); !strings.Contains(out, "  scenario on: deny-ack\n") {
			t.Errorf("banner does not name the scenario:\n%s", out)
		}
		if logs := s.stderr.String(); !strings.Contains(logs, `msg="rule fired" rule=deletes-fail-1 operation=remove path=/outgoing/orders.csv user=test ordinal=1`) {
			t.Errorf("stderr does not log the rule firing:\n%s", logs)
		}
	}
}

func TestServeTurnsOnABuiltInScenario(t *testing.T) {
	s := startServe(t, "--scenario", "unreliable-light")
	if want := "  scenario on: unreliable-light\n"; !strings.Contains(s.stdout.String(), want) {
		t.Errorf("the banner lacks %q:\n%s", want, s.stdout.String())
	}
	got := requestJSON(t, "http://"+s.apiAddr+"/api/faults")
	list, _ := got["faults"].([]any)
	if len(list) != 2 || list[0].(map[string]any)["scenario"] != "unreliable-light" {
		t.Errorf("the faults = %v, want the scenario's two", got)
	}
	requestJSONStatus(t, "POST", "http://"+s.apiAddr+"/api/reset", "", http.StatusNoContent)
	if got := requestJSON(t, "http://"+s.apiAddr+"/api/faults"); len(got["faults"].([]any)) != 0 {
		t.Errorf("after a reset, the faults = %v, want none", got)
	}
}

func TestServeInjectsFaultsAtLogin(t *testing.T) {
	config := filepath.Join(t.TempDir(), "sftpit.yaml")
	testutil.WriteFile(t, config, `schema_version: 1
scenarios:
  cut-first-login:
    faults:
      - {steps: [authenticate], do: drop, only: 1}
`)
	s := startServe(t, "--config", config, "--scenario", "cut-first-login")
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
	if logs := s.stderr.String(); !strings.Contains(logs, `msg="injected fault" conn=1 operation=authenticate user=test fault=close_connection mode=fin`) {
		t.Errorf("stderr does not log the fault at the first login:\n%s", logs)
	}
}

func TestServeTakesTheListenerDownAtAMomentOfTheRun(t *testing.T) {
	config := filepath.Join(t.TempDir(), "sftpit.yaml")
	testutil.WriteFile(t, config, `schema_version: 1
scenarios:
  outage:
    faults:
      - {preset: server_goes_down, seconds: 60}
`)
	s := startServe(t, "--config", config, "--scenario", "outage")
	// The run starts with the outage, before serve announces itself.
	if want := `msg="injected fault" fault=listener_down when=timer duration=1m0s close_existing=true`; !strings.Contains(s.stderr.String(), want) {
		t.Fatalf("serve did not take the listener down as the run started:\n%s", s.stderr.String())
	}
	if conn, err := net.Dial("tcp", s.addr); !errors.Is(err, syscall.ECONNREFUSED) {
		if err == nil {
			conn.Close()
		}
		t.Errorf("Dial during the outage = %v, want the connection refused", err)
	}
}

func TestServeKeepsADataDirectory(t *testing.T) {
	dataDir := filepath.Join(t.TempDir(), "sandbox-data")

	first := startServe(t, "--data-dir", dataDir)
	if out := first.stdout.String(); !strings.Contains(out, "workspace: "+dataDir+" (kept, with its last five runs)") || !strings.Contains(out, "host keys, from the workspace:") {
		t.Errorf("banner does not say the workspace, and its host keys, are kept:\n%s", out)
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

	second := startServe(t, "--data-dir", dataDir)
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
	testutil.WriteFile(t, filepath.Join(notEmpty, "notes.txt"), "keep me")
	var stdout, stderr testutil.SyncBuffer
	code := run(commandContext(t), []string{"serve", "--sftp-listen", "127.0.0.1:0", "--http-listen", "127.0.0.1:0", "--data-dir", notEmpty}, &stdout, &stderr)
	if code != exitUsage || !strings.Contains(stderr.String(), "is not empty: not an sftpit workspace") {
		t.Errorf("a directory with other files: exit %d, stderr %q", code, stderr.String())
	}

	inUse := t.TempDir()
	startServe(t, "--data-dir", inUse)
	stderr = testutil.SyncBuffer{}
	code = run(commandContext(t), []string{"serve", "--sftp-listen", "127.0.0.1:0", "--http-listen", "127.0.0.1:0", "--data-dir", inUse}, &stdout, &stderr)
	if code != exitFailure || !strings.Contains(stderr.String(), "workspace in use by another sftpit process") {
		t.Errorf("a workspace in use: exit %d, stderr %q", code, stderr.String())
	}
}

func TestServeStartsEveryRunFromTheSeed(t *testing.T) {
	seed := t.TempDir()
	if err := os.MkdirAll(filepath.Join(seed, "outgoing"), 0o755); err != nil {
		t.Fatal(err)
	}
	testutil.WriteFile(t, filepath.Join(seed, "outgoing", "orders.csv"), "id,total\n1,9.99\n")

	for run := 1; run <= 2; run++ {
		s := startServe(t, "--seed-dir", seed)
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

func TestServeResetsThroughTheControlAPI(t *testing.T) {
	seed := t.TempDir()
	testutil.WriteFile(t, filepath.Join(seed, "orders.csv"), "id,total\n")
	s := startServe(t, "--seed-dir", seed)
	c := s.dial(t, "test", "test")
	if err := c.Remove("/orders.csv"); err != nil {
		t.Fatalf("Remove: %v", err)
	}
	api := "http://" + s.apiAddr + "/api"
	if status := requestJSON(t, api+"/status"); status["run"].(map[string]any)["id"] != s.run {
		t.Errorf("status = %v, want the run in the banner, %s", status, s.run)
	}

	requestJSONStatus(t, "POST", api+"/reset", "", http.StatusNoContent)
	next, _ := requestJSON(t, api+"/status")["run"].(map[string]any)["id"].(string)
	if next == "" || next == s.run {
		t.Fatalf("after a reset the run is %q, want a new one", next)
	}
	if _, err := s.dial(t, "test", "test").Stat("/orders.csv"); err != nil {
		t.Errorf("the next run lacks the seeded file: %v", err)
	}
	if want := "msg=reset run=" + next; !strings.Contains(s.stderr.String(), want) {
		t.Errorf("stderr lacks %q:\n%s", want, s.stderr.String())
	}
}

func TestServeAnswersTheControlHostsItIsGiven(t *testing.T) {
	s := startServe(t, "--control-host", "sftpit", "--control-host", "files.test")
	if !strings.Contains(s.stdout.String(), "control hosts: sftpit, files.test") {
		t.Errorf("banner does not list the control hosts:\n%s", s.stdout.String())
	}
	for host, want := range map[string]int{"sftpit:8122": http.StatusOK, "FILES.test": http.StatusOK, "other:8122": http.StatusForbidden} {
		req, err := http.NewRequest(http.MethodGet, "http://"+s.apiAddr+"/api/status", nil)
		if err != nil {
			t.Fatal(err)
		}
		req.Host = host
		resp, err := http.DefaultClient.Do(req)
		if err != nil {
			t.Fatalf("GET status as %s: %v", host, err)
		}
		resp.Body.Close()
		if resp.StatusCode != want {
			t.Errorf("GET status as %s = %s, want %d", host, resp.Status, want)
		}
	}
}

func TestServeWarnsOfLoopbackAddressesInTheContainerProfile(t *testing.T) {
	s := startServe(t, "--profile", "container")
	if !strings.Contains(s.stdout.String(), "profile: container") {
		t.Errorf("banner does not show the profile:\n%s", s.stdout.String())
	}
	for _, setting := range []string{"sftp_listen", "http_listen"} {
		if want := `warning: ` + setting + ` "127.0.0.1:0" is a loopback address, which other containers cannot reach`; !strings.Contains(s.stderr.String(), want) {
			t.Errorf("stderr lacks %q:\n%s", want, s.stderr.String())
		}
	}
	s.dial(t, "test", "test")
}

func TestServeListensOnEveryInterfaceInTheContainerProfile(t *testing.T) {
	if runtime.GOOS != "linux" {
		t.Skip("listening on every interface makes the firewall of macOS ask to allow it")
	}
	s := startServe(t, "--profile", "container", "--sftp-listen", ":0", "--http-listen", ":0")
	if stderr := s.stderr.String(); stderr != "" {
		t.Errorf("serve logged:\n%s", stderr)
	}
	// Another container reaches it on the address of an interface that is
	// not loopback.
	other := nonLoopbackAddress(t)
	for _, addr := range []string{s.addr, s.apiAddr} {
		host, port, err := net.SplitHostPort(addr)
		if ip := net.ParseIP(host); err != nil || ip == nil || !ip.IsUnspecified() {
			t.Fatalf("serving on %s, want every interface", addr)
		}
		conn, err := net.Dial("tcp", net.JoinHostPort(other, port))
		if err != nil {
			t.Fatalf("connecting on %s: %v", other, err)
		}
		conn.Close()
	}
	s.dial(t, "test", "test")
}

// nonLoopbackAddress returns an IPv4 address of this host's that is not
// loopback, or skips the test if it has none.
func nonLoopbackAddress(t *testing.T) string {
	t.Helper()
	addrs, err := net.InterfaceAddrs()
	if err != nil {
		t.Fatal(err)
	}
	for _, a := range addrs {
		if ipNet, ok := a.(*net.IPNet); ok && ipNet.IP.To4() != nil && !ipNet.IP.IsLoopback() {
			return ipNet.IP.String()
		}
	}
	t.Skip("no interface has an IPv4 address that is not loopback")
	return ""
}

func TestServeReportsHowToConnectAndServesTheDashboard(t *testing.T) {
	s := startServe(t)
	if want := "  dashboard: http://" + s.apiAddr + "/\n"; !strings.Contains(s.stdout.String(), want) {
		t.Errorf("the banner lacks %q:\n%s", want, s.stdout.String())
	}
	resp, err := http.Get("http://" + s.apiAddr + "/")
	if err != nil {
		t.Fatalf("GET /: %v", err)
	}
	resp.Body.Close()
	if resp.StatusCode != http.StatusOK || !strings.HasPrefix(resp.Header.Get("Content-Type"), "text/html") {
		t.Errorf("GET / = %s with %q, want the dashboard", resp.Status, resp.Header.Get("Content-Type"))
	}

	server := requestJSON(t, "http://"+s.apiAddr+"/api/server")
	if server["sftp_address"] != s.addr || server["profile"] != "loopback" || server["workspace"] != s.workspace {
		t.Errorf("server = %v, want %s in the loopback profile, with workspace %s", server, s.addr, s.workspace)
	}
	if login, _ := server["default_login"].(map[string]any); login["user"] != "test" || login["password"] != "test" {
		t.Errorf("default_login = %v, want test/test", server["default_login"])
	}
	var keys []string
	for _, k := range server["host_keys"].([]any) {
		keys = append(keys, k.(map[string]any)["fingerprint"].(string))
	}
	if got, want := strings.Join(keys, " "), fingerprints(s.stdout.String()); got != want {
		t.Errorf("server's host keys are %s, want the banner's, %s", got, want)
	}
}

func TestServeKeepsConfiguredPasswordsOutOfTheAPI(t *testing.T) {
	t.Setenv("SFTPIT_SERVE_TEST_PASSWORD", "a-real-secret")
	config := filepath.Join(t.TempDir(), "sftpit.yaml")
	testutil.WriteFile(t, config, "schema_version: 1\nusers:\n  - {name: partner, password_env: SFTPIT_SERVE_TEST_PASSWORD, home: /partner}\n")
	s := startServe(t, "--config", config)
	resp, err := http.Get("http://" + s.apiAddr + "/api/server")
	if err != nil {
		t.Fatalf("GET /api/server: %v", err)
	}
	defer resp.Body.Close()
	raw, err := io.ReadAll(resp.Body)
	if err != nil {
		t.Fatal(err)
	}
	if strings.Contains(string(raw), "a-real-secret") || strings.Contains(string(raw), "default_login") {
		t.Errorf("server shows a password: %s", raw)
	}
	if !strings.Contains(string(raw), `"users":[{"name":"partner","home":"/partner","password":true,"keys":0}]`) {
		t.Errorf("server = %s, want partner with a password", raw)
	}
}

func TestServeRunsScenarioFiles(t *testing.T) {
	dir := t.TempDir()
	config := filepath.Join(dir, "sftpit.yaml")
	testutil.WriteFile(t, config, "schema_version: 1\nscenarios:\n  configured: {faults: [{preset: deletes_fail}]}\n")
	testutil.WriteFile(t, filepath.Join(dir, "scenarios", "from-file.yaml"), `schema_version: 1
faults:
  - {steps: [stat], do: refuse, error: permission_denied}
`)
	s := startServe(t, "--config", config, "--scenario", "from-file")
	if want := "  scenario on: from-file\n"; !strings.Contains(s.stdout.String(), want) {
		t.Errorf("the banner lacks %q:\n%s", want, s.stdout.String())
	}
	if _, err := s.dial(t, "test", "test").Stat("/"); !errors.Is(err, os.ErrPermission) {
		t.Errorf("Stat = %v, want the scenario file's fault", err)
	}

}

func requestJSON(t *testing.T, url string) map[string]any {
	t.Helper()
	resp, err := http.Get(url)
	if err != nil {
		t.Fatalf("GET %s: %v", url, err)
	}
	defer resp.Body.Close()
	var decoded map[string]any
	if err := json.NewDecoder(resp.Body).Decode(&decoded); err != nil || resp.StatusCode != http.StatusOK {
		t.Fatalf("GET %s = %s %v (%v)", url, resp.Status, decoded, err)
	}
	return decoded
}

func TestServeRejectsUnusableSeeds(t *testing.T) {
	withLink := t.TempDir()
	testutil.WriteFile(t, filepath.Join(withLink, "orders.csv"), "data")
	if err := os.Symlink("orders.csv", filepath.Join(withLink, "link.csv")); err != nil {
		t.Skipf("cannot create a symlink here: %v", err)
	}
	var stdout, stderr testutil.SyncBuffer
	code := run(commandContext(t), []string{"serve", "--sftp-listen", "127.0.0.1:0", "--http-listen", "127.0.0.1:0", "--seed-dir", withLink}, &stdout, &stderr)
	if code != exitUsage || !strings.Contains(stderr.String(), "link.csv: only regular files and directories") {
		t.Errorf("seed with a symlink: exit %d, stderr %q", code, stderr.String())
	}

	tooBig := t.TempDir()
	testutil.WriteFile(t, filepath.Join(tooBig, "orders.csv"), "data!")
	config := filepath.Join(t.TempDir(), "sftpit.yaml")
	testutil.WriteFile(t, config, "schema_version: 1\nstorage:\n  max_file_bytes: 4\n")
	stderr = testutil.SyncBuffer{}
	code = run(commandContext(t), []string{"serve", "--sftp-listen", "127.0.0.1:0", "--http-listen", "127.0.0.1:0", "--config", config, "--seed-dir", tooBig}, &stdout, &stderr)
	if code != exitUsage || !strings.Contains(stderr.String(), "orders.csv: storage limit reached: max_file_bytes is 4") {
		t.Errorf("seed past a limit: exit %d, stderr %q", code, stderr.String())
	}

	holdsWorkspace := t.TempDir()
	tmp := filepath.Join(holdsWorkspace, "tmp")
	if err := os.Mkdir(tmp, 0o700); err != nil {
		t.Fatal(err)
	}
	t.Setenv("TMPDIR", tmp)
	stderr = testutil.SyncBuffer{}
	code = run(commandContext(t), []string{"serve", "--sftp-listen", "127.0.0.1:0", "--http-listen", "127.0.0.1:0", "--seed-dir", holdsWorkspace}, &stdout, &stderr)
	if code != exitUsage || !strings.Contains(stderr.String(), "overlaps the workspace") {
		t.Errorf("seed holding the workspace: exit %d, stderr %q", code, stderr.String())
	}
	if entries, _ := os.ReadDir(tmp); len(entries) != 0 {
		t.Errorf("workspace left behind in %s: %v", tmp, entries)
	}
}

func TestServeRejectsInvalidSettings(t *testing.T) {
	missingSecret := filepath.Join(t.TempDir(), "sftpit.yaml")
	testutil.WriteFile(t, missingSecret, "schema_version: 1\nusers:\n  - {name: a, password_env: SFTPIT_SERVE_TEST_UNSET}\n")

	tests := []struct {
		name string
		args []string
		want string
	}{
		{"non-loopback address", []string{"--sftp-listen", "0.0.0.0:2122"}, "not a loopback address"},
		{"unknown flag", []string{"--smtp-listen", "127.0.0.1:0"}, "flag provided but not defined"},
		{"non-loopback control address", []string{"--http-listen", "0.0.0.0:8122"}, `http_listen "0.0.0.0:8122" is not a loopback address`},
		{"unknown profile", []string{"--profile", "remote"}, `invalid value "remote" for flag -profile: profile "remote" is not loopback or container`},
		{"control host with a port", []string{"--control-host", "sftpit:8122"}, `control host "sftpit:8122" is not a host name or IP address without a port`},
		{"stray argument", []string{"extra"}, `unexpected arguments ["extra"]`},
		{"missing config", []string{"--config", "missing.yaml"}, "missing.yaml"},
		{"missing secret", []string{"--config", missingSecret}, "SFTPIT_SERVE_TEST_UNSET is not set"},
		{"undefined scenario", []string{"--scenario", "upload-recovery"}, `unknown scenario "upload-recovery"; the scenarios are unreliable-heavy, unreliable-light, unreliable-moderate`},
		{"unknown log level", []string{"--log-level", "loud"}, `invalid value "loud" for flag -log-level: log level "loud" is not debug, info, warn or error`},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			var stdout, stderr testutil.SyncBuffer
			code := run(commandContext(t), append([]string{"serve"}, tt.args...), &stdout, &stderr)
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

	occupied := ln.Addr().String()
	for _, setting := range []string{"sftp_listen", "http_listen"} {
		// A busy port must fail before the workspace changes, so that a kept
		// run is never pruned for a run that never served.
		dataDir := t.TempDir()
		var stdout, stderr testutil.SyncBuffer
		args := []string{"serve", "--sftp-listen", "127.0.0.1:0", "--http-listen", "127.0.0.1:0", "--data-dir", dataDir, "--" + strings.ReplaceAll(setting, "_", "-"), occupied}
		code := run(commandContext(t), args, &stdout, &stderr)
		if code != exitFailure {
			t.Errorf("%s: exit code = %d, want %d", setting, code, exitFailure)
		}
		if !strings.Contains(stderr.String(), setting+": listen tcp") || !strings.Contains(stderr.String(), "address already in use") {
			t.Errorf("%s: stderr = %q, want the listen error, naming the setting", setting, stderr.String())
		}
		if entries, err := os.ReadDir(dataDir); err != nil || len(entries) != 0 {
			t.Errorf("%s: the data directory holds %v (%v), want it untouched", setting, entries, err)
		}
	}
}

func TestListenRefusesAnAddressThatIsNotLoopbackInTheLoopbackProfile(t *testing.T) {
	// The configuration refuses every address but localhost and loopback
	// ones, so only localhost resolving elsewhere would reach the check.
	// The test listens on every interface instead.
	if runtime.GOOS != "linux" {
		t.Skip("listening on every interface makes the firewall of macOS ask to allow it")
	}
	ln, err := listen(config.Loopback, "http_listen", "0.0.0.0:0")
	if err == nil {
		ln.Close()
	}
	if err == nil || !strings.HasPrefix(err.Error(), `http_listen "0.0.0.0:0" resolved to `) || !strings.HasSuffix(err.Error(), "which is not a loopback address") {
		t.Errorf("listen = %v, want it refused as not loopback", err)
	}
}

func TestServeHelp(t *testing.T) {
	var stdout, stderr testutil.SyncBuffer
	if code := run(commandContext(t), []string{"serve", "--help"}, &stdout, &stderr); code != exitOK {
		t.Errorf("exit code = %d, want %d", code, exitOK)
	}
	if !strings.Contains(stdout.String(), "Usage: sftpit serve") {
		t.Errorf("stdout = %q, want the serve usage", stdout.String())
	}
}
