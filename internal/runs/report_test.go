package runs

import (
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"io/fs"
	"os"
	"path/filepath"
	"slices"
	"strings"
	"testing"
	"time"

	"github.com/pkg/sftp"
	"golang.org/x/crypto/ssh"

	"github.com/nebarg/sftpit/internal/config"
	"github.com/nebarg/sftpit/internal/events"
	"github.com/nebarg/sftpit/internal/faults"
	"github.com/nebarg/sftpit/internal/sftpproxy"
	"github.com/nebarg/sftpit/internal/sftpwire"
	"github.com/nebarg/sftpit/internal/testutil"
)

var denyStat = faults.Rule{ID: "deny-stat", Match: faults.Match{Operations: []faults.Operation{faults.Stat}}, Action: sftpproxy.Fail{When: sftpproxy.Before, Status: sftpwire.StatusPermissionDenied}}

func exactly(n uint64) config.Count { return config.Count{Min: n, Max: &n} }

// write creates the file name holding content.
func write(t *testing.T, c *sftp.Client, name, content string) {
	t.Helper()
	f, err := c.Create(name)
	if err != nil {
		t.Fatalf("Create %s: %v", name, err)
	}
	if _, err := f.Write([]byte(content)); err != nil {
		t.Fatalf("Write %s: %v", name, err)
	}
	if err := f.Close(); err != nil {
		t.Fatalf("Close %s: %v", name, err)
	}
}

func sha(content string) string {
	sum := sha256.Sum256([]byte(content))
	return hex.EncodeToString(sum[:])
}

// startAsserting starts runs of a scenario with assertions, and a fixture
// orders.csv holding "id,total\n".
func startAsserting(t *testing.T, opts Options, s config.Scenario) (*Manager, string) {
	t.Helper()
	expected := t.TempDir()
	testutil.WriteFile(t, filepath.Join(expected, "orders.csv"), "id,total\n")
	opts.ExpectedDir = expected
	opts.Scenarios, opts.Scenario = map[string]config.Scenario{"s": s}, "s"
	return startManager(t, opts)
}

func TestARunPassesWhenEveryAssertionHolds(t *testing.T) {
	m, addr := startAsserting(t, Options{}, config.Scenario{Rules: []faults.Rule{denyStat}, Assertions: []config.Assertion{
		{Type: config.RuleFired, Rule: "deny-stat", Count: exactly(1)},
		{Type: config.SuccessfulOperation, Operation: faults.Rename, Source: "/a.part", Target: "/a", Count: exactly(1)},
		{Type: config.SuccessfulOperation, Operation: faults.Rename, Target: "/b", Count: exactly(1)},
		{Type: config.SuccessfulOperation, Operation: faults.Rename, Source: "/a.part", Count: exactly(1)},
		{Type: config.SuccessfulOperation, Operation: faults.Remove, Path: "/old", Count: config.Count{Min: 1}},
		{Type: config.SuccessfulOperation, Operation: faults.Mkdir, Path: "/dir", Count: exactly(1)},
		{Type: config.SuccessfulOperation, Operation: faults.Rmdir, Path: "/gone", Count: exactly(1)},
		{Type: config.SuccessfulOperation, Operation: faults.SetStat, Path: "/a", Count: exactly(1)},
		{Type: config.SuccessfulOperation, Operation: faults.LStat, Path: "/a", Count: exactly(1)},
		{Type: config.FileEqualsFixture, Path: "/a", Fixture: "orders.csv"},
		{Type: config.FileHash, Path: "/b", SHA256: sha("b\n")},
		{Type: config.PathAbsent, Path: "/a.part"},
		{Type: config.PathAbsent, Path: "/never"},
	}})
	run := m.Status().Run.ID
	c, _ := dialSFTP(t, addr)
	if _, err := c.Stat("/a"); err == nil {
		t.Error("Stat succeeded, want the rule to deny it")
	}
	write(t, c, "/a.part", "id,total\n")
	if err := c.PosixRename("/a.part", "/a"); err != nil {
		t.Fatalf("PosixRename: %v", err)
	}
	write(t, c, "/b.part", "b\n")
	if err := c.Rename("/b.part", "/b"); err != nil {
		t.Fatalf("Rename: %v", err)
	}
	write(t, c, "/old", "")
	if err := c.Remove("/old"); err != nil {
		t.Fatalf("Remove: %v", err)
	}
	for _, dir := range []string{"/dir", "/gone"} {
		if err := c.Mkdir(dir); err != nil {
			t.Fatalf("Mkdir: %v", err)
		}
	}
	if err := c.RemoveDirectory("/gone"); err != nil {
		t.Fatalf("RemoveDirectory: %v", err)
	}
	if err := c.Chmod("/a", 0o640); err != nil {
		t.Fatalf("Chmod: %v", err)
	}
	if _, err := c.Lstat("/a"); err != nil {
		t.Fatalf("Lstat: %v", err)
	}

	r, err := m.Assert(t.Context(), run, time.Second)
	if err != nil {
		t.Fatalf("Assert: %v", err)
	}
	if !r.Passed || len(r.Problems) != 0 {
		t.Errorf("the run failed: %+v", r)
	}
	for _, a := range r.Assertions {
		if !a.Passed {
			t.Errorf("%s failed: %s", a.Description, a.Detail)
		}
	}
	if len(r.Assertions) != 13 {
		t.Errorf("the report has %d assertions, want 13", len(r.Assertions))
	}
	if r.Run.ID != run || r.Run.Scenario != "s" || r.Run.Seed == "" || r.SchemaVersion != reportVersion || r.Interactive {
		t.Errorf("the report describes the run as %+v, interactive %v", r.Run, r.Interactive)
	}
	if f := r.Rules["deny-stat"]; f.Fired != 1 {
		t.Errorf("the report has the rule's counts as %+v, want 1 firing", f)
	}
	if !slices.ContainsFunc(r.Files, func(f FinalFile) bool { return f.Path == "/a" && f.SHA256 == sha("id,total\n") && f.Size == 9 }) {
		t.Errorf("the report's files are %+v, want /a with its hash", r.Files)
	}
	if !r.Trace.Complete || r.Trace.Bytes == 0 {
		t.Errorf("the report's trace is %+v", r.Trace)
	}
}

func TestEachAssertionFailsClearly(t *testing.T) {
	fixture := func(name string) config.Assertion {
		return config.Assertion{Type: config.FileEqualsFixture, Path: "/f", Fixture: name}
	}
	tests := []struct {
		name      string
		assertion config.Assertion
		want      string
	}{
		{"a rule that did not fire", config.Assertion{Type: config.RuleFired, Rule: "deny-stat", Count: config.Count{Min: 1}}, "fired 0 times"},
		{"a rule that fired too often", config.Assertion{Type: config.RuleFired, Rule: "deny-mkdir", Count: exactly(0)}, "fired 1 time"},
		{"an operation that did not succeed", config.Assertion{Type: config.SuccessfulOperation, Operation: faults.Mkdir, Path: "/denied", Count: config.Count{Min: 1}}, "succeeded 0 times"},
		{"an operation on another path", config.Assertion{Type: config.SuccessfulOperation, Operation: faults.Remove, Path: "/other", Count: config.Count{Min: 1}}, "succeeded 0 times"},
		{"a rename to elsewhere", config.Assertion{Type: config.SuccessfulOperation, Operation: faults.Rename, Target: "/other", Count: config.Count{Min: 1}}, "succeeded 0 times"},
		{"different content", fixture("orders.csv"), "the fixture holds 9 bytes"},
		{"a fixture not in the snapshot", fixture("later.csv"), "not in the snapshot"},
		{"no file", config.Assertion{Type: config.FileEqualsFixture, Path: "/missing", Fixture: "orders.csv"}, "no file is there"},
		{"a directory for a file", config.Assertion{Type: config.FileHash, Path: "/d", SHA256: sha("")}, "a directory is there, not a file"},
		{"another hash", config.Assertion{Type: config.FileHash, Path: "/f", SHA256: sha("x")}, "holds 5 bytes with sha256 " + sha("wrong")},
		{"a file left", config.Assertion{Type: config.PathAbsent, Path: "/f"}, "a file of 5 bytes is there"},
		{"a directory left", config.Assertion{Type: config.PathAbsent, Path: "/d"}, "a directory is there"},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			denyMkdir := faults.Rule{ID: "deny-mkdir", Match: faults.Match{Operations: []faults.Operation{faults.Mkdir}, Path: faults.Location{Kind: faults.Exactly, Pattern: "/denied"}}, Action: sftpproxy.Fail{When: sftpproxy.Before, Status: sftpwire.StatusPermissionDenied}}
			m, addr := startAsserting(t, Options{}, config.Scenario{Rules: []faults.Rule{denyStat, denyMkdir}, Assertions: []config.Assertion{tt.assertion}})
			c, _ := dialSFTP(t, addr)
			write(t, c, "/f", "wrong")
			if err := c.Mkdir("/d"); err != nil {
				t.Fatalf("Mkdir: %v", err)
			}
			if err := c.Mkdir("/denied"); err == nil {
				t.Fatal("Mkdir /denied succeeded")
			}
			write(t, c, "/g", "")
			if err := c.Rename("/g", "/h"); err != nil {
				t.Fatalf("Rename: %v", err)
			}
			write(t, c, "/removed", "")
			if err := c.Remove("/removed"); err != nil {
				t.Fatalf("Remove: %v", err)
			}
			r, err := m.Assert(t.Context(), m.Status().Run.ID, time.Second)
			if err != nil {
				t.Fatalf("Assert: %v", err)
			}
			if r.Passed || len(r.Assertions) != 1 || r.Assertions[0].Passed || !strings.Contains(r.Assertions[0].Detail, tt.want) {
				t.Errorf("the report is %+v, want the assertion failed saying %q", r.Assertions, tt.want)
			}
		})
	}
}

func TestARunWithoutAssertionsFails(t *testing.T) {
	m, _ := startManager(t, Options{})
	r, err := m.Assert(t.Context(), m.Status().Run.ID, time.Second)
	if err != nil {
		t.Fatalf("Assert: %v", err)
	}
	if r.Passed || len(r.Problems) != 1 || !strings.Contains(r.Problems[0], "states no assertions") {
		t.Errorf("the report is %+v, want a failure saying nothing was checked", r)
	}
	if r.Assertions == nil || r.Files == nil {
		t.Errorf("the report has %v and %v, want empty lists", r.Assertions, r.Files)
	}
}

func TestAssertingAgainGivesTheSameVerdictAndAResetStartsAgain(t *testing.T) {
	m, addr := startAsserting(t, Options{}, config.Scenario{Assertions: []config.Assertion{{Type: config.PathAbsent, Path: "/f"}}})
	run := m.Status().Run.ID
	first, err := m.Assert(t.Context(), run, time.Second)
	if err != nil {
		t.Fatalf("Assert: %v", err)
	}
	if !first.Passed {
		t.Errorf("the run failed: %+v", first)
	}
	if s := m.Status(); s.State != StateDrained {
		t.Errorf("the state after a verdict is %s, want %s", s.State, StateDrained)
	}
	if err := sshDial(addr); err == nil {
		t.Error("a client logged in to a run that has been drained")
	}
	if _, err := m.ChangeRules(run, 1, nil, nil); !errors.Is(err, ErrDrained) {
		t.Errorf("ChangeRules of a drained run = %v, want %v", err, ErrDrained)
	}
	again, err := m.Assert(t.Context(), run, time.Second)
	if err != nil {
		t.Fatalf("Assert again: %v", err)
	}
	a, _ := json.Marshal(first)
	b, _ := json.Marshal(again)
	if string(a) != string(b) {
		t.Errorf("the second verdict is %s, want %s", b, a)
	}

	f, err := m.OpenReport(run)
	if err != nil {
		t.Fatalf("OpenReport: %v", err)
	}
	defer f.Close()
	var saved Report
	if err := json.NewDecoder(f).Decode(&saved); err != nil {
		t.Fatalf("the saved report: %v", err)
	}
	c, _ := json.Marshal(saved)
	if string(c) != string(a) {
		t.Errorf("the saved report is %s, want %s", c, a)
	}

	next, err := m.Reset(t.Context(), ResetRequest{})
	if err != nil {
		t.Fatalf("Reset: %v", err)
	}
	if next.State != StateUp || next.Run.ID == run {
		t.Errorf("after a reset, the status is %+v, want a new run, up", next)
	}
	client, _ := dialSFTP(t, addr)
	write(t, client, "/f", "new")
	if _, err := m.OpenReport(next.Run.ID); !errors.Is(err, fs.ErrNotExist) {
		t.Errorf("OpenReport of a run not asserted = %v, want %v", err, fs.ErrNotExist)
	}
	if _, err := m.OpenReport(run); err != nil {
		t.Errorf("OpenReport of the ended run: %v", err)
	}
	if _, err := m.Assert(t.Context(), run, time.Second); !errors.Is(err, ErrStaleRun) {
		t.Errorf("Assert of the ended run = %v, want %v", err, ErrStaleRun)
	}
	if _, err := m.OpenReport("20260101-000000.000-0000"); !errors.Is(err, ErrUnknownRun) {
		t.Errorf("OpenReport of an unknown run = %v, want %v", err, ErrUnknownRun)
	}
}

func TestADrainLetsClientsFinishAndThenEndsThem(t *testing.T) {
	m, addr := startAsserting(t, Options{}, config.Scenario{Assertions: []config.Assertion{{Type: config.FileEqualsFixture, Path: "/f", Fixture: "orders.csv"}}})
	c, ended := dialSFTP(t, addr)
	f, err := c.Create("/f")
	if err != nil {
		t.Fatalf("Create: %v", err)
	}
	if _, err := f.Write([]byte("id,")); err != nil {
		t.Fatalf("Write: %v", err)
	}

	result := make(chan Report, 1)
	go func() {
		r, err := m.Assert(t.Context(), m.Status().Run.ID, time.Minute)
		if err != nil {
			t.Errorf("Assert: %v", err)
		}
		result <- r
	}()
	deadline := time.After(waitTimeout)
	for m.Status().State != StateDraining {
		select {
		case <-deadline:
			t.Fatal("the drain did not start")
		case <-time.After(time.Millisecond):
		}
	}

	// A new client is refused, but one under way can finish.
	if err := sshDial(addr); err == nil {
		t.Error("a client logged in during a drain")
	}
	select {
	case r := <-result:
		t.Fatalf("the drain ended with a file open: %+v", r)
	case <-time.After(100 * time.Millisecond):
	}
	if _, err := f.Write([]byte("total\n")); err != nil {
		t.Fatalf("Write during the drain: %v", err)
	}
	if err := f.Close(); err != nil {
		t.Fatalf("Close during the drain: %v", err)
	}

	r := testutil.Receive(t, result)
	if !r.Passed || len(r.Unfinished) != 0 {
		t.Errorf("the verdict is %+v, want a pass with nothing unfinished", r)
	}
	_ = testutil.Receive(t, ended)
}

func TestAFileStillOpenAtTheTimeoutIsUnfinished(t *testing.T) {
	m, addr := startAsserting(t, Options{}, config.Scenario{Assertions: []config.Assertion{{Type: config.PathAbsent, Path: "/other"}}})
	rec, err := m.Events(m.Status().Run.ID)
	if err != nil {
		t.Fatal(err)
	}
	c, ended := dialSFTP(t, addr)
	if _, err := c.Create("/open.part"); err != nil {
		t.Fatalf("Create: %v", err)
	}

	start := time.Now()
	r, err := m.Assert(t.Context(), m.Status().Run.ID, 50*time.Millisecond)
	if err != nil {
		t.Fatalf("Assert: %v", err)
	}
	if took := time.Since(start); took < 50*time.Millisecond {
		t.Errorf("the drain took %v, want it to wait for the handle", took)
	}
	if r.Passed || !slices.Equal(r.Unfinished, []string{"/open.part"}) || len(r.Problems) != 1 || !strings.Contains(r.Problems[0], "/open.part was unfinished") {
		t.Errorf("the verdict is %+v, want a failure naming /open.part", r)
	}
	_ = testutil.Receive(t, ended)
	drained := rec.Events(0, maxEvents, events.Filter{Kinds: []events.Kind{events.RunDrained}}).Events
	if len(drained) != 1 || !slices.Equal(drained[0].Unfinished, []string{"/open.part"}) {
		t.Errorf("the drained events are %+v, want one naming /open.part", drained)
	}
	if got := kinds(readTrace(t, m, r.Run.ID)); got[len(got)-1] != events.RunDrained {
		t.Errorf("the trace ends with %s, want %s", got[len(got)-1], events.RunDrained)
	}
}

// A handle that a client lost before the drain began is a fault's doing,
// not something the drain left unfinished.
func TestAHandleLostBeforeTheDrainIsNotUnfinished(t *testing.T) {
	m, addr := startAsserting(t, Options{}, config.Scenario{Assertions: []config.Assertion{{Type: config.PathAbsent, Path: "/other"}}})
	rec, err := m.Events(m.Status().Run.ID)
	if err != nil {
		t.Fatal(err)
	}
	conn := dialSSH(t, addr)
	c, err := sftp.NewClient(conn)
	if err != nil {
		t.Fatalf("sftp.NewClient: %v", err)
	}
	if _, err := c.Create("/lost.part"); err != nil {
		t.Fatalf("Create: %v", err)
	}
	conn.Close()
	awaitEvent(t, rec, events.Disconnected)

	r, err := m.Assert(t.Context(), m.Status().Run.ID, time.Second)
	if err != nil {
		t.Fatalf("Assert: %v", err)
	}
	if !r.Passed || len(r.Unfinished) != 0 {
		t.Errorf("the verdict is %+v, want a pass with nothing unfinished", r)
	}
}

// A harness may drain as soon as its client sees a fault drop the
// connection, while the server is still ending the session. Its transfer was
// ended by the fault, not left unfinished by the drain. The race this guards
// against lost about one drain in twenty, hence the repeats.
func TestADrainStraightAfterADroppedConnectionLeavesNothingUnfinished(t *testing.T) {
	drop := faults.Rule{ID: "drop", Match: faults.Match{Operations: []faults.Operation{faults.Write}}, Action: sftpproxy.Drop{When: sftpproxy.Before}}
	m, addr := startManager(t, Options{Scenarios: map[string]config.Scenario{"s": {Rules: []faults.Rule{drop}}}, Scenario: "s"})
	for i := range 100 {
		run := m.Status().Run.ID
		c, ended := dialSFTP(t, addr)
		f, err := c.Create("/a.part")
		if err != nil {
			t.Fatalf("Create: %v", err)
		}
		if _, err := f.Write([]byte("id,total\n")); err == nil {
			t.Fatal("a write that the rule drops succeeded")
		}
		_ = testutil.Receive(t, ended)

		d, err := m.Drain(t.Context(), run, time.Second)
		if err != nil {
			t.Fatalf("Drain: %v", err)
		}
		if len(d.Unfinished) != 0 {
			t.Fatalf("drain %d calls %v unfinished, want nothing", i+1, d.Unfinished)
		}
		if _, err := m.Reset(t.Context(), ResetRequest{}); err != nil {
			t.Fatalf("Reset: %v", err)
		}
	}
}

func TestDrainSaysWhatWasUnfinishedAndCanBeRepeated(t *testing.T) {
	m, addr := startManager(t, Options{})
	run := m.Status().Run.ID
	c, _ := dialSFTP(t, addr)
	if _, err := c.Create("/open"); err != nil {
		t.Fatalf("Create: %v", err)
	}
	for range 2 {
		d, err := m.Drain(t.Context(), run, 10*time.Millisecond)
		if err != nil {
			t.Fatalf("Drain: %v", err)
		}
		if !slices.Equal(d.Unfinished, []string{"/open"}) {
			t.Errorf("Drain = %+v, want /open unfinished", d)
		}
	}
	if s := m.Status(); s.State != StateDrained {
		t.Errorf("the state is %s, want %s", s.State, StateDrained)
	}
	if _, err := m.Drain(t.Context(), "20260101-000000.000-0000", 0); !errors.Is(err, ErrStaleRun) {
		t.Errorf("Drain of another run = %v, want %v", err, ErrStaleRun)
	}
}

func TestAnIncompleteTraceFailsOnlyWhatNeedsIt(t *testing.T) {
	m, addr := startAsserting(t, Options{MaxTraceBytes: 256}, config.Scenario{Assertions: []config.Assertion{
		{Type: config.SuccessfulOperation, Operation: faults.Mkdir, Path: "/d", Count: config.Count{}},
		{Type: config.PathAbsent, Path: "/other"},
	}})
	c, _ := dialSFTP(t, addr)
	if err := c.Mkdir("/d"); err != nil {
		t.Fatalf("Mkdir: %v", err)
	}
	r, err := m.Assert(t.Context(), m.Status().Run.ID, time.Second)
	if err != nil {
		t.Fatalf("Assert: %v", err)
	}
	if r.Passed || r.Trace.Complete {
		t.Errorf("the verdict is %+v, want a failure with the trace incomplete", r)
	}
	if a := r.Assertions[0]; a.Passed || !strings.Contains(a.Detail, "the trace is incomplete") || !strings.Contains(a.Detail, "events.max_disk_bytes") {
		t.Errorf("the operation's result is %+v, want it failed for want of the trace", a)
	}
	if a := r.Assertions[1]; !a.Passed {
		t.Errorf("the file's result is %+v, want it to hold without the trace", a)
	}
}

func TestChangingARunsRulesShowsInItsVerdict(t *testing.T) {
	m, _ := startAsserting(t, Options{}, config.Scenario{Rules: []faults.Rule{denyStat}, Assertions: []config.Assertion{{Type: config.RuleFired, Rule: "deny-stat", Count: exactly(0)}}})
	run := m.Status().Run.ID
	if _, err := m.ChangeRules(run, 1, nil, nil); err != nil {
		t.Fatalf("ChangeRules: %v", err)
	}
	r, err := m.Assert(t.Context(), run, time.Second)
	if err != nil {
		t.Fatalf("Assert: %v", err)
	}
	if !r.Interactive {
		t.Error("the report does not say that the rules changed")
	}
	if a := r.Assertions[0]; r.Passed || a.Passed || !strings.Contains(a.Detail, "removed during the run") {
		t.Errorf("the verdict is %+v, want the removed rule's assertion failed", a)
	}
}

func TestADrainAfterAFailedResetIsRefused(t *testing.T) {
	seed := t.TempDir()
	testutil.WriteFile(t, filepath.Join(seed, "orders.csv"), "id\n")
	m, _ := startManager(t, Options{SeedDir: seed})
	run := m.Status().Run.ID
	if err := os.WriteFile(filepath.Join(m.fixtures.dir, "orders.csv"), []byte("changed"), 0o600); err != nil {
		t.Fatal(err)
	}
	if _, err := m.Reset(t.Context(), ResetRequest{}); err == nil {
		t.Fatal("Reset succeeded with a changed snapshot")
	}
	if _, err := m.Drain(t.Context(), run, 0); !errors.Is(err, ErrUnavailable) {
		t.Errorf("Drain = %v, want %v", err, ErrUnavailable)
	}
	if _, err := m.Assert(t.Context(), run, 0); !errors.Is(err, ErrUnavailable) {
		t.Errorf("Assert = %v, want %v", err, ErrUnavailable)
	}
}

// A stall holds a request, not a file handle, and ending its connection ends it.
func TestADrainEndsAStalledSession(t *testing.T) {
	stuck := faults.Rule{ID: "stuck", Match: faults.Match{Operations: []faults.Operation{faults.Stat}}, Action: sftpproxy.Stall{When: sftpproxy.Before, Limit: time.Hour}}
	m, addr := startManager(t, Options{Scenarios: map[string]config.Scenario{"s": {Rules: []faults.Rule{stuck}}}, Scenario: "s"})
	c, _ := dialSFTP(t, addr)
	go func() { _, _ = c.Stat("/") }()
	awaitFired(t, m, "stuck", 1)
	if _, err := m.Drain(t.Context(), m.Status().Run.ID, 0); err != nil {
		t.Errorf("Drain = %v, want the stalled session ended", err)
	}
}

// sshDial tries to log in to the server at addr, and logs out if it can.
func sshDial(addr string) error {
	conn, err := ssh.Dial("tcp", addr, &ssh.ClientConfig{
		User:            testUser,
		Auth:            []ssh.AuthMethod{ssh.Password(testPassword)},
		HostKeyCallback: ssh.InsecureIgnoreHostKey(),
		Timeout:         waitTimeout,
	})
	if err != nil {
		return err
	}
	return conn.Close()
}
