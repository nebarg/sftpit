package runs

import (
	"context"
	"errors"
	"io"
	"log/slog"
	"net"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"testing"
	"testing/synctest"
	"time"

	"github.com/pkg/sftp"

	"github.com/nebarg/sftpit/internal/config"
	"github.com/nebarg/sftpit/internal/faults"
	"github.com/nebarg/sftpit/internal/sftpproxy"
	"github.com/nebarg/sftpit/internal/sftpwire"
	"github.com/nebarg/sftpit/internal/sshfront"
)

func TestResetStartsAFreshRunFromTheSeed(t *testing.T) {
	seed := t.TempDir()
	if err := os.Mkdir(filepath.Join(seed, "outgoing"), 0o755); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(seed, "outgoing", "orders.csv"), []byte("id,total\n"), 0o644); err != nil {
		t.Fatal(err)
	}
	m, addr := startManager(t, Options{
		SeedDir: seed,
		Server:  sshfront.Config{Users: []sshfront.User{{Name: testUser, Password: testPassword, Home: "/partner"}}},
	})
	first := m.Status().Run
	c, ended := dialSFTP(t, addr)
	if err := c.Remove("/outgoing/orders.csv"); err != nil {
		t.Fatalf("Remove: %v", err)
	}
	upload(t, c, "/outgoing/uploaded.csv", "uploaded")
	// The seed's later changes reach no run.
	if err := os.WriteFile(filepath.Join(seed, "outgoing", "orders.csv"), []byte("changed"), 0o644); err != nil {
		t.Fatal(err)
	}

	next, err := m.Reset(t.Context(), ResetRequest{})
	if err != nil {
		t.Fatalf("Reset: %v", err)
	}
	receive(t, ended)
	if next.ID == first.ID || m.Status().Run != *next {
		t.Errorf("Reset started run %+v after %+v, and the status has %+v", next, first, m.Status().Run)
	}
	if b, err := os.ReadFile(filepath.Join(first.Files, "outgoing", "uploaded.csv")); err != nil || string(b) != "uploaded" {
		t.Errorf("the first run's upload holds %q (%v), want it kept", b, err)
	}

	c, _ = dialSFTP(t, addr)
	if got := download(t, c, "/outgoing/orders.csv"); got != "id,total\n" {
		t.Errorf("the next run's seeded file holds %q, want the seed as it was at the start", got)
	}
	if _, err := c.Stat("/outgoing/uploaded.csv"); !errors.Is(err, os.ErrNotExist) {
		t.Errorf("the next run has the first run's upload (%v)", err)
	}
	if info, err := c.Stat("/partner"); err != nil || !info.IsDir() {
		t.Errorf("the next run has no home directory for the user (%v)", err)
	}
}

func TestResetChoosesTheNextRunsScenarioAndSeed(t *testing.T) {
	scenarios := map[string]config.Scenario{"chaos": {}, "own": {Seed: new(faults.Seed(9))}}
	tests := []struct {
		name     string
		scenario string
		seed     *faults.Seed
		req      ResetRequest
		want     Scenario
		// fresh is set if the next run draws a fresh seed, which want
		// leaves out.
		fresh bool
	}{
		{name: "a fresh seed is drawn again", scenario: "chaos", fresh: true, want: Scenario{Name: "chaos"}},
		{name: "a pinned seed is kept", scenario: "chaos", seed: new(faults.Seed(7)), want: Scenario{Name: "chaos", Seed: 7, Pinned: true}},
		{name: "the scenario's seed is kept", scenario: "own", want: Scenario{Name: "own", Seed: 9, Pinned: true}},
		{name: "a seed is pinned", scenario: "chaos", req: ResetRequest{Seed: new(faults.Seed(8))}, want: Scenario{Name: "chaos", Seed: 8, Pinned: true}},
		{name: "a seed overrides the scenario's", scenario: "own", req: ResetRequest{Seed: new(faults.Seed(8))}, want: Scenario{Name: "own", Seed: 8, Pinned: true}},
		{name: "a named scenario draws afresh", scenario: "chaos", seed: new(faults.Seed(7)), req: ResetRequest{Scenario: new("chaos")}, fresh: true, want: Scenario{Name: "chaos"}},
		{name: "a named scenario has its own seed", scenario: "chaos", seed: new(faults.Seed(7)), req: ResetRequest{Scenario: new("own")}, want: Scenario{Name: "own", Seed: 9, Pinned: true}},
		{name: "a named scenario with a seed", scenario: "chaos", req: ResetRequest{Scenario: new("own"), Seed: new(faults.Seed(5))}, want: Scenario{Name: "own", Seed: 5, Pinned: true}},
		{name: "no scenario", scenario: "chaos", req: ResetRequest{Scenario: new("")}, fresh: true, want: Scenario{}},
		{name: "still no scenario", fresh: true, want: Scenario{}},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			m, _ := startManager(t, Options{Scenarios: scenarios, Scenario: tt.scenario, Seed: tt.seed})
			first := m.Status().Run
			next, err := m.Reset(t.Context(), tt.req)
			if err != nil {
				t.Fatalf("Reset: %v", err)
			}
			got := next.Scenario
			if tt.fresh {
				if got.Seed == first.Scenario.Seed {
					t.Errorf("the next run has seed %d again, want a fresh one", got.Seed)
				}
				got.Seed = 0
			}
			if got != tt.want {
				t.Errorf("after %+v, the next run has %+v, want %+v", first.Scenario, got, tt.want)
			}
		})
	}
}

func TestResetRefusesARunItCannotStart(t *testing.T) {
	scenarios := map[string]config.Scenario{"chaos": {}, "own": {}}
	tests := []struct {
		name     string
		scenario string
		req      ResetRequest
		err      error
		want     string
	}{
		{name: "an unknown scenario", req: ResetRequest{Scenario: new("flaky")}, err: ErrUnknownScenario, want: `runs: unknown scenario "flaky"; the configuration defines chaos, own`},
		{name: "a seed without a scenario", scenario: "chaos", req: ResetRequest{Scenario: new(""), Seed: new(faults.Seed(7))}, err: ErrSeedWithoutScenario, want: "a seed needs a scenario"},
		{name: "a seed for a run without one", req: ResetRequest{Seed: new(faults.Seed(7))}, err: ErrSeedWithoutScenario, want: "a seed needs a scenario"},
		{name: "a stale run", req: ResetRequest{Run: "20260101-000000.000-0000"}, err: ErrStaleRun, want: "the current run is "},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			m, addr := startManager(t, Options{Scenarios: scenarios, Scenario: tt.scenario})
			first := m.Status()
			_, ended := dialSFTP(t, addr)
			if _, err := m.Reset(t.Context(), tt.req); !errors.Is(err, tt.err) || !strings.Contains(err.Error(), tt.want) {
				t.Errorf("Reset = %v, want %v saying %q", err, tt.err, tt.want)
			}
			if got := m.Status(); got != first {
				t.Errorf("after the refused reset, the status is %+v, want %+v", got, first)
			}
			select {
			case err := <-ended:
				t.Errorf("the refused reset ended a connection: %v", err)
			default:
			}
		})
	}

	m, _ := startManager(t, Options{Scenarios: scenarios})
	if _, err := m.Reset(t.Context(), ResetRequest{Run: m.Status().Run.ID}); err != nil {
		t.Errorf("Reset of the current run: %v", err)
	}
}

func TestResetStartsTheRulesAgain(t *testing.T) {
	deny := faults.Rule{ID: "deny-first-stat", MaxTriggers: 1, Match: faults.Match{Operations: []faults.Operation{faults.Stat}}, Action: sftpproxy.Fail{Status: sftpwire.StatusPermissionDenied}}
	m, addr := startManager(t, Options{Scenarios: map[string]config.Scenario{"deny": {Rules: []faults.Rule{deny}}}, Scenario: "deny"})
	for run := 1; run <= 2; run++ {
		c, _ := dialSFTP(t, addr)
		if _, err := c.Stat("/"); !errors.Is(err, os.ErrPermission) {
			t.Errorf("run %d: the first stat = %v, want it denied", run, err)
		}
		if _, err := c.Stat("/"); err != nil {
			t.Errorf("run %d: the second stat = %v, want the rule used up", run, err)
		}
		if _, err := m.Reset(t.Context(), ResetRequest{}); err != nil {
			t.Fatalf("Reset: %v", err)
		}
	}
}

func TestResetEndsAnOutageAndTimesTheNextRunFromItsStart(t *testing.T) {
	synctest.Test(t, func(t *testing.T) {
		m := newManager(t, Options{Scenarios: map[string]config.Scenario{"outage": {Rules: []faults.Rule{outageAt(time.Second)}}}, Scenario: "outage"})
		for run := 1; run <= 2; run++ {
			time.Sleep(time.Second - time.Nanosecond)
			synctest.Wait()
			if s := m.Status(); s.State != StateUp {
				t.Errorf("run %d: just before a second into the run, the status is %+v, want up", run, s)
			}
			time.Sleep(time.Nanosecond)
			synctest.Wait()
			if s := m.Status(); s.State != StateDown || !s.DownUntil.Equal(time.Now().Add(time.Minute)) {
				t.Errorf("run %d: a second into the run, the status is %+v, want down for a minute", run, s)
			}
			if _, err := m.Reset(t.Context(), ResetRequest{}); err != nil {
				t.Fatalf("Reset: %v", err)
			}
			if s := m.Status(); s.State != StateUp {
				t.Errorf("run %d: after the reset, the status is %+v, want the next run up", run, s)
			}
		}
	})
}

func TestAnOutageAtTheStartOfARunBeginsWithIt(t *testing.T) {
	m, _ := startManager(t, Options{Scenarios: map[string]config.Scenario{"outage": {Rules: []faults.Rule{outageAt(0)}}}, Scenario: "outage"})
	for run := 1; run <= 2; run++ {
		if s := m.Status(); s.State != StateDown {
			t.Errorf("run %d: the status is %+v, want the server down from the run's start", run, s)
		}
		if _, err := m.Reset(t.Context(), ResetRequest{}); err != nil {
			t.Fatalf("Reset: %v", err)
		}
	}
}

func TestResetStopsTheRunsTimers(t *testing.T) {
	synctest.Test(t, func(t *testing.T) {
		m := newManager(t, Options{Scenarios: map[string]config.Scenario{"outage": {Rules: []faults.Rule{outageAt(300 * time.Millisecond)}}}, Scenario: "outage"})
		if _, err := m.Reset(t.Context(), ResetRequest{Scenario: new("")}); err != nil {
			t.Fatalf("Reset: %v", err)
		}
		time.Sleep(time.Hour)
		if s := m.Status(); s.State != StateUp {
			t.Errorf("the status is %+v, want the next run, which has no faults, up", s)
		}
	})
}

func TestResetWaitsForEverySessionToFinish(t *testing.T) {
	slowWrites := faults.Rule{ID: "slow-writes", Match: faults.Match{Operations: []faults.Operation{faults.Write}}, Action: sftpproxy.Delay{Duration: 20 * time.Millisecond}}
	tests := []struct {
		name   string
		rule   faults.Rule
		upload bool
	}{
		{"a slow upload", slowWrites, true},
		{"a delayed read", faults.Rule{ID: "slow", Match: faults.Match{Operations: []faults.Operation{faults.Read}}, Action: sftpproxy.Delay{When: sftpproxy.After, Duration: time.Minute}}, false},
		{"a frozen connection", faults.Rule{ID: "freeze", Match: faults.Match{Operations: []faults.Operation{faults.Read}}, Action: sftpproxy.Freeze{Limit: time.Minute}}, false},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			injected := make(messages, 64)
			seed := t.TempDir()
			if err := os.WriteFile(filepath.Join(seed, "big.bin"), make([]byte, 1<<20), 0o644); err != nil {
				t.Fatal(err)
			}
			m, addr := startManager(t, Options{
				SeedDir:   seed,
				Scenarios: map[string]config.Scenario{"slow": {Rules: []faults.Rule{tt.rule}}},
				Scenario:  "slow",
				Logger:    slog.New(injected),
			})
			first := m.Status().Run
			c, _ := dialSFTP(t, addr)
			go func() {
				if tt.upload {
					f, err := c.Create("/upload.bin")
					if err == nil {
						for err == nil {
							_, err = f.Write(make([]byte, 32<<10))
						}
					}
					return
				}
				f, err := c.Open("/big.bin")
				if err == nil {
					io.Copy(io.Discard, f)
				}
			}()
			for msg := receive(t, injected); msg != "injected fault"; msg = receive(t, injected) {
			}

			start := time.Now()
			if _, err := m.Reset(t.Context(), ResetRequest{}); err != nil {
				t.Fatalf("Reset: %v", err)
			}
			if took := time.Since(start); took > waitTimeout {
				t.Errorf("Reset took %v, want it to end the fault", took)
			}
			if !tt.upload {
				return
			}
			uploaded := filepath.Join(first.Files, "upload.bin")
			before, err := os.Stat(uploaded)
			if err != nil {
				t.Fatalf("the upload left no file: %v", err)
			}
			time.Sleep(200 * time.Millisecond)
			if after, err := os.Stat(uploaded); err != nil || after.Size() != before.Size() {
				t.Errorf("the upload grew from %d to %d bytes (%v) after the reset", before.Size(), after.Size(), err)
			}
		})
	}
}

func TestAFailedResetLeavesTheRunUnavailableUntilOneSucceeds(t *testing.T) {
	m, addr := startManager(t, Options{})
	release := make(chan struct{})
	free := sync.OnceFunc(func() { close(release) })
	// Cleanups run last first, so this frees the session before the
	// server is closed.
	t.Cleanup(free)
	started := make(chan struct{}, 1)
	// A session that outlasts its connection, as none of the proxy's do.
	m.mu.Lock()
	m.current.handler = func(context.Context, *sshfront.Conn, io.ReadWriteCloser) error {
		started <- struct{}{}
		<-release
		return nil
	}
	m.mu.Unlock()
	first := m.Status().Run
	session, err := dialSSH(t, addr).NewSession()
	if err != nil {
		t.Fatalf("NewSession: %v", err)
	}
	defer session.Close()
	if err := session.RequestSubsystem("sftp"); err != nil {
		t.Fatalf("RequestSubsystem(sftp): %v", err)
	}
	receive(t, started)

	ctx, cancel := context.WithTimeout(t.Context(), 100*time.Millisecond)
	defer cancel()
	if _, err := m.Reset(ctx, ResetRequest{}); !errors.Is(err, context.DeadlineExceeded) {
		t.Fatalf("Reset = %v, want the deadline exceeded", err)
	}
	if s := m.Status(); s.State != StateUnavailable || !errors.Is(s.Err, context.DeadlineExceeded) || s.Run != first {
		t.Errorf("after the failed reset, the status is %+v, want the first run unavailable", s)
	}
	assertNotAdmitted(t, addr)

	reset := make(chan error, 1)
	go func() {
		_, err := m.Reset(t.Context(), ResetRequest{})
		reset <- err
	}()
	awaitState(t, m, StateResetting)
	free()
	if err := receive(t, reset); err != nil {
		t.Fatalf("Reset once the session has finished: %v", err)
	}
	if s := m.Status(); s.State != StateUp || s.Err != nil || s.Run.ID == first.ID {
		t.Errorf("after the reset, the status is %+v, want the next run up", s)
	}
	c, _ := dialSFTP(t, addr)
	if _, err := c.Stat("/"); err != nil {
		t.Errorf("Stat in the next run: %v", err)
	}
}

func TestCloseEndsTheRun(t *testing.T) {
	m, addr := startManager(t, Options{})
	_, ended := dialSFTP(t, addr)
	if err := m.Close(); err != nil {
		t.Fatalf("Close: %v", err)
	}
	receive(t, ended)
	if _, err := m.current.root.Stat("."); err == nil {
		t.Error("the run's files are still open after Close")
	}
}

func TestCloseStopsTheRunsTimers(t *testing.T) {
	synctest.Test(t, func(t *testing.T) {
		m := newManager(t, Options{Scenarios: map[string]config.Scenario{"outage": {Rules: []faults.Rule{outageAt(300 * time.Millisecond)}}}, Scenario: "outage"})
		if err := m.Close(); err != nil {
			t.Fatalf("Close: %v", err)
		}
		time.Sleep(time.Hour)
		if fired := m.current.rules.Counts()["outage"].Fired; fired != 0 {
			t.Errorf("the run's timer fired %d times after Close", fired)
		}
	})
}

func awaitState(t *testing.T, m *Manager, want State) Status {
	t.Helper()
	deadline := time.Now().Add(waitTimeout)
	for {
		s := m.Status()
		if s.State == want {
			return s
		}
		if time.Now().After(deadline) {
			t.Fatalf("the status is %+v, want %s", s, want)
		}
		time.Sleep(10 * time.Millisecond)
	}
}

// assertNotAdmitted checks that the server at addr closes a connection
// before its handshake.
func assertNotAdmitted(t *testing.T, addr string) {
	t.Helper()
	raw, err := net.Dial("tcp", addr)
	if err != nil {
		t.Fatalf("Dial: %v", err)
	}
	defer raw.Close()
	if err := raw.SetDeadline(time.Now().Add(waitTimeout)); err != nil {
		t.Fatal(err)
	}
	if got, err := io.ReadAll(raw); err != nil || len(got) > 0 {
		t.Errorf("the server sent %q (%v), want the connection closed before its handshake", got, err)
	}
}

func upload(t *testing.T, c *sftp.Client, name, content string) {
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

func download(t *testing.T, c *sftp.Client, name string) string {
	t.Helper()
	f, err := c.Open(name)
	if err != nil {
		t.Fatalf("Open %s: %v", name, err)
	}
	defer f.Close()
	b, err := io.ReadAll(f)
	if err != nil {
		t.Fatalf("Read %s: %v", name, err)
	}
	return string(b)
}
