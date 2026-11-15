package runs

import (
	"context"
	"errors"
	"io"
	"log/slog"
	"net"
	"os"
	"path/filepath"
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
	"github.com/nebarg/sftpit/internal/testutil"
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

	next, err := m.Reset(t.Context())
	if err != nil {
		t.Fatalf("Reset: %v", err)
	}
	_ = testutil.Receive(t, ended)
	if next.Run.ID == first.ID || m.Status().Run != next.Run {
		t.Errorf("Reset started run %+v after %+v, and the status has %+v", next.Run, first, m.Status().Run)
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

func TestEveryRunStartsWithItsFolders(t *testing.T) {
	m, addr := startManager(t, Options{Folders: []string{"/upload", "/in/orders"}})
	for _, run := range []string{"the first run", "the run after a reset"} {
		c, ended := dialSFTP(t, addr)
		for _, folder := range []string{"/upload", "/in/orders"} {
			if info, err := c.Stat(folder); err != nil || !info.IsDir() {
				t.Errorf("%s has no folder %s (%v)", run, folder, err)
			}
		}
		if err := c.RemoveDirectory("/upload"); err != nil {
			t.Fatalf("RemoveDirectory: %v", err)
		}
		if _, err := m.Reset(t.Context()); err != nil {
			t.Fatalf("Reset: %v", err)
		}
		_ = testutil.Receive(t, ended)
	}
}

func TestResetStartsARunWithoutFaultsAndAFreshSeed(t *testing.T) {
	m, addr := startManager(t, Options{Scenarios: testScenarios(t), Scenario: "unreliable-light"})
	deny := faults.Rule{ID: "deny-stats", Match: faults.Match{Operations: []faults.Operation{faults.Stat}}, Action: sftpproxy.Fail{Status: sftpwire.StatusPermissionDenied}}
	if _, err := m.AddFault(config.Fault{Preset: "deletes_fail"}); err != nil {
		t.Fatalf("AddFault: %v", err)
	}
	set := m.Status()
	// Ahead of the scenario's rules, which would otherwise delay or fail
	// the stat now and then.
	if _, err := changeRules(m, set.Revision, append([]faults.Rule{deny}, m.current.rules.Rules().Rules...)); err != nil {
		t.Fatalf("changeRules: %v", err)
	}
	first := m.Status().Run
	c, _ := dialSFTP(t, addr)
	if _, err := c.Stat("/"); !errors.Is(err, os.ErrPermission) {
		t.Fatalf("a stat in the first run = %v, want it denied", err)
	}

	next, err := m.Reset(t.Context())
	if err != nil {
		t.Fatalf("Reset: %v", err)
	}
	if next.Run.Seed == first.Seed {
		t.Errorf("the next run has the seed %d of the first", next.Run.Seed)
	}
	if got := m.Faults(); len(got) != 0 {
		t.Errorf("after a reset, Faults = %+v, want none", got)
	}
	if set := m.Rules(); len(set.Rules) != 0 {
		t.Errorf("after a reset, the rules are %+v, want none", set)
	}
	scenarios, err := m.Scenarios()
	if err != nil {
		t.Fatalf("Scenarios: %v", err)
	}
	for _, s := range scenarios {
		if s.On {
			t.Errorf("after a reset, scenario %s is on", s.Name)
		}
	}
	c, _ = dialSFTP(t, addr)
	if _, err := c.Stat("/"); err != nil {
		t.Errorf("a stat after the reset = %v, want it to work", err)
	}
}

func TestResetEndsAnOutage(t *testing.T) {
	synctest.Test(t, func(t *testing.T) {
		m := newManager(t, Options{})
		withRules(t, m, outageAt(time.Second))
		time.Sleep(time.Second)
		synctest.Wait()
		if s := m.Status(); s.State != StateDown || !s.DownUntil.Equal(time.Now().Add(time.Minute)) {
			t.Errorf("a second into the run, the status is %+v, want down for a minute", s)
		}
		if _, err := m.Reset(t.Context()); err != nil {
			t.Fatalf("Reset: %v", err)
		}
		if s := m.Status(); s.State != StateUp {
			t.Errorf("after the reset, the status is %+v, want the next run up", s)
		}
	})
}

func TestResetStopsTheRunsTimers(t *testing.T) {
	synctest.Test(t, func(t *testing.T) {
		m := newManager(t, Options{})
		withRules(t, m, outageAt(300*time.Millisecond))
		if _, err := m.Reset(t.Context()); err != nil {
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
			m, addr := startManager(t, Options{SeedDir: seed, Logger: slog.New(injected)})
			withRules(t, m, tt.rule)
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
					_, _ = io.Copy(io.Discard, f)
				}
			}()
			testutil.ReceiveUntil(t, injected, "injected fault")

			start := time.Now()
			if _, err := m.Reset(t.Context()); err != nil {
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
			switch after, err := os.Stat(uploaded); {
			case err != nil:
				t.Errorf("the upload's file after the reset: %v", err)
			case after.Size() != before.Size():
				t.Errorf("the upload grew from %d to %d bytes after the reset", before.Size(), after.Size())
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
	testutil.Receive(t, started)

	ctx, cancel := context.WithTimeout(t.Context(), 100*time.Millisecond)
	defer cancel()
	if _, err := m.Reset(ctx); !errors.Is(err, context.DeadlineExceeded) {
		t.Fatalf("Reset = %v, want the deadline exceeded", err)
	}
	if s := m.Status(); s.State != StateUnavailable || !errors.Is(s.Err, context.DeadlineExceeded) || s.Run != first {
		t.Errorf("after the failed reset, the status is %+v, want the first run unavailable", s)
	}
	assertNotAdmitted(t, addr)

	reset := make(chan error, 1)
	go func() {
		_, err := m.Reset(t.Context())
		reset <- err
	}()
	awaitState(t, m, StateResetting)
	free()
	if err := testutil.Receive(t, reset); err != nil {
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
	_ = testutil.Receive(t, ended)
	if _, err := m.current.root.Stat("."); err == nil {
		t.Error("the run's files are still open after Close")
	}
}

func TestCloseStopsTheRunsTimers(t *testing.T) {
	synctest.Test(t, func(t *testing.T) {
		m := newManager(t, Options{})
		withRules(t, m, outageAt(300*time.Millisecond))
		if err := m.Close(); err != nil {
			t.Fatalf("Close: %v", err)
		}
		time.Sleep(time.Hour)
		if fired := m.current.rules.Rules().Counts["outage"].Fired; fired != 0 {
			t.Errorf("the run's timer fired %d times after Close", fired)
		}
	})
}

func awaitState(t *testing.T, m *Manager, want State) {
	t.Helper()
	deadline := time.Now().Add(waitTimeout)
	for {
		s := m.Status()
		if s.State == want {
			return
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

// TestAResetUnderwayWhenTheManagerClosesStartsNoRun checks that a reset
// still waiting for a session when the Manager closes fails, rather than
// starting a run that nothing would serve.
func TestAResetUnderwayWhenTheManagerClosesStartsNoRun(t *testing.T) {
	m, addr := startManager(t, Options{})
	release := make(chan struct{})
	free := sync.OnceFunc(func() { close(release) })
	t.Cleanup(free)
	started := make(chan struct{}, 1)
	m.mu.Lock()
	m.current.handler = func(context.Context, *sshfront.Conn, io.ReadWriteCloser) error {
		started <- struct{}{}
		<-release
		return nil
	}
	m.mu.Unlock()
	client := dialSSH(t, addr)
	session, err := client.NewSession()
	if err != nil {
		t.Fatalf("NewSession: %v", err)
	}
	defer session.Close()
	if err := session.RequestSubsystem("sftp"); err != nil {
		t.Fatalf("RequestSubsystem(sftp): %v", err)
	}
	testutil.Receive(t, started)

	reset := make(chan error, 1)
	go func() {
		_, err := m.Reset(t.Context())
		reset <- err
	}()
	awaitState(t, m, StateResetting)
	closed := make(chan error, 1)
	go func() { closed <- m.Close() }()
	// The server closes its listener once it is closed, while the reset
	// still waits for the session.
	awaitRefused(t, addr)
	free()

	if err := testutil.Receive(t, reset); !errors.Is(err, sshfront.ErrServerClosed) {
		t.Errorf("Reset = %v, want ErrServerClosed", err)
	}
	if err := testutil.Receive(t, closed); err != nil {
		t.Errorf("Close: %v", err)
	}
	if runs, err := os.ReadDir(filepath.Join(m.workspace.Dir(), runsDir)); err != nil || len(runs) != 1 {
		t.Errorf("the workspace holds runs %v (%v), want only the first", runs, err)
	}
	if _, err := m.AddFault(config.Fault{Preset: "deletes_fail"}); !errors.Is(err, sshfront.ErrServerClosed) {
		t.Errorf("AddFault after Close = %v, want ErrServerClosed", err)
	}
}
