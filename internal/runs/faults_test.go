package runs

import (
	"errors"
	"os"
	"reflect"
	"slices"
	"sync"
	"testing"
	"time"

	"github.com/pkg/sftp"

	"github.com/nebarg/sftpit/internal/config"
	"github.com/nebarg/sftpit/internal/faults"
	"github.com/nebarg/sftpit/internal/sshfront"
	"github.com/nebarg/sftpit/internal/testutil"
)

func TestAFaultCanBeAddedSwitchedAndRemoved(t *testing.T) {
	m, addr := startManager(t, Options{})
	c, _ := dialSFTP(t, addr)
	put := func(name string) {
		t.Helper()
		f, err := c.Create(name)
		if err != nil {
			t.Fatalf("Create %s: %v", name, err)
		}
		f.Close()
	}
	if err := c.Mkdir("/outgoing"); err != nil {
		t.Fatalf("Mkdir: %v", err)
	}

	added, err := m.AddFault(config.Fault{Preset: "deletes_fail", Folder: "/outgoing"})
	if err != nil {
		t.Fatalf("AddFault: %v", err)
	}
	if added.ID != "deletes-fail-1" || !added.On || added.Happened != 0 || added.Spec.Name != "Deletes fail" || added.Spec.Do != "refuse" {
		t.Errorf("AddFault = %+v, want deletes-fail-1, on, with the preset filled in", added)
	}
	put("/outgoing/a.csv")
	put("/b.csv")
	if err := c.Remove("/outgoing/a.csv"); !errors.Is(err, os.ErrPermission) {
		t.Errorf("a delete in /outgoing = %v, want it refused", err)
	}
	if err := c.Remove("/b.csv"); err != nil {
		t.Errorf("a delete elsewhere = %v, want it to work", err)
	}
	if got, err := m.Fault("deletes-fail-1"); err != nil || got.Happened != 1 {
		t.Errorf("Fault = %+v, %v; want it to have happened once", got, err)
	}

	if off, err := m.SwitchFault("deletes-fail-1", false); err != nil || off.On || off.Happened != 0 {
		t.Errorf("SwitchFault off = %+v, %v; want it off", off, err)
	}
	if err := c.Remove("/outgoing/a.csv"); err != nil {
		t.Errorf("a delete with the fault off = %v, want it to work", err)
	}
	put("/outgoing/a.csv")
	if _, err := m.SwitchFault("deletes-fail-1", true); err != nil {
		t.Fatalf("SwitchFault on: %v", err)
	}
	if err := c.Remove("/outgoing/a.csv"); !errors.Is(err, os.ErrPermission) {
		t.Errorf("a delete with the fault on again = %v, want it refused", err)
	}
	if got, _ := m.Fault("deletes-fail-1"); got.Happened != 1 {
		t.Errorf("after switching on, the fault has happened %d times, want 1, counted from the switch", got.Happened)
	}

	if err := m.RemoveFault("deletes-fail-1"); err != nil {
		t.Fatalf("RemoveFault: %v", err)
	}
	if err := c.Remove("/outgoing/a.csv"); err != nil {
		t.Errorf("a delete once the fault is removed = %v, want it to work", err)
	}
	if got := m.Faults(); len(got) != 0 {
		t.Errorf("Faults = %+v, want none", got)
	}
	for _, err := range []error{m.RemoveFault("deletes-fail-1"), errOf(m.SwitchFault("nope", true)), errOf(m.Fault("nope"))} {
		if !errors.Is(err, ErrUnknownFault) {
			t.Errorf("a missing fault = %v, want ErrUnknownFault", err)
		}
	}
}

func errOf(_ Fault, err error) error { return err }

func TestFaultsKeepTheRunsOwnRules(t *testing.T) {
	m, addr := startManager(t, Options{})
	if _, err := changeRules(m, 1, []faults.Rule{denyStats}); err != nil {
		t.Fatalf("changeRules: %v", err)
	}
	c, _ := dialSFTP(t, addr)
	if _, err := c.Stat("/"); !errors.Is(err, os.ErrPermission) {
		t.Fatalf("a stat = %v, want deny-stats to refuse it", err)
	}

	if _, err := m.AddFault(config.Fault{Preset: "deletes_fail"}); err != nil {
		t.Fatalf("AddFault: %v", err)
	}
	set := m.Rules()
	if ids := ruleIDs(set.Rules); !slices.Equal(ids, []string{"deny-stats", "deletes-fail-1"}) {
		t.Errorf("the run's rules are %v, want its own, then the fault's", ids)
	}
	if set.Counts["deny-stats"].Fired != 1 {
		t.Errorf("deny-stats has fired %d times, want its count kept", set.Counts["deny-stats"].Fired)
	}

	if err := m.RemoveFaults(); err != nil {
		t.Fatalf("RemoveFaults: %v", err)
	}
	if set := m.Rules(); !slices.Equal(ruleIDs(set.Rules), []string{"deny-stats"}) {
		t.Errorf("after RemoveFaults, the rules are %v, want only the run's own", ruleIDs(set.Rules))
	}
}

func TestAFaultThatCannotWorkChangesNothing(t *testing.T) {
	m, _ := startManager(t, Options{})
	if _, err := m.AddFault(config.Fault{Preset: "deletes_fail", User: "nobody"}); err == nil {
		t.Fatal("AddFault succeeded for an unknown user")
	} else if !errors.Is(err, config.ErrInvalidFault) {
		t.Errorf("AddFault for an unknown user = %v, want ErrInvalidFault", err)
	}
	if s := m.Status(); s.Revision != 1 || len(m.Faults()) != 0 {
		t.Errorf("after a refused fault, revision %d and faults %+v, want nothing changed", s.Revision, m.Faults())
	}
	if f, err := m.AddFault(config.Fault{Preset: "deletes_fail"}); err != nil || f.ID != "deletes-fail-1" {
		t.Errorf("AddFault after a refused fault = %q, %v; want deletes-fail-1, its number not taken", f.ID, err)
	}
}

func TestFaultsCannotChangeOnceTheManagerCloses(t *testing.T) {
	m := newManager(t, Options{})
	if _, err := m.AddFault(config.Fault{Preset: "deletes_fail"}); err != nil {
		t.Fatalf("AddFault: %v", err)
	}
	revision := m.Status().Revision
	if err := m.Close(); err != nil {
		t.Fatalf("Close: %v", err)
	}
	changes := map[string]func() error{
		"AddFault": func() error {
			_, err := m.AddFault(config.Fault{Preset: "deletes_fail"})
			return err
		},
		"SwitchFault": func() error {
			_, err := m.SwitchFault("deletes-fail-1", false)
			return err
		},
		"RemoveFault":  func() error { return m.RemoveFault("deletes-fail-1") },
		"RemoveFaults": m.RemoveFaults,
	}
	for name, change := range changes {
		if err := change(); !errors.Is(err, sshfront.ErrServerClosed) {
			t.Errorf("%s after Close = %v, want ErrServerClosed", name, err)
		}
	}
	if got := m.Faults(); len(got) != 1 || !got[0].On || m.Status().Revision != revision {
		t.Errorf("after Close, faults %+v at revision %d, want deletes-fail-1 on at revision %d", got, m.Status().Revision, revision)
	}
}

func TestFaultIDsComeFromTheirNames(t *testing.T) {
	m, _ := startManager(t, Options{})
	for _, tt := range []struct {
		fault config.Fault
		want  string
	}{
		{config.Fault{Preset: "deletes_fail"}, "deletes-fail-1"},
		{config.Fault{Preset: "deletes_fail"}, "deletes-fail-2"},
		{config.Fault{Name: "Partner B's slow week!", Preset: "slow_responses"}, "partner-b-s-slow-week-3"},
		{config.Fault{Name: "Chaos", Preset: "slow_responses"}, "chaos-4"},
		{config.Fault{Name: "!!!", Preset: "slow_responses"}, "fault-5"},
	} {
		got, err := m.AddFault(tt.fault)
		if err != nil || got.ID != tt.want {
			t.Errorf("AddFault(%+v) = %q, %v; want %q", tt.fault, got.ID, err, tt.want)
		}
	}
}

func TestAResetRemovesTheFaults(t *testing.T) {
	m, addr := startManager(t, Options{})
	if _, err := m.AddFault(config.Fault{Preset: "deletes_fail"}); err != nil {
		t.Fatalf("AddFault: %v", err)
	}
	if _, err := m.Reset(t.Context()); err != nil {
		t.Fatalf("Reset: %v", err)
	}
	if got := m.Faults(); len(got) != 0 {
		t.Errorf("after a reset, Faults = %+v, want none", got)
	}
	c, _ := dialSFTP(t, addr)
	mustCreate(t, c, "/a.csv")
	if err := c.Remove("/a.csv"); err != nil {
		t.Errorf("after a reset, a delete = %v, want it to work", err)
	}
}

func TestFaultsAndScenariosCanBeReadWhileAResetWaits(t *testing.T) {
	m, addr := startManager(t, Options{Scenarios: testScenarios(t)})
	if _, err := m.SwitchScenario("unreliable-light", true); err != nil {
		t.Fatalf("SwitchScenario: %v", err)
	}
	added, err := m.AddFault(config.Fault{Preset: "deletes_fail"})
	if err != nil {
		t.Fatalf("AddFault: %v", err)
	}
	had := m.Faults()
	free := holdSession(t, m, addr)
	reset := make(chan error, 1)
	go func() {
		_, err := m.Reset(t.Context())
		reset <- err
	}()
	awaitState(t, m, StateResetting)

	// promptly calls read, failing the test if it waits for the reset.
	promptly := func(name string, read func()) {
		t.Helper()
		done := make(chan struct{})
		go func() {
			read()
			close(done)
		}()
		select {
		case <-done:
		case <-time.After(waitTimeout):
			t.Fatalf("%s waited for the reset to end", name)
		}
	}
	var got []Fault
	promptly("Faults", func() { got = m.Faults() })
	if !reflect.DeepEqual(got, had) {
		t.Errorf("during the reset, Faults = %+v, want the run's %+v", got, had)
	}
	var fault Fault
	promptly("Fault", func() { fault, err = m.Fault(added.ID) })
	if err != nil || !reflect.DeepEqual(fault, added) {
		t.Errorf("during the reset, Fault = %+v, %v; want %+v", fault, err, added)
	}
	var list []Scenario
	promptly("Scenarios", func() { list, err = m.Scenarios() })
	if err != nil {
		t.Errorf("during the reset, Scenarios: %v", err)
	}
	if i := slices.IndexFunc(list, func(s Scenario) bool { return s.Name == "unreliable-light" }); i < 0 || !list[i].On {
		t.Errorf("during the reset, Scenarios = %+v, want unreliable-light on", list)
	}

	free()
	if err := testutil.Receive(t, reset); err != nil {
		t.Fatalf("Reset: %v", err)
	}
	if got := m.Faults(); len(got) != 0 {
		t.Errorf("after the reset, Faults = %+v, want none", got)
	}
}

// TestReadersSeeOnlyWholeChangesOfTheFaults checks that while faults are
// added, switched and removed, a scenario is turned on and off, and a
// change whose rules the engine refuses is made, a reader sees each change
// whole or not at all, and the run's rules as of the same moment.
func TestReadersSeeOnlyWholeChangesOfTheFaults(t *testing.T) {
	m := newManager(t, Options{Scenarios: testScenarios(t)})
	withRules(t, m, denyStats)
	const scenario, rounds = "unreliable-moderate", 50
	resolved, rule, err := config.Fault{Preset: "deletes_fail"}.Compile(m.opts.Server.Users)
	if err != nil {
		t.Fatalf("Compile: %v", err)
	}
	// refused adds a fault whose ID the run's own rule has, which the
	// engine refuses.
	refused := func() error {
		m.resetting.Lock()
		defer m.resetting.Unlock()
		current := m.active()
		f := newPlainFault(denyStats.ID, resolved, rule, "")
		_, err := m.replaceFaults(current, append(slices.Clone(current.faults), f))
		return err
	}

	var writers sync.WaitGroup
	writers.Go(func() {
		for range rounds {
			f, err := m.AddFault(config.Fault{Preset: "deletes_fail"})
			if err != nil {
				t.Errorf("AddFault: %v", err)
				return
			}
			if _, err := m.SwitchFault(f.ID, false); err != nil {
				t.Errorf("SwitchFault: %v", err)
			}
			if err := m.RemoveFault(f.ID); err != nil {
				t.Errorf("RemoveFault: %v", err)
			}
		}
	})
	writers.Go(func() {
		for range rounds {
			for _, on := range []bool{true, false} {
				if _, err := m.SwitchScenario(scenario, on); err != nil {
					t.Errorf("SwitchScenario(%t): %v", on, err)
				}
			}
		}
	})
	writers.Go(func() {
		for range rounds {
			if err := refused(); err == nil {
				t.Error("a fault with the ID of the run's own rule was added")
			}
		}
	})

	done := make(chan struct{})
	var readers sync.WaitGroup
	readers.Go(func() {
		for {
			select {
			case <-done:
				return
			default:
			}
			list := m.Faults()
			if n := len(slices.DeleteFunc(slices.Clone(list), func(f Fault) bool { return f.Scenario != scenario })); n != 0 && n != 4 {
				t.Errorf("Faults has %d of the scenario's 4 faults: %+v", n, list)
			}
			if slices.ContainsFunc(list, func(f Fault) bool { return f.ID == denyStats.ID }) {
				t.Errorf("Faults has the refused fault: %+v", list)
			}
			if _, err := m.Scenarios(); err != nil {
				t.Errorf("Scenarios: %v", err)
			}
		}
	})
	readers.Go(func() {
		for {
			select {
			case <-done:
				return
			default:
			}
			m.mu.Lock()
			list, set := m.current.faults, m.current.rules.Rules()
			m.mu.Unlock()
			for _, r := range set.Rules {
				on := slices.ContainsFunc(list, func(f plainFault) bool { return f.id == r.ID && f.on })
				if !on && r.ID != denyStats.ID {
					t.Errorf("rule %s is of no fault switched on: %+v", r.ID, list)
				}
			}
			for _, f := range list {
				if _, ruled := set.Counts[f.id]; ruled != f.on {
					t.Errorf("fault %s is on: %t, but has a rule: %t", f.id, f.on, ruled)
				}
			}
		}
	})
	writers.Wait()
	close(done)
	readers.Wait()
}

func mustCreate(t *testing.T, c *sftp.Client, name string) {
	t.Helper()
	f, err := c.Create(name)
	if err != nil {
		t.Fatalf("Create %s: %v", name, err)
	}
	f.Close()
}

func ruleIDs(rules []faults.Rule) []string {
	ids := make([]string, len(rules))
	for i, r := range rules {
		ids[i] = r.ID
	}
	return ids
}
