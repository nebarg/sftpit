package runs

import (
	"errors"
	"os"
	"slices"
	"testing"

	"github.com/pkg/sftp"

	"github.com/nebarg/sftpit/internal/config"
	"github.com/nebarg/sftpit/internal/faults"
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
