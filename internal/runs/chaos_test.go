package runs

import (
	"reflect"
	"testing"

	"github.com/nebarg/sftpit/internal/config"
	"github.com/nebarg/sftpit/internal/faults"
)

func TestChaosIsPausedAndResumedDuringARun(t *testing.T) {
	light := &faults.Chaos{Preset: faults.Light}
	paused := &faults.Chaos{Preset: faults.Light, Paused: true}
	heavy := &faults.Chaos{Preset: faults.Heavy}
	m, addr := startManager(t, Options{Scenarios: map[string]config.Scenario{"dev": {Chaos: light}, "unpinned": {Chaos: heavy}}, Scenario: "dev"})
	run := m.Status().Run.ID
	if set, err := m.Rules(run); err != nil || !reflect.DeepEqual(set.Chaos, light) || len(set.Rules) != 0 || len(set.Counts) != 2 {
		t.Errorf("the run starts with %+v (%v), want the scenario's chaos and its two rules", set, err)
	}

	if _, err := m.changeRules(run, 1, nil, paused); err != nil {
		t.Fatalf("changeRules: %v", err)
	}
	c, _ := dialSFTP(t, addr)
	for i := range 50 {
		if _, err := c.Stat("/"); err != nil {
			t.Fatalf("stat %d while chaos is paused = %v", i+1, err)
		}
	}
	if set, err := m.Rules(run); err != nil || !reflect.DeepEqual(set.Chaos, paused) || set.Counts["chaos-delay"] != (faults.Counts{}) {
		t.Errorf("while paused, the rules are %+v (%v), want paused chaos that has matched nothing", set, err)
	}

	if _, err := m.changeRules(run, 2, nil, light); err != nil {
		t.Fatalf("changeRules: %v", err)
	}
	// The stat may fail, or be delayed, by chaos.
	_, _ = c.Stat("/")
	if set, err := m.Rules(run); err != nil || set.Counts["chaos-delay"].Matched != 1 || set.Counts["chaos-fail"].Matched != 1 {
		t.Errorf("once resumed, the rules are %+v (%v), want chaos to have matched the stat", set, err)
	}

	next, err := m.Reset(t.Context(), ResetRequest{Scenario: new("unpinned")})
	if err != nil {
		t.Fatalf("Reset: %v", err)
	}
	if set, err := m.Rules(next.Run.ID); err != nil || !reflect.DeepEqual(set.Chaos, heavy) {
		t.Errorf("a run of another scenario with chaos has %+v (%v), want its chaos", set, err)
	}
}
