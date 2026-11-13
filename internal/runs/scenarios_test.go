package runs

import (
	"errors"
	"os"
	"slices"
	"testing"

	"github.com/nebarg/sftpit/internal/config"
)

// faultsOf returns the IDs of the current run's faults that the scenario
// name added.
func faultsOf(m *Manager, name string) []string {
	var ids []string
	for _, f := range m.Faults() {
		if f.Scenario == name {
			ids = append(ids, f.ID)
		}
	}
	return ids
}

// isOnIn reports whether Scenarios lists the scenario name as on.
func isOnIn(t *testing.T, m *Manager, name string) bool {
	t.Helper()
	list, err := m.Scenarios()
	if err != nil {
		t.Fatalf("Scenarios: %v", err)
	}
	i := slices.IndexFunc(list, func(s Scenario) bool { return s.Name == name })
	if i < 0 {
		t.Fatalf("Scenarios does not list %s", name)
	}
	return list[i].On
}

func TestAScenarioTurnsItsFaultsOnAndOff(t *testing.T) {
	m, addr := startManager(t, Options{Scenarios: testScenarios(t)})
	if _, err := m.AddFault(config.Fault{Preset: "renames_fail"}); err != nil {
		t.Fatalf("AddFault: %v", err)
	}
	s, err := m.SwitchScenario("unreliable-moderate", true)
	if err != nil {
		t.Fatalf("SwitchScenario on: %v", err)
	}
	want := []string{"slow-commands-2", "commands-fail-3", "uploads-stop-partway-4", "downloads-stop-partway-5"}
	if got := faultsOf(m, "unreliable-moderate"); !s.On || s.Source != config.BuiltIn || !slices.Equal(got, want) {
		t.Errorf("turned on, the scenario is %+v with faults %v, want on with %v", s, got, want)
	}
	if !isOnIn(t, m, "unreliable-moderate") || isOnIn(t, m, "unreliable-light") {
		t.Error("Scenarios does not list only unreliable-moderate as on")
	}
	for _, f := range m.Faults() {
		if f.Scenario != "" && (!f.On || f.Spec.Name == "") {
			t.Errorf("the scenario's fault %+v is not on with its defaults filled in", f)
		}
	}

	// Turning it on again starts its faults afresh rather than adding more.
	if _, err := m.SwitchScenario("unreliable-moderate", true); err != nil {
		t.Fatalf("SwitchScenario on again: %v", err)
	}
	if got := faultsOf(m, "unreliable-moderate"); len(got) != 4 || got[0] != "slow-commands-6" {
		t.Errorf("turned on again, the scenario's faults are %v, want four new ones", got)
	}

	if s, err := m.SwitchScenario("unreliable-moderate", false); err != nil || s.On {
		t.Fatalf("SwitchScenario off = %+v, %v", s, err)
	}
	if got := m.Faults(); len(got) != 1 || got[0].ID != "renames-fail-1" {
		t.Errorf("turned off, the run's faults are %+v, want only the one added on its own", got)
	}
	c, _ := dialSFTP(t, addr)
	if _, err := c.Stat("/"); err != nil {
		t.Errorf("a stat with the scenario off = %v, want it to work", err)
	}
}

func TestSwitchScenarioRefusesAnUnknownName(t *testing.T) {
	m, _ := startManager(t, Options{Scenarios: testScenarios(t)})
	for _, on := range []bool{true, false} {
		if _, err := m.SwitchScenario("flaky", on); !errors.Is(err, config.ErrUnknownScenario) {
			t.Errorf("SwitchScenario(flaky, %v) = %v, want ErrUnknownScenario", on, err)
		}
	}
	if s := m.Status(); s.Revision != 1 {
		t.Errorf("after refused switches, the revision is %d, want 1", s.Revision)
	}
}

func TestStartTurnsTheChosenScenarioOn(t *testing.T) {
	m, _ := startManager(t, Options{Scenarios: testScenarios(t), Scenario: "unreliable-light"})
	if got := faultsOf(m, "unreliable-light"); len(got) != 2 {
		t.Errorf("the first run has the scenario's faults %v, want two", got)
	}
}

func TestSavingAScenarioThatIsOnReplacesItsFaults(t *testing.T) {
	m, _ := startManager(t, Options{Scenarios: testScenarios(t)})
	if s, err := m.SaveScenario("partner", config.Scenario{Faults: []config.Fault{{Preset: "deletes_fail"}}}); err != nil || s.On || s.Source != config.Saved {
		t.Fatalf("SaveScenario = %+v, %v, want it saved and off", s, err)
	}
	if got := m.Faults(); len(got) != 0 {
		t.Errorf("saving a scenario that is off added faults %+v", got)
	}
	if _, err := m.SwitchScenario("partner", true); err != nil {
		t.Fatalf("SwitchScenario: %v", err)
	}
	s, err := m.SaveScenario("partner", config.Scenario{Faults: []config.Fault{{Preset: "renames_fail"}, {Preset: "slow_responses"}}})
	if err != nil || !s.On {
		t.Fatalf("SaveScenario = %+v, %v, want it on", s, err)
	}
	if got := faultsOf(m, "partner"); !slices.Equal(got, []string{"renames-fail-2", "slow-responses-3"}) {
		t.Errorf("after saving it while on, the scenario's faults are %v, want the new ones", got)
	}
	if _, err := m.SaveScenario("unreliable-light", config.Scenario{Faults: []config.Fault{{Preset: "deletes_fail"}}}); !errors.Is(err, config.ErrFixedScenario) {
		t.Errorf("SaveScenario over a built-in = %v, want ErrFixedScenario", err)
	}
}

func TestDeletingAScenarioRemovesItsFaults(t *testing.T) {
	m, _ := startManager(t, Options{Scenarios: testScenarios(t)})
	if _, err := m.SaveScenario("partner", config.Scenario{Faults: []config.Fault{{Preset: "deletes_fail"}}}); err != nil {
		t.Fatalf("SaveScenario: %v", err)
	}
	if _, err := m.SwitchScenario("partner", true); err != nil {
		t.Fatalf("SwitchScenario: %v", err)
	}
	if err := m.DeleteScenario("partner"); err != nil {
		t.Fatalf("DeleteScenario: %v", err)
	}
	if got := m.Faults(); len(got) != 0 {
		t.Errorf("after deleting the scenario, the run's faults are %+v, want none", got)
	}
	if err := m.DeleteScenario("partner"); !errors.Is(err, config.ErrUnknownScenario) {
		t.Errorf("a second DeleteScenario = %v, want ErrUnknownScenario", err)
	}
}

func TestAScenarioWhoseFileHasGoneCanStillBeTurnedOff(t *testing.T) {
	m, _ := startManager(t, Options{Scenarios: testScenarios(t)})
	saved, err := m.SaveScenario("partner", config.Scenario{Faults: []config.Fault{{Preset: "deletes_fail"}}})
	if err != nil {
		t.Fatalf("SaveScenario: %v", err)
	}
	if _, err := m.SwitchScenario("partner", true); err != nil {
		t.Fatalf("SwitchScenario: %v", err)
	}
	if err := os.Remove(saved.Path); err != nil {
		t.Fatal(err)
	}
	if s, err := m.SwitchScenario("partner", false); err != nil || s.On || s.Name != "partner" {
		t.Errorf("SwitchScenario off = %+v, %v, want it off", s, err)
	}
	if got := m.Faults(); len(got) != 0 {
		t.Errorf("the run's faults are %+v, want none", got)
	}
	if _, err := m.SwitchScenario("partner", true); !errors.Is(err, config.ErrUnknownScenario) {
		t.Errorf("SwitchScenario on = %v, want ErrUnknownScenario", err)
	}
}
