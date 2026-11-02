package runs

import (
	"errors"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/nebarg/sftpit/internal/config"
	"github.com/nebarg/sftpit/internal/faults"
	"github.com/nebarg/sftpit/internal/sftpproxy"
	"github.com/nebarg/sftpit/internal/sftpwire"
	"github.com/nebarg/sftpit/internal/sshfront"
)

func TestResetReadsAScenarioFileAsItIsThen(t *testing.T) {
	dir := t.TempDir()
	configured := map[string]config.Scenario{"configured": {}}
	files := config.NewScenarioFiles(dir, []sshfront.User{{Name: testUser}}, configured)
	m, _ := startManager(t, Options{Scenarios: configured, ScenarioFiles: files})

	deny := faults.Rule{ID: "deny", Match: faults.Match{Operations: []faults.Operation{faults.Remove}}, Action: sftpproxy.Fail{When: sftpproxy.Before, Status: sftpwire.StatusPermissionDenied}}
	saved, err := m.SaveScenario("saved", config.Scenario{Seed: new(faults.Seed(4)), Rules: []faults.Rule{deny}}, "")
	if err != nil {
		t.Fatalf("SaveScenario: %v", err)
	}
	next, err := m.Reset(t.Context(), ResetRequest{Scenario: new("saved")})
	if err != nil {
		t.Fatalf("Reset to the saved scenario: %v", err)
	}
	if got := next.Run.Scenario; got != (Scenario{Name: "saved", Seed: 4, Pinned: true}) {
		t.Errorf("the run of the saved scenario is %+v", got)
	}
	set, err := m.Rules(next.Run.ID)
	if err != nil || len(set.Rules) != 1 || set.Rules[0].ID != "deny" {
		t.Errorf("the run of the saved scenario has rules %+v, %v, want deny", set.Rules, err)
	}

	edited := strings.Replace(readFile(t, saved.Path), "id: deny", "id: edited-by-hand", 1)
	if err := os.WriteFile(saved.Path, []byte(edited), 0o644); err != nil {
		t.Fatal(err)
	}
	next, err = m.Reset(t.Context(), ResetRequest{})
	if err != nil {
		t.Fatalf("Reset that repeats the saved scenario: %v", err)
	}
	if set, err := m.Rules(next.Run.ID); err != nil || len(set.Rules) != 1 || set.Rules[0].ID != "edited-by-hand" {
		t.Errorf("the run after an edit by hand has rules %+v, %v, want the edit", set.Rules, err)
	}

	if err := os.WriteFile(saved.Path, []byte("schema_version: 1\nfaults: [{id: Bad}]\n"), 0o644); err != nil {
		t.Fatal(err)
	}
	if _, err := m.Reset(t.Context(), ResetRequest{}); !errors.Is(err, config.ErrInvalidScenarioFile) {
		t.Errorf("Reset to a broken file = %v, want ErrInvalidScenarioFile", err)
	}
	if err := m.Status().Err; err != nil {
		t.Errorf("a reset refused for a broken file left the runs failed: %v", err)
	}

	if err := os.Remove(saved.Path); err != nil {
		t.Fatal(err)
	}
	_, err = m.Reset(t.Context(), ResetRequest{})
	if !errors.Is(err, ErrUnknownScenario) || !strings.Contains(err.Error(), "the configuration defines configured") {
		t.Errorf("Reset to a removed file = %v, want ErrUnknownScenario naming the scenarios left", err)
	}
}

func TestScenariosListsTheConfigurationsAndTheFiles(t *testing.T) {
	dir := t.TempDir()
	configured := map[string]config.Scenario{"configured": {Description: "from the config"}}
	files := config.NewScenarioFiles(dir, []sshfront.User{{Name: testUser}}, configured)
	m := newManager(t, Options{Scenarios: configured, ScenarioFiles: files})
	if _, err := m.SaveScenario("saved", config.Scenario{}, ""); err != nil {
		t.Fatalf("SaveScenario: %v", err)
	}
	if err := os.WriteFile(filepath.Join(dir, "broken.yaml"), []byte("faults: []\n"), 0o644); err != nil {
		t.Fatal(err)
	}
	got, err := m.Scenarios()
	if err != nil {
		t.Fatalf("Scenarios: %v", err)
	}
	if got.Dir != dir || got.Configured["configured"].Description != "from the config" || len(got.Files) != 2 {
		t.Fatalf("Scenarios = %+v, want the configured scenario and two files in %s", got, dir)
	}
	if broken, saved := got.Files[0], got.Files[1]; broken.Name != "broken" || broken.Err == nil || saved.Name != "saved" || saved.Err != nil {
		t.Errorf("the files are %+v, want broken with its error, then saved", got.Files)
	}
	if _, err := m.SaveScenario("configured", config.Scenario{}, ""); !errors.Is(err, config.ErrConfiguredScenario) {
		t.Errorf("SaveScenario of a configured scenario = %v, want ErrConfiguredScenario", err)
	}
}

func readFile(t *testing.T, name string) string {
	t.Helper()
	data, err := os.ReadFile(name)
	if err != nil {
		t.Fatal(err)
	}
	return string(data)
}
