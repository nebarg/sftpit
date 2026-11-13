package config

import (
	"errors"
	"io/fs"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/nebarg/sftpit/internal/testutil"
)

func TestLoadRefusesNamesAFileCannotHave(t *testing.T) {
	files := NewScenarioFiles(t.TempDir(), testUsers, nil)
	for _, name := range []string{"", "../escape", "a/b", "Upper", "-dash", "dot.yaml"} {
		if _, err := files.Load(name); !errors.Is(err, fs.ErrNotExist) {
			t.Errorf("Load(%q) = %v, want fs.ErrNotExist", name, err)
		}
	}
}

func TestListSkipsWhatIsNotAScenarioFile(t *testing.T) {
	dir := t.TempDir()
	files := NewScenarioFiles(filepath.Join(dir, "missing"), testUsers, nil)
	if listed, err := files.List(); err != nil || len(listed) != 0 {
		t.Errorf("List of a directory that does not exist = %v, %v, want nothing", listed, err)
	}
	files = NewScenarioFiles(dir, testUsers, nil)
	testutil.WriteFile(t, filepath.Join(dir, "kept.yaml"), "schema_version: 1\nfaults: []\n")
	testutil.WriteFile(t, filepath.Join(dir, ".kept.yaml.123.tmp"), "half a file")
	testutil.WriteFile(t, filepath.Join(dir, ".hidden.yaml"), "half a file")
	testutil.WriteFile(t, filepath.Join(dir, "notes.yml"), "not a scenario")
	testutil.WriteFile(t, filepath.Join(dir, "README.md"), "not a scenario")
	if err := os.Mkdir(filepath.Join(dir, "dir.yaml"), 0o755); err != nil {
		t.Fatal(err)
	}
	listed, err := files.List()
	if err != nil || len(listed) != 1 || listed[0].Name != "kept" || listed[0].Err != nil {
		t.Errorf("List = %+v, %v, want only kept", listed, err)
	}
}

func TestLoadReadsScenarioFilesBesideTheConfiguration(t *testing.T) {
	dir := t.TempDir()
	writeAuthorizedKeys(t, filepath.Join(dir, "partner-b.pub"), "")
	testutil.WriteFile(t, filepath.Join(dir, "scenarios", "flaky-partner.yaml"), `schema_version: 1
description: Fails partner-b's listings.
faults:
  - id: listing
    match: {user: partner-b, operation: list}
    action: {type: fail, when: before, status: failure}
`)
	cfg, err := loadScenarios(t, dir, "  configured: {faults: []}\n", "flaky-partner")
	if err != nil {
		t.Fatalf("Load: %v", err)
	}
	chosen := cfg.Chosen()
	if cfg.ScenarioFiles.Dir() != filepath.Join(dir, "scenarios") || chosen.Description != "Fails partner-b's listings." || len(chosen.Rules) != 1 || chosen.Rules[0].ID != "listing" {
		t.Errorf("Load chose %+v from %s, want flaky-partner from the scenarios directory", chosen, cfg.ScenarioFiles.Dir())
	}
	if _, ok := cfg.Scenarios["flaky-partner"]; ok || len(cfg.Scenarios) != 1 {
		t.Errorf("the configuration's scenarios are %v, want only configured", cfg.Scenarios)
	}

	_, err = loadScenarios(t, dir, "  configured: {faults: []}\n", "missing")
	if err == nil || !strings.Contains(err.Error(), `scenario "missing" is not defined; the configuration defines configured, flaky-partner`) {
		t.Errorf("Load of a missing scenario = %v, want the files' scenarios named", err)
	}
}

func TestLoadFindsScenarioFilesInTheWorkingDirectoryWithoutAConfigFile(t *testing.T) {
	t.Chdir(t.TempDir())
	testutil.WriteFile(t, "sftpit-scenarios/quiet.yaml", "schema_version: 1\nfaults: []\n")
	cfg, err := Load(Options{Scenario: "quiet", LookupEnv: noEnv})
	if err != nil {
		t.Fatalf("Load: %v", err)
	}
	wd, err := os.Getwd()
	if err != nil {
		t.Fatal(err)
	}
	if cfg.ScenarioFiles.Dir() != filepath.Join(wd, "sftpit-scenarios") {
		t.Errorf("the scenarios directory is %s, want sftpit-scenarios in %s", cfg.ScenarioFiles.Dir(), wd)
	}
}

func TestLoadRejectsInvalidScenarioFiles(t *testing.T) {
	tests := []struct {
		name, file, content, want string
	}{
		{"unknown field", "s.yaml", "schema_version: 1\nfaults: []\nnotes: x\n", "field notes not found"},
		{"no schema version", "s.yaml", "faults: []\n", "schema_version is required"},
		{"empty", "s.yaml", "", "the file is empty"},
		{"two documents", "s.yaml", "schema_version: 1\n---\nschema_version: 1\n", "expected a single YAML document"},
		{"bad rule", "s.yaml", "schema_version: 1\nfaults:\n  - {id: r, match: {operation: list}, action: {type: explode}}\n", "scenario s.faults[0] (r): action"},
		{"unknown user", "s.yaml", "schema_version: 1\nfaults:\n  - {id: r, match: {user: nobody, operation: list}, action: {type: hide}}\n", "nobody"},
		{"bad name", "Upper.yaml", "schema_version: 1\nfaults: []\n", `invalid scenario name "Upper"`},
		{"configured name", "configured.yaml", "schema_version: 1\nfaults: []\n", "the configuration file defines a scenario configured too"},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			dir := t.TempDir()
			writeAuthorizedKeys(t, filepath.Join(dir, "partner-b.pub"), "")
			path := testutil.WriteFile(t, filepath.Join(dir, "saved", tt.file), tt.content)
			config := testutil.WriteFile(t, filepath.Join(dir, "sftpit.yaml"), "scenarios_dir: saved\n"+withScenarios+"  configured: {faults: []}\n")
			_, err := Load(Options{ConfigFile: config, LookupEnv: fakeEnv{"P": "password"}.lookup})
			if !errors.Is(err, ErrInvalidScenarioFile) || !strings.Contains(err.Error(), path) || !strings.Contains(err.Error(), tt.want) {
				t.Errorf("Load = %v, want ErrInvalidScenarioFile naming %s and saying %q", err, path, tt.want)
			}
		})
	}
}
