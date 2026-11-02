package config

import (
	"crypto/sha256"
	"encoding/hex"
	"errors"
	"io/fs"
	"os"
	"path/filepath"
	"reflect"
	"runtime"
	"strings"
	"testing"

	"github.com/nebarg/sftpit/internal/testutil"
)

func TestSavedScenariosLoadAsTheSame(t *testing.T) {
	cfg, err := Load(writeEveryAction(t))
	if err != nil {
		t.Fatalf("Load: %v", err)
	}
	files := cfg.ScenarioFiles
	for name, want := range cfg.Scenarios {
		saved, err := files.Save("copy-"+name, want, "")
		if err != nil {
			t.Fatalf("Save of a copy of %s: %v", name, err)
		}
		data, err := os.ReadFile(saved.Path)
		if err != nil {
			t.Fatal(err)
		}
		if saved.Path != filepath.Join(files.Dir(), "copy-"+name+".yaml") || saved.Hash != sha256Hex(data) {
			t.Errorf("Save of %s = %s with hash %s, want %s.yaml in %s with the hash of its content", name, saved.Path, saved.Hash, "copy-"+name, files.Dir())
		}
		if !strings.HasPrefix(string(data), scenarioFileHeader+"schema_version: 1\n") {
			t.Errorf("the file saved of %s does not open with the header and the schema version:\n%s", name, data)
		}
		if info, err := os.Stat(saved.Path); err != nil || runtime.GOOS != "windows" && info.Mode().Perm() != 0o644 {
			t.Errorf("the file saved of %s has mode %v, %v, want 0644", name, info.Mode(), err)
		}
		got, err := files.Load("copy-" + name)
		if err != nil {
			t.Fatalf("Load of the copy of %s: %v\n%s", name, err, data)
		}
		if !reflect.DeepEqual(got.Scenario, want) || got.Hash != saved.Hash {
			t.Errorf("the copy of %s loads as\n%+v\nwant\n%+v\nfile:\n%s", name, got.Scenario, want, data)
		}
	}
	listed, err := files.List()
	if err != nil {
		t.Fatalf("List: %v", err)
	}
	if len(listed) != len(cfg.Scenarios) {
		t.Errorf("List gives %d files, want %d", len(listed), len(cfg.Scenarios))
	}
	for _, f := range listed {
		if f.Err != nil {
			t.Errorf("List gives %s with %v", f.Name, f.Err)
		}
	}
}

func TestSaveReplacesOnlyTheFileItWasGiven(t *testing.T) {
	files := NewScenarioFiles(filepath.Join(t.TempDir(), "made", "on", "save"), testUsers, nil)
	first, err := files.Save("s", Scenario{Description: "first"}, "")
	if err != nil {
		t.Fatalf("Save of a new file: %v", err)
	}
	if _, err := files.Save("s", Scenario{Description: "again"}, ""); !errors.Is(err, ErrScenarioChanged) {
		t.Errorf("Save over the file without its hash = %v, want ErrScenarioChanged", err)
	}
	second, err := files.Save("s", Scenario{Description: "second"}, first.Hash)
	if err != nil {
		t.Fatalf("Save with the file's hash: %v", err)
	}
	if _, err := files.Save("s", Scenario{Description: "stale"}, first.Hash); !errors.Is(err, ErrScenarioChanged) {
		t.Errorf("Save with the hash the file had before = %v, want ErrScenarioChanged", err)
	}

	edited := strings.Replace(readFile(t, second.Path), "second", "edited by hand", 1)
	testutil.WriteFile(t, second.Path, edited)
	if _, err := files.Save("s", Scenario{Description: "over the edit"}, second.Hash); !errors.Is(err, ErrScenarioChanged) {
		t.Errorf("Save over a file edited by hand = %v, want ErrScenarioChanged", err)
	}
	if got := readFile(t, second.Path); got != edited {
		t.Errorf("the file edited by hand now holds\n%s", got)
	}
	got, err := files.Load("s")
	if err != nil || got.Scenario.Description != "edited by hand" || got.Hash != sha256Hex([]byte(edited)) {
		t.Errorf("Load = %+v, %v, want the edit by hand", got, err)
	}

	if err := os.Remove(second.Path); err != nil {
		t.Fatal(err)
	}
	if _, err := files.Save("s", Scenario{}, got.Hash); !errors.Is(err, ErrScenarioChanged) {
		t.Errorf("Save over a file that was removed = %v, want ErrScenarioChanged", err)
	}
	entries, err := os.ReadDir(files.Dir())
	if err != nil || len(entries) != 0 {
		t.Errorf("the directory holds %v, %v, want no files, temporary ones included", entries, err)
	}
}

func TestSaveRefusesNamesAFileCannotHave(t *testing.T) {
	dir := t.TempDir()
	files := NewScenarioFiles(dir, testUsers, map[string]Scenario{"configured": {}})
	for _, name := range []string{"", "../escape", "a/b", "Upper", "-dash", "dot.yaml"} {
		if _, err := files.Save(name, Scenario{}, ""); !errors.Is(err, ErrScenarioName) {
			t.Errorf("Save(%q) = %v, want ErrScenarioName", name, err)
		}
	}
	if _, err := files.Save("configured", Scenario{}, ""); !errors.Is(err, ErrConfiguredScenario) {
		t.Errorf("Save of a configured scenario = %v, want ErrConfiguredScenario", err)
	}
	entries, err := os.ReadDir(dir)
	if err != nil || len(entries) != 0 {
		t.Errorf("the directory holds %v, %v, want nothing", entries, err)
	}
	if _, err := files.Load("../escape"); !errors.Is(err, fs.ErrNotExist) {
		t.Errorf("Load of a name a file cannot have = %v, want fs.ErrNotExist", err)
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
seed: 7
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
	if cfg.ScenarioFiles.Dir() != filepath.Join(dir, "scenarios") || chosen.Description != "Fails partner-b's listings." || chosen.Seed == nil || *chosen.Seed != 7 || len(chosen.Rules) != 1 || chosen.Rules[0].ID != "listing" {
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

func readFile(t *testing.T, name string) string {
	t.Helper()
	data, err := os.ReadFile(name)
	if err != nil {
		t.Fatal(err)
	}
	return string(data)
}

func sha256Hex(data []byte) string {
	sum := sha256.Sum256(data)
	return hex.EncodeToString(sum[:])
}
