package config

import (
	"errors"
	"os"
	"path/filepath"
	"reflect"
	"strings"
	"testing"

	"github.com/nebarg/sftpit/internal/testutil"
)

// deletesFail is a scenario file's content with one fault.
const deletesFail = "schema_version: 1\nfaults:\n  - preset: deletes_fail\n"

func TestEveryBuiltInScenarioCanBeTurnedOn(t *testing.T) {
	for name, sc := range builtIn {
		if err := checkScenarioName(name); err != nil {
			t.Errorf("built-in scenario %s: %v", name, err)
		}
		if err := sc.check(testUsers); err != nil {
			t.Errorf("built-in scenario %s: %v", name, err)
		}
	}
}

func TestLoadReadsScenariosOfPlainFaults(t *testing.T) {
	dir := t.TempDir()
	writeAuthorizedKeys(t, filepath.Join(dir, "partner-b.pub"), "")
	cfg, err := loadScenarios(t, dir, `  partner-trouble:
    description: Deletes fail for partner-b, and uploads stop partway.
    faults:
      - {preset: deletes_fail, user: partner-b}
      - {name: Slow listings, steps: [list], do: wait, seconds: 1.5, folder: /outgoing, first: 2}
`, "partner-trouble")
	if err != nil {
		t.Fatalf("Load: %v", err)
	}
	got, err := cfg.Scenarios.Get("partner-trouble")
	if err != nil {
		t.Fatalf("Get: %v", err)
	}
	want := NamedScenario{Name: "partner-trouble", Source: Configured, Scenario: Scenario{
		Description: "Deletes fail for partner-b, and uploads stop partway.",
		Faults: []Fault{
			{Preset: "deletes_fail", User: "partner-b"},
			{Name: "Slow listings", Steps: []string{"list"}, Do: "wait", Seconds: new(1.5), Folder: "/outgoing", First: new(uint64(2))},
		},
	}}
	if !reflect.DeepEqual(got, want) || cfg.Scenario != "partner-trouble" {
		t.Errorf("Get = %+v, and the startup scenario %q, want %+v", got, cfg.Scenario, want)
	}
}

func TestLoadRejectsInvalidScenarios(t *testing.T) {
	dir := t.TempDir()
	writeAuthorizedKeys(t, filepath.Join(dir, "partner-b.pub"), "")
	tests := []struct {
		name, scenarios, selected, want string
	}{
		{"an unknown scenario at startup", "  s: {faults: [{preset: deletes_fail}]}\n", "missing", `unknown scenario "missing"; the scenarios are s, unreliable-heavy, unreliable-light, unreliable-moderate`},
		{"a bad name", "  Bad_Name: {faults: [{preset: deletes_fail}]}\n", "", `scenarios.Bad_Name: scenario name "Bad_Name" may hold only`},
		{"a built-in name", "  unreliable-light: {faults: [{preset: deletes_fail}]}\n", "", "scenarios.unreliable-light: sftpit has a built-in scenario named unreliable-light"},
		{"no faults", "  s: {faults: []}\n", "", "scenarios.s: a scenario needs at least one fault"},
		{"a bad fault", "  s: {faults: [{preset: deletes_fail}, {steps: [upload], do: refuse}]}\n", "", `scenarios.s: faults[1]: there is no step "upload"`},
		{"an unknown user", "  s: {faults: [{preset: deletes_fail, user: nobody}]}\n", "", `scenarios.s: faults[0]: match: user "nobody" is not a configured user`},
		{"an unknown field", "  s: {faults: [{preset: deletes_fail, percentage: 5}]}\n", "", "field percentage not found"},
		{"a rule in the long form", "  s: {faults: [{id: r, match: {operation: stat}, action: {type: hide}}]}\n", "", "field id not found"},
		{"chaos", "  s: {chaos: {preset: light}, faults: [{preset: deletes_fail}]}\n", "", "field chaos not found"},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			_, err := loadScenarios(t, dir, tt.scenarios, tt.selected)
			if err == nil || !strings.Contains(err.Error(), tt.want) {
				t.Errorf("Load = %v, want %q", err, tt.want)
			}
		})
	}
}

func TestListGivesEachScenarioWithItsSource(t *testing.T) {
	dir := t.TempDir()
	writeAuthorizedKeys(t, filepath.Join(dir, "partner-b.pub"), "")
	testutil.WriteFile(t, filepath.Join(dir, "scenarios", "saved.yaml"), deletesFail)
	cfg, err := loadScenarios(t, dir, "  configured: {faults: [{preset: renames_fail}]}\n", "saved")
	if err != nil {
		t.Fatalf("Load: %v", err)
	}
	if got := cfg.Scenarios.Dir(); got != filepath.Join(dir, "scenarios") {
		t.Errorf("Dir = %s, want scenarios beside the configuration", got)
	}
	listed, err := cfg.Scenarios.List()
	if err != nil {
		t.Fatalf("List: %v", err)
	}
	var got []string
	for _, s := range listed {
		got = append(got, string(s.Source)+":"+s.Name)
	}
	want := []string{"built_in:unreliable-heavy", "built_in:unreliable-light", "built_in:unreliable-moderate", "config:configured", "file:saved"}
	if !reflect.DeepEqual(got, want) {
		t.Errorf("List = %v, want %v", got, want)
	}
	if saved := listed[len(listed)-1]; saved.Path != filepath.Join(dir, "scenarios", "saved.yaml") || len(saved.Scenario.Faults) != 1 {
		t.Errorf("the saved scenario is %+v, want its path and fault", saved)
	}
}

func TestListSkipsWhatIsNotAScenarioFile(t *testing.T) {
	dir := t.TempDir()
	missing, err := NewScenarios(filepath.Join(dir, "missing"), nil, testUsers)
	if err != nil {
		t.Fatal(err)
	}
	if names, err := missing.fileNames(); err != nil || len(names) != 0 {
		t.Errorf("the files of a directory that does not exist = %v, %v, want none", names, err)
	}
	testutil.WriteFile(t, filepath.Join(dir, "kept.yaml"), deletesFail)
	testutil.WriteFile(t, filepath.Join(dir, ".kept.yaml.tmp-123"), "half a file")
	testutil.WriteFile(t, filepath.Join(dir, ".hidden.yaml"), "half a file")
	testutil.WriteFile(t, filepath.Join(dir, "notes.yml"), "not a scenario")
	testutil.WriteFile(t, filepath.Join(dir, "README.md"), "not a scenario")
	if err := os.Mkdir(filepath.Join(dir, "dir.yaml"), 0o755); err != nil {
		t.Fatal(err)
	}
	scenarios, err := NewScenarios(dir, nil, testUsers)
	if err != nil {
		t.Fatal(err)
	}
	if names, err := scenarios.fileNames(); err != nil || !reflect.DeepEqual(names, []string{"kept"}) {
		t.Errorf("the files = %v, %v, want only kept", names, err)
	}
}

func TestGetNamesTheScenariosThereAre(t *testing.T) {
	dir := t.TempDir()
	testutil.WriteFile(t, filepath.Join(dir, "saved.yaml"), deletesFail)
	scenarios, err := NewScenarios(dir, map[string]Scenario{"configured": {Faults: []Fault{{Preset: "renames_fail"}}}}, testUsers)
	if err != nil {
		t.Fatal(err)
	}
	for _, name := range []string{"missing", "", "../escape", "a/b", "Upper", "saved.yaml"} {
		_, err := scenarios.Get(name)
		if !errors.Is(err, ErrUnknownScenario) || !strings.Contains(err.Error(), "the scenarios are configured, saved, unreliable-heavy") {
			t.Errorf("Get(%q) = %v, want ErrUnknownScenario naming the scenarios", name, err)
		}
	}
	for name, source := range map[string]Source{"unreliable-light": BuiltIn, "configured": Configured, "saved": Saved} {
		if got, err := scenarios.Get(name); err != nil || got.Source != source {
			t.Errorf("Get(%s) = %+v, %v, want it from %s", name, got, err, source)
		}
	}
}

func TestLoadFindsScenarioFilesInTheWorkingDirectoryWithoutAConfigFile(t *testing.T) {
	t.Chdir(t.TempDir())
	testutil.WriteFile(t, "sftpit-scenarios/quiet.yaml", deletesFail)
	cfg, err := Load(Options{Scenario: "quiet", LookupEnv: noEnv})
	if err != nil {
		t.Fatalf("Load: %v", err)
	}
	wd, err := os.Getwd()
	if err != nil {
		t.Fatal(err)
	}
	if cfg.Scenarios.Dir() != filepath.Join(wd, "sftpit-scenarios") {
		t.Errorf("the scenarios directory is %s, want sftpit-scenarios in %s", cfg.Scenarios.Dir(), wd)
	}
}

func TestLoadRejectsInvalidScenarioFiles(t *testing.T) {
	tests := []struct {
		name, file, content, want string
	}{
		{"unknown field", "s.yaml", deletesFail + "notes: x\n", "field notes not found"},
		{"no schema version", "s.yaml", "faults: [{preset: deletes_fail}]\n", "schema_version is required"},
		{"empty", "s.yaml", "", "the file is empty"},
		{"two documents", "s.yaml", deletesFail + "---\nschema_version: 1\n", "expected a single YAML document"},
		{"no faults", "s.yaml", "schema_version: 1\nfaults: []\n", "a scenario needs at least one fault"},
		{"bad fault", "s.yaml", "schema_version: 1\nfaults:\n  - {steps: [list], do: explode}\n", `faults[0]: there is nothing to do called "explode"`},
		{"unknown user", "s.yaml", "schema_version: 1\nfaults:\n  - {preset: deletes_fail, user: nobody}\n", "nobody"},
		{"bad name", "Upper.yaml", deletesFail, `scenario name "Upper" may hold only`},
		{"built-in name", "unreliable-heavy.yaml", deletesFail, "sftpit has a built-in scenario named unreliable-heavy"},
		{"configured name", "configured.yaml", deletesFail, "the configuration file defines a scenario configured too"},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			dir := t.TempDir()
			writeAuthorizedKeys(t, filepath.Join(dir, "partner-b.pub"), "")
			path := testutil.WriteFile(t, filepath.Join(dir, "saved", tt.file), tt.content)
			config := testutil.WriteFile(t, filepath.Join(dir, "sftpit.yaml"), "scenarios_dir: saved\n"+withScenarios+"  configured: {faults: [{preset: deletes_fail}]}\n")
			_, err := Load(Options{ConfigFile: config, LookupEnv: fakeEnv{"P": "password"}.lookup})
			if !errors.Is(err, ErrInvalidScenario) || !strings.Contains(err.Error(), path) || !strings.Contains(err.Error(), tt.want) {
				t.Errorf("Load = %v, want ErrInvalidScenario naming %s and saying %q", err, path, tt.want)
			}
		})
	}
}

func TestSaveWritesAFileThatGetReads(t *testing.T) {
	dir := filepath.Join(t.TempDir(), "made-on-save")
	scenarios, err := NewScenarios(dir, nil, testUsers)
	if err != nil {
		t.Fatal(err)
	}
	sc := Scenario{Description: "Uploads stop partway, now and then.", Faults: []Fault{{Preset: "upload_stops_partway", KB: new(uint64(8)), Percent: new(25.0)}}}
	saved, err := scenarios.Save("flaky-uploads", sc)
	if err != nil {
		t.Fatalf("Save: %v", err)
	}
	want := NamedScenario{Name: "flaky-uploads", Source: Saved, Scenario: sc, Path: filepath.Join(dir, "flaky-uploads.yaml")}
	if !reflect.DeepEqual(saved, want) {
		t.Errorf("Save = %+v, want %+v", saved, want)
	}
	if got, err := scenarios.Get("flaky-uploads"); err != nil || !reflect.DeepEqual(got, want) {
		t.Errorf("Get = %+v, %v, want %+v", got, err, want)
	}
	content, err := os.ReadFile(want.Path)
	if err != nil {
		t.Fatal(err)
	}
	wantContent := `schema_version: 1
description: Uploads stop partway, now and then.
faults:
  - preset: upload_stops_partway
    kb: 8
    percent: 25
`
	if string(content) != wantContent {
		t.Errorf("the file holds\n%s\nwant\n%s", content, wantContent)
	}

	replacement := Scenario{Faults: []Fault{{Preset: "deletes_fail"}}}
	if _, err := scenarios.Save("flaky-uploads", replacement); err != nil {
		t.Fatalf("Save over the file: %v", err)
	}
	if got, err := scenarios.Get("flaky-uploads"); err != nil || !reflect.DeepEqual(got.Scenario, replacement) {
		t.Errorf("Get after a second save = %+v, %v, want %+v", got, err, replacement)
	}
}

func TestSaveRefusesWhatItCannotTurnOn(t *testing.T) {
	scenarios, err := NewScenarios(t.TempDir(), map[string]Scenario{"configured": {Faults: []Fault{{Preset: "renames_fail"}}}}, testUsers)
	if err != nil {
		t.Fatal(err)
	}
	valid := Scenario{Faults: []Fault{{Preset: "deletes_fail"}}}
	tests := []struct {
		name     string
		scenario Scenario
		want     error
		says     string
	}{
		{"Upper", valid, ErrInvalidScenario, `scenario name "Upper" may hold only`},
		{"../escape", valid, ErrInvalidScenario, "may hold only"},
		{"unreliable-light", valid, ErrFixedScenario, "unreliable-light is built in, so it can't be changed or deleted"},
		{"configured", valid, ErrFixedScenario, "configured is defined in the configuration file, so it can't be changed or deleted"},
		{"empty", Scenario{}, ErrInvalidScenario, "a scenario needs at least one fault"},
		{"stranger", Scenario{Faults: []Fault{{Preset: "deletes_fail", User: "nobody"}}}, ErrInvalidScenario, `faults[0]: match: user "nobody"`},
	}
	for _, tt := range tests {
		if _, err := scenarios.Save(tt.name, tt.scenario); !errors.Is(err, tt.want) || !strings.Contains(err.Error(), tt.says) {
			t.Errorf("Save(%q) = %v, want %v saying %q", tt.name, err, tt.want, tt.says)
		}
	}
	if names, err := scenarios.fileNames(); err != nil || len(names) != 0 {
		t.Errorf("the files after refused saves = %v, %v, want none", names, err)
	}
}

func TestDeleteRemovesOnlySavedScenarios(t *testing.T) {
	dir := t.TempDir()
	path := testutil.WriteFile(t, filepath.Join(dir, "saved.yaml"), deletesFail)
	scenarios, err := NewScenarios(dir, map[string]Scenario{"configured": {Faults: []Fault{{Preset: "renames_fail"}}}}, testUsers)
	if err != nil {
		t.Fatal(err)
	}
	for name, want := range map[string]error{"unreliable-light": ErrFixedScenario, "configured": ErrFixedScenario, "missing": ErrUnknownScenario, "Upper": ErrInvalidScenario} {
		if err := scenarios.Delete(name); !errors.Is(err, want) {
			t.Errorf("Delete(%q) = %v, want %v", name, err, want)
		}
	}
	if err := scenarios.Delete("saved"); err != nil {
		t.Fatalf("Delete: %v", err)
	}
	if _, err := os.Stat(path); !errors.Is(err, os.ErrNotExist) {
		t.Errorf("the file after Delete: %v, want it gone", err)
	}
	if _, err := scenarios.Get("saved"); !errors.Is(err, ErrUnknownScenario) {
		t.Errorf("Get after Delete = %v, want ErrUnknownScenario", err)
	}
}
