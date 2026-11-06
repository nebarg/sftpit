package config

import (
	"encoding/json"
	"errors"
	"io/fs"
	"os"
	"path/filepath"
	"reflect"
	"strings"
	"testing"

	"github.com/nebarg/sftpit/internal/faults"
	"github.com/nebarg/sftpit/internal/testutil"
)

const testHash = "e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855"

func TestParseAssertionsReadsEachType(t *testing.T) {
	expected := t.TempDir()
	testutil.WriteFile(t, filepath.Join(expected, "out", "orders.csv"), "id\n")
	rules := []faults.Rule{{ID: "cut"}}
	chaos := &faults.Chaos{Preset: faults.Heavy}
	two, three := uint64(2), uint64(3)
	zero := uint64(0)
	tests := []struct {
		name string
		json string
		want Assertion
	}{
		{"a rule fired at least once by default", `{"type": "rule_fired", "rule_id": "cut"}`, Assertion{Type: RuleFired, Rule: "cut", Count: Count{Min: 1}}},
		{"a rule fired exactly", `{"type": "rule_fired", "rule_id": "cut", "exactly": 2}`, Assertion{Type: RuleFired, Rule: "cut", Count: Count{Min: 2, Max: &two}}},
		{"a rule that never fired", `{"type": "rule_fired", "rule_id": "cut", "exactly": 0}`, Assertion{Type: RuleFired, Rule: "cut", Count: Count{Max: &zero}}},
		{"a rule fired between", `{"type": "rule_fired", "rule_id": "cut", "at_least": 2, "at_most": 3}`, Assertion{Type: RuleFired, Rule: "cut", Count: Count{Min: 2, Max: &three}}},
		{"a rule fired at most", `{"type": "rule_fired", "rule_id": "cut", "at_most": 3}`, Assertion{Type: RuleFired, Rule: "cut", Count: Count{Max: &three}}},
		{"a rule of the chaos", `{"type": "rule_fired", "rule_id": "chaos-delay"}`, Assertion{Type: RuleFired, Rule: "chaos-delay", Count: Count{Min: 1}}},
		{"a rename", `{"type": "successful_operation", "operation": "rename", "source": "/in/a.part", "target": "/in/a"}`, Assertion{Type: SuccessfulOperation, Operation: faults.Rename, Source: "/in/a.part", Target: "/in/a", Count: Count{Min: 1}}},
		{"a rename to a target", `{"type": "successful_operation", "operation": "rename", "target": "/in/a"}`, Assertion{Type: SuccessfulOperation, Operation: faults.Rename, Target: "/in/a", Count: Count{Min: 1}}},
		{"a removal, its path cleaned", `{"type": "successful_operation", "operation": "remove", "path": "/in/../a", "exactly": 2}`, Assertion{Type: SuccessfulOperation, Operation: faults.Remove, Path: "/a", Count: Count{Min: 2, Max: &two}}},
		{"a fixture", `{"type": "file_equals_fixture", "path": "/in/a", "fixture": "out/orders.csv"}`, Assertion{Type: FileEqualsFixture, Path: "/in/a", Fixture: "out/orders.csv"}},
		{"a hash, in lower case", `{"type": "file_hash", "path": "/in/a", "sha256": "` + strings.ToUpper(testHash) + `"}`, Assertion{Type: FileHash, Path: "/in/a", SHA256: testHash}},
		{"a path gone", `{"type": "path_absent", "path": "/in/a.part"}`, Assertion{Type: PathAbsent, Path: "/in/a.part"}},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got, err := ParseAssertions([]byte("["+tt.json+"]"), rules, chaos, expected)
			if err != nil {
				t.Fatalf("ParseAssertions: %v", err)
			}
			if !reflect.DeepEqual(got, []Assertion{tt.want}) {
				t.Errorf("assertions = %+v, want %+v", got, tt.want)
			}
			written, err := AssertionsJSON(got)
			if err != nil {
				t.Fatalf("AssertionsJSON: %v", err)
			}
			again, err := ParseAssertions(written, rules, chaos, expected)
			if err != nil {
				t.Fatalf("ParseAssertions of %s: %v", written, err)
			}
			if !reflect.DeepEqual(again, got) {
				t.Errorf("%s reads as %+v, want %+v", written, again, got)
			}
		})
	}
}

func TestParseAssertionsRefuses(t *testing.T) {
	expected := t.TempDir()
	testutil.WriteFile(t, filepath.Join(expected, "out", "orders.csv"), "id\n")
	if err := os.Symlink(filepath.Join(expected, "out", "orders.csv"), filepath.Join(expected, "link.csv")); err != nil {
		t.Fatal(err)
	}
	tests := []struct {
		name string
		json string
		want string
	}{
		{"no type", `{"path": "/a"}`, `type "" is not rule_fired`},
		{"an unknown type", `{"type": "file_exists", "path": "/a"}`, `type "file_exists" is not rule_fired`},
		{"an unknown field", `{"type": "path_absent", "path": "/a", "user": "test"}`, `unknown field "user"`},
		{"a negative count", `{"type": "rule_fired", "rule_id": "cut", "at_least": -1}`, "cannot unmarshal"},
		{"no rule", `{"type": "rule_fired"}`, "rule_id is required"},
		{"a rule the scenario lacks", `{"type": "rule_fired", "rule_id": "typo"}`, `rule_id "typo" is not a rule of this scenario`},
		{"exactly with a bound", `{"type": "rule_fired", "rule_id": "cut", "exactly": 1, "at_most": 2}`, "exactly cannot be set with at_least or at_most"},
		{"crossed bounds", `{"type": "rule_fired", "rule_id": "cut", "at_least": 3, "at_most": 2}`, "at_least 3 is more than at_most 2"},
		{"a field of another type", `{"type": "rule_fired", "rule_id": "cut", "path": "/a"}`, "rule_fired has no path"},
		{"a count on a file", `{"type": "path_absent", "path": "/a", "exactly": 1}`, "path_absent has no exactly"},
		{"no operation", `{"type": "successful_operation", "path": "/a"}`, "operation is required"},
		{"a write", `{"type": "successful_operation", "operation": "write", "path": "/a"}`, `operation "write" is not rename`},
		{"an open", `{"type": "successful_operation", "operation": "open_write", "path": "/a"}`, `operation "open_write" is not rename`},
		{"a rename with a path", `{"type": "successful_operation", "operation": "rename", "path": "/a"}`, "a rename gives source and target, not path"},
		{"a rename with neither", `{"type": "successful_operation", "operation": "rename"}`, "a rename gives source, target or both"},
		{"a removal with a target", `{"type": "successful_operation", "operation": "remove", "target": "/a"}`, "remove gives path, not source or target"},
		{"a relative path", `{"type": "path_absent", "path": "a"}`, `path "a" must be an absolute SFTP path`},
		{"no path", `{"type": "path_absent"}`, `path "" must be an absolute SFTP path`},
		{"a relative source", `{"type": "successful_operation", "operation": "rename", "source": "a"}`, `source "a" must be an absolute SFTP path`},
		{"no fixture", `{"type": "file_equals_fixture", "path": "/a"}`, "fixture is required"},
		{"a fixture outside", `{"type": "file_equals_fixture", "path": "/a", "fixture": "../secret"}`, "must be a clean path relative to storage.expected_dir"},
		{"an absolute fixture", `{"type": "file_equals_fixture", "path": "/a", "fixture": "/etc/passwd"}`, "must be a clean path relative to storage.expected_dir"},
		{"a missing fixture", `{"type": "file_equals_fixture", "path": "/a", "fixture": "out/missing.csv"}`, `fixture "out/missing.csv"`},
		{"a directory as fixture", `{"type": "file_equals_fixture", "path": "/a", "fixture": "out"}`, "is not a regular file"},
		{"a link as fixture", `{"type": "file_equals_fixture", "path": "/a", "fixture": "link.csv"}`, "is not a regular file"},
		{"a short hash", `{"type": "file_hash", "path": "/a", "sha256": "abc"}`, `sha256 "abc" is not a SHA-256 in hex`},
		{"no hash", `{"type": "file_hash", "path": "/a"}`, `sha256 "" is not a SHA-256 in hex`},
		{"a hash not in hex", `{"type": "file_hash", "path": "/a", "sha256": "` + strings.Repeat("z", 64) + `"}`, "is not a SHA-256 in hex"},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			_, err := ParseAssertions([]byte("["+tt.json+"]"), []faults.Rule{{ID: "cut"}}, nil, expected)
			if err == nil || !strings.Contains(err.Error(), tt.want) {
				t.Errorf("ParseAssertions = %v, want an error saying %q", err, tt.want)
			}
			if err != nil && !strings.HasPrefix(err.Error(), "assertions[0]") {
				t.Errorf("the error %q does not say which assertion", err)
			}
		})
	}
	if _, err := ParseAssertions([]byte(`[{"type": "file_equals_fixture", "path": "/a", "fixture": "a"}]`), nil, nil, ""); err == nil || !strings.Contains(err.Error(), "needs storage.expected_dir") {
		t.Errorf("a fixture without an expected directory = %v", err)
	}
	if _, err := ParseAssertions([]byte(`[{"type": "file_equals_fixture", "path": "/a", "fixture": "missing"}]`), nil, nil, expected); !errors.Is(err, fs.ErrNotExist) {
		t.Errorf("a missing fixture = %v, want it to wrap %v", err, fs.ErrNotExist)
	}
}

func TestCountAllows(t *testing.T) {
	two := uint64(2)
	tests := []struct {
		count Count
		allow []uint64
		deny  []uint64
	}{
		{Count{Min: 1}, []uint64{1, 2, 100}, []uint64{0}},
		{Count{Min: 2, Max: &two}, []uint64{2}, []uint64{1, 3}},
		{Count{Max: &two}, []uint64{0, 2}, []uint64{3}},
	}
	for _, tt := range tests {
		for _, n := range tt.allow {
			if !tt.count.Allows(n) {
				t.Errorf("%+v does not allow %d", tt.count, n)
			}
		}
		for _, n := range tt.deny {
			if tt.count.Allows(n) {
				t.Errorf("%+v allows %d", tt.count, n)
			}
		}
	}
}

func TestAssertionsDescribeThemselves(t *testing.T) {
	two := uint64(2)
	zero := uint64(0)
	tests := []struct {
		assertion Assertion
		want      string
	}{
		{Assertion{Type: RuleFired, Rule: "cut", Count: Count{Min: 1}}, "rule_fired cut, at least 1"},
		{Assertion{Type: RuleFired, Rule: "cut", Count: Count{Min: 2, Max: &two}}, "rule_fired cut, exactly 2"},
		{Assertion{Type: RuleFired, Rule: "cut", Count: Count{Max: &zero}}, "rule_fired cut, exactly 0"},
		{Assertion{Type: RuleFired, Rule: "cut", Count: Count{Max: &two}}, "rule_fired cut, at most 2"},
		{Assertion{Type: RuleFired, Rule: "cut", Count: Count{Min: 1, Max: &two}}, "rule_fired cut, 1 to 2"},
		{Assertion{Type: SuccessfulOperation, Operation: faults.Remove, Path: "/a", Count: Count{Min: 1}}, "successful_operation remove /a, at least 1"},
		{Assertion{Type: SuccessfulOperation, Operation: faults.Rename, Source: "/a", Target: "/b", Count: Count{Min: 1}}, "successful_operation rename /a to /b, at least 1"},
		{Assertion{Type: SuccessfulOperation, Operation: faults.Rename, Target: "/b", Count: Count{Min: 1}}, "successful_operation rename to /b, at least 1"},
		{Assertion{Type: SuccessfulOperation, Operation: faults.Rename, Source: "/a", Count: Count{Min: 1}}, "successful_operation rename from /a, at least 1"},
		{Assertion{Type: FileEqualsFixture, Path: "/a", Fixture: "f"}, "file_equals_fixture /a, fixture f"},
		{Assertion{Type: FileHash, Path: "/a", SHA256: "abc"}, "file_hash /a, sha256 abc"},
		{Assertion{Type: PathAbsent, Path: "/a"}, "path_absent /a"},
	}
	for _, tt := range tests {
		if got := tt.assertion.String(); got != tt.want {
			t.Errorf("String() = %q, want %q", got, tt.want)
		}
	}
}

func TestAssertionsJSONOfNoneIsAnEmptyList(t *testing.T) {
	b, err := AssertionsJSON(nil)
	if err != nil {
		t.Fatal(err)
	}
	var list []any
	if err := json.Unmarshal(b, &list); err != nil || list == nil || len(list) != 0 {
		t.Errorf("AssertionsJSON(nil) = %s, want []", b)
	}
}

func TestLoadChecksAScenariosAssertions(t *testing.T) {
	dir := t.TempDir()
	testutil.WriteFile(t, filepath.Join(dir, "expected", "orders.csv"), "id\n")
	config := testutil.WriteFile(t, filepath.Join(dir, "sftpit.yaml"), `schema_version: 1
storage: {expected_dir: ./expected}
scenarios:
  only-assertions:
    faults: []
    assertions:
      - {type: file_equals_fixture, path: /in/orders.csv, fixture: orders.csv}
`)
	cfg, err := Load(Options{ConfigFile: config, LookupEnv: noEnv})
	if err != nil {
		t.Fatalf("Load: %v", err)
	}
	if want := filepath.Join(dir, "expected"); cfg.ExpectedDir != want {
		t.Errorf("ExpectedDir = %q, want %q", cfg.ExpectedDir, want)
	}
	want := []Assertion{{Type: FileEqualsFixture, Path: "/in/orders.csv", Fixture: "orders.csv"}}
	if got := cfg.Scenarios["only-assertions"].Assertions; !reflect.DeepEqual(got, want) {
		t.Errorf("assertions = %+v, want %+v", got, want)
	}

	tests := []struct {
		name string
		yaml string
		want string
	}{
		{"a rule it lacks", "schema_version: 1\nscenarios:\n  s:\n    faults: []\n    assertions:\n      - {type: rule_fired, rule_id: typo}\n", `scenarios.s.assertions[0]: rule_id "typo"`},
		{"a fixture without a directory", "schema_version: 1\nscenarios:\n  s:\n    faults: []\n    assertions:\n      - {type: file_equals_fixture, path: /a, fixture: a}\n", "needs storage.expected_dir"},
		{"a misspelt field", "schema_version: 1\nscenarios:\n  s:\n    faults: []\n    assertions:\n      - {type: path_absent, pth: /a}\n", "field pth not found"},
		{"no expected directory", "schema_version: 1\nstorage: {expected_dir: ./missing}\n", "expected_dir: "},
		{"an expected file", "schema_version: 1\nstorage: {expected_dir: ./sftpit.yaml}\n", "is not a directory"},
		{"expected inside the seed", "schema_version: 1\nstorage: {seed_dir: ., expected_dir: ./expected}\n", "is inside seed_dir"},
		{"expected as the seed", "schema_version: 1\nstorage: {seed_dir: ./expected, expected_dir: ./expected}\n", "is inside seed_dir"},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			testutil.WriteFile(t, config, tt.yaml)
			if _, err := Load(Options{ConfigFile: config, LookupEnv: noEnv}); err == nil || !strings.Contains(err.Error(), tt.want) {
				t.Errorf("Load = %v, want an error saying %q", err, tt.want)
			}
		})
	}
}

func TestScenarioFilesKeepAssertions(t *testing.T) {
	dir := t.TempDir()
	expected := filepath.Join(dir, "expected")
	testutil.WriteFile(t, filepath.Join(expected, "orders.csv"), "id\n")
	files := NewScenarioFiles(filepath.Join(dir, "scenarios"), testUsers, nil, expected)
	two := uint64(2)
	s := Scenario{Assertions: []Assertion{
		{Type: FileEqualsFixture, Path: "/in/orders.csv", Fixture: "orders.csv"},
		{Type: SuccessfulOperation, Operation: faults.Remove, Path: "/in/a", Count: Count{Min: 2, Max: &two}},
	}}
	saved, err := files.Save("recovery", s, "")
	if err != nil {
		t.Fatalf("Save: %v", err)
	}
	if !reflect.DeepEqual(saved.Scenario.Assertions, s.Assertions) {
		t.Errorf("the saved scenario has %+v, want %+v", saved.Scenario.Assertions, s.Assertions)
	}

	// Its fixture goes, so the next read of the file says why it cannot run.
	if err := os.Remove(filepath.Join(expected, "orders.csv")); err != nil {
		t.Fatal(err)
	}
	if _, err := files.Load("recovery"); !errors.Is(err, ErrInvalidScenarioFile) || !strings.Contains(err.Error(), `fixture "orders.csv"`) {
		t.Errorf("Load without its fixture = %v, want %v naming it", err, ErrInvalidScenarioFile)
	}
}
