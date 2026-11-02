package control_test

import (
	"errors"
	"io/fs"
	"net/http"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/nebarg/sftpit/internal/config"
	"github.com/nebarg/sftpit/internal/runs"
)

// startWithScenarioFiles starts runs as start does, with scenario files in
// a new directory, which it returns.
func startWithScenarioFiles(t *testing.T) (*runs.Manager, http.Handler, string) {
	t.Helper()
	dir := filepath.Join(t.TempDir(), "scenarios")
	m, api := start(t, runs.Options{ScenarioFiles: config.NewScenarioFiles(dir, testUsers, testScenarios)})
	return m, api, dir
}

func TestScenariosAreSavedListedAndReset(t *testing.T) {
	m, api, dir := startWithScenarioFiles(t)
	code, body := call(t, api, "GET", "/api/v1/scenarios", "")
	want := map[string]any{"dir": dir, "scenarios": []any{
		map[string]any{"name": "chaos", "source": "config", "faults": []any{}},
		map[string]any{"name": "own", "source": "config", "seed": "9", "faults": []any{}},
	}}
	if code != http.StatusOK || !equalJSON(body, want) {
		t.Errorf("the scenarios before a save are %d %v, want %v", code, body, want)
	}

	code, saved := call(t, api, "PUT", "/api/v1/scenarios/saved", `{"description": "Denies stats.", "seed": 7, "faults": [`+denyStats+`]}`)
	path := filepath.Join(dir, "saved.yaml")
	if code != http.StatusCreated || saved["name"] != "saved" || saved["source"] != "file" || saved["path"] != path || saved["seed"] != "7" || saved["description"] != "Denies stats." {
		t.Fatalf("a save of a new file = %d %v, want it created at %s", code, saved, path)
	}
	if code, body := call(t, api, "PUT", "/api/v1/scenarios/saved", `{"faults": []}`); code != http.StatusConflict || !strings.Contains(body["error"].(string), "give its hash") {
		t.Errorf("a save over the file without its hash = %d %v, want 409", code, body)
	}
	code, replaced := call(t, api, "PUT", "/api/v1/scenarios/saved", `{"hash": "`+saved["hash"].(string)+`", "seed": "8", "faults": [`+denyStats+`]}`)
	if code != http.StatusOK || replaced["hash"] == saved["hash"] || replaced["seed"] != "8" {
		t.Errorf("a save with the file's hash = %d %v, want it replaced", code, replaced)
	}

	_, body = call(t, api, "GET", "/api/v1/scenarios", "")
	listed, _ := body["scenarios"].([]any)
	if len(listed) != 3 || !equalJSON(listed[2], replaced) {
		t.Errorf("the scenarios after a save are %v, want the file listed after chaos and own as %v", listed, replaced)
	}

	code, body = call(t, api, "POST", "/api/v1/reset", `{"scenario": "saved"}`)
	if run, _ := body["run"].(map[string]any); code != http.StatusOK || run["scenario"] != "saved" || run["seed"] != "8" {
		t.Errorf("a reset to the saved scenario = %d %v", code, body)
	}

	if err := os.WriteFile(path, []byte("faults: []\n"), 0o644); err != nil {
		t.Fatal(err)
	}
	if code, body := call(t, api, "POST", "/api/v1/reset", `{"scenario": "saved"}`); code != http.StatusBadRequest || !strings.Contains(body["error"].(string), "schema_version is required") {
		t.Errorf("a reset to a broken file = %d %v, want 400", code, body)
	}
	_, body = call(t, api, "GET", "/api/v1/scenarios", "")
	listed, _ = body["scenarios"].([]any)
	if broken, _ := listed[2].(map[string]any); broken["path"] != path || broken["hash"] == nil || !strings.Contains(broken["error"].(string), "schema_version is required") || broken["faults"] != nil {
		t.Errorf("a broken file is listed as %v, want its path, hash and error", broken)
	}
	if m.Status().Err != nil {
		t.Errorf("a refused reset left the runs failed: %v", m.Status().Err)
	}
}

func TestTheLiveRulesAreSavedAsAScenario(t *testing.T) {
	m, api, _ := startWithScenarioFiles(t)
	run := m.Status().Run.ID
	chaos := `{"preset": "light", "scope": {"user": "test"}, "extras": [], "paused": true}`
	if code, body := call(t, api, "PUT", "/api/v1/runs/"+run+"/rules", `{"revision": 1, "faults": [`+denyStats+`], "chaos": `+chaos+`}`); code != http.StatusOK {
		t.Fatalf("a change of rules = %d %v", code, body)
	}
	_, live := call(t, api, "GET", "/api/v1/runs/"+run+"/rules", "")
	saveBody := mustJSON(t, map[string]any{"faults": live["faults"], "chaos": live["chaos"]})
	code, saved := call(t, api, "PUT", "/api/v1/scenarios/live", saveBody)
	if code != http.StatusCreated || !equalJSON(saved["faults"], live["faults"]) || !equalJSON(saved["chaos"], live["chaos"]) {
		t.Fatalf("a save of the live rules = %d %v, want the rules and chaos %v", code, saved, live)
	}

	code, body := call(t, api, "POST", "/api/v1/reset", `{"scenario": "live"}`)
	if code != http.StatusOK {
		t.Fatalf("a reset to the saved live rules = %d %v", code, body)
	}
	_, next := call(t, api, "GET", "/api/v1/runs/"+m.Status().Run.ID+"/rules", "")
	if !equalJSON(next["faults"], live["faults"]) || !equalJSON(next["chaos"], live["chaos"]) {
		t.Errorf("the run of the saved live rules has %v, want %v", next, live)
	}
}

func TestSaveScenarioRefusesABadRequest(t *testing.T) {
	tests := []struct {
		name, path, body string
		code             int
		want             string
	}{
		{"no faults", "/api/v1/scenarios/s", `{}`, http.StatusBadRequest, "faults is required"},
		{"a bad rule", "/api/v1/scenarios/s", `{"faults": [{"id": "r"}]}`, http.StatusBadRequest, "faults[0] (r)"},
		{"bad chaos", "/api/v1/scenarios/s", `{"faults": [], "chaos": {"preset": "wild"}}`, http.StatusBadRequest, "chaos"},
		{"an unknown field", "/api/v1/scenarios/s", `{"faults": [], "notes": "x"}`, http.StatusBadRequest, "notes"},
		{"a bad seed", "/api/v1/scenarios/s", `{"faults": [], "seed": "-1"}`, http.StatusBadRequest, "seed"},
		{"a bad name", "/api/v1/scenarios/Upper", `{"faults": []}`, http.StatusBadRequest, `invalid scenario name "Upper"`},
		{"a configured scenario", "/api/v1/scenarios/chaos", `{"faults": []}`, http.StatusConflict, "the configuration file defines this scenario"},
		{"a hash for no file", "/api/v1/scenarios/s", `{"faults": [], "hash": "abc"}`, http.StatusConflict, "it was removed"},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			_, api, dir := startWithScenarioFiles(t)
			code, body := call(t, api, "PUT", tt.path, tt.body)
			if msg, _ := body["error"].(string); code != tt.code || !strings.Contains(msg, tt.want) {
				t.Errorf("PUT %s %s = %d %v, want %d and %q", tt.path, tt.body, code, body, tt.code, tt.want)
			}
			if _, err := os.Stat(dir); !errors.Is(err, fs.ErrNotExist) {
				t.Errorf("a refused save made the scenarios directory (%v)", err)
			}
		})
	}
}
