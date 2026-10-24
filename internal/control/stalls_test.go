package control_test

import (
	"net/http"
	"strings"
	"testing"

	"github.com/nebarg/sftpit/internal/runs"
)

func TestResetStartsAnInlineScenario(t *testing.T) {
	m, api := start(t, runs.Options{Scenario: "chaos"})
	code, body := call(t, api, "POST", "/api/v1/reset", `{"faults": [`+denyStats+`], "seed": "7"}`)
	run, _ := body["run"].(map[string]any)
	if want := map[string]any{"id": m.Status().Run.ID, "inline": true, "seed": "7", "seed_pinned": true, "revision": 1}; code != http.StatusOK || !equalJSON(run, want) {
		t.Errorf("an inline reset = %d %v, want the run %v", code, body, want)
	}
	_, rules := call(t, api, "GET", "/api/v1/runs/"+m.Status().Run.ID+"/rules", "")
	if faults, _ := rules["faults"].([]any); len(faults) != 1 || faults[0].(map[string]any)["id"] != "deny-stats" {
		t.Errorf("the inline run's rules are %v, want deny-stats", rules)
	}
	// A null faults is no inline scenario, so the reset repeats the run.
	code, body = call(t, api, "POST", "/api/v1/reset", `{"faults": null}`)
	if run, _ := body["run"].(map[string]any); code != http.StatusOK || run["inline"] != true || run["seed"] != "7" {
		t.Errorf("a reset with null faults = %d %v, want the inline scenario repeated", code, body)
	}
}

func TestReleaseStallsAnswersWithTheStatus(t *testing.T) {
	m, api := start(t, runs.Options{Scenario: "chaos"})
	run := m.Status().Run.ID
	code, body := call(t, api, "POST", "/api/v1/runs/"+run+"/release-stalls", "")
	if got, _ := body["run"].(map[string]any); code != http.StatusOK || got["id"] != run {
		t.Errorf("release-stalls = %d %v, want the status", code, body)
	}
	code, body = call(t, api, "POST", "/api/v1/runs/20260101-000000.000-0000/release-stalls", "")
	if msg, _ := body["error"].(string); code != http.StatusConflict || !strings.Contains(msg, "stale run: the current run is "+run) {
		t.Errorf("release-stalls of another run = %d %v, want 409", code, body)
	}
}
