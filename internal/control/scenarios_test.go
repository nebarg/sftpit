package control_test

import (
	"net/http"
	"strings"
	"testing"

	"github.com/nebarg/sftpit/internal/runs"
)

// scenarioNamed returns the scenario name from a GET /api/scenarios body.
func scenarioNamed(t *testing.T, body map[string]any, name string) map[string]any {
	t.Helper()
	for _, s := range body["scenarios"].([]any) {
		if s := s.(map[string]any); s["name"] == name {
			return s
		}
	}
	t.Fatalf("the scenarios %v do not include %s", body, name)
	return nil
}

func TestScenariosAreListedWithTheirFaults(t *testing.T) {
	_, api := start(t, runs.Options{})
	code, body := call(t, api, "GET", "/api/scenarios", "")
	if code != http.StatusOK {
		t.Fatalf("GET /api/scenarios = %d %v", code, body)
	}
	var names []string
	for _, s := range body["scenarios"].([]any) {
		names = append(names, s.(map[string]any)["name"].(string))
	}
	if want := "unreliable-heavy unreliable-light unreliable-moderate own"; strings.Join(names, " ") != want {
		t.Errorf("the scenarios are %v, want %s", names, want)
	}
	want := map[string]any{
		"name":        "own",
		"source":      "config",
		"on":          false,
		"description": "Stats fail.",
		"faults":      []any{map[string]any{"name": "Stats fail", "steps": []any{"stat"}, "do": "refuse", "error": "permission_denied", "user": "test"}},
	}
	if got := scenarioNamed(t, body, "own"); !equalJSON(got, want) {
		t.Errorf("own = %v, want %v", got, want)
	}
	light := scenarioNamed(t, body, "unreliable-light")
	if faults := light["faults"].([]any); light["source"] != "built_in" || len(faults) != 2 || faults[0].(map[string]any)["name"] != "Slow commands" {
		t.Errorf("unreliable-light = %v, want it built in with its two faults", light)
	}
}

func TestAScenarioIsTurnedOnAndOff(t *testing.T) {
	m, api := start(t, runs.Options{})
	code, body := call(t, api, "PATCH", "/api/scenarios/own", `{"on": true}`)
	if code != http.StatusOK || body["on"] != true || body["name"] != "own" {
		t.Fatalf("PATCH on = %d %v, want 200 and on", code, body)
	}
	_, faults := call(t, api, "GET", "/api/faults", "")
	list := faults["faults"].([]any)
	if len(list) != 1 || list[0].(map[string]any)["scenario"] != "own" || list[0].(map[string]any)["id"] != "stats-fail-1" {
		t.Errorf("the faults with own on are %v, want its fault, tagged with it", faults)
	}
	if _, body := call(t, api, "GET", "/api/scenarios", ""); scenarioNamed(t, body, "own")["on"] != true {
		t.Error("GET /api/scenarios does not list own as on")
	}

	if code, body := call(t, api, "PATCH", "/api/scenarios/own", `{"on": false}`); code != http.StatusOK || body["on"] != false {
		t.Errorf("PATCH off = %d %v, want 200 and off", code, body)
	}
	if got := m.Faults(); len(got) != 0 {
		t.Errorf("with own off, the faults are %+v, want none", got)
	}

	tests := []struct {
		path, body string
		code       int
		want       string
	}{
		{"/api/scenarios/own", `{}`, http.StatusBadRequest, "on is required"},
		{"/api/scenarios/own", `{"on": true, "off": true}`, http.StatusBadRequest, "unknown field"},
		{"/api/scenarios/flaky", `{"on": true}`, http.StatusNotFound, `unknown scenario "flaky"`},
	}
	for _, tt := range tests {
		if code, body := call(t, api, "PATCH", tt.path, tt.body); code != tt.code || !strings.Contains(body["error"].(string), tt.want) {
			t.Errorf("PATCH %s %s = %d %v, want %d saying %q", tt.path, tt.body, code, body, tt.code, tt.want)
		}
	}
}

func TestAScenarioIsSavedAndDeleted(t *testing.T) {
	m, api := start(t, runs.Options{})
	code, body := call(t, api, "PUT", "/api/scenarios/partner", `{"description": "Partner trouble.", "faults": [{"preset": "deletes_fail"}]}`)
	want := map[string]any{
		"name":        "partner",
		"source":      "file",
		"on":          false,
		"description": "Partner trouble.",
		"faults":      []any{map[string]any{"name": "Deletes fail", "preset": "deletes_fail", "steps": []any{"remove"}, "do": "refuse", "error": "permission_denied"}},
	}
	if code != http.StatusOK || !equalJSON(body, want) {
		t.Fatalf("PUT = %d %v, want 200 and %v", code, body, want)
	}
	if _, body := call(t, api, "GET", "/api/scenarios", ""); !equalJSON(scenarioNamed(t, body, "partner"), want) {
		t.Errorf("GET /api/scenarios lists partner as %v, want %v", scenarioNamed(t, body, "partner"), want)
	}
	if code, _ := call(t, api, "PATCH", "/api/scenarios/partner", `{"on": true}`); code != http.StatusOK {
		t.Fatalf("PATCH on = %d", code)
	}

	refused := []struct {
		method, path, body string
		code               int
		want               string
	}{
		{"PUT", "/api/scenarios/unreliable-light", `{"faults": [{"preset": "deletes_fail"}]}`, http.StatusConflict, "it is built in"},
		{"PUT", "/api/scenarios/own", `{"faults": [{"preset": "deletes_fail"}]}`, http.StatusConflict, "defined in the configuration file"},
		{"PUT", "/api/scenarios/Bad_Name", `{"faults": [{"preset": "deletes_fail"}]}`, http.StatusBadRequest, "may hold only"},
		{"PUT", "/api/scenarios/empty", `{"faults": []}`, http.StatusBadRequest, "a scenario needs at least one fault"},
		{"PUT", "/api/scenarios/bad", `{"faults": [{"steps": ["upload"], "do": "refuse"}]}`, http.StatusBadRequest, `faults[0]: there is no step "upload"`},
		{"PUT", "/api/scenarios/bad", `{"faults": [], "chaos": {}}`, http.StatusBadRequest, "unknown field"},
		{"DELETE", "/api/scenarios/unreliable-light", "", http.StatusConflict, "it is built in"},
		{"DELETE", "/api/scenarios/missing", "", http.StatusNotFound, `unknown scenario "missing"`},
	}
	for _, tt := range refused {
		if code, body := call(t, api, tt.method, tt.path, tt.body); code != tt.code || !strings.Contains(body["error"].(string), tt.want) {
			t.Errorf("%s %s %s = %d %v, want %d saying %q", tt.method, tt.path, tt.body, code, body, tt.code, tt.want)
		}
	}

	if code, got := send(t, api, "DELETE", "/api/scenarios/partner", ""); code != http.StatusNoContent {
		t.Errorf("DELETE = %d %s, want 204", code, got)
	}
	if got := m.Faults(); len(got) != 0 {
		t.Errorf("after deleting partner, the faults are %+v, want none", got)
	}
	if code, _ := call(t, api, "PATCH", "/api/scenarios/partner", `{"on": true}`); code != http.StatusNotFound {
		t.Errorf("PATCH of a deleted scenario = %d, want 404", code)
	}
}
