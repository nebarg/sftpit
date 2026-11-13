package control_test

import (
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	"github.com/nebarg/sftpit/internal/control"
	"github.com/nebarg/sftpit/internal/runs"
)

func TestFaultsThroughTheAPI(t *testing.T) {
	m, api := start(t, runs.Options{})

	code, body := call(t, api, "POST", "/api/faults", `{"preset": "deletes_fail", "folder": "/outgoing"}`)
	want := map[string]any{
		"id": "deletes-fail-1", "on": true, "happened": 0,
		"name": "Deletes fail", "preset": "deletes_fail", "steps": []any{"remove"}, "do": "refuse",
		"error": "permission_denied", "folder": "/outgoing",
	}
	if code != http.StatusCreated || !equalJSON(body, want) {
		t.Errorf("POST /api/faults = %d %v, want 201 %v", code, body, want)
	}
	if code, body := call(t, api, "GET", "/api/faults/deletes-fail-1", ""); code != http.StatusOK || !equalJSON(body, want) {
		t.Errorf("GET /api/faults/deletes-fail-1 = %d %v, want %v", code, body, want)
	}
	if code, body := call(t, api, "GET", "/api/faults", ""); code != http.StatusOK || !equalJSON(body, map[string]any{"faults": []any{want}}) {
		t.Errorf("GET /api/faults = %d %v, want the fault", code, body)
	}
	if set, err := m.Rules(m.Status().Run.ID); err != nil || len(set.Rules) != 1 || set.Rules[0].ID != "deletes-fail-1" {
		t.Errorf("the run's rules are %+v, %v; want the fault's", set.Rules, err)
	}

	code, body = call(t, api, "PATCH", "/api/faults/deletes-fail-1", `{"on": false}`)
	want["on"] = false
	if code != http.StatusOK || !equalJSON(body, want) {
		t.Errorf("PATCH off = %d %v, want %v", code, body, want)
	}
	if set, _ := m.Rules(m.Status().Run.ID); len(set.Rules) != 0 {
		t.Errorf("with the fault off, the run has rules %+v, want none", set.Rules)
	}

	if code, _ := send(t, api, "DELETE", "/api/faults/deletes-fail-1", ""); code != http.StatusNoContent {
		t.Errorf("DELETE /api/faults/deletes-fail-1 = %d, want 204", code)
	}
	if code, body := call(t, api, "GET", "/api/faults/deletes-fail-1", ""); code != http.StatusNotFound || !strings.Contains(body["error"].(string), "unknown fault") {
		t.Errorf("GET of a removed fault = %d %v, want 404", code, body)
	}
}

func TestFaultsAreRemovedAllAtOnceAndByAReset(t *testing.T) {
	m, api := start(t, runs.Options{Scenario: "own"})
	for range 2 {
		if code, body := call(t, api, "POST", "/api/faults", `{"preset": "slow_responses", "seconds": 1}`); code != http.StatusCreated {
			t.Fatalf("POST /api/faults = %d %v", code, body)
		}
	}
	if code, _ := send(t, api, "DELETE", "/api/faults", ""); code != http.StatusNoContent || len(m.Faults()) != 0 {
		t.Errorf("DELETE /api/faults = %d, leaving %+v; want 204 and none", code, m.Faults())
	}
	if set, _ := m.Rules(m.Status().Run.ID); len(set.Rules) != 1 || set.Rules[0].ID != "deny-stats" {
		t.Errorf("after removing the faults, the rules are %+v, want the scenario's", set.Rules)
	}

	if code, body := call(t, api, "POST", "/api/faults", `{"preset": "deletes_fail"}`); code != http.StatusCreated {
		t.Fatalf("POST /api/faults = %d %v", code, body)
	}
	before := m.Status().Run.ID
	for _, body := range []string{"", "{}"} {
		if code, got := send(t, api, "POST", "/api/reset", body); code != http.StatusNoContent {
			t.Errorf("POST /api/reset with %q = %d %s, want 204", body, code, got)
		}
	}
	s := m.Status()
	if s.Run.ID == before || s.Run.Scenario.Name != "" || len(m.Faults()) != 0 {
		t.Errorf("after a reset, run %s with scenario %q and faults %+v; want a new run with neither", s.Run.ID, s.Run.Scenario.Name, m.Faults())
	}
	if code, got := send(t, api, "POST", "/api/reset", `{"scenario": "x"}`); code != http.StatusBadRequest || !strings.Contains(got, "unknown field") {
		t.Errorf("POST /api/reset with a field = %d %s, want 400", code, got)
	}
}

func TestTheAPIRefusesFaultsThatCannotWork(t *testing.T) {
	_, api := start(t, runs.Options{})
	tests := []struct {
		method, path, body string
		code               int
		want               string
	}{
		{"POST", "/api/faults", `{"preset": "oops"}`, http.StatusBadRequest, `there is no preset \"oops\"`},
		{"POST", "/api/faults", `{"steps": ["remove"], "do": "refuse", "user": "nobody"}`, http.StatusBadRequest, `user \"nobody\" is not a configured user`},
		{"POST", "/api/faults", `{"preset": "deletes_fail", "colour": "red"}`, http.StatusBadRequest, `unknown field \"colour\"`},
		{"PATCH", "/api/faults/nope", `{"on": true}`, http.StatusNotFound, "unknown fault"},
		{"PATCH", "/api/faults/nope", `{}`, http.StatusBadRequest, "on is required"},
		{"DELETE", "/api/faults/nope", ``, http.StatusNotFound, "unknown fault"},
	}
	for _, tt := range tests {
		code, body := send(t, api, tt.method, tt.path, tt.body)
		if code != tt.code || !strings.Contains(body, tt.want) {
			t.Errorf("%s %s %s = %d %s, want %d and %q", tt.method, tt.path, tt.body, code, body, tt.code, tt.want)
		}
	}
}

func TestPresetsListWhatAFaultCanBe(t *testing.T) {
	_, api := start(t, runs.Options{})
	code, body := call(t, api, "GET", "/api/presets", "")
	if code != http.StatusOK {
		t.Fatalf("GET /api/presets = %d %v", code, body)
	}
	first := body["presets"].([]any)[0].(map[string]any)
	if first["id"] != "deletes_fail" || first["name"] != "Deletes fail" || first["fault"].(map[string]any)["do"] != "refuse" {
		t.Errorf("the first preset is %v, want deletes_fail", first)
	}
	if steps := body["steps"].([]any); len(steps) != 14 || steps[0].(map[string]any)["id"] != "connect" {
		t.Errorf("steps = %v, want the 14, from connect", steps)
	}
	if errs := body["errors"].([]any); len(errs) != 4 {
		t.Errorf("errors = %v, want the 4 a refusal can answer with", errs)
	}
}

// send makes a request to api as the command line would, and returns the
// status code and the body as it is.
func send(t *testing.T, api http.Handler, method, path, body string) (int, string) {
	t.Helper()
	req := httptest.NewRequest(method, path, strings.NewReader(body))
	req.Host = host
	req.Header.Set(control.RequestHeader, "1")
	rec := httptest.NewRecorder()
	api.ServeHTTP(rec, req)
	return rec.Code, rec.Body.String()
}

func TestActivityRefusesABadLimit(t *testing.T) {
	_, api := start(t, runs.Options{})
	if code, body := call(t, api, "GET", "/api/activity", ""); code != http.StatusOK || len(body["lines"].([]any)) != 0 || body["partial"] != false {
		t.Errorf("GET /api/activity = %d %v, want no lines yet", code, body)
	}
	for _, limit := range []string{"0", "5001", "many"} {
		if code, body := call(t, api, "GET", "/api/activity?limit="+limit, ""); code != http.StatusBadRequest || !strings.Contains(body["error"].(string), "is not a number from 1 to 5000") {
			t.Errorf("GET /api/activity?limit=%s = %d %v, want 400", limit, code, body)
		}
	}
}

func TestTheCurrentRunsRoutesNeedNoRunID(t *testing.T) {
	m, api := start(t, runs.Options{})
	if code, body := call(t, api, "GET", "/api/status", ""); code != http.StatusOK || body["run"].(map[string]any)["id"] != m.Status().Run.ID {
		t.Errorf("GET /api/status = %d %v, want the current run", code, body)
	}
	if code, body := call(t, api, "GET", "/api/server", ""); code != http.StatusOK || body["sftp_address"] == nil {
		t.Errorf("GET /api/server = %d %v, want how to connect", code, body)
	}
	if code, body := call(t, api, "GET", "/api/files", ""); code != http.StatusOK || body["live"] != true {
		t.Errorf("GET /api/files = %d %v, want the current run's files", code, body)
	}
	if code, body := send(t, api, "GET", "/api/files/content?path=/missing", ""); code != http.StatusNotFound {
		t.Errorf("GET /api/files/content of a missing file = %d %s, want 404", code, body)
	}
	if code, body := call(t, api, "POST", "/api/release", ""); code != http.StatusOK || body["run"].(map[string]any)["id"] != m.Status().Run.ID {
		t.Errorf("POST /api/release = %d %v, want the status", code, body)
	}
}
