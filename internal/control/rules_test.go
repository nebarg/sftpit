package control_test

import (
	"encoding/json"
	"net/http"
	"strings"
	"testing"

	"github.com/nebarg/sftpit/internal/runs"
)

const (
	denyStats = `{"id": "deny-stats", "match": {"operation": "stat", "user": "test"}, "action": {"type": "fail", "when": "before", "status": "permission_denied"}}`

	// outageLater is selected for the run as it is applied, so it has
	// counts at once.
	outageLater = `{"id": "outage-later", "trigger": {"at": "1h", "anchor": "run"}, "action": {"type": "listener_down", "duration": "1s"}}`
)

func TestRulesChangeThroughTheAPI(t *testing.T) {
	m, api := start(t, runs.Options{Scenario: "chaos"})
	path := "/api/v1/runs/" + m.Status().Run.ID + "/rules"
	code, body := call(t, api, "GET", path, "")
	if want := map[string]any{"revision": 1, "faults": []any{}, "counts": map[string]any{}}; code != http.StatusOK || !equalJSON(body, want) {
		t.Errorf("GET %s = %d %v, want %v", path, code, body, want)
	}

	code, body = call(t, api, "PUT", path, `{"revision": 1, "faults": [`+denyStats+`, `+outageLater+`]}`)
	var want map[string]any
	if err := json.Unmarshal([]byte(`{
		"revision": 2,
		"faults": [
			{"id": "deny-stats", "priority": 0, "max_triggers": 0, "match": {"user": "test", "operation": ["stat"]}, "action": {"type": "fail", "when": "before", "status": "permission_denied"}},
			{"id": "outage-later", "priority": 0, "max_triggers": 0, "match": {}, "trigger": {"at": "1h0m0s", "anchor": "run"}, "action": {"type": "listener_down", "duration": "1s", "close_existing": false}}
		],
		"counts": {"deny-stats": {"matched": 0, "selected": 0, "fired": 0}, "outage-later": {"matched": 1, "selected": 1, "fired": 0}}
	}`), &want); err != nil {
		t.Fatal(err)
	}
	if code != http.StatusOK || !equalJSON(body, want) {
		t.Errorf("PUT %s = %d %v, want %v", path, code, body, want)
	}
	if code, got := call(t, api, "GET", path, ""); code != http.StatusOK || !equalJSON(got, want) {
		t.Errorf("GET %s after the change = %d %v, want %v", path, code, got, want)
	}
	if got := m.Status().Revision; got != 2 {
		t.Errorf("the run's revision is %d, want 2", got)
	}
	_, status := call(t, api, "GET", "/api/v1/status", "")
	if got := status["run"].(map[string]any)["revision"]; got != 2.0 {
		t.Errorf("status reports revision %v, want 2", got)
	}

	// The rules a GET returns can be put back as they are.
	faults, err := json.Marshal(body["faults"])
	if err != nil {
		t.Fatal(err)
	}
	code, body = call(t, api, "PUT", path, `{"revision": 2, "faults": `+string(faults)+`}`)
	want["revision"] = 3
	if code != http.StatusOK || !equalJSON(body, want) {
		t.Errorf("PUT of the rules as GET returned them = %d %v, want %v", code, body, want)
	}
}

func TestRuleChangesFailClearly(t *testing.T) {
	m, api := start(t, runs.Options{Scenario: "chaos"})
	run := m.Status().Run.ID
	path := "/api/v1/runs/" + run + "/rules"
	other := "/api/v1/runs/20260101-000000.000-0000/rules"
	tests := []struct {
		method, path, body string
		code               int
		want               string
	}{
		{"GET", other, "", http.StatusConflict, "stale run: the current run is " + run},
		{"PUT", other, `{"revision": 1, "faults": []}`, http.StatusConflict, "stale run: the current run is " + run},
		{"PUT", path, `{"revision": 2, "faults": []}`, http.StatusConflict, "stale revision: the current revision is 1, not 2"},
		{"PUT", path, `{"faults": []}`, http.StatusBadRequest, "revision is required"},
		{"PUT", path, `{"revision": 1}`, http.StatusBadRequest, "faults is required"},
		{"PUT", path, `{"revision": 1, "faults": null}`, http.StatusBadRequest, "faults is required"},
		{"PUT", path, `{"revision": 1, "faults": [], "seed": 7}`, http.StatusBadRequest, `invalid request body: json: unknown field "seed"`},
		{"PUT", path, `{"revision": 1, "faults": [{"id": "r"}]}`, http.StatusBadRequest, "faults[0] (r): match: operation is required"},
		{"PUT", path, `{"revision": 1, "faults": [` + strings.Replace(denyStats, `"test"`, `"nobody"`, 1) + `]}`, http.StatusBadRequest, `user "nobody" is not a configured user`},
		{"PUT", path, `{"revision": 1, "faults": [` + denyStats + `, ` + denyStats + `]}`, http.StatusBadRequest, `faults: rule ID "deny-stats" is used twice`},
		{"PUT", path, `{"revision": 1, "faults": [` + strings.Replace(denyStats, `"deny-stats"`, `"chaos-stats"`, 1) + `]}`, http.StatusBadRequest, `faults: rule ID "chaos-stats" starts with chaos-`},
		{"PUT", path, `{"revision": 1, "faults": [], "chaos": {"preset": "light", "extras": ["corrupt_upload"]}}`, http.StatusBadRequest, `chaos: faults: chaos extra "corrupt_upload" is not corrupt_download or wrong_size`},
		{"PUT", path, `{"revision": 1, "faults": [], "chaos": {"preset": "light", "level": 3}}`, http.StatusBadRequest, `chaos: json: unknown field "level"`},
		{"PUT", path, `{"revision": 1, "chaos": {"preset": "light"}}`, http.StatusBadRequest, "faults is required"},
	}
	for _, tt := range tests {
		code, body := call(t, api, tt.method, tt.path, tt.body)
		if msg, _ := body["error"].(string); code != tt.code || !strings.Contains(msg, tt.want) {
			t.Errorf("%s %s %s = %d %v, want %d and %q", tt.method, tt.path, tt.body, code, body, tt.code, tt.want)
		}
	}
	if got := m.Status().Revision; got != 1 {
		t.Errorf("after only refused changes, the revision is %d, want 1", got)
	}
}
