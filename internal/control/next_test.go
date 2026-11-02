package control_test

import (
	"net/http"
	"strings"
	"testing"

	"github.com/nebarg/sftpit/internal/runs"
)

func TestTheNextRunIsQueuedShownAndCleared(t *testing.T) {
	m, api := start(t, runs.Options{Scenario: "chaos"})
	if code, body := call(t, api, "GET", "/api/v1/next", ""); code != http.StatusNotFound || !strings.Contains(body["error"].(string), "nothing is queued") {
		t.Errorf("GET next with nothing queued = %d %v, want 404", code, body)
	}
	code, queued := call(t, api, "PUT", "/api/v1/next", `{"faults": [`+denyStats+`], "chaos": {"preset": "light"}}`)
	if code != http.StatusOK || queued["faults"].([]any)[0].(map[string]any)["id"] != "deny-stats" || queued["chaos"].(map[string]any)["preset"] != "light" {
		t.Fatalf("PUT next = %d %v", code, queued)
	}
	if _, got := call(t, api, "GET", "/api/v1/next", ""); !equalJSON(got, queued) {
		t.Errorf("GET next = %v, want %v", got, queued)
	}
	if _, status := call(t, api, "GET", "/api/v1/status", ""); status["queued"] != true {
		t.Errorf("status = %v, want queued", status)
	}

	code, status := call(t, api, "POST", "/api/v1/reset", "")
	if run, _ := status["run"].(map[string]any); code != http.StatusOK || run["inline"] != true || status["queued"] != false {
		t.Errorf("a bare reset = %d %v, want the queued rules inline and nothing queued", code, status)
	}
	if _, rules := call(t, api, "GET", "/api/v1/runs/"+m.Status().Run.ID+"/rules", ""); !equalJSON(rules["faults"], queued["faults"]) {
		t.Errorf("the next run's rules are %v, want %v", rules["faults"], queued["faults"])
	}

	call(t, api, "PUT", "/api/v1/next", `{"faults": []}`)
	if code, status := call(t, api, "DELETE", "/api/v1/next", ""); code != http.StatusOK || status["queued"] != false {
		t.Errorf("DELETE next = %d %v, want nothing queued", code, status)
	}
}

func TestCheckRulesValidatesWithoutApplying(t *testing.T) {
	m, api := start(t, runs.Options{Scenario: "chaos"})
	code, body := call(t, api, "POST", "/api/v1/rules/check", `{"faults": [{"id": "cut", "fail_upload": {"path": "/a.csv", "attempts": [1], "after_bytes": 5}}], "chaos": {"preset": "light", "scope": {"user": "test"}}}`)
	if code != http.StatusOK {
		t.Fatalf("check = %d %v", code, body)
	}
	cut := body["faults"].([]any)[0].(map[string]any)
	if action := cut["action"].(map[string]any); action["type"] != "partial_upload" || cut["fail_upload"] != nil {
		t.Errorf("the checked recipe is %v, want it in the long form", cut)
	}
	var compiled []string
	for _, r := range body["compiled_chaos"].([]any) {
		compiled = append(compiled, r.(map[string]any)["id"].(string))
	}
	if strings.Join(compiled, " ") != "chaos-delay chaos-fail" {
		t.Errorf("light chaos compiles to %v, want chaos-delay and chaos-fail", compiled)
	}
	if s := m.Status(); s.Revision != 1 || s.Queued {
		t.Errorf("a check changed the run: revision %d, queued %v", s.Revision, s.Queued)
	}

	for _, bad := range []string{`{}`, `{"faults": [{"id": "r"}]}`, `{"faults": [], "chaos": {"preset": "wild"}}`, `{"faults": [{"id": "r", "match": {"user": "nobody", "operation": "stat"}, "action": {"type": "hide"}}]}`} {
		if code, body := call(t, api, "POST", "/api/v1/rules/check", bad); code != http.StatusBadRequest {
			t.Errorf("check %s = %d %v, want 400", bad, code, body)
		}
	}
	twice := `{"faults": [` + denyStats + `, ` + denyStats + `]}`
	if code, body := call(t, api, "POST", "/api/v1/rules/check", twice); code != http.StatusBadRequest || !strings.Contains(body["error"].(string), "used twice") {
		t.Errorf("check of a rule ID twice = %d %v, want 400", code, body)
	}
	if code, _ := call(t, api, "PUT", "/api/v1/next", twice); code != http.StatusBadRequest || m.Status().Queued {
		t.Errorf("PUT next with a rule ID twice = %d, want 400 and nothing queued", code)
	}
}
