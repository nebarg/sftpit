package control_test

import (
	"encoding/json"
	"errors"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"

	"github.com/nebarg/sftpit/internal/control"
	"github.com/nebarg/sftpit/internal/runs"
)

const absentAssertion = `{"assertions": [{"type": "path_absent", "path": "/f"}]}`

func TestAssertAnswersWithTheVerdictAndKeepsTheReport(t *testing.T) {
	m, api := start(t, runs.Options{Scenario: "chaos"})
	if code, body := call(t, api, "POST", "/api/v1/reset", absentAssertion); code != http.StatusOK {
		t.Fatalf("reset = %d %v", code, body)
	}
	run := "/api/v1/runs/" + m.Status().Run.ID
	if code, body := call(t, api, "GET", run+"/report", ""); code != http.StatusNotFound {
		t.Errorf("the report before an assert = %d %v, want 404", code, body)
	}

	code, report := call(t, api, "POST", run+"/assert", `{"timeout": "1s"}`)
	if code != http.StatusOK || report["passed"] != true {
		t.Fatalf("assert = %d %v, want it passed", code, report)
	}
	assertions, _ := report["assertions"].([]any)
	want := map[string]any{"assertion": map[string]any{"type": "path_absent", "path": "/f"}, "description": "path_absent /f", "passed": true, "detail": "nothing is there"}
	if len(assertions) != 1 || !equalJSON(assertions[0], want) {
		t.Errorf("the assertions are %v, want %v", assertions, want)
	}
	if _, status := call(t, api, "GET", "/api/v1/status", ""); status["sftp"].(map[string]any)["state"] != "drained" {
		t.Errorf("the status after an assert is %v, want it drained", status["sftp"])
	}
	if code, body := call(t, api, "PUT", run+"/rules", `{"revision": 1, "faults": []}`); code != http.StatusConflict || !strings.Contains(body["error"].(string), "drained") {
		t.Errorf("a change of the rules of a drained run = %d %v, want 409", code, body)
	}

	resp := get(t, api, run+"/report", nil)
	h := resp.Header
	if resp.StatusCode != http.StatusOK || h.Get("Content-Type") != "application/json" || !strings.Contains(h.Get("Content-Disposition"), "report-"+m.Status().Run.ID+".json") || h.Get("Cache-Control") != "no-store" {
		t.Errorf("the report = %s with %v", resp.Status, h)
	}
	var saved map[string]any
	if err := json.Unmarshal([]byte(body(t, resp)), &saved); err != nil {
		t.Fatalf("the report: %v", err)
	}
	if !equalJSON(saved, report) {
		t.Errorf("the saved report is %v, want %v", saved, report)
	}

	if code, status := call(t, api, "POST", "/api/v1/reset", ""); code != http.StatusOK || status["sftp"].(map[string]any)["state"] != "up" {
		t.Errorf("a reset of a drained run = %d %v, want the next run up", code, status)
	}
	if code, _ := call(t, api, "GET", run+"/report", ""); code != http.StatusOK {
		t.Errorf("the ended run's report = %d, want 200", code)
	}
}

func TestAFailedRunIsNotAFailedRequest(t *testing.T) {
	m, api := start(t, runs.Options{Scenario: "chaos"})
	code, report := call(t, api, "POST", "/api/v1/runs/"+m.Status().Run.ID+"/assert", "")
	problems, _ := report["problems"].([]any)
	if code != http.StatusOK || report["passed"] != false || len(problems) != 1 {
		t.Errorf("assert of a run with no assertions = %d %v, want 200 with a failure", code, report)
	}
}

func TestDrainAnswersWithWhatIsUnfinished(t *testing.T) {
	m, api := start(t, runs.Options{Scenario: "chaos"})
	code, body := call(t, api, "POST", "/api/v1/runs/"+m.Status().Run.ID+"/drain", "")
	if code != http.StatusOK || !equalJSON(body, map[string]any{"unfinished": []any{}}) {
		t.Errorf("drain = %d %v, want nothing unfinished", code, body)
	}
}

func TestDrainAndAssertRefuse(t *testing.T) {
	m, api := start(t, runs.Options{Scenario: "chaos"})
	run := "/api/v1/runs/" + m.Status().Run.ID
	for _, route := range []string{"/drain", "/assert"} {
		for _, tt := range []struct {
			name, path, body string
			code             int
			want             string
		}{
			{"a bad timeout", run + route, `{"timeout": "soon"}`, http.StatusBadRequest, `timeout "soon"`},
			{"a timeout without a unit", run + route, `{"timeout": "10"}`, http.StatusBadRequest, `timeout "10"`},
			{"a negative timeout", run + route, `{"timeout": "-1s"}`, http.StatusBadRequest, `timeout "-1s"`},
			{"a timeout too long", run + route, `{"timeout": "1h"}`, http.StatusBadRequest, "up to 10m0s"},
			{"an unknown field", run + route, `{"wait": "1s"}`, http.StatusBadRequest, "unknown field"},
			{"another run", "/api/v1/runs/20260101-000000.000-0000" + route, "", http.StatusConflict, "the current run is"},
		} {
			if code, body := call(t, api, "POST", tt.path, tt.body); code != tt.code || !strings.Contains(body["error"].(string), tt.want) {
				t.Errorf("%s of %s = %d %v, want %d saying %q", route, tt.name, code, body, tt.code, tt.want)
			}
		}
	}
	if s := m.Status(); s.State != runs.StateUp {
		t.Errorf("the refused requests left the state %s", s.State)
	}
	for _, route := range []string{"/drain", "/assert"} {
		req := httptest.NewRequest(http.MethodPost, run+route, nil)
		req.Host = host
		rec := httptest.NewRecorder()
		api.ServeHTTP(rec, req)
		if rec.Code != http.StatusForbidden {
			t.Errorf("%s without the control header = %d, want 403", route, rec.Code)
		}
	}
	if code, body := call(t, api, "GET", "/api/v1/runs/not-a-run/report", ""); code != http.StatusNotFound {
		t.Errorf("the report of no run = %d %v, want 404", code, body)
	}
}

func TestClientAsserts(t *testing.T) {
	m, api := start(t, runs.Options{Scenario: "chaos"})
	srv := httptest.NewServer(api)
	defer srv.Close()
	c := &control.Client{Addr: srv.Listener.Addr().String()}
	status, err := c.Status(t.Context())
	if err != nil || status.Run.ID != m.Status().Run.ID {
		t.Fatalf("Status = %+v, %v", status, err)
	}
	report, err := c.Assert(t.Context(), status.Run.ID, time.Second)
	if err != nil || report.Passed || report.Run.ID != status.Run.ID || report.Problems == nil {
		t.Errorf("Assert = %+v, %v; want a verdict of failure", report, err)
	}
	if _, err := c.Assert(t.Context(), "20260101-000000.000-0000", time.Second); err == nil {
		t.Error("Assert of another run succeeded")
	} else if refused, ok := errors.AsType[*control.Error](err); !ok || refused.StatusCode != http.StatusConflict {
		t.Errorf("Assert of another run = %v, want a 409", err)
	}
}
