package control_test

import (
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/nebarg/sftpit/internal/control"
	"github.com/nebarg/sftpit/internal/faults"
	"github.com/nebarg/sftpit/internal/runs"
)

func TestHealthReadinessAndStatus(t *testing.T) {
	m, api := start(t, runs.Options{Scenario: "chaos", Seed: new(faults.Seed(18446744073709551615))})

	if code, body := call(t, api, "GET", "/api/v1/health", ""); code != http.StatusOK || body["status"] != "ok" {
		t.Errorf("health = %d %v", code, body)
	}
	if code, body := call(t, api, "GET", "/api/v1/ready", ""); code != http.StatusOK || body["ready"] != true {
		t.Errorf("ready = %d %v", code, body)
	}
	code, body := call(t, api, "GET", "/api/v1/status", "")
	want := map[string]any{
		"sftp":    map[string]any{"state": "up"},
		"backend": "embedded",
		"run":     map[string]any{"id": m.Status().Run.ID, "scenario": "chaos", "seed": "18446744073709551615", "seed_pinned": true, "revision": 1},
	}
	if code != http.StatusOK || !equalJSON(body, want) {
		t.Errorf("status = %d %v, want %v", code, body, want)
	}

	m.Server().Down(time.Minute, false)
	_, body = call(t, api, "GET", "/api/v1/status", "")
	sftp := body["sftp"].(map[string]any)
	until, err := time.Parse(time.RFC3339Nano, sftp["down_until"].(string))
	if sftp["state"] != "down" || err != nil || time.Until(until) < 50*time.Second {
		t.Errorf("status during an outage reports %v", sftp)
	}
}

func TestResetStartsTheNextRun(t *testing.T) {
	m, api := start(t, runs.Options{Scenario: "chaos", Seed: new(faults.Seed(7))})
	tests := []struct {
		body string
		want map[string]any
		// fresh is set if the next run draws a fresh seed, which want
		// leaves out.
		fresh bool
	}{
		{"", map[string]any{"scenario": "chaos", "seed": "7", "seed_pinned": true, "revision": 1}, false},
		{`{"seed": "8"}`, map[string]any{"scenario": "chaos", "seed": "8", "seed_pinned": true, "revision": 1}, false},
		{`{"seed": 18446744073709551615}`, map[string]any{"scenario": "chaos", "seed": "18446744073709551615", "seed_pinned": true, "revision": 1}, false},
		{`{"scenario": "own", "seed": null}`, map[string]any{"scenario": "own", "seed": "9", "seed_pinned": true, "revision": 1}, false},
		{`{"scenario": ""}`, map[string]any{"revision": 1}, true},
	}
	for _, tt := range tests {
		before := m.Status().Run.ID
		code, body := call(t, api, "POST", "/api/v1/reset", tt.body)
		if code != http.StatusOK {
			t.Fatalf("reset with %q = %d %v", tt.body, code, body)
		}
		run := body["run"].(map[string]any)
		id := run["id"]
		delete(run, "id")
		if seed, _ := run["seed"].(string); tt.fresh && seed != "" && strings.Trim(seed, "0123456789") == "" {
			delete(run, "seed")
		}
		if id == before || id != m.Status().Run.ID || !equalJSON(run, tt.want) {
			t.Errorf("reset with %q started run %v %v after %s, want a new run with %v", tt.body, id, run, before, tt.want)
		}
	}

	code, body := call(t, api, "POST", "/api/v1/reset", `{"run": "`+m.Status().Run.ID+`"}`)
	if code != http.StatusOK {
		t.Errorf("reset of the current run = %d %v", code, body)
	}
}

func TestResetRefusesABadRequest(t *testing.T) {
	m, api := start(t, runs.Options{Scenario: "chaos"})
	tests := []struct {
		body string
		code int
		want string
	}{
		{`{"scenario": "flaky"}`, http.StatusBadRequest, `unknown scenario "flaky"; the configuration defines chaos, own`},
		{`{"scenario": "", "seed": 7}`, http.StatusBadRequest, "a seed needs a scenario"},
		{`{"run": "20260101-000000.000-0000"}`, http.StatusConflict, "the current run is "},
		{`{"seed": -1}`, http.StatusBadRequest, "a seed is a whole number from 0 to 18446744073709551615"},
		{`{"seed": "1.5"}`, http.StatusBadRequest, "a seed is a whole number"},
		{`{"scenarios": "chaos"}`, http.StatusBadRequest, `unknown field "scenarios"`},
		{`{"scenario": "chaos", "faults": []}`, http.StatusBadRequest, "a reset names a scenario or gives one inline, not both"},
		{`{"faults": [{"id": "r"}]}`, http.StatusBadRequest, "faults[0] (r): match: operation is required"},
		{`{"faults": [` + strings.Replace(denyStats, `"test"`, `"nobody"`, 1) + `]}`, http.StatusBadRequest, `user "nobody" is not a configured user`},
		{`{"scenario": "chaos", "chaos": {"preset": "light"}}`, http.StatusBadRequest, "a reset names a scenario or gives one inline, not both"},
		{`{"chaos": {"preset": "wild"}}`, http.StatusBadRequest, `chaos: faults: chaos preset "wild" is not light, moderate or heavy`},
		{`{"faults": [], "chaos": {"preset": "light", "scope": {"user": "nobody"}}}`, http.StatusBadRequest, `chaos: scope: user "nobody" is not a configured user`},
		{`{"faults": [{"id": "r"}], "chaos": {"preset": "light"}}`, http.StatusBadRequest, "faults[0] (r): match: operation is required"},
		{`{} {}`, http.StatusBadRequest, "a single JSON object"},
		{`{}}`, http.StatusBadRequest, "a single JSON object"},
		{`{} ]`, http.StatusBadRequest, "a single JSON object"},
		{`{"run": "` + strings.Repeat("x", 70<<10) + `"}`, http.StatusRequestEntityTooLarge, "request body too large"},
		{`{}` + strings.Repeat(" ", 70<<10), http.StatusRequestEntityTooLarge, "request body too large"},
		{`[]`, http.StatusBadRequest, "invalid request body"},
	}
	for _, tt := range tests {
		before := m.Status()
		code, body := call(t, api, "POST", "/api/v1/reset", tt.body)
		if msg, _ := body["error"].(string); code != tt.code || !strings.Contains(msg, tt.want) {
			t.Errorf("reset with %s = %d %v, want %d saying %q", tt.body, code, body, tt.code, tt.want)
		}
		if after := m.Status(); after != before {
			t.Errorf("the refused reset with %s changed the status from %+v to %+v", tt.body, before, after)
		}
	}
}

func TestAFailedResetMakesTheRunsUnavailable(t *testing.T) {
	seed := t.TempDir()
	if err := os.WriteFile(filepath.Join(seed, "orders.csv"), []byte("data"), 0o644); err != nil {
		t.Fatal(err)
	}
	m, api := start(t, runs.Options{SeedDir: seed})
	snapshot := filepath.Join(filepath.Dir(m.Status().Run.Dir), "..", "fixtures", "seed", "orders.csv")
	info, err := os.Stat(snapshot)
	if err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(snapshot, []byte("DATA"), 0o644); err != nil {
		t.Fatal(err)
	}

	if code, body := call(t, api, "POST", "/api/v1/reset", ""); code != http.StatusInternalServerError || !strings.Contains(body["error"].(string), "orders.csv has changed") {
		t.Errorf("reset with a changed snapshot = %d %v", code, body)
	}
	if code, body := call(t, api, "GET", "/api/v1/ready", ""); code != http.StatusServiceUnavailable || body["ready"] != false || !strings.Contains(body["error"].(string), "orders.csv has changed") {
		t.Errorf("ready after a failed reset = %d %v", code, body)
	}
	_, body := call(t, api, "GET", "/api/v1/status", "")
	if sftp := body["sftp"].(map[string]any); sftp["state"] != "unavailable" || !strings.Contains(sftp["error"].(string), "orders.csv has changed") {
		t.Errorf("status after a failed reset = %v", body)
	}

	if err := os.WriteFile(snapshot, []byte("data"), 0o644); err != nil {
		t.Fatal(err)
	}
	if err := os.Chtimes(snapshot, info.ModTime(), info.ModTime()); err != nil {
		t.Fatal(err)
	}
	if code, body := call(t, api, "POST", "/api/v1/reset", ""); code != http.StatusOK {
		t.Errorf("reset once the snapshot is restored = %d %v", code, body)
	}
	if code, _ := call(t, api, "GET", "/api/v1/ready", ""); code != http.StatusOK {
		t.Errorf("ready after a reset that succeeded = %d", code)
	}
}

func TestTheAPIRefusesRequestsFromElsewhere(t *testing.T) {
	m, api := start(t, runs.Options{})
	tests := []struct {
		name    string
		method  string
		host    string
		headers map[string]string
		code    int
	}{
		{name: "a loopback address", method: "GET", host: "127.0.0.1:8122", code: http.StatusOK},
		{name: "another loopback address", method: "GET", host: "127.1.2.3", code: http.StatusOK},
		{name: "localhost", method: "GET", host: "LocalHost:8122", code: http.StatusOK},
		{name: "IPv6 loopback", method: "GET", host: "[::1]:8122", code: http.StatusOK},
		{name: "IPv6 loopback without a port", method: "GET", host: "[::1]", code: http.StatusOK},
		{name: "a rebound name", method: "GET", host: "attacker.example:8122", code: http.StatusForbidden},
		{name: "a subdomain of localhost", method: "GET", host: "localhost.attacker.example", code: http.StatusForbidden},
		{name: "no host", method: "GET", host: "", code: http.StatusForbidden},
		{name: "a change without the header", method: "POST", host: host, code: http.StatusForbidden},
		{name: "a change from another site", method: "POST", host: host, headers: map[string]string{control.RequestHeader: "1", "Sec-Fetch-Site": "cross-site", "Origin": "https://attacker.example"}, code: http.StatusForbidden},
		{name: "a change from another origin", method: "POST", host: host, headers: map[string]string{control.RequestHeader: "1", "Origin": "http://localhost:3000"}, code: http.StatusForbidden},
		{name: "a change from the same origin", method: "POST", host: host, headers: map[string]string{control.RequestHeader: "1", "Sec-Fetch-Site": "same-origin", "Origin": "http://" + host}, code: http.StatusOK},
		{name: "a change from the command line", method: "POST", host: host, headers: map[string]string{control.RequestHeader: "1"}, code: http.StatusOK},
		{name: "a preflight", method: "OPTIONS", host: host, headers: map[string]string{"Origin": "https://attacker.example", "Access-Control-Request-Method": "POST", "Access-Control-Request-Headers": control.RequestHeader}, code: http.StatusMethodNotAllowed},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			before := m.Status().Run.ID
			path := "/api/v1/status"
			if tt.method != "GET" {
				path = "/api/v1/reset"
			}
			req := httptest.NewRequest(tt.method, path, nil)
			req.Host = tt.host
			for k, v := range tt.headers {
				req.Header.Set(k, v)
			}
			rec := httptest.NewRecorder()
			api.ServeHTTP(rec, req)
			if rec.Code != tt.code {
				t.Errorf("%s %s from %q = %d %s, want %d", tt.method, path, tt.host, rec.Code, rec.Body, tt.code)
			}
			if got := rec.Header().Get("Access-Control-Allow-Origin"); got != "" {
				t.Errorf("the response allows the origin %q", got)
			}
			if reset := m.Status().Run.ID != before; reset != (tt.method == "POST" && tt.code == http.StatusOK) {
				t.Errorf("the request reset the run: %v", reset)
			}
		})
	}
}

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
