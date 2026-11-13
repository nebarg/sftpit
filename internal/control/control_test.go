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
	"github.com/nebarg/sftpit/internal/runs"
)

func TestStatus(t *testing.T) {
	m, api := start(t, runs.Options{})
	code, body := call(t, api, "GET", "/api/status", "")
	want := map[string]any{
		"sftp": map[string]any{"state": "up"},
		"run":  map[string]any{"id": m.Status().Run.ID, "stalled": 0, "frozen": 0},
	}
	if code != http.StatusOK || !equalJSON(body, want) {
		t.Errorf("status = %d %v, want %v", code, body, want)
	}

	m.Server().Down(time.Minute, false)
	_, body = call(t, api, "GET", "/api/status", "")
	sftp := body["sftp"].(map[string]any)
	until, err := time.Parse(time.RFC3339Nano, sftp["down_until"].(string))
	if sftp["state"] != "down" || err != nil || time.Until(until) < 50*time.Second {
		t.Errorf("status during an outage reports %v", sftp)
	}
}

func TestTheAPIRefusesABadBody(t *testing.T) {
	m, api := start(t, runs.Options{})
	tests := []struct {
		body string
		code int
		want string
	}{
		{`{} {}`, http.StatusBadRequest, "a single JSON object"},
		{`{}}`, http.StatusBadRequest, "a single JSON object"},
		{`{} ]`, http.StatusBadRequest, "a single JSON object"},
		{`{"name": "` + strings.Repeat("x", 70<<10) + `"}`, http.StatusRequestEntityTooLarge, "request body too large"},
		{`{}` + strings.Repeat(" ", 70<<10), http.StatusRequestEntityTooLarge, "request body too large"},
		{`[]`, http.StatusBadRequest, "invalid request body"},
	}
	for _, tt := range tests {
		code, body := call(t, api, "POST", "/api/faults", tt.body)
		if msg, _ := body["error"].(string); code != tt.code || !strings.Contains(msg, tt.want) {
			t.Errorf("POST /api/faults with %.40s = %d %v, want %d saying %q", tt.body, code, body, tt.code, tt.want)
		}
	}
	if len(m.Faults()) != 0 {
		t.Errorf("refused requests added faults: %+v", m.Faults())
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

	if code, body := send(t, api, "POST", "/api/reset", ""); code != http.StatusInternalServerError || !strings.Contains(body, "orders.csv has changed") {
		t.Errorf("reset with a changed copy of the seed = %d %s", code, body)
	}
	_, body := call(t, api, "GET", "/api/status", "")
	if sftp := body["sftp"].(map[string]any); sftp["state"] != "unavailable" || !strings.Contains(sftp["error"].(string), "orders.csv has changed") {
		t.Errorf("status after a failed reset = %v", body)
	}

	if err := os.WriteFile(snapshot, []byte("data"), 0o644); err != nil {
		t.Fatal(err)
	}
	if err := os.Chtimes(snapshot, info.ModTime(), info.ModTime()); err != nil {
		t.Fatal(err)
	}
	if code, body := send(t, api, "POST", "/api/reset", ""); code != http.StatusNoContent {
		t.Errorf("reset once the copy is restored = %d %s", code, body)
	}
	if _, body := call(t, api, "GET", "/api/status", ""); body["sftp"].(map[string]any)["state"] != "up" {
		t.Errorf("status after a reset that succeeded = %v", body)
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
		{name: "a change from the same origin", method: "POST", host: host, headers: map[string]string{control.RequestHeader: "1", "Sec-Fetch-Site": "same-origin", "Origin": "http://" + host}, code: http.StatusNoContent},
		{name: "a change from the command line", method: "POST", host: host, headers: map[string]string{control.RequestHeader: "1"}, code: http.StatusNoContent},
		{name: "a preflight", method: "OPTIONS", host: host, headers: map[string]string{"Origin": "https://attacker.example", "Access-Control-Request-Method": "POST", "Access-Control-Request-Headers": control.RequestHeader}, code: http.StatusMethodNotAllowed},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			before := m.Status().Run.ID
			path := "/api/status"
			if tt.method != "GET" {
				path = "/api/reset"
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
			if reset := m.Status().Run.ID != before; reset != (tt.method == "POST" && tt.code == http.StatusNoContent) {
				t.Errorf("the request reset the run: %v", reset)
			}
		})
	}
}

func TestTheAPIAnswersTheHostsItIsGiven(t *testing.T) {
	m, _ := start(t, runs.Options{})
	api := control.Handler(m, control.Options{Hosts: []string{"sftpit", "fd00::1"}})
	for host, want := range map[string]int{
		"sftpit:8122":             http.StatusOK,
		"SFTPIT":                  http.StatusOK,
		"[fd00::1]:8122":          http.StatusOK,
		"127.0.0.1:8122":          http.StatusOK,
		"sftpit.attacker.example": http.StatusForbidden,
		"other:8122":              http.StatusForbidden,
		"":                        http.StatusForbidden,
	} {
		req := httptest.NewRequest(http.MethodGet, "/api/status", nil)
		req.Host = host
		rec := httptest.NewRecorder()
		api.ServeHTTP(rec, req)
		if rec.Code != want {
			t.Errorf("GET /api/status from %q = %d %s, want %d", host, rec.Code, rec.Body, want)
		}
	}
}
