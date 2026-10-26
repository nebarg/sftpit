package control_test

import (
	"net/http"
	"strings"
	"testing"

	"github.com/nebarg/sftpit/internal/runs"
)

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
