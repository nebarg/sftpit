package control_test

import (
	"encoding/json"
	"net/http"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/nebarg/sftpit/internal/runs"
)

func TestTraceDownloadsARunsEventsAsJSONLines(t *testing.T) {
	m, api := start(t, runs.Options{})
	first := m.Status().Run.ID
	if code, body := call(t, api, "POST", "/api/v1/reset", ""); code != http.StatusOK {
		t.Fatalf("reset = %d %v", code, body)
	}
	for _, run := range []string{first, m.Status().Run.ID} {
		resp := get(t, api, "/api/v1/runs/"+run+"/trace", nil)
		h := resp.Header
		if resp.StatusCode != http.StatusOK || h.Get("Content-Type") != "application/jsonl" {
			t.Fatalf("trace of %s = %s with %q, want 200 with application/jsonl", run, resp.Status, h.Get("Content-Type"))
		}
		if want := `attachment; filename=events-` + run + `.jsonl`; h.Get("Content-Disposition") != want {
			t.Errorf("trace of %s has the disposition %q, want %q", run, h.Get("Content-Disposition"), want)
		}
		if h.Get("Content-Security-Policy") != "default-src 'none'; sandbox" || h.Get("Cache-Control") != "no-store" {
			t.Errorf("trace of %s has the headers %v", run, h)
		}
		var started struct {
			ID   uint64 `json:"id"`
			Kind string `json:"kind"`
			Run  struct {
				ID string `json:"id"`
			} `json:"run"`
		}
		lines := strings.Split(strings.TrimSuffix(body(t, resp), "\n"), "\n")
		if err := json.Unmarshal([]byte(lines[0]), &started); err != nil {
			t.Fatalf("the first line of %s's trace, %q: %v", run, lines[0], err)
		}
		if started.ID != 1 || started.Kind != "run_started" || started.Run.ID != run {
			t.Errorf("the first line of %s's trace is %+v, want the run's start", run, started)
		}
	}
}

func TestTraceAnswersARangeRequest(t *testing.T) {
	m, api := start(t, runs.Options{})
	resp := get(t, api, "/api/v1/runs/"+m.Status().Run.ID+"/trace", map[string]string{"Range": "bytes=0-5"})
	if got := body(t, resp); resp.StatusCode != http.StatusPartialContent || got != `{"id":` {
		t.Errorf("a range of the trace = %s %q, want 206 with its first bytes", resp.Status, got)
	}
}

func TestTraceOfARunWithoutOneIsNotFound(t *testing.T) {
	m, api := start(t, runs.Options{})
	status := m.Status()
	if err := os.Remove(filepath.Join(status.Run.Dir, "events.jsonl")); err != nil {
		t.Fatal(err)
	}
	for _, run := range []string{status.Run.ID, "20260101-000000.000-0000", "not-a-run"} {
		if code, body := call(t, api, "GET", "/api/v1/runs/"+run+"/trace", ""); code != http.StatusNotFound {
			t.Errorf("trace of %s = %d %v, want 404", run, code, body)
		}
	}
}

func TestStatusSaysATraceIsIncomplete(t *testing.T) {
	_, api := start(t, runs.Options{MaxTraceBytes: 1})
	_, status := call(t, api, "GET", "/api/v1/status", "")
	trace, _ := status["run"].(map[string]any)["trace"].(map[string]any)
	if bytes, _ := trace["bytes"].(float64); trace["complete"] != false || bytes <= 0 || trace["error"] != nil {
		t.Errorf("the trace of a run past its bound is %v, want it incomplete, holding the trace_full line, without an error", trace)
	}
}
