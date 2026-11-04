package control_test

import (
	"bufio"
	"net/http"
	"net/http/httptest"
	"strconv"
	"strings"
	"testing"
	"time"

	"github.com/nebarg/sftpit/internal/runs"
)

func TestEventsPageThroughARunsHistory(t *testing.T) {
	m, api := start(t, runs.Options{Scenario: "chaos"})
	run := m.Status().Run.ID
	path := "/api/v1/runs/" + run + "/events"
	for revision := range 2 {
		if code, body := call(t, api, "PUT", "/api/v1/runs/"+run+"/rules", `{"revision": `+strconv.Itoa(revision+1)+`, "faults": []}`); code != http.StatusOK {
			t.Fatalf("PUT rules = %d %v", code, body)
		}
	}

	tests := []struct {
		query string
		ids   []float64
		next  float64
	}{
		{"", []float64{1, 2, 3}, 3},
		{"?kind=rules_changed&limit=1", []float64{2}, 2},
		{"?kind=run_started,connected", []float64{1}, 3},
		{"?kind=connected&kind=rules_changed&after=2", []float64{3}, 3},
		{"?rule=nothing", nil, 3},
	}
	for _, tt := range tests {
		code, body := call(t, api, "GET", path+tt.query, "")
		var ids []float64
		for _, e := range body["events"].([]any) {
			ids = append(ids, e.(map[string]any)["id"].(float64))
		}
		if code != http.StatusOK || !equalJSON(ids, tt.ids) || body["next"] != tt.next || body["first_id"] != 1.0 {
			t.Errorf("GET %s = %d %v, want events %v and next %v", tt.query, code, body, tt.ids, tt.next)
		}
	}
	_, body := call(t, api, "GET", path+"?limit=1", "")
	if e := body["events"].([]any)[0].(map[string]any); e["kind"] != "run_started" || e["run"].(map[string]any)["id"] != run {
		t.Errorf("first event = %v, want run_started for %s", e, run)
	}

	for query, want := range map[string]string{
		"?limit=0":          `limit "0" is not a number from 1 to 5000`,
		"?limit=5001":       `limit "5001" is not a number from 1 to 5000`,
		"?after=-1":         `after "-1" is not an event ID`,
		"?connection=first": `connection "first" is not a connection ID`,
	} {
		if code, body := call(t, api, "GET", path+query, ""); code != http.StatusBadRequest || !strings.Contains(body["error"].(string), want) {
			t.Errorf("GET %s = %d %v, want 400 with %q", query, code, body, want)
		}
	}
	if code, body := call(t, api, "GET", "/api/v1/runs/20261024-101500.123-3f9a/events", ""); code != http.StatusNotFound {
		t.Errorf("events of an unknown run = %d %v, want 404", code, body)
	}

	// A run's events outlast it.
	if code, _ := call(t, api, "POST", "/api/v1/reset", ""); code != http.StatusOK {
		t.Fatal("reset failed")
	}
	if code, body := call(t, api, "GET", path, ""); code != http.StatusOK || len(body["events"].([]any)) != 3 {
		t.Errorf("events of the run before the reset = %d %v, want its 3", code, body)
	}
}

func TestEventsStreamAsTheyAreRecorded(t *testing.T) {
	m, api := start(t, runs.Options{Scenario: "chaos"})
	srv := httptest.NewServer(api)
	defer srv.Close()
	run := m.Status().Run.ID
	path := "/api/v1/runs/" + run + "/events"
	changeRules := func(revision string) {
		t.Helper()
		if code, body := call(t, api, "PUT", "/api/v1/runs/"+run+"/rules", `{"revision": `+revision+`, "faults": []}`); code != http.StatusOK {
			t.Fatalf("PUT rules = %d %v", code, body)
		}
	}

	s := openStream(t, srv.URL+path, "")
	if got := s.next(t); !strings.HasPrefix(got, "id: 1\ndata: {\"id\":1,") || !strings.Contains(got, `"kind":"run_started"`) {
		t.Errorf("first event = %q, want run_started", got)
	}
	changeRules("1")
	if got := s.next(t); !strings.HasPrefix(got, "id: 2\n") || !strings.Contains(got, `"kind":"rules_changed"`) {
		t.Errorf("second event = %q, want rules_changed", got)
	}
	s.close()

	// A client that reconnects carries on after the last event it had.
	changeRules("2")
	s = openStream(t, srv.URL+path, "2")
	if got := s.next(t); !strings.HasPrefix(got, "id: 3\n") {
		t.Errorf("event after reconnecting = %q, want 3", got)
	}
	if code, _ := call(t, api, "POST", "/api/v1/reset", ""); code != http.StatusOK {
		t.Fatal("reset failed")
	}
	if got := s.next(t); got != "event: end\ndata: {}" {
		t.Errorf("event at the reset = %q, want the end of the run", got)
	}
	if got := s.next(t); got != "" {
		t.Errorf("after the end: %q, want the stream closed", got)
	}
}

// eventStream reads server-sent events.
type eventStream struct {
	resp *http.Response
	in   *bufio.Reader
}

func openStream(t *testing.T, url, lastEventID string) *eventStream {
	t.Helper()
	req, err := http.NewRequestWithContext(t.Context(), http.MethodGet, url, nil)
	if err != nil {
		t.Fatal(err)
	}
	req.Header.Set("Accept", "text/event-stream")
	if lastEventID != "" {
		req.Header.Set("Last-Event-ID", lastEventID)
	}
	resp, err := http.DefaultClient.Do(req)
	if err != nil {
		t.Fatalf("GET %s: %v", url, err)
	}
	if ct := resp.Header.Get("Content-Type"); resp.StatusCode != http.StatusOK || ct != "text/event-stream" {
		t.Fatalf("GET %s = %s with Content-Type %q, want a stream", url, resp.Status, ct)
	}
	s := &eventStream{resp: resp, in: bufio.NewReader(resp.Body)}
	t.Cleanup(s.close)
	return s
}

// next returns the next event, without its blank line, skipping comments,
// or "" once the stream has ended.
func (s *eventStream) next(t *testing.T) string {
	t.Helper()
	read := make(chan string, 1)
	go func() {
		var lines []string
		for {
			line, err := s.in.ReadString('\n')
			if err != nil {
				read <- strings.Join(lines, "\n")
				return
			}
			line = strings.TrimSuffix(line, "\n")
			switch {
			case line == "" && len(lines) > 0:
				read <- strings.Join(lines, "\n")
				return
			case line == "", strings.HasPrefix(line, ":"):
			default:
				lines = append(lines, line)
			}
		}
	}()
	select {
	case event := <-read:
		return event
	case <-time.After(5 * time.Second):
		t.Fatal("no event within 5s")
		return ""
	}
}

func (s *eventStream) close() { s.resp.Body.Close() }
