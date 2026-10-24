package control_test

import (
	"encoding/json"
	"net/http"
	"slices"
	"testing"

	"github.com/nebarg/sftpit/internal/runs"
)

func TestChaosChangesThroughTheAPI(t *testing.T) {
	m, api := start(t, runs.Options{Scenario: "chaos"})
	path := "/api/v1/runs/" + m.Status().Run.ID + "/rules"
	code, body := call(t, api, "PUT", path, `{"revision": 1, "faults": [`+denyStats+`], "chaos": {"preset": "moderate", "scope": {"user": "test"}, "extras": ["wrong_size"]}}`)
	chaos := map[string]any{"preset": "moderate", "scope": map[string]any{"user": "test"}, "extras": []any{"wrong_size"}, "paused": false}
	if code != http.StatusOK || body["revision"] != 2.0 || !equalJSON(body["chaos"], chaos) {
		t.Errorf("PUT %s with chaos = %d %v, want revision 2 and the chaos %v", path, code, body, chaos)
	}
	if faults, _ := body["faults"].([]any); len(faults) != 1 {
		t.Errorf("PUT %s with chaos answered faults %v, want only the rule it gave", path, body["faults"])
	}
	counts, _ := body["counts"].(map[string]any)
	ids := make([]string, 0, len(counts))
	for id := range counts {
		ids = append(ids, id)
	}
	if want := []string{"chaos-delay", "chaos-drop", "chaos-fail", "chaos-wrong-size", "deny-stats"}; !slices.Equal(slices.Sorted(slices.Values(ids)), want) {
		t.Errorf("PUT %s with chaos counted %v, want %v", path, ids, want)
	}

	// Pausing sends back what GET returned, with paused set.
	_, got := call(t, api, "GET", path, "")
	got["chaos"].(map[string]any)["paused"] = true
	delete(got, "counts")
	paused, err := json.Marshal(got)
	if err != nil {
		t.Fatal(err)
	}
	code, body = call(t, api, "PUT", path, string(paused))
	chaos["paused"] = true
	if code != http.StatusOK || body["revision"] != 3.0 || !equalJSON(body["chaos"], chaos) || !equalJSON(body["counts"], counts) {
		t.Errorf("PUT %s pausing chaos = %d %v, want revision 3, the chaos %v and the counts kept", path, code, body, chaos)
	}

	// A change without chaos ends it.
	code, body = call(t, api, "PUT", path, `{"revision": 3, "faults": []}`)
	if _, has := body["chaos"]; code != http.StatusOK || has || !equalJSON(body["counts"], map[string]any{}) {
		t.Errorf("PUT %s without chaos = %d %v, want no chaos and no rules", path, code, body)
	}
}

func TestResetStartsAnInlineScenarioOfChaos(t *testing.T) {
	m, api := start(t, runs.Options{Scenario: "chaos"})
	code, body := call(t, api, "POST", "/api/v1/reset", `{"chaos": {"preset": "light"}, "faults": null}`)
	if run, _ := body["run"].(map[string]any); code != http.StatusOK || run["inline"] != true {
		t.Errorf("a reset with chaos = %d %v, want an inline run", code, body)
	}
	_, rules := call(t, api, "GET", "/api/v1/runs/"+m.Status().Run.ID+"/rules", "")
	chaos := map[string]any{"preset": "light", "scope": map[string]any{}, "extras": []any{}, "paused": false}
	if !equalJSON(rules["chaos"], chaos) || !equalJSON(rules["faults"], []any{}) {
		t.Errorf("the inline run's rules are %v, want the chaos %v and no rules", rules, chaos)
	}
}
