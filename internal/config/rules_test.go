package config

import (
	"reflect"
	"strings"
	"testing"
	"time"

	"github.com/nebarg/sftpit/internal/faults"
	"github.com/nebarg/sftpit/internal/sftpproxy"
	"github.com/nebarg/sftpit/internal/sftpwire"
)

func TestParseRulesReadsTheLongFormAndRecipes(t *testing.T) {
	got, err := ParseRules([]byte(`[
		{"id": "slow", "match": {"operation": "stat", "user": "test"}, "action": {"type": "delay", "when": "after", "duration": {"min": "1s", "max": "2s"}}},
		{"id": "denied", "priority": 1, "match": {"operation": ["mkdir", "rmdir"]}, "action": {"type": "fail", "when": "before", "status": "permission_denied"}},
		{"id": "cut", "fail_upload": {"path": "/in/a.csv", "attempts": [1], "after_bytes": 10}}
	]`), testUsers)
	if err != nil {
		t.Fatalf("ParseRules: %v", err)
	}
	failure := sftpproxy.Fail{When: sftpproxy.Before, Status: sftpwire.StatusFailure}
	want := []faults.Rule{
		{ID: "slow", Match: faults.Match{User: "test", Operations: []faults.Operation{faults.Stat}}, Duration: &faults.Range[time.Duration]{Min: time.Second, Max: 2 * time.Second}, Action: sftpproxy.Delay{When: sftpproxy.After}},
		{ID: "denied", Priority: 1, Match: faults.Match{Operations: []faults.Operation{faults.Mkdir, faults.Rmdir}}, Action: sftpproxy.Fail{When: sftpproxy.Before, Status: sftpwire.StatusPermissionDenied}},
		{ID: "cut", Match: faults.Match{Operations: []faults.Operation{faults.Write}, Path: faults.Location{Kind: faults.Exactly, Pattern: "/in/a.csv"}, Attempt: &faults.Attempt{PerUser: true, PerPath: true, Numbers: []uint64{1}}}, Action: sftpproxy.PartialUpload{Cutoff: 10, Result: failure}},
	}
	if !reflect.DeepEqual(got, want) {
		t.Errorf("ParseRules =\n%+v\nwant\n%+v", got, want)
	}
}

func TestParseRulesRejectsWhatLoadRejects(t *testing.T) {
	const deny = `"action": {"type": "fail", "when": "before", "status": "permission_denied"}`
	tests := []struct {
		name, rules, want string
	}{
		{"not a list", `{"id": "r"}`, "faults: json: cannot unmarshal object"},
		{"an unknown field", `[{"id": "r", "match": {"operation": "stat"}, "action": {"type": "delay", "duraton": "1s"}}]`, `faults[0]: json: unknown field "duraton"`},
		{"an unknown bound", `[{"id": "r", "match": {"operation": "stat"}, "action": {"type": "delay", "when": "before", "duration": {"min": "1s", "mx": "2s", "avg": "1s"}}}]`, "faults[0]: a range has min and max, not avg"},
		{"a bound missing", `[{"id": "r", "match": {"operation": "stat"}, "action": {"type": "delay", "when": "before", "duration": {"min": "1s"}}}]`, "faults[0]: a range needs both min and max"},
		{"a bound of the wrong type", `[{"id": "r", "match": {"operation": "write"}, "action": {"type": "partial_upload", "cutoff_offset": {"min": 1, "max": "2"}, "result": "status", "status": "failure"}}]`, "faults[0]: json: cannot unmarshal string"},
		{"a value of the wrong type", `[{"id": "r", "match": {"operation": "stat"}, "action": {"type": "delay", "when": "before", "duration": 2}}]`, "faults[0]: json: cannot unmarshal number"},
		{"an operation that is not a name", `[{"id": "r", "match": {"operation": 7}, ` + deny + `}]`, "faults[0]: expected a string or a list of strings"},
		{"no operation", `[{"id": "r", "match": {"operation": null}, ` + deny + `}]`, "faults[0] (r): match: operation is required"},
		{"a bad rule ID", `[{"id": "Bad", "match": {"operation": "stat"}, ` + deny + `}]`, `faults[0]: id "Bad" must hold only`},
		{"no rule ID", `[{"match": {"operation": "stat"}, ` + deny + `}]`, "faults[0]: id is required"},
		{"an unknown user", `[{"id": "r", "match": {"operation": "stat", "user": "nobody"}, ` + deny + `}]`, `faults[0] (r): match: user "nobody" is not a configured user`},
		{"a bad recipe", `[{"id": "ok", "match": {"operation": "stat"}, ` + deny + `}, {"id": "r", "fail_upload": {"path": "/a"}}]`, "faults[1] (r): fail_upload: after_bytes is required"},
		{"a repeated rule ID", `[{"id": "r", "match": {"operation": "stat"}, ` + deny + `}, {"id": "r", "match": {"operation": "stat"}, ` + deny + `}]`, `faults: rule ID "r" is used twice`},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			rules, err := ParseRules([]byte(tt.rules), testUsers)
			if err == nil || !strings.HasPrefix(err.Error(), tt.want) {
				t.Errorf("ParseRules = %+v, %v; want an error starting %q", rules, err, tt.want)
			}
		})
	}
}
