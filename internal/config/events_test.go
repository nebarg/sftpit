package config

import (
	"path/filepath"
	"reflect"
	"strings"
	"testing"
	"time"

	"github.com/nebarg/sftpit/internal/faults"
	"github.com/nebarg/sftpit/internal/sftpproxy"
)

func TestLoadReadsRulesForConnectionEvents(t *testing.T) {
	dir := t.TempDir()
	writeAuthorizedKeys(t, filepath.Join(dir, "partner-b.pub"), "")
	config := writeTestFile(t, filepath.Join(dir, "sftpit.yaml"), withScenarios+`  logins:
    faults:
      - id: slow-connect
        match: {operation: connect}
        action: {type: delay, duration: {min: 1s, max: 3s}}
      - id: first-login
        max_triggers: 1
        match: {operation: authenticate, user: test, occurrence: [1]}
        action: {type: close_connection, mode: rst}
      - id: outage
        match: {operation: [connect, authenticate]}
        trigger: {window: {from: 10s, until: 15s}, anchor: run}
        action: {type: freeze_connection, max_freeze: 5s}
`, 0o600)
	cfg, err := Load(Options{ConfigFile: config, LookupEnv: fakeEnv{"P": "password"}.lookup})
	if err != nil {
		t.Fatalf("Load: %v", err)
	}
	want := []faults.Rule{
		{
			ID:       "slow-connect",
			Match:    faults.Match{Operations: []faults.Operation{faults.Connect}},
			Duration: &faults.Range[time.Duration]{Min: time.Second, Max: 3 * time.Second},
			Action:   sftpproxy.Delay{},
		},
		{
			ID:          "first-login",
			MaxTriggers: 1,
			Match:       faults.Match{User: "test", Operations: []faults.Operation{faults.Authenticate}, Occurrence: []uint64{1}},
			Action:      sftpproxy.Drop{Reset: true},
		},
		{
			ID:      "outage",
			Match:   faults.Match{Operations: []faults.Operation{faults.Connect, faults.Authenticate}},
			Trigger: &faults.Trigger{Anchor: faults.Run, Window: &faults.Window{From: 10 * time.Second, Until: 15 * time.Second}},
			Action:  sftpproxy.Freeze{Limit: 5 * time.Second},
		},
	}
	if got := cfg.Scenarios["logins"].Rules; !reflect.DeepEqual(got, want) {
		t.Errorf("rules =\n%+v\nwant\n%+v", got, want)
	}
}

func TestLoadRejectsInvalidRulesForConnectionEvents(t *testing.T) {
	dir := t.TempDir()
	writeAuthorizedKeys(t, filepath.Join(dir, "partner-b.pub"), "")
	tests := []struct {
		name, rule, want string
	}{
		{"a when", "match: {operation: authenticate}\n        action: {type: delay, when: before, duration: 1s}", "scenarios.s.faults[0] (r): action: when does not apply to a delay at connect or authenticate, which have no request to act before or after"},
		{"a failure", "match: {operation: authenticate}\n        action: {type: fail, status: permission_denied}", "action: connect and authenticate take a delay, close_connection or freeze_connection, not a fail"},
		{"an end of session", "match: {operation: [connect]}\n        action: {type: close_subsystem}", "not a close_subsystem"},
		{"file operations", "match: {operation: [authenticate, stat]}\n        action: {type: close_connection}", "connect and authenticate cannot share a rule with file operations"},
		{"a path", "match: {operation: authenticate, path_prefix: /incoming}\n        action: {type: close_connection}", "connect and authenticate have no path"},
		{"a user at connect", "match: {operation: connect, user: test}\n        action: {type: close_connection}", "connect comes before the client logs in, so it has no user or key"},
		{"a connection's window", "match: {operation: authenticate}\n        trigger: {window: {from: 0s, until: 1s}, anchor: connection}\n        action: {type: close_connection}", "connect and authenticate are timed from the run, not the connection"},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			config := writeTestFile(t, filepath.Join(dir, "sftpit.yaml"), withScenarios+"  s:\n    faults:\n      - id: r\n        "+tt.rule+"\n", 0o600)
			_, err := Load(Options{ConfigFile: config, LookupEnv: fakeEnv{"P": "password"}.lookup})
			if err == nil || !strings.Contains(err.Error(), tt.want) {
				t.Errorf("error = %v, want %q", err, tt.want)
			}
		})
	}
}
