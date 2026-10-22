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

func TestLoadReadsListenerDown(t *testing.T) {
	dir := t.TempDir()
	writeAuthorizedKeys(t, filepath.Join(dir, "partner-b.pub"), "")
	config := writeTestFile(t, filepath.Join(dir, "sftpit.yaml"), withScenarios+`  outages:
    faults:
      - id: at-first-login
        max_triggers: 1
        match: {operation: authenticate}
        action: {type: listener_down, duration: 5s, close_existing: true}
      - id: ten-seconds-in
        trigger: {at: 10s, anchor: run}
        action: {type: listener_down, duration: {min: 1s, max: 5s}}
      - id: after-publishing
        match: {operation: rename}
        action: {type: listener_down, when: after, duration: 2s, close_existing: false}
`, 0o600)
	cfg, err := Load(Options{ConfigFile: config, LookupEnv: fakeEnv{"P": "password"}.lookup})
	if err != nil {
		t.Fatalf("Load: %v", err)
	}
	want := []faults.Rule{
		{
			ID:          "at-first-login",
			MaxTriggers: 1,
			Match:       faults.Match{Operations: []faults.Operation{faults.Authenticate}},
			Action:      sftpproxy.ListenerDown{Duration: 5 * time.Second, CloseExisting: true},
		},
		{
			ID:       "ten-seconds-in",
			Trigger:  &faults.Trigger{Anchor: faults.Run, At: &faults.Range[time.Duration]{Min: 10 * time.Second, Max: 10 * time.Second}},
			Duration: &faults.Range[time.Duration]{Min: time.Second, Max: 5 * time.Second},
			Action:   sftpproxy.ListenerDown{},
		},
		{
			ID:     "after-publishing",
			Match:  faults.Match{Operations: []faults.Operation{faults.Rename}},
			Action: sftpproxy.ListenerDown{When: sftpproxy.After, Duration: 2 * time.Second},
		},
	}
	if got := cfg.Scenarios["outages"].Rules; !reflect.DeepEqual(got, want) {
		t.Errorf("rules =\n%+v\nwant\n%+v", got, want)
	}
}

func TestLoadRejectsInvalidListenerDown(t *testing.T) {
	dir := t.TempDir()
	writeAuthorizedKeys(t, filepath.Join(dir, "partner-b.pub"), "")
	tests := []struct {
		name, rule, want string
	}{
		{"no duration", "match: {operation: authenticate}\n        action: {type: listener_down}", "action: duration is required"},
		{"a zero duration", "match: {operation: authenticate}\n        action: {type: listener_down, duration: 0s}", `action: duration "0s" is not a positive duration`},
		{"close_existing off listener_down", "match: {operation: stat}\n        action: {type: delay, when: before, duration: 1s, close_existing: true}", "action: close_existing does not apply to a delay"},
		{"a when at a moment", "trigger: {at: 1s, anchor: run}\n        action: {type: listener_down, when: before, duration: 1s}", "action: when does not apply to a listener_down at a moment"},
		{"a user at a moment of the run", "match: {user: test}\n        trigger: {at: 1s, anchor: run}\n        action: {type: listener_down, duration: 1s}", "a listener_down at a moment of the run takes the listener down for everyone, so it matches no user or key"},
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
