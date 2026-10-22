package config

import (
	"path/filepath"
	"reflect"
	"strings"
	"testing"
	"time"

	"github.com/nebarg/sftpit/internal/faults"
	"github.com/nebarg/sftpit/internal/sftpproxy"
	"github.com/nebarg/sftpit/internal/sftpwire"
)

func TestLoadReadsTriggersAndConnectionActions(t *testing.T) {
	dir := t.TempDir()
	writeAuthorizedKeys(t, filepath.Join(dir, "partner-b.pub"), "")
	config := writeTestFile(t, filepath.Join(dir, "sftpit.yaml"), withScenarios+`  timed:
    faults:
      - id: bad-five-seconds
        match: {operation: any}
        trigger: {window: {from: 10s, until: 15s}, anchor: run}
        action: {type: fail, when: before, status: failure}
      - id: reset-2s-into-upload
        match: {operation: write, path_prefix: /incoming}
        trigger: {at: 2s, anchor: transfer}
        action: {type: close_connection, mode: rst}
      - id: random-freeze
        trigger: {at: {min: 1s, max: 5s}, anchor: connection}
        action: {type: freeze_connection, max_freeze: 30s}
      - id: idle-timeout
        match: {user: test}
        trigger: {at: 5m, anchor: connection}
        action: {type: close_subsystem}
      - id: slow-after-a-minute
        match: {operation: stat}
        trigger: {at: 0s, anchor: run}
        action: {type: delay, when: before, duration: 1s}
      - id: end-at-remove
        match: {operation: remove}
        action: {type: close_subsystem, when: after}
      - id: random-download-reset
        match: {operation: read}
        trigger: {at: 1s, anchor: transfer}
        decision: {probability: 0.5}
        action: {type: close_connection}
`, 0o600)
	cfg, err := Load(Options{ConfigFile: config, LookupEnv: fakeEnv{"P": "password"}.lookup})
	if err != nil {
		t.Fatalf("Load: %v", err)
	}
	half := 0.5
	want := []faults.Rule{
		{
			ID:      "bad-five-seconds",
			Match:   faults.Match{Operations: []faults.Operation{faults.Any}},
			Trigger: &faults.Trigger{Anchor: faults.Run, Window: &faults.Window{From: 10 * time.Second, Until: 15 * time.Second}},
			Action:  sftpproxy.Fail{When: sftpproxy.Before, Status: sftpwire.StatusFailure},
		},
		{
			ID:      "reset-2s-into-upload",
			Match:   faults.Match{Operations: []faults.Operation{faults.Write}, Path: faults.Location{Kind: faults.Under, Pattern: "/incoming"}},
			Trigger: &faults.Trigger{Anchor: faults.Transfer, At: &faults.Range[time.Duration]{Min: 2 * time.Second, Max: 2 * time.Second}},
			Action:  sftpproxy.Drop{Reset: true},
		},
		{
			ID:      "random-freeze",
			Trigger: &faults.Trigger{Anchor: faults.Connection, At: &faults.Range[time.Duration]{Min: time.Second, Max: 5 * time.Second}},
			Action:  sftpproxy.Freeze{Limit: 30 * time.Second},
		},
		{
			ID:      "idle-timeout",
			Match:   faults.Match{User: "test"},
			Trigger: &faults.Trigger{Anchor: faults.Connection, At: &faults.Range[time.Duration]{Min: 5 * time.Minute, Max: 5 * time.Minute}},
			Action:  sftpproxy.EndSession{},
		},
		{
			ID:      "slow-after-a-minute",
			Match:   faults.Match{Operations: []faults.Operation{faults.Stat}},
			Trigger: &faults.Trigger{Anchor: faults.Run, At: &faults.Range[time.Duration]{}},
			Action:  sftpproxy.Delay{When: sftpproxy.Before, Duration: time.Second},
		},
		{
			ID:     "end-at-remove",
			Match:  faults.Match{Operations: []faults.Operation{faults.Remove}},
			Action: sftpproxy.EndSession{When: sftpproxy.After},
		},
		{
			ID:          "random-download-reset",
			Match:       faults.Match{Operations: []faults.Operation{faults.Read}},
			Trigger:     &faults.Trigger{Anchor: faults.Transfer, At: &faults.Range[time.Duration]{Min: time.Second, Max: time.Second}},
			Probability: &half,
			Action:      sftpproxy.Drop{},
		},
	}
	if got := cfg.Scenarios["timed"].Rules; !reflect.DeepEqual(got, want) {
		t.Errorf("rules =\n%+v\nwant\n%+v", got, want)
	}
}

func TestLoadRejectsInvalidTriggers(t *testing.T) {
	dir := t.TempDir()
	writeAuthorizedKeys(t, filepath.Join(dir, "partner-b.pub"), "")
	tests := []struct {
		name, rule, want string
	}{
		{"no anchor", "match: {operation: stat}\n        trigger: {at: 1s}\n        action: {type: fail, when: before, status: failure}", "scenarios.s.faults[0] (r): trigger: anchor is required: one of connection, run, transfer"},
		{"an unknown anchor", "match: {operation: stat}\n        trigger: {at: 1s, anchor: handle}\n        action: {type: fail, when: before, status: failure}", `trigger: anchor "handle" is not one of connection, run, transfer`},
		{"no moment or window", "match: {operation: stat}\n        trigger: {anchor: run}\n        action: {type: fail, when: before, status: failure}", "trigger: at or window is required"},
		{"both a moment and a window", "match: {operation: stat}\n        trigger: {at: 1s, window: {from: 0s, until: 1s}, anchor: run}\n        action: {type: fail, when: before, status: failure}", "trigger: set at or window, not both"},
		{"a negative moment", "match: {operation: stat}\n        trigger: {at: -1s, anchor: run}\n        action: {type: fail, when: before, status: failure}", `trigger: at "-1s" is not a duration of 0 or more`},
		{"a moment that is not a duration", "match: {operation: stat}\n        trigger: {at: soon, anchor: run}\n        action: {type: fail, when: before, status: failure}", `at "soon" is not a duration`},
		{"an empty range of moments", "match: {operation: stat}\n        trigger: {at: {min: 5s, max: 1s}, anchor: run}\n        action: {type: fail, when: before, status: failure}", "the at range's min 5s is above its max 1s"},
		{"a window without its end", "match: {operation: stat}\n        trigger: {window: {from: 1s}, anchor: run}\n        action: {type: fail, when: before, status: failure}", "trigger: window until is required"},
		{"a window that ends first", "match: {operation: stat}\n        trigger: {window: {from: 15s, until: 10s}, anchor: run}\n        action: {type: fail, when: before, status: failure}", "the window from 15s until 10s is empty"},
		{"an unknown trigger field", "match: {operation: stat}\n        trigger: {after: 1s, anchor: run}\n        action: {type: fail, when: before, status: failure}", "field after not found"},
		{"when at a moment", "trigger: {at: 1s, anchor: connection}\n        action: {type: close_connection, when: before}", "action: when does not apply to a close_connection at a moment, which acts whatever the client is doing"},
		{"a moment's operation", "match: {operation: stat}\n        trigger: {at: 1s, anchor: run}\n        action: {type: close_subsystem}", "a connection action at a moment of the run matches only the user and key"},
		{"a moment by chance", "trigger: {at: 1s, anchor: run}\n        decision: {probability: 0.5}\n        action: {type: close_subsystem}", "a connection action at a moment of the run takes no probability"},
		{"a transfer's failure", "match: {operation: write}\n        trigger: {at: 1s, anchor: transfer}\n        action: {type: fail, when: before, status: failure}", "a transfer anchor needs at and a connection action"},
		{"a transfer's moment per operation", "match: {operation: write}\n        trigger: {at: 1s, anchor: transfer}\n        decision: {scope: operation, probability: 0.5}\n        action: {type: close_connection}", "decision: a close_connection is decided once for each transfer, at its open, so its scope is transfer"},
		{"a transfer's moment without an operation", "trigger: {at: 1s, anchor: transfer}\n        action: {type: close_connection}", "match: operation is required"},
		{"a delay at a moment without an operation", "trigger: {at: 1s, anchor: run}\n        action: {type: delay, when: before, duration: 1s}", "match: operation is required"},
		{"a request's close without an operation", "trigger: {window: {from: 0s, until: 1s}, anchor: run}\n        action: {type: close_connection, when: before}", "match: operation is required"},
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
