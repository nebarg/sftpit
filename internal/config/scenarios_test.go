package config

import (
	"path/filepath"
	"reflect"
	"strings"
	"testing"
	"time"

	"golang.org/x/crypto/ssh"

	"github.com/nebarg/sftpit/internal/faults"
	"github.com/nebarg/sftpit/internal/sftpproxy"
	"github.com/nebarg/sftpit/internal/sftpwire"
	"github.com/nebarg/sftpit/internal/testutil"
)

func TestLoadReadsTheSelectedScenariosRules(t *testing.T) {
	dir := t.TempDir()
	key := writeAuthorizedKeys(t, filepath.Join(dir, "partner-b.pub"), "")
	cfg, err := loadScenarios(t, dir, `  upload-recovery:
    seed: 481516
    faults:
      - id: first-upload-cutoff
        priority: 10
        match:
          user: test
          operation: write
          path: /incoming/orders.csv.part
          attempt:
            per: [user, path]
            numbers: [1]
        action:
          type: partial_upload
          cutoff_offset: 1048576
          result: status
          status: failure
      - id: lost-publish-reply
        max_triggers: 1
        match:
          operation: rename
          source: /incoming/orders.csv.part
          target_glob: /incoming/*.csv
        action: {type: close_connection, when: after, mode: rst}
      - id: partner-b-orders
        match:
          key_fingerprint: `+ssh.FingerprintSHA256(key)+`
          operation: read
          filename: orders.csv
        action: {type: corrupt_download, transform: flip_bytes, offset: 0, length: 64}
      - id: slow-listing
        match: {operation: [stat, list], path_prefix: /outgoing, occurrence: [2, 3]}
        action: {type: delay, when: before, duration: 1500ms}
      - id: short-size
        match: {operation: list, filename_glob: "*.csv"}
        action: {type: wrong_size, size_delta: -1024}
      - id: dead-reply
        match: {operation: any, path_glob: /dead/*}
        action: {type: freeze_connection, when: before, max_freeze: 2m}
      - id: cut-and-close
        match: {operation: write, path: /in/b.csv}
        action: {type: partial_upload, cutoff_offset: 0, result: close_connection, mode: rst}
      - id: cut-and-freeze
        match: {operation: write, path: /in/c.csv, attempt: {numbers: [2]}}
        action: {type: partial_upload, cutoff_offset: 10, result: freeze_connection, max_freeze: 30s}
      - id: slow-stat
        match: {operation: stat}
        decision: {probability: 0.05}
        action: {type: delay, when: before, duration: {min: 200ms, max: 3s}}
      - id: flaky-upload
        match: {operation: write, path_prefix: /in}
        decision: {scope: transfer, probability: 0.25}
        action: {type: partial_upload, cutoff_offset: {min: 65536, max: 1048576}, result: close_connection, mode: rst}
      - id: failed-opens
        match: {operation: [open_read, open_write]}
        decision: {scope: transfer, probability: 1}
        action: {type: fail, when: before, status: failure}
      - id: never
        match: {operation: remove}
        decision: {scope: operation, probability: 0}
        action: {type: fail, when: after, status: failure}
      - id: stuck-open
        match: {operation: open_read}
        action: {type: stall, when: before, max_stall: 30s}
      - id: stuck-reply
        match: {operation: rename}
        action: {type: stall, when: after, max_stall: 1m}
  other:
    faults:
      - id: deny
        match: {operation: remove}
        action: {type: fail, when: before, status: permission_denied}
`, "upload-recovery")
	if err != nil {
		t.Fatalf("Load: %v", err)
	}
	want := []faults.Rule{
		{
			ID:       "first-upload-cutoff",
			Priority: 10,
			Match: faults.Match{
				User:       "test",
				Operations: []faults.Operation{faults.Write},
				Path:       faults.Location{Kind: faults.Exactly, Pattern: "/incoming/orders.csv.part"},
				Attempt:    &faults.Attempt{PerUser: true, PerPath: true, Numbers: []uint64{1}},
			},
			Action: sftpproxy.PartialUpload{Cutoff: 1 << 20, Result: sftpproxy.Fail{Status: sftpwire.StatusFailure}},
		},
		{
			ID:          "lost-publish-reply",
			MaxTriggers: 1,
			Match: faults.Match{
				Operations: []faults.Operation{faults.Rename},
				Path:       faults.Location{Kind: faults.Exactly, Pattern: "/incoming/orders.csv.part"},
				Target:     faults.Location{Kind: faults.Glob, Pattern: "/incoming/*.csv"},
			},
			Action: sftpproxy.Drop{When: sftpproxy.After, Reset: true},
		},
		{
			ID: "partner-b-orders",
			Match: faults.Match{
				KeyFingerprint: ssh.FingerprintSHA256(key),
				Operations:     []faults.Operation{faults.Read},
				Path:           faults.Location{Kind: faults.Named, Pattern: "orders.csv"},
			},
			Action: sftpproxy.CorruptDownload{Corruption: sftpproxy.FlipBytes, Offset: 0, Length: 64},
		},
		{
			ID: "slow-listing",
			Match: faults.Match{
				Operations: []faults.Operation{faults.Stat, faults.List},
				Path:       faults.Location{Kind: faults.Under, Pattern: "/outgoing"},
				Occurrence: []uint64{2, 3},
			},
			Action: sftpproxy.Delay{When: sftpproxy.Before, Duration: 1500 * time.Millisecond},
		},
		{
			ID:     "short-size",
			Match:  faults.Match{Operations: []faults.Operation{faults.List}, Path: faults.Location{Kind: faults.NamedGlob, Pattern: "*.csv"}},
			Action: sftpproxy.WrongSize{Delta: -1024},
		},
		{
			ID:     "dead-reply",
			Match:  faults.Match{Operations: []faults.Operation{faults.Any}, Path: faults.Location{Kind: faults.Glob, Pattern: "/dead/*"}},
			Action: sftpproxy.Freeze{When: sftpproxy.Before, Limit: 2 * time.Minute},
		},
		{
			ID:     "cut-and-close",
			Match:  faults.Match{Operations: []faults.Operation{faults.Write}, Path: faults.Location{Kind: faults.Exactly, Pattern: "/in/b.csv"}},
			Action: sftpproxy.PartialUpload{Cutoff: 0, Result: sftpproxy.Drop{Reset: true}},
		},
		{
			ID: "cut-and-freeze",
			Match: faults.Match{
				Operations: []faults.Operation{faults.Write},
				Path:       faults.Location{Kind: faults.Exactly, Pattern: "/in/c.csv"},
				// Attempts count per user and path unless per says otherwise.
				Attempt: &faults.Attempt{PerUser: true, PerPath: true, Numbers: []uint64{2}},
			},
			Action: sftpproxy.PartialUpload{Cutoff: 10, Result: sftpproxy.Freeze{Limit: 30 * time.Second}},
		},
		{
			ID:          "slow-stat",
			Match:       faults.Match{Operations: []faults.Operation{faults.Stat}},
			Probability: new(0.05),
			Duration:    &faults.Range[time.Duration]{Min: 200 * time.Millisecond, Max: 3 * time.Second},
			Action:      sftpproxy.Delay{When: sftpproxy.Before},
		},
		{
			ID:          "flaky-upload",
			Match:       faults.Match{Operations: []faults.Operation{faults.Write}, Path: faults.Location{Kind: faults.Under, Pattern: "/in"}},
			Probability: new(0.25),
			Cutoff:      &faults.Range[uint64]{Min: 65536, Max: 1048576},
			Action:      sftpproxy.PartialUpload{Result: sftpproxy.Drop{Reset: true}},
		},
		{
			ID:          "failed-opens",
			Match:       faults.Match{Operations: []faults.Operation{faults.OpenRead, faults.OpenWrite}},
			Probability: new(1.0),
			Action:      sftpproxy.Fail{When: sftpproxy.Before, Status: sftpwire.StatusFailure},
		},
		{
			ID:          "never",
			Match:       faults.Match{Operations: []faults.Operation{faults.Remove}},
			Probability: new(0.0),
			Action:      sftpproxy.Fail{When: sftpproxy.After, Status: sftpwire.StatusFailure},
		},
		{
			ID:     "stuck-open",
			Match:  faults.Match{Operations: []faults.Operation{faults.OpenRead}},
			Action: sftpproxy.Stall{When: sftpproxy.Before, Limit: 30 * time.Second},
		},
		{
			ID:     "stuck-reply",
			Match:  faults.Match{Operations: []faults.Operation{faults.Rename}},
			Action: sftpproxy.Stall{When: sftpproxy.After, Limit: time.Minute},
		},
	}
	if cfg.Scenario != "upload-recovery" || !reflect.DeepEqual(cfg.Rules(), want) {
		t.Errorf("scenario %q has rules\n%+v\nwant\n%+v", cfg.Scenario, cfg.Rules(), want)
	}
	if s := cfg.Scenarios["upload-recovery"].Seed; s == nil || *s != 481516 {
		t.Errorf("the scenario's Seed = %v, want 481516", s)
	}
}

// TestLoadKeepsTheSeedOptionApartFromTheScenariosSeed checks that the seed
// option, which a run puts in place of its scenario's own, is kept as given,
// beside the scenario's seed.
func TestLoadKeepsTheSeedOptionApartFromTheScenariosSeed(t *testing.T) {
	config := testutil.WriteFile(t, filepath.Join(t.TempDir(), "sftpit.yaml"), `schema_version: 1
scenarios:
  pinned:
    seed: 0
    faults: []
  fresh:
    faults: []
`)
	tests := []struct {
		scenario string
		seed     *faults.Seed
	}{
		{"pinned", nil},
		{"pinned", new(faults.Seed(7))},
		{"fresh", nil},
		{"fresh", new(faults.Seed(7))},
		{"", nil},
	}
	for _, tt := range tests {
		cfg, err := Load(Options{ConfigFile: config, Scenario: tt.scenario, Seed: tt.seed, LookupEnv: noEnv})
		if err != nil {
			t.Fatalf("Load: %v", err)
		}
		if !reflect.DeepEqual(cfg.Seed, tt.seed) {
			t.Errorf("scenario %q with option %v has Seed %v, want the option", tt.scenario, tt.seed, cfg.Seed)
		}
		if s := cfg.Scenarios["pinned"].Seed; s == nil || *s != 0 {
			t.Errorf("scenario pinned's own seed = %v, want 0", s)
		}
	}
}

func TestLoadChecksEveryScenarioButInjectsOnlyTheSelectedOne(t *testing.T) {
	dir := t.TempDir()
	writeAuthorizedKeys(t, filepath.Join(dir, "partner-b.pub"), "")
	valid := `  valid:
    faults:
      - id: deny
        match: {operation: remove}
        action: {type: fail, when: before, status: permission_denied}
`
	cfg, err := loadScenarios(t, dir, valid, "")
	if err != nil {
		t.Fatalf("Load: %v", err)
	}
	if cfg.Scenario != "" || len(cfg.Rules()) != 0 {
		t.Errorf("Load chose scenario %q with %d rules, want none without --scenario", cfg.Scenario, len(cfg.Rules()))
	}

	broken := testutil.WriteFile(t, filepath.Join(dir, "broken.yaml"), withScenarios+valid+`  broken:
    faults:
      - id: deny
        match: {operation: upload}
        action: {type: fail, when: before, status: failure}
`)
	if _, err := Load(Options{ConfigFile: broken, Scenario: "valid", LookupEnv: fakeEnv{"P": "password"}.lookup}); err == nil || !strings.Contains(err.Error(), `scenarios.broken: faults: rule "deny": unknown operation "upload"`) {
		t.Errorf("Load = %v, want the broken scenario reported although another is selected", err)
	}
}

func TestLoadRejectsInvalidScenarios(t *testing.T) {
	dir := t.TempDir()
	writeAuthorizedKeys(t, filepath.Join(dir, "partner-b.pub"), "")
	rule := func(match, action string) string {
		return "  s:\n    faults:\n      - id: r\n        match: " + match + "\n        action: " + action + "\n"
	}
	decided := func(decision, match, action string) string {
		return "  s:\n    faults:\n      - id: r\n        match: " + match + "\n        decision: " + decision + "\n        action: " + action + "\n"
	}
	deny := "{type: fail, when: before, status: failure}"
	tests := []struct {
		name      string
		scenarios string
		selected  string
		want      string
	}{
		{"an undefined scenario", rule("{operation: stat}", deny), "missing", `scenario "missing" is not defined; the configuration defines s`},
		{"a bad scenario name", "  Bad_Name:\n    faults: []\n", "", "scenarios.Bad_Name: a scenario name may hold only"},
		{"a bad rule ID", "  s:\n    faults:\n      - id: First Rule\n        match: {operation: stat}\n        action: " + deny + "\n", "", `scenarios.s.faults[0]: id "First Rule" must hold only`},
		{"no rule ID", "  s:\n    faults:\n      - match: {operation: stat}\n        action: " + deny + "\n", "", "scenarios.s.faults[0]: id is required"},
		{"a repeated rule ID", "  s:\n    faults:\n      - {id: r, match: {operation: stat}, action: " + deny + "}\n      - {id: r, match: {operation: stat}, action: " + deny + "}\n", "", `scenarios.s: faults: rule ID "r" is used twice`},
		{"an operation that is not a name", rule("{operation: {a: b}}", deny), "", "expected a string or a list of strings"},
		{"an unknown field", rule("{operation: stat, paths: /a}", deny), "", "field paths not found"},
		{"no operation", rule("{path: /a}", deny), "", "scenarios.s.faults[0] (r): match: operation is required"},
		{"two path fields", rule("{operation: stat, path: /a, path_prefix: /b}", deny), "", "path and path_prefix cannot both be set"},
		{"a source off a rename", rule("{operation: remove, source: /a}", deny), "", "the source fields need operation rename"},
		{"a source and a path", rule("{operation: rename, source: /a, path: /b}", deny), "", "set the source fields or the path fields, not both"},
		{"two target fields", rule("{operation: rename, target: /a, target_glob: /b*}", deny), "", "target and target_glob cannot both be set"},
		{"attempts per nothing", rule("{operation: open_write, attempt: {per: [], numbers: [1]}}", deny), "", "attempt per needs user, path or both"},
		{"attempts per host", rule("{operation: open_write, attempt: {per: [host], numbers: [1]}}", deny), "", `attempt per "host" is not user or path`},
		{"an unknown user", rule("{operation: stat, user: nobody}", deny), "", `user "nobody" is not a configured user`},
		{"an unknown key", rule("{operation: stat, key_fingerprint: \"SHA256:abc\"}", deny), "", `key_fingerprint "SHA256:abc" is not one of the configured users' authorized keys`},
		{"another user's key", rule("{operation: stat, user: test, key_fingerprint: \"SHA256:abc\"}", deny), "", "is not one of test's authorized keys"},
		{"an unknown action", rule("{operation: stat}", "{type: explode}"), "", `action: type "explode" is not one of close_connection, close_subsystem, corrupt_download, delay, fail, freeze_connection, listener_down, partial_upload, stall, wrong_size`},
		{"a field of another action", rule("{operation: stat}", "{type: fail, when: before, status: failure, duration: 1s}"), "", "action: duration does not apply to a fail"},
		{"no when", rule("{operation: stat}", "{type: fail, status: failure}"), "", "when is required: before the server acts, or after"},
		{"a bad when", rule("{operation: stat}", "{type: fail, when: during, status: failure}"), "", `when "during" is not before or after`},
		{"no duration", rule("{operation: stat}", "{type: delay, when: after}"), "", "duration is required"},
		{"a bare number duration", rule("{operation: stat}", "{type: delay, when: after, duration: 5}"), "", `duration "5" is not a positive duration`},
		{"a negative duration", rule("{operation: stat}", "{type: delay, when: after, duration: -1s}"), "", `duration "-1s" is not a positive duration`},
		{"no status", rule("{operation: stat}", "{type: fail, when: before}"), "", "status is required"},
		{"a status a server cannot send", rule("{operation: stat}", "{type: fail, when: before, status: connection_lost}"), "", `status "connection_lost" is not one of bad_message, eof, failure, no_such_file, op_unsupported, permission_denied`},
		{"a bad mode", rule("{operation: stat}", "{type: close_connection, when: before, mode: hangup}"), "", `mode "hangup" is not fin or rst`},
		{"a freeze without a bound", rule("{operation: stat}", "{type: freeze_connection, when: before}"), "", "max_freeze is required"},
		{"a stall without a bound", rule("{operation: stat}", "{type: stall, when: before}"), "", "max_stall is required"},
		{"a stall without when", rule("{operation: stat}", "{type: stall, max_stall: 1s}"), "", "when is required: before the server acts, or after"},
		{"a duration on a stall", rule("{operation: stat}", "{type: stall, when: before, max_stall: 1s, duration: 1s}"), "", "duration does not apply to a stall"},
		{"a stall's bound on a freeze", rule("{operation: stat}", "{type: freeze_connection, when: before, max_freeze: 1s, max_stall: 1s}"), "", "max_stall does not apply to a freeze_connection"},
		{"a bound on a close", rule("{operation: stat}", "{type: close_connection, when: before, max_freeze: 1s}"), "", "max_freeze does not apply to a close_connection"},
		{"a mode on a freeze", rule("{operation: stat}", "{type: freeze_connection, when: before, mode: rst, max_freeze: 1s}"), "", "mode does not apply to a freeze_connection"},
		{"a connection action without when", rule("{operation: stat}", "{type: close_subsystem}"), "", "when is required: before the server acts, or after"},
		{"no cutoff", rule("{operation: write}", "{type: partial_upload, result: status, status: failure}"), "", "cutoff_offset is required"},
		{"no result", rule("{operation: write}", "{type: partial_upload, cutoff_offset: 1}"), "", "result is required"},
		{"a bad result", rule("{operation: write}", "{type: partial_upload, cutoff_offset: 1, result: retry}"), "", `result "retry" is not status`},
		{"a status that closes", rule("{operation: write}", "{type: partial_upload, cutoff_offset: 1, result: close_connection, status: failure}"), "", "status applies only to result status"},
		{"a mode that answers", rule("{operation: write}", "{type: partial_upload, cutoff_offset: 1, result: status, status: failure, mode: rst}"), "", "mode and max_freeze apply only to result close_connection or freeze_connection"},
		{"a close that freezes", rule("{operation: write}", "{type: partial_upload, cutoff_offset: 1, result: close_connection, mode: freeze}"), "", `mode "freeze" is not fin or rst`},
		{"a freeze with a mode", rule("{operation: write}", "{type: partial_upload, cutoff_offset: 1, result: freeze_connection, mode: rst, max_freeze: 1s}"), "", "mode applies only to result close_connection"},
		{"a cutoff of a read", rule("{operation: read}", "{type: partial_upload, cutoff_offset: 1, result: status, status: failure}"), "", "a partial upload needs the rule to match the write operation only"},
		{"an unknown transform", rule("{operation: read}", "{type: corrupt_download, transform: shuffle, offset: 0}"), "", `transform "shuffle" is not one of flip_bytes, omit_range, truncate`},
		{"no offset", rule("{operation: read}", "{type: corrupt_download, transform: truncate}"), "", "offset is required"},
		{"a truncate with a length", rule("{operation: read}", "{type: corrupt_download, transform: truncate, offset: 0, length: 1}"), "", "length does not apply to truncate"},
		{"an omission without a length", rule("{operation: read}", "{type: corrupt_download, transform: omit_range, offset: 0}"), "", "omit_range needs a length of at least 1"},
		{"no size", rule("{operation: stat}", "{type: wrong_size}"), "", "size or a size_delta other than 0 is required"},
		{"a size delta of 0", rule("{operation: stat}", "{type: wrong_size, size_delta: 0}"), "", "size or a size_delta other than 0 is required"},
		{"two sizes", rule("{operation: stat}", "{type: wrong_size, size: 1, size_delta: 1}"), "", "set size or size_delta, not both"},
		{"a negative seed", "  s:\n    seed: -1\n    faults: []\n", "", "cannot unmarshal !!int `-1` into faults.Seed"},
		{"a decision without a probability", decided("{scope: operation}", "{operation: stat}", deny), "", "scenarios.s.faults[0] (r): decision: probability is required"},
		{"a probability above 1", decided("{probability: 1.5}", "{operation: stat}", deny), "", "probability 1.5 is not from 0 to 1"},
		{"an unknown decision field", decided("{probability: 0.5, chance: 0.5}", "{operation: stat}", deny), "", "field chance not found"},
		{"an unknown scope", decided("{scope: chunk, probability: 0.5}", "{operation: stat}", deny), "", `decision: scope "chunk" is not operation or transfer`},
		{"a transfer decided per operation", decided("{scope: operation, probability: 0.5}", "{operation: write}", "{type: partial_upload, cutoff_offset: 1, result: status, status: failure}"), "", "a partial_upload is decided once for each transfer, at its open, so its scope is transfer"},
		{"a corrupt download decided per operation", decided("{scope: operation, probability: 0.5}", "{operation: read}", "{type: corrupt_download, transform: truncate, offset: 0}"), "", "a corrupt_download is decided once for each transfer"},
		{"a delay of every read of a transfer", decided("{scope: transfer, probability: 0.5}", "{operation: [open_read, read]}", "{type: delay, when: before, duration: 1s}"), "", "scope transfer needs a partial_upload, a corrupt_download or the open_read and open_write operations; a delay on every request of a chosen transfer is not supported"},
		{"an empty duration range", rule("{operation: stat}", "{type: delay, when: before, duration: {min: 3s, max: 200ms}}"), "", "the duration range's min 3s is above its max 200ms"},
		{"an empty cutoff range", rule("{operation: write}", "{type: partial_upload, cutoff_offset: {min: 2, max: 1}, result: status, status: failure}"), "", "the cutoff_offset range's min 2 is above its max 1"},
		{"a range without a max", rule("{operation: stat}", "{type: delay, when: before, duration: {min: 1s}}"), "", "a range needs both min and max"},
		{"a range with another bound", rule("{operation: stat}", "{type: delay, when: before, duration: {min: 1s, mid: 2s, max: 3s}}"), "", "a range has min and max, not mid"},
		{"a range with two minimums", rule("{operation: stat}", "{type: delay, when: before, duration: {min: 1s, min: 2s, max: 3s}}"), "", "a range's min is set twice"},
		{"a range of bad durations", rule("{operation: stat}", "{type: delay, when: before, duration: {min: 1s, max: soon}}"), "", `duration "soon" is not a positive duration`},
		{"a range of bad offsets", rule("{operation: write}", "{type: partial_upload, cutoff_offset: {min: 0, max: 1MiB}, result: status, status: failure}"), "", "cannot unmarshal !!str `1MiB` into uint64"},
		{"a list for a range", rule("{operation: stat}", "{type: delay, when: before, duration: [1s, 2s]}"), "", "cannot unmarshal !!seq into string"},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			_, err := loadScenarios(t, dir, tt.scenarios, tt.selected)
			if err == nil || !strings.Contains(err.Error(), tt.want) {
				t.Errorf("error = %v, want %q", err, tt.want)
			}
		})
	}
}

func TestLoadNamesTheMissingScenarioWithoutAConfigFile(t *testing.T) {
	_, err := Load(Options{Scenario: "upload-recovery", LookupEnv: noEnv})
	if err == nil || !strings.Contains(err.Error(), `scenario "upload-recovery" is not defined; the configuration defines no scenarios`) {
		t.Errorf("Load = %v, want the scenario reported as undefined", err)
	}
}
