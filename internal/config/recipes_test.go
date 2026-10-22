package config

import (
	"path/filepath"
	"reflect"
	"strings"
	"testing"

	"golang.org/x/crypto/ssh"
)

func TestRecipesCompileToTheirLongForm(t *testing.T) {
	dir := t.TempDir()
	fingerprint := ssh.FingerprintSHA256(writeAuthorizedKeys(t, filepath.Join(dir, "partner-b.pub"), ""))
	tests := []struct {
		name, recipe, long string
	}{
		{
			"an upload cut off at its first attempt",
			`fail_upload: {path: /incoming/orders.csv.part, attempts: [1], after_bytes: 1048576, result: status}`,
			`match: {operation: write, path: /incoming/orders.csv.part, attempt: {per: [user, path], numbers: [1]}}
        action: {type: partial_upload, cutoff_offset: 1048576, result: status, status: failure}`,
		},
		{
			"an upload cut off with the defaults",
			`fail_upload: {user: test, filename_glob: "*.part", after_bytes: 0}`,
			`match: {operation: write, user: test, filename_glob: "*.part"}
        action: {type: partial_upload, cutoff_offset: 0, result: status, status: failure}`,
		},
		{
			"a random upload cut off at a random offset",
			`fail_upload: {path_prefix: /incoming, probability: 0.25, after_bytes: {min: 65536, max: 1048576}, result: close_connection, mode: rst}`,
			`match: {operation: write, path_prefix: /incoming}
        decision: {probability: 0.25}
        action: {type: partial_upload, cutoff_offset: {min: 65536, max: 1048576}, result: close_connection, mode: rst}`,
		},
		{
			"an upload frozen at its cutoff",
			`fail_upload: {path_glob: /in/*.csv, after_bytes: 10, result: freeze_connection, max_freeze: 30s}`,
			`match: {operation: write, path_glob: /in/*.csv}
        action: {type: partial_upload, cutoff_offset: 10, result: freeze_connection, max_freeze: 30s}`,
		},
		{
			"random failures",
			`fail_randomly: {operations: [open_write, write, close, rename, stat, list], path_glob: /incoming/*, probability: 0.05, status: failure, when: before}`,
			`match: {operation: [open_write, write, close, rename, stat, list], path_glob: /incoming/*}
        decision: {scope: operation, probability: 0.05}
        action: {type: fail, when: before, status: failure}`,
		},
		{
			"random failures with the defaults",
			`fail_randomly: {operations: any, filename: orders.csv, probability: 0.5}`,
			`match: {operation: any, filename: orders.csv}
        decision: {probability: 0.5}
        action: {type: fail, when: before, status: failure}`,
		},
		{
			"random failures for a key",
			`fail_randomly: {operations: mkdir, key_fingerprint: "` + fingerprint + `", probability: 0.5}`,
			`match: {operation: mkdir, key_fingerprint: "` + fingerprint + `"}
        decision: {probability: 0.5}
        action: {type: fail, when: before, status: failure}`,
		},
		{
			"random failures after the server acts",
			`fail_randomly: {operations: rename, user: test, probability: 1, status: permission_denied, when: after}`,
			`match: {operation: rename, user: test}
        decision: {probability: 1}
        action: {type: fail, when: after, status: permission_denied}`,
		},
		{
			"a download missing a chunk",
			`corrupt_download: {path_glob: /outgoing/*.csv, attempts: [1], transform: omit_range, offset: 1048576, length: 4096}`,
			`match: {operation: read, path_glob: /outgoing/*.csv, attempt: {numbers: [1]}}
        action: {type: corrupt_download, transform: omit_range, offset: 1048576, length: 4096}`,
		},
		{
			"one user's corrupt downloads",
			`corrupt_download: {user: partner-b, filename: orders.csv, transform: flip_bytes, offset: 0, length: 64}`,
			`match: {operation: read, user: partner-b, filename: orders.csv}
        action: {type: corrupt_download, transform: flip_bytes, offset: 0, length: 64}`,
		},
		{
			"random truncated downloads",
			`corrupt_download: {path_prefix: /outgoing, probability: 0.1, transform: truncate, offset: 100}`,
			`match: {operation: read, path_prefix: /outgoing}
        decision: {scope: transfer, probability: 0.1}
        action: {type: corrupt_download, transform: truncate, offset: 100}`,
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			config := writeTestFile(t, filepath.Join(dir, "sftpit.yaml"), withScenarios+`  recipe:
    faults:
      - id: r
        priority: 5
        max_triggers: 2
        `+tt.recipe+`
  long:
    faults:
      - id: r
        priority: 5
        max_triggers: 2
        `+tt.long+`
`, 0o600)
			cfg, err := Load(Options{ConfigFile: config, LookupEnv: fakeEnv{"P": "password"}.lookup})
			if err != nil {
				t.Fatalf("Load: %v", err)
			}
			if recipe, long := cfg.Scenarios["recipe"].Rules, cfg.Scenarios["long"].Rules; !reflect.DeepEqual(recipe, long) {
				t.Errorf("the recipe compiles to\n%+v\nwant, as from the long form,\n%+v", recipe, long)
			}
		})
	}
}

func TestLoadRejectsInvalidRecipes(t *testing.T) {
	dir := t.TempDir()
	writeAuthorizedKeys(t, filepath.Join(dir, "partner-b.pub"), "")
	tests := []struct {
		name, rule, want string
	}{
		{"a recipe with a match", "fail_upload: {after_bytes: 1}\n        match: {operation: write}", "scenarios.s.faults[0] (r): a rule with the fail_upload recipe has no match, decision or action"},
		{"a recipe with an action", "fail_randomly: {operations: stat, probability: 0.5}\n        action: {type: fail, when: before, status: failure}", "a rule with the fail_randomly recipe has no match, decision or action"},
		{"a recipe with a decision", "corrupt_download: {transform: truncate, offset: 0}\n        decision: {probability: 0.5}", "a rule with the corrupt_download recipe has no match, decision or action"},
		{"two recipes", "fail_upload: {after_bytes: 1}\n        corrupt_download: {transform: truncate, offset: 0}", "corrupt_download and fail_upload cannot both be set; a rule has one recipe at most"},
		{"an upload without its cutoff", "fail_upload: {path: /a}", "scenarios.s.faults[0] (r): fail_upload: after_bytes is required"},
		{"an empty cutoff range", "fail_upload: {after_bytes: {min: 2, max: 1}}", "fail_upload: the after_bytes range's min 2 is above its max 1"},
		{"an unknown status", "fail_upload: {after_bytes: 1, status: oops}", `scenarios.s.faults[0] (r): fail_upload: action: status "oops" is not one of`},
		{"a status that closes", "fail_upload: {after_bytes: 1, result: close_connection, status: failure}", "status applies only to result status"},
		{"a freeze without a bound", "fail_upload: {after_bytes: 1, result: freeze_connection}", "max_freeze is required"},
		{"an unknown recipe field", "fail_upload: {after_bytes: 1, operation: write}", "field operation not found"},
		{"two locations", "fail_upload: {after_bytes: 1, path: /a, path_glob: /b*}", "fail_upload: match: path and path_glob cannot both be set"},
		{"an unknown user", "fail_upload: {after_bytes: 1, user: nobody}", `user "nobody" is not a configured user`},
		{"zero attempts", "fail_upload: {after_bytes: 1, attempts: [0]}", "attempt numbers count from 1"},
		{"no attempts", "corrupt_download: {transform: truncate, offset: 0, attempts: []}", "attempt needs at least one number"},
		{"random failures of nothing", "fail_randomly: {probability: 0.5}", "fail_randomly: operations is required"},
		{"random failures without a chance", "fail_randomly: {operations: stat}", "fail_randomly: probability is required"},
		{"a chance above 1", "fail_randomly: {operations: stat, probability: 1.5}", "probability 1.5 is not from 0 to 1"},
		{"random failures of an unknown operation", "fail_randomly: {operations: upload, probability: 0.5}", `unknown operation "upload"`},
		{"a bad when", "fail_randomly: {operations: stat, probability: 0.5, when: during}", `fail_randomly: action: when "during" is not before or after`},
		{"a corruption without a transform", "corrupt_download: {offset: 0}", "corrupt_download: action: transform is required: one of flip_bytes, omit_range, truncate"},
		{"a corruption without an offset", "corrupt_download: {transform: truncate}", "corrupt_download: action: offset is required"},
		{"a truncation with a length", "corrupt_download: {transform: truncate, offset: 0, length: 1}", "length does not apply to truncate"},
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
