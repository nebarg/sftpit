package config

import (
	"cmp"
	"path/filepath"
	"reflect"
	"slices"
	"strings"
	"testing"

	"golang.org/x/crypto/ssh"

	"github.com/nebarg/sftpit/internal/faults"
)

func TestExplainedConfigurationsLoadTheSame(t *testing.T) {
	opts := writeEveryAction(t)
	want, err := Load(opts)
	if err != nil {
		t.Fatalf("Load: %v", err)
	}
	explained, err := Explain(opts)
	if err != nil {
		t.Fatalf("Explain: %v", err)
	}
	for _, secret := range []string{"first-secret", "second-secret"} {
		if strings.Contains(string(explained), secret) {
			t.Errorf("the explained configuration shows the secret %q:\n%s", secret, explained)
		}
	}
	for _, want := range []string{"source_glob: /in/*.part\n", "source_filename: a.part\n"} {
		if !strings.Contains(string(explained), want) {
			t.Errorf("the explained configuration does not name a rename's source as such, %q:\n%s", want, explained)
		}
	}
	// The comment ends with chaos-wrong-size, whatever order the extras are
	// listed in.
	for _, want := range []string{"    # Chaos applies these rules, after the scenario's own:\n    # - id: chaos-delay\n", "    #   match:\n    #     user: partner-b\n    #     operation: any\n    #     filename: orders.csv\n", "    #     size_delta: -1024\n    chaos:\n      preset: heavy\n"} {
		if !strings.Contains(string(explained), want) {
			t.Errorf("the explained configuration does not show chaos's rules before it, %q:\n%s", want, explained)
		}
	}
	tried := []string{"id: failed-close\n", "id: slow-reply\n", "id: missing-chunk\n", "id: slow-stat\n"}
	for i := 1; i < len(tried); i++ {
		if strings.Index(string(explained), tried[i-1]) > strings.Index(string(explained), tried[i]) {
			t.Errorf("the explained configuration lists %q after %q, which is tried after it:\n%s", tried[i-1], tried[i], explained)
		}
	}
	elsewhere := writeTestFile(t, filepath.Join(t.TempDir(), "explained.yaml"), string(explained), 0o600)
	got, err := Load(Options{ConfigFile: elsewhere, LookupEnv: opts.LookupEnv})
	if err != nil {
		t.Fatalf("Load of the explained configuration: %v\n%s", err, explained)
	}
	// Explain lists rules in the order they are tried, which only an
	// engine's priorities decide.
	for _, cfg := range []*Config{want, got} {
		for _, s := range cfg.Scenarios {
			slices.SortStableFunc(s.Rules, func(a, b faults.Rule) int { return cmp.Compare(a.Priority, b.Priority) })
		}
	}
	if !reflect.DeepEqual(got, want) {
		t.Errorf("the explained configuration loads as\n%+v\nwant\n%+v\nexplained:\n%s", got, want, explained)
	}
}

func TestRulesInJSONParseAsTheSameRules(t *testing.T) {
	cfg, err := Load(writeEveryAction(t))
	if err != nil {
		t.Fatalf("Load: %v", err)
	}
	want := cfg.Scenarios["every-action"].Rules
	b, err := RulesJSON(want)
	if err != nil {
		t.Fatalf("RulesJSON: %v", err)
	}
	for _, field := range []string{`"id":"slow-stat","priority":10,"max_triggers":0,"match":{"operation":["stat","lstat"],"path_prefix":"/out"}`, `"duration":{"min":"200ms","max":"3s"}`, `"cutoff_offset":10,`} {
		if !strings.Contains(string(b), field) {
			t.Errorf("the rules in JSON lack %s:\n%s", field, b)
		}
	}
	got, err := ParseRules(b, cfg.Users)
	if err != nil {
		t.Fatalf("ParseRules: %v\n%s", err, b)
	}
	if !reflect.DeepEqual(got, want) {
		t.Errorf("the rules in JSON parse as\n%+v\nwant\n%+v\nJSON:\n%s", got, want, b)
	}
}

// writeEveryAction writes a configuration whose scenario every-action has a
// rule for every action and every way of matching, and returns the options
// that load it.
func writeEveryAction(t *testing.T) Options {
	t.Helper()
	dir := t.TempDir()
	key := writeAuthorizedKeys(t, filepath.Join(dir, "keys", "partner-b.pub"), "")
	writeAuthorizedKeys(t, filepath.Join(dir, "keys", "robot.pub"), "")
	writeTestFile(t, filepath.Join(dir, ".env"), "P2=second-secret\n", 0o600)
	writeTestFile(t, filepath.Join(dir, "seed", "incoming", ".gitkeep"), "", 0o600)
	config := writeTestFile(t, filepath.Join(dir, "sftpit.yaml"), `schema_version: 1
env_file: .env
server: {sftp_listen: "127.0.0.1:2200", http_listen: "127.0.0.1:8200", host_key: ./hostkeys}
storage: {data_dir: ./data, seed_dir: ./seed, max_files: 500}
users:
  - {name: test, password_env: P}
  - {name: partner-b, password_env: P2, authorized_keys: keys/partner-b.pub, home: /partner-b}
  - {name: robot, authorized_keys: keys/robot.pub}
scenarios:
  empty: {faults: []}
  zero: {seed: 0, faults: []}
  dev-chaos:
    chaos: {preset: heavy, scope: {user: partner-b, filename: orders.csv}, extras: [wrong_size, corrupt_download], paused: true}
    faults:
      - {id: deny, match: {operation: remove}, action: {type: fail, when: before, status: permission_denied}}
  every-action:
    seed: 7
    faults:
      - {id: slow-reply, match: {operation: rename}, action: {type: delay, when: after, duration: 1500ms}}
      - {id: stuck-open, match: {operation: open_write}, action: {type: stall, when: before, max_stall: 30s}}
      - {id: stuck-reply, match: {operation: setstat}, action: {type: stall, when: after, max_stall: 2m}}
      - {id: slow-stat, priority: 10, match: {operation: [stat, lstat], path_prefix: /out}, decision: {probability: 0.5}, action: {type: delay, when: before, duration: {min: 200ms, max: 3s}}}
      - {id: failed-close, priority: -1, match: {operation: close, filename: orders.csv}, action: {type: fail, when: after, status: failure}}
      - {id: fin, max_triggers: 3, match: {operation: mkdir, occurrence: [2, 3]}, action: {type: close_connection, when: before}}
      - {id: rst, match: {operation: remove, user: partner-b, key_fingerprint: "`+ssh.FingerprintSHA256(key)+`"}, action: {type: close_connection, when: after, mode: rst}}
      - {id: freeze, match: {operation: any, path_glob: /dead/*}, action: {type: freeze_connection, when: before, max_freeze: 2m}}
      - {id: cut-status, match: {operation: write, path: /in/a.csv, attempt: {per: [user], numbers: [1, 3]}}, action: {type: partial_upload, cutoff_offset: 0, result: status, status: permission_denied}}
      - {id: cut-rst, match: {operation: write, filename_glob: "*.part"}, decision: {scope: transfer, probability: 0.25}, action: {type: partial_upload, cutoff_offset: {min: 1, max: 9}, result: close_connection, mode: rst}}
      - {id: cut-freeze, match: {operation: write, path_glob: /in/*, attempt: {per: [path], numbers: [2]}}, action: {type: partial_upload, cutoff_offset: 10, result: freeze_connection, max_freeze: 30s}}
      - {id: truncated, match: {operation: read}, decision: {probability: 0.1}, action: {type: corrupt_download, transform: truncate, offset: 5}}
      - {id: omitted, match: {operation: read, path: /out/a.csv}, action: {type: corrupt_download, transform: omit_range, offset: 0, length: 4096}}
      - {id: flipped, match: {operation: read, filename: b.csv}, action: {type: corrupt_download, transform: flip_bytes, offset: 7, length: 1}}
      - {id: empty-size, match: {operation: fstat}, action: {type: wrong_size, size: 0}}
      - {id: short-size, match: {operation: [stat, list], path_glob: /out/*.csv}, action: {type: wrong_size, size_delta: -1024}}
      - {id: renames, match: {operation: rename, source_glob: /in/*.part, target_prefix: /in}, action: {type: fail, when: before, status: no_such_file}}
      - {id: named-renames, match: {operation: rename, source_filename: a.part, target_filename_glob: "*.csv"}, action: {type: fail, when: before, status: op_unsupported}}
      - {id: random-opens, match: {operation: [open_read, open_write]}, decision: {scope: transfer, probability: 1}, action: {type: fail, when: before, status: eof}}
      - {id: window, match: {operation: any, user: test}, trigger: {window: {from: 10s, until: 15s}, anchor: connection}, action: {type: fail, when: before, status: failure}}
      - {id: first-stat-after, match: {operation: stat}, trigger: {at: 1m30s, anchor: run}, action: {type: delay, when: after, duration: 2s}}
      - {id: reset-into-upload, match: {operation: [open_write, write], path_prefix: /incoming}, trigger: {at: 2s, anchor: transfer}, decision: {probability: 0.5}, action: {type: close_connection, mode: rst}}
      - {id: random-freeze, match: {user: partner-b}, trigger: {at: {min: 1s, max: 5s}, anchor: connection}, action: {type: freeze_connection, max_freeze: 1m}}
      - {id: idle, trigger: {at: 5m, anchor: run}, action: {type: close_subsystem}}
      - {id: end-at-remove, match: {operation: remove}, action: {type: close_subsystem, when: after}}
      - {id: slow-connect, match: {operation: connect}, decision: {probability: 0.5}, action: {type: delay, duration: {min: 1s, max: 3s}}}
      - {id: first-login, max_triggers: 1, match: {operation: authenticate, user: partner-b, occurrence: [1]}, action: {type: close_connection, mode: rst}}
      - {id: outage, match: {operation: [connect, authenticate]}, trigger: {window: {from: 10s, until: 15s}, anchor: run}, action: {type: freeze_connection, max_freeze: 5s}}
      - {id: down-at-login, match: {operation: authenticate}, action: {type: listener_down, duration: 5s, close_existing: true}}
      - {id: down-in-the-run, trigger: {at: 10s, anchor: run}, action: {type: listener_down, duration: {min: 1s, max: 5s}}}
      - {id: down-after-publishing, match: {operation: rename}, action: {type: listener_down, when: after, duration: 2s}}
      - {id: down-into-upload, match: {operation: write}, trigger: {at: 2s, anchor: transfer}, action: {type: listener_down, duration: 3s, close_existing: true}}
      - id: first-upload-cutoff
        fail_upload: {path: /incoming/orders.csv.part, attempts: [1], after_bytes: 1048576}
      - id: random-failures
        fail_randomly: {operations: [write, rename], path_glob: /incoming/*, probability: 0.05}
      - id: missing-chunk
        corrupt_download: {path_glob: /outgoing/*.csv, attempts: [1], transform: omit_range, offset: 1048576, length: 4096}
`, 0o600)
	return Options{ConfigFile: config, LookupEnv: fakeEnv{"P": "first-secret"}.lookup}
}

func TestExplainWritesRecipesInTheLongForm(t *testing.T) {
	config := writeTestFile(t, filepath.Join(t.TempDir(), "sftpit.yaml"), `schema_version: 1
scenarios:
  upload-recovery:
    seed: 481516
    faults:
      - id: first-upload-cutoff
        fail_upload: {path: /incoming/orders.csv.part, attempts: [1], after_bytes: 1048576, result: status}
`, 0o600)
	explained, err := Explain(Options{ConfigFile: config, LookupEnv: noEnv})
	if err != nil {
		t.Fatalf("Explain: %v", err)
	}
	want := `scenarios:
  upload-recovery:
    seed: 481516
    faults:
      - id: first-upload-cutoff
        priority: 0
        max_triggers: 0
        match:
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
`
	if !strings.HasSuffix(string(explained), want) {
		t.Errorf("Explain wrote\n%s\nwant it to end with\n%s", explained, want)
	}
	if !strings.Contains(string(explained), "# No users are configured, so sftpit accepts the user test with the password test.\n") {
		t.Errorf("Explain does not say which login the default users allow:\n%s", explained)
	}
}

func TestExplainSaysWhereEachSecretComesFrom(t *testing.T) {
	dir := t.TempDir()
	envFile := writeTestFile(t, filepath.Join(dir, ".env"), "FROM_FILE=x\nEMPTY=\n", 0o600)
	absent := filepath.Join(dir, "absent.env")
	config := writeTestFile(t, filepath.Join(dir, "sftpit.yaml"), `schema_version: 1
env_file: [.env, absent.env]
users:
  - {name: a, password_env: FROM_ENV}
  - {name: b, password_env: FROM_FILE}
  - {name: c, password_env: EMPTY}
  - {name: d, password_env: MISSING}
`, 0o600)
	opts := Options{ConfigFile: config, LookupEnv: fakeEnv{"FROM_ENV": "x"}.lookup}
	if _, err := Load(opts); err == nil {
		t.Fatal("Load accepted a missing secret")
	}
	explained, err := Explain(opts)
	if err != nil {
		t.Fatalf("Explain: %v", err)
	}
	want := "# Secrets, whose values are never shown:\n" +
		"#   EMPTY: empty, in " + envFile + "\n" +
		"#   FROM_ENV: from the environment\n" +
		"#   FROM_FILE: from " + envFile + "\n" +
		"#   MISSING: missing; it is not in the environment or " + envFile + ", " + absent + " (not found)\n"
	if !strings.Contains(string(explained), want) {
		t.Errorf("Explain wrote\n%s\nwant it to hold\n%s", explained, want)
	}
	if !strings.Contains(string(explained), "env_file: ["+envFile+", "+absent+"]\n") {
		t.Errorf("Explain does not list the env files:\n%s", explained)
	}
}

func TestExplainStillRejectsInvalidConfigurations(t *testing.T) {
	config := writeTestFile(t, filepath.Join(t.TempDir(), "sftpit.yaml"), "schema_version: 1\nscenarios:\n  s:\n    faults:\n      - {id: r, match: {operation: upload}, action: {type: fail, when: before, status: failure}}\n", 0o600)
	if _, err := Explain(Options{ConfigFile: config, LookupEnv: noEnv}); err == nil || !strings.Contains(err.Error(), `unknown operation "upload"`) {
		t.Errorf("Explain = %v, want the unknown operation reported", err)
	}
}
