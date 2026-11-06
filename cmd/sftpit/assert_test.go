package main

import (
	"encoding/json"
	"errors"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/nebarg/sftpit/internal/runs"
	"github.com/nebarg/sftpit/internal/testutil"
)

// recoveryConfig is the upload recovery of the quickstart: the first upload
// is cut off, and the run must end with the whole file published.
const recoveryConfig = `schema_version: 1
storage: {expected_dir: ./expected}
scenarios:
  recovery:
    faults:
      - id: first-upload-cutoff
        fail_upload: {path: /orders.csv.part, attempts: [1], after_bytes: 8, result: status}
    assertions:
      - {type: rule_fired, rule_id: first-upload-cutoff, exactly: 1}
      - {type: successful_operation, operation: rename, source: /orders.csv.part, target: /orders.csv}
      - {type: file_equals_fixture, path: /orders.csv, fixture: orders.csv}
      - {type: path_absent, path: /orders.csv.part}
`

const recoveryContent = "id,total\n1,9.99\n"

// serveRecovery serves recoveryConfig, and returns a client's login and the
// ready file.
func serveRecovery(t *testing.T) (*running, string) {
	t.Helper()
	dir := t.TempDir()
	testutil.WriteFile(t, filepath.Join(dir, "expected", "orders.csv"), recoveryContent)
	config := testutil.WriteFile(t, filepath.Join(dir, "sftpit.yaml"), recoveryConfig)
	ready := filepath.Join(dir, "ready.json")
	return startServe(t, "--config", config, "--scenario", "recovery", "--ready-file", ready), ready
}

// upload writes the whole file to its temporary name over a new handle,
// returning the first error, the handle closed either way.
func upload(t *testing.T, s *running) error {
	t.Helper()
	c := s.dial(t, "test", "test")
	f, err := c.Create("/orders.csv.part")
	if err != nil {
		t.Fatalf("Create: %v", err)
	}
	_, err = f.Write([]byte(recoveryContent))
	return errors.Join(err, f.Close())
}

func TestAssertPassesARunThatRecovers(t *testing.T) {
	s, ready := serveRecovery(t)
	if err := upload(t, s); err == nil {
		t.Fatal("the first upload succeeded, want it cut off")
	}
	if err := upload(t, s); err != nil {
		t.Fatalf("the retry: %v", err)
	}
	if err := s.dial(t, "test", "test").Rename("/orders.csv.part", "/orders.csv"); err != nil {
		t.Fatalf("Rename: %v", err)
	}

	var stdout, stderr testutil.SyncBuffer
	code := run(commandContext(t), []string{"assert", "--ready-file", ready, "--timeout", "5s"}, &stdout, &stderr)
	if code != exitOK {
		t.Fatalf("assert: exit %d, stdout %q, stderr %q", code, stdout.String(), stderr.String())
	}
	for _, want := range []string{
		"scenario recovery",
		"  pass  rule_fired first-upload-cutoff, exactly 1: fired 1 time\n",
		"  pass  successful_operation rename /orders.csv.part to /orders.csv, at least 1: succeeded 1 time\n",
		"  pass  file_equals_fixture /orders.csv, fixture orders.csv: holds the fixture's 16 bytes\n",
		"  pass  path_absent /orders.csv.part: nothing is there\n",
		"\npassed\n",
	} {
		if !strings.Contains(stdout.String(), want) {
			t.Errorf("the verdict lacks %q:\n%s", want, stdout.String())
		}
	}
}

func TestAssertFailsARunThatDidNotRecover(t *testing.T) {
	s, ready := serveRecovery(t)
	if err := upload(t, s); err == nil {
		t.Fatal("the first upload succeeded, want it cut off")
	}

	var stdout, stderr testutil.SyncBuffer
	code := run(commandContext(t), []string{"assert", "--ready-file", ready}, &stdout, &stderr)
	if code != exitAssertionsFailed {
		t.Fatalf("assert: exit %d, stdout %q, stderr %q; want %d", code, stdout.String(), stderr.String(), exitAssertionsFailed)
	}
	for _, want := range []string{
		"  pass  rule_fired first-upload-cutoff, exactly 1: fired 1 time\n",
		"  FAIL  successful_operation rename /orders.csv.part to /orders.csv, at least 1: succeeded 0 times\n",
		"  FAIL  file_equals_fixture /orders.csv, fixture orders.csv: no file is there\n",
		"  FAIL  path_absent /orders.csv.part: a file of 8 bytes is there\n",
		"\nfailed\n",
	} {
		if !strings.Contains(stdout.String(), want) {
			t.Errorf("the verdict lacks %q:\n%s", want, stdout.String())
		}
	}

	// The next run starts clean, once a reset starts it.
	var out testutil.SyncBuffer
	if code := run(commandContext(t), []string{"reset", "--ready-file", ready}, &out, &stderr); code != exitOK {
		t.Fatalf("reset: exit %d, stderr %q", code, stderr.String())
	}
	if err := upload(t, s); err == nil {
		t.Error("the next run's first upload succeeded, want its rule to cut it off")
	}
}

func TestAssertWritesItsVerdictAsJSONToAFile(t *testing.T) {
	_, ready := serveRecovery(t)
	output := filepath.Join(t.TempDir(), "result.json")
	var stdout, stderr testutil.SyncBuffer
	code := run(commandContext(t), []string{"assert", "--ready-file", ready, "--format", "json", "--output", output}, &stdout, &stderr)
	if code != exitAssertionsFailed || stdout.String() != "" {
		t.Fatalf("assert: exit %d, stdout %q, stderr %q; want %d and nothing printed", code, stdout.String(), stderr.String(), exitAssertionsFailed)
	}
	data, err := os.ReadFile(output)
	if err != nil {
		t.Fatal(err)
	}
	var report runs.Report
	if err := json.Unmarshal(data, &report); err != nil {
		t.Fatalf("the verdict: %v\n%s", err, data)
	}
	if report.Passed || len(report.Assertions) != 4 || report.Run.Scenario != "recovery" {
		t.Errorf("the verdict is %+v", report)
	}
}

func TestAssertFailsClearly(t *testing.T) {
	_, ready := serveRecovery(t)
	missing := filepath.Join(t.TempDir(), "missing.json")
	tests := []struct {
		name string
		args []string
		code int
		want string
	}{
		{"no ready file", nil, exitUsage, "--ready-file is required"},
		{"a bad format", []string{"--ready-file", ready, "--format", "xml"}, exitUsage, `--format "xml"`},
		{"a bad timeout", []string{"--ready-file", ready, "--timeout", "soon"}, exitUsage, "invalid value"},
		{"a negative timeout", []string{"--ready-file", ready, "--timeout", "-1s"}, exitUsage, "negative"},
		{"an argument", []string{"--ready-file", ready, "extra"}, exitUsage, "unexpected arguments"},
		{"a missing ready file", []string{"--ready-file", missing}, exitFailure, "missing.json"},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			var stdout, stderr testutil.SyncBuffer
			code := run(commandContext(t), append([]string{"assert"}, tt.args...), &stdout, &stderr)
			if code != tt.code || !strings.Contains(stderr.String(), tt.want) {
				t.Errorf("assert %q: exit %d, stderr %q; want %d saying %q", tt.args, code, stderr.String(), tt.code, tt.want)
			}
		})
	}

	t.Run("a verdict it cannot write", func(t *testing.T) {
		var stdout, stderr testutil.SyncBuffer
		code := run(commandContext(t), []string{"assert", "--ready-file", ready, "--output", filepath.Join(t.TempDir(), "no", "dir", "x")}, &stdout, &stderr)
		if code != exitFailure {
			t.Errorf("exit %d, stderr %q; want %d", code, stderr.String(), exitFailure)
		}
	})

	var stdout, stderr testutil.SyncBuffer
	if code := run(commandContext(t), []string{"assert", "--help"}, &stdout, &stderr); code != exitOK || !strings.Contains(stdout.String(), "Usage: sftpit assert") {
		t.Errorf("assert --help: exit %d, stdout %q", code, stdout.String())
	}
}
