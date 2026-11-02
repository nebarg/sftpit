package main

import (
	"bytes"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/nebarg/sftpit/internal/testutil"
)

const validConfig = `schema_version: 1
env_file: .env
users:
  - {name: test, password_env: SFTPIT_CONFIG_TEST_PASSWORD}
  - {name: partner-b, password_env: SFTPIT_CONFIG_TEST_OTHER}
scenarios:
  upload-recovery:
    faults:
      - id: first-upload-cutoff
        fail_upload: {path: /incoming/orders.csv.part, attempts: [1], after_bytes: 1048576}
`

func runConfig(t *testing.T, args ...string) (code int, stdout, stderr string) {
	t.Helper()
	var out, errs bytes.Buffer
	code = run(commandContext(t), append([]string{"config"}, args...), &out, &errs)
	return code, out.String(), errs.String()
}

func TestConfigValidateChecksWithoutStarting(t *testing.T) {
	t.Setenv("SFTPIT_CONFIG_TEST_PASSWORD", "secret")
	dir := t.TempDir()
	config := filepath.Join(dir, "sftpit.yaml")
	testutil.WriteFile(t, config, validConfig)
	testutil.WriteFile(t, filepath.Join(dir, ".env"), "SFTPIT_CONFIG_TEST_OTHER=other\n")

	code, stdout, stderr := runConfig(t, "validate", "--config", config)
	if code != exitOK || stdout != config+" is valid: 2 users and 1 scenario\n" || stderr != "" {
		t.Errorf("validate = %d with stdout %q and stderr %q, want the configuration reported valid", code, stdout, stderr)
	}
	if entries, err := os.ReadDir(dir); err != nil || len(entries) != 2 {
		t.Errorf("validate left %v in the config's directory (%v), want only the config and env file", entries, err)
	}

	testutil.WriteFile(t, filepath.Join(dir, "scenarios", "quiet.yaml"), "schema_version: 1\nfaults: []\n")
	if code, stdout, _ := runConfig(t, "validate", "--config", config); code != exitOK || stdout != config+" is valid: 2 users, 1 scenario and 1 scenario file\n" {
		t.Errorf("validate = %d with stdout %q, want the scenario file counted", code, stdout)
	}
	testutil.WriteFile(t, filepath.Join(dir, "scenarios", "upload-recovery.yaml"), "schema_version: 1\nfaults: []\n")
	if code, _, stderr := runConfig(t, "validate", "--config", config); code != exitUsage || !strings.Contains(stderr, "the configuration file defines a scenario upload-recovery too") {
		t.Errorf("validate = %d with stderr %q, want the clash with the configuration reported", code, stderr)
	}
	if err := os.Remove(filepath.Join(dir, "scenarios", "upload-recovery.yaml")); err != nil {
		t.Fatal(err)
	}

	if err := os.Chmod(filepath.Join(dir, ".env"), 0o644); err != nil {
		t.Fatal(err)
	}
	if code, _, stderr := runConfig(t, "validate", "--config", config); code != exitOK || !strings.Contains(stderr, "sftpit config validate: warning: env file") {
		t.Errorf("validate = %d with stderr %q, want a warning about the readable env file", code, stderr)
	}

	tests := []struct {
		name, config, want string
	}{
		{"an invalid scenario", strings.Replace(validConfig, "after_bytes: 1048576", "after_bytes: 1048576, result: retry", 1), `sftpit config validate: scenarios.upload-recovery.faults[0] (first-upload-cutoff): fail_upload: action: result "retry" is not status`},
		{"a missing secret", strings.Replace(validConfig, "SFTPIT_CONFIG_TEST_OTHER", "SFTPIT_CONFIG_TEST_UNSET", 1), "sftpit config validate: SFTPIT_CONFIG_TEST_UNSET is not set in the environment or "},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			testutil.WriteFile(t, config, tt.config)
			code, stdout, stderr := runConfig(t, "validate", "--config", config)
			if code != exitUsage || stdout != "" || !strings.Contains(stderr, tt.want) {
				t.Errorf("validate = %d with stdout %q and stderr %q, want %d and %q", code, stdout, stderr, exitUsage, tt.want)
			}
		})
	}
}

func TestConfigExplainPrintsTheConfigurationAsRead(t *testing.T) {
	dir := t.TempDir()
	config := filepath.Join(dir, "sftpit.yaml")
	testutil.WriteFile(t, config, validConfig)
	extra := filepath.Join(dir, "extra.env")
	testutil.WriteFile(t, extra, "SFTPIT_CONFIG_TEST_PASSWORD=secret\n")

	// A missing secret is shown, not refused.
	code, stdout, stderr := runConfig(t, "explain", "--config", config, "--env-file", extra)
	if code != exitOK || stderr != "" {
		t.Fatalf("explain = %d with stderr %q", code, stderr)
	}
	for _, want := range []string{
		"# The configuration sftpit reads from " + config + ".\n",
		"#   SFTPIT_CONFIG_TEST_PASSWORD: from " + extra + "\n",
		"#   SFTPIT_CONFIG_TEST_OTHER: missing; it is not in the environment or " + filepath.Join(dir, ".env") + " (not found), " + extra + "\n",
		"env_file: [" + filepath.Join(dir, ".env") + ", " + extra + "]\n",
		"          type: partial_upload\n          cutoff_offset: 1048576\n          result: status\n          status: failure\n",
	} {
		if !strings.Contains(stdout, want) {
			t.Errorf("explain printed\n%s\nwant it to hold\n%s", stdout, want)
		}
	}
	if strings.Contains(stdout, "secret\n") {
		t.Errorf("explain printed a secret:\n%s", stdout)
	}

	testutil.WriteFile(t, config, validConfig+"      - {id: bad, match: {operation: upload}, action: {type: fail, when: before, status: failure}}\n")
	if code, stdout, stderr := runConfig(t, "explain", "--config", config); code != exitUsage || stdout != "" || !strings.Contains(stderr, `sftpit config explain: scenarios.upload-recovery: faults: rule "bad": unknown operation "upload"`) {
		t.Errorf("explain = %d with stdout %q and stderr %q, want the invalid rule reported", code, stdout, stderr)
	}
}

func TestConfigReadsTheFileAsTheProfileWould(t *testing.T) {
	config := filepath.Join(t.TempDir(), "sftpit.yaml")
	testutil.WriteFile(t, config, "schema_version: 1\nserver:\n  sftp_listen: \"0.0.0.0:2122\"\n")
	if code, _, stderr := runConfig(t, "validate", "--config", config); code != exitUsage || !strings.Contains(stderr, "is not a loopback address") {
		t.Errorf("validate = %d with stderr %q, want the address refused in the loopback profile", code, stderr)
	}
	if code, stdout, stderr := runConfig(t, "validate", "--profile", "container", "--config", config); code != exitOK || stderr != "" {
		t.Errorf("validate --profile container = %d with stdout %q and stderr %q, want it valid", code, stdout, stderr)
	}
	code, stdout, stderr := runConfig(t, "explain", "--profile", "container", "--config", config)
	if code != exitOK || !strings.Contains(stdout, "sftp_listen: 0.0.0.0:2122\n") || !strings.Contains(stdout, "http_listen: :8122\n") {
		t.Errorf("explain --profile container = %d with stderr %q, want the container profile's addresses:\n%s", code, stderr, stdout)
	}
}

func TestConfigRejectsBadCommandLines(t *testing.T) {
	config := filepath.Join(t.TempDir(), "sftpit.yaml")
	testutil.WriteFile(t, config, "schema_version: 1\n")
	tests := []struct {
		name string
		args []string
		want string
	}{
		{"no command", nil, "sftpit config: expected validate or explain"},
		{"an unknown command", []string{"check"}, "sftpit config: expected validate or explain"},
		{"no config", []string{"validate"}, "sftpit config validate: --config is required"},
		{"an unknown flag", []string{"explain", "--config", config, "--scenario", "s"}, "sftpit config explain: flag provided but not defined: -scenario"},
		{"a stray argument", []string{"validate", "--config", config, "extra"}, `sftpit config validate: unexpected arguments ["extra"]`},
		{"a missing file", []string{"validate", "--config", config + ".missing"}, "sftpit config validate: config: open "},
		{"an unknown profile", []string{"validate", "--config", config, "--profile", "remote"}, `sftpit config validate: invalid value "remote" for flag -profile`},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			code, stdout, stderr := runConfig(t, tt.args...)
			if code != exitUsage || stdout != "" || !strings.Contains(stderr, tt.want) {
				t.Errorf("config %q = %d with stdout %q and stderr %q, want %d and %q", tt.args, code, stdout, stderr, exitUsage, tt.want)
			}
		})
	}
	for _, args := range [][]string{{"--help"}, {"help"}, {"validate", "--help"}, {"explain", "-h"}} {
		if code, stdout, _ := runConfig(t, args...); code != exitOK || !strings.HasPrefix(stdout, "Usage: sftpit config <command>") {
			t.Errorf("config %q = %d with stdout %q, want the usage", args, code, stdout)
		}
	}
}
