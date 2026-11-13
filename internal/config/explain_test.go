package config

import (
	"os"
	"path/filepath"
	"reflect"
	"strings"
	"testing"

	"github.com/nebarg/sftpit/internal/testutil"
)

func TestExplainedConfigurationsLoadTheSame(t *testing.T) {
	opts := writeFullConfig(t)
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
	elsewhere := testutil.WriteFile(t, filepath.Join(t.TempDir(), "explained.yaml"), string(explained))
	got, err := Load(Options{ConfigFile: elsewhere, LookupEnv: opts.LookupEnv})
	if err != nil {
		t.Fatalf("Load of the explained configuration: %v\n%s", err, explained)
	}
	// Explain fills in each fault's preset and defaults, which describe
	// the same faults.
	for _, cfg := range []*Config{want, got} {
		for name, sc := range cfg.Scenarios.configured {
			if cfg.Scenarios.configured[name], err = sc.Resolved(); err != nil {
				t.Fatal(err)
			}
		}
	}
	if !reflect.DeepEqual(got, want) {
		t.Errorf("the explained configuration loads as\n%+v\nwant\n%+v\nexplained:\n%s", got, want, explained)
	}
}

// writeFullConfig writes a configuration that sets every field, and returns
// the options that load it.
func writeFullConfig(t *testing.T) Options {
	t.Helper()
	dir := t.TempDir()
	writeAuthorizedKeys(t, filepath.Join(dir, "keys", "partner-b.pub"), "")
	writeAuthorizedKeys(t, filepath.Join(dir, "keys", "robot.pub"), "")
	testutil.WriteFile(t, filepath.Join(dir, ".env"), "P2=second-secret\n")
	testutil.WriteFile(t, filepath.Join(dir, "seed", "incoming", ".gitkeep"), "")
	config := testutil.WriteFile(t, filepath.Join(dir, "sftpit.yaml"), `schema_version: 1
env_file: .env
scenarios_dir: ./saved
server: {sftp_listen: "127.0.0.1:2200", http_listen: "127.0.0.1:8200", host_key: ./hostkeys, reply_order: completion}
storage: {data_dir: ./data, seed_dir: ./seed, max_files: 500}
users:
  - {name: test, password_env: P}
  - {name: partner-b, password_env: P2, authorized_keys: keys/partner-b.pub, home: /partner-b}
  - {name: robot, authorized_keys: keys/robot.pub}
policy:
  read_only:
    - {path_prefix: /reference}
    - {path_prefix: /outgoing, users: [partner-b, robot]}
scenarios:
  partner-trouble:
    description: "Deletes fail for partner-b,\nand listings are slow."
    faults:
      - {preset: deletes_fail, user: partner-b}
      - {name: Slow listings, steps: [list, stat], do: wait, seconds: 1.5, folder: /outgoing, percent: 50}
  outage:
    faults:
      - {preset: server_goes_down, seconds: 10}
      - {steps: [authenticate], do: drop, abrupt: true, only: 2}
`)
	return Options{ConfigFile: config, LookupEnv: fakeEnv{"P": "first-secret"}.lookup}
}

func TestExplainFillsInEachFaultsPresetAndDefaults(t *testing.T) {
	config := testutil.WriteFile(t, filepath.Join(t.TempDir(), "sftpit.yaml"), `schema_version: 1
scenarios:
  upload-recovery:
    faults:
      - {preset: upload_stops_partway, first: 1}
      - {steps: [rename], do: refuse}
`)
	explained, err := Explain(Options{ConfigFile: config, LookupEnv: noEnv})
	if err != nil {
		t.Fatalf("Explain: %v", err)
	}
	want := `scenarios:
  upload-recovery:
    faults:
      - name: Uploads stop partway
        preset: upload_stops_partway
        steps: [write]
        do: stop_partway
        kb: 32
        first: 1
      - name: Custom fault
        steps: [rename]
        do: refuse
        error: failure
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
	envFile := testutil.WriteFile(t, filepath.Join(dir, ".env"), "FROM_FILE=x\nEMPTY=\n")
	absent := filepath.Join(dir, "absent.env")
	config := testutil.WriteFile(t, filepath.Join(dir, "sftpit.yaml"), `schema_version: 1
env_file: [.env, absent.env]
users:
  - {name: a, password_env: FROM_ENV}
  - {name: b, password_env: FROM_FILE}
  - {name: c, password_env: EMPTY}
  - {name: d, password_env: MISSING}
`)
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
	config := testutil.WriteFile(t, filepath.Join(t.TempDir(), "sftpit.yaml"), "schema_version: 1\nscenarios:\n  s:\n    faults:\n      - {steps: [upload], do: refuse}\n")
	if _, err := Explain(Options{ConfigFile: config, LookupEnv: noEnv}); err == nil || !strings.Contains(err.Error(), `there is no step "upload"`) {
		t.Errorf("Explain = %v, want the unknown step reported", err)
	}
}

// TestExplainWritesAbsolutePathsForARelativeConfig checks a configuration
// named by a relative path, whose own paths are relative too: ./workspace
// must not come out as the keyword for the workspace's own keys.
func TestExplainWritesAbsolutePathsForARelativeConfig(t *testing.T) {
	t.Chdir(t.TempDir())
	writeAuthorizedKeys(t, "configs/keys/partner.pub", "")
	testutil.WriteFile(t, "configs/.env", "P=first\n")
	testutil.WriteFile(t, "extra.env", "Q=second\n")
	testutil.WriteFile(t, "configs/sftpit.yaml", `schema_version: 1
env_file: .env
server:
  host_key: ./workspace
users:
  - name: partner
    password_env: P
    authorized_keys: keys/partner.pub
`)
	opts := Options{ConfigFile: "configs/sftpit.yaml", EnvFiles: []string{"extra.env"}, LookupEnv: noEnv}
	want, err := Load(opts)
	if err != nil {
		t.Fatalf("Load: %v", err)
	}
	explained, err := Explain(opts)
	if err != nil {
		t.Fatalf("Explain: %v", err)
	}
	dir, err := os.Getwd()
	if err != nil {
		t.Fatal(err)
	}
	for _, name := range []string{"configs/.env", "configs/workspace", "configs/keys/partner.pub", "extra.env"} {
		if abs := filepath.Join(dir, name); !strings.Contains(string(explained), abs) {
			t.Errorf("the explained configuration lacks the absolute path %s:\n%s", abs, explained)
		}
	}

	t.Chdir(t.TempDir())
	got, err := Load(Options{ConfigFile: testutil.WriteFile(t, "explained.yaml", string(explained)), LookupEnv: noEnv})
	if err != nil {
		t.Fatalf("Load of the explained configuration from elsewhere: %v\n%s", err, explained)
	}
	if !reflect.DeepEqual(got, want) {
		t.Errorf("the explained configuration loads as\n%+v\nwant\n%+v\nexplained:\n%s", got, want, explained)
	}
}
