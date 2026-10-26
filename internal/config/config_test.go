package config

import (
	"maps"
	"os"
	"path/filepath"
	"slices"
	"strings"
	"testing"

	"github.com/nebarg/sftpit/internal/backend"
	"github.com/nebarg/sftpit/internal/sftpproxy"
)

func TestLoadWithoutAConfigFileUsesTheDefaults(t *testing.T) {
	cfg, err := Load(Options{LookupEnv: noEnv})
	if err != nil {
		t.Fatalf("Load: %v", err)
	}
	if cfg.SFTPListen != DefaultSFTPListen || cfg.HTTPListen != DefaultHTTPListen || cfg.HostKeyDir != "" || !cfg.DefaultCredentials {
		t.Errorf("Load = %+v, want the defaults", cfg)
	}
	if len(cfg.Users) != 1 || cfg.Users[0].Name != "test" || cfg.Users[0].Password != "test" || cfg.Users[0].Home != "/" {
		t.Errorf("users = %+v, want test/test", cfg.Users)
	}
	want := backend.Limits{MaxFileBytes: 1 << 30, MaxTotalBytes: 4 << 30, MaxFiles: 10000, MaxOpenFiles: 256}
	if cfg.Limits != want {
		t.Errorf("Limits = %+v, want %+v", cfg.Limits, want)
	}
}

func TestLoadReadsEachStorageLimit(t *testing.T) {
	config := writeTestFile(t, filepath.Join(t.TempDir(), "sftpit.yaml"), `
schema_version: 1
storage:
  max_file_bytes: 16777216
  max_total_bytes: 67108864
  max_files: 1
  max_open_files: 2
`)
	cfg, err := Load(Options{ConfigFile: config, LookupEnv: noEnv})
	if err != nil {
		t.Fatalf("Load: %v", err)
	}
	want := backend.Limits{MaxFileBytes: 16777216, MaxTotalBytes: 67108864, MaxFiles: 1, MaxOpenFiles: 2}
	if cfg.Limits != want {
		t.Errorf("Limits = %+v, want %+v", cfg.Limits, want)
	}

	config = writeTestFile(t, config, "schema_version: 1\nstorage:\n  max_files: 1\n")
	cfg, err = Load(Options{ConfigFile: config, LookupEnv: noEnv})
	if err != nil {
		t.Fatalf("Load: %v", err)
	}
	want = DefaultLimits()
	want.MaxFiles = 1
	if cfg.Limits != want {
		t.Errorf("Limits with one set = %+v, want the defaults for the others, %+v", cfg.Limits, want)
	}
}

func TestLoadReadsAFullConfig(t *testing.T) {
	dir := t.TempDir()
	key := writeAuthorizedKeys(t, filepath.Join(dir, "keys", "partner-b.pub"), "")
	writeTestFile(t, filepath.Join(dir, ".env"), "SFTPIT_TEST_PASSWORD='from the env file'\n")
	config := writeTestFile(t, filepath.Join(dir, "sftpit.yaml"), `
schema_version: 1
env_file: ".env"
server:
  sftp_listen: "127.0.0.1:2200"
  http_listen: "127.0.0.1:8200"
  host_key: "./hostkeys"
users:
  - name: "test"
    password_env: "SFTPIT_TEST_PASSWORD"
  - name: "partner-b"
    authorized_keys: "./keys/partner-b.pub"
    home: "/partner-b/./in/.."
`)

	cfg, err := Load(Options{ConfigFile: config, LookupEnv: noEnv})
	if err != nil {
		t.Fatalf("Load: %v", err)
	}
	if cfg.SFTPListen != "127.0.0.1:2200" || cfg.HTTPListen != "127.0.0.1:8200" {
		t.Errorf("SFTPListen = %q, HTTPListen = %q", cfg.SFTPListen, cfg.HTTPListen)
	}
	if cfg.HostKeyDir != filepath.Join(dir, "hostkeys") {
		t.Errorf("HostKeyDir = %q, want it next to the config file", cfg.HostKeyDir)
	}
	if cfg.DefaultCredentials || len(cfg.Warnings) != 0 {
		t.Errorf("DefaultCredentials = %v, Warnings = %v", cfg.DefaultCredentials, cfg.Warnings)
	}
	if len(cfg.Users) != 2 {
		t.Fatalf("users = %+v", cfg.Users)
	}
	if u := cfg.Users[0]; u.Name != "test" || u.Password != "from the env file" || u.Home != "/" || len(u.AuthorizedKeys) != 0 {
		t.Errorf("users[0] = %+v", u)
	}
	u := cfg.Users[1]
	if u.Name != "partner-b" || u.Password != "" || u.Home != "/partner-b" {
		t.Errorf("users[1] = %+v", u)
	}
	if len(u.AuthorizedKeys) != 1 || string(u.AuthorizedKeys[0].Marshal()) != string(key.Marshal()) {
		t.Errorf("users[1] keys = %v, want the key from the file", u.AuthorizedKeys)
	}
}

func TestLoadAppliesTheFlagOverrides(t *testing.T) {
	config := writeTestFile(t, filepath.Join(t.TempDir(), "sftpit.yaml"), "schema_version: 1\nserver:\n  sftp_listen: \"127.0.0.1:2200\"\n  http_listen: \"127.0.0.1:8200\"\n")
	cfg, err := Load(Options{ConfigFile: config, SFTPListen: "[::1]:0", HTTPListen: "localhost:0", LookupEnv: noEnv})
	if err != nil {
		t.Fatalf("Load: %v", err)
	}
	if cfg.SFTPListen != "[::1]:0" || cfg.HTTPListen != "localhost:0" {
		t.Errorf("SFTPListen = %q, HTTPListen = %q, want the flags' values", cfg.SFTPListen, cfg.HTTPListen)
	}
}

func TestLoadResolvesTheSeedDirectory(t *testing.T) {
	dir := t.TempDir()
	if err := os.MkdirAll(filepath.Join(dir, "fixtures", "seed"), 0o755); err != nil {
		t.Fatal(err)
	}
	config := writeTestFile(t, filepath.Join(dir, "sftpit.yaml"), "schema_version: 1\nstorage:\n  seed_dir: fixtures/seed\n")

	cfg, err := Load(Options{ConfigFile: config, LookupEnv: noEnv})
	if err != nil {
		t.Fatalf("Load: %v", err)
	}
	if want := filepath.Join(dir, "fixtures", "seed"); cfg.SeedDir != want {
		t.Errorf("SeedDir = %q, want %q", cfg.SeedDir, want)
	}

	override := t.TempDir()
	cfg, err = Load(Options{ConfigFile: config, SeedDir: override, LookupEnv: noEnv})
	if err != nil {
		t.Fatalf("Load with --seed-dir: %v", err)
	}
	if cfg.SeedDir != override {
		t.Errorf("SeedDir = %q, want the flag's %q", cfg.SeedDir, override)
	}
}

func TestLoadRejectsUnsuitableSeedDirectories(t *testing.T) {
	file := writeTestFile(t, filepath.Join(t.TempDir(), "orders.csv"), "data")
	home, err := os.UserHomeDir()
	if err != nil {
		t.Skipf("no home directory: %v", err)
	}
	tests := map[string]string{
		filepath.Join(t.TempDir(), "missing"): "no such file",
		file:                                  "is not a directory",
		home:                                  "would copy the whole tree",
		string(filepath.Separator):            "would copy the whole tree",
	}
	for seed, want := range tests {
		if _, err := Load(Options{SeedDir: seed, LookupEnv: noEnv}); err == nil || !strings.Contains(err.Error(), want) {
			t.Errorf("%s: error = %v, want %q", seed, err, want)
		}
	}
}

func TestLoadResolvesTheDataDirectory(t *testing.T) {
	dir := t.TempDir()
	config := writeTestFile(t, filepath.Join(dir, "sftpit.yaml"), "schema_version: 1\nstorage:\n  data_dir: sandbox-data\n")

	cfg, err := Load(Options{ConfigFile: config, LookupEnv: noEnv})
	if err != nil {
		t.Fatalf("Load: %v", err)
	}
	if want := filepath.Join(dir, "sandbox-data"); cfg.DataDir != want {
		t.Errorf("DataDir = %q, want %q, which need not exist yet", cfg.DataDir, want)
	}

	override := t.TempDir()
	cfg, err = Load(Options{ConfigFile: config, DataDir: override, LookupEnv: noEnv})
	if err != nil {
		t.Fatalf("Load with --data-dir: %v", err)
	}
	if cfg.DataDir != override {
		t.Errorf("DataDir = %q, want the flag's %q", cfg.DataDir, override)
	}
}

func TestLoadRejectsUnsuitableDataDirectories(t *testing.T) {
	home, err := os.UserHomeDir()
	if err != nil {
		t.Skipf("no home directory: %v", err)
	}
	seed := t.TempDir()
	tests := []struct {
		dataDir string
		want    string
	}{
		{dataDir: home, want: "is the filesystem root or the home directory"},
		{dataDir: string(filepath.Separator), want: "is the filesystem root or the home directory"},
		{dataDir: seed, want: "is inside seed_dir"},
		{dataDir: filepath.Join(seed, "sandbox-data"), want: "is inside seed_dir"},
	}
	for _, tt := range tests {
		if _, err := Load(Options{DataDir: tt.dataDir, SeedDir: seed, LookupEnv: noEnv}); err == nil || !strings.Contains(err.Error(), tt.want) {
			t.Errorf("%s: error = %v, want %q", tt.dataDir, err, tt.want)
		}
	}
}

func TestLoadAcceptsOnlyLoopbackAddresses(t *testing.T) {
	settings := map[string]func(addr string) Options{
		"sftp_listen": func(addr string) Options { return Options{SFTPListen: addr, LookupEnv: noEnv} },
		"http_listen": func(addr string) Options { return Options{HTTPListen: addr, LookupEnv: noEnv} },
	}
	for setting, options := range settings {
		for _, addr := range []string{"127.0.0.1:2122", "127.0.0.2:22", "[::1]:0", "localhost:2122"} {
			if _, err := Load(options(addr)); err != nil {
				t.Errorf("%s %s: %v", setting, addr, err)
			}
		}
		tests := map[string]string{
			":2122":          "not a loopback address; sftpit listens only on loopback, such as 127.0.0.1:2122 or [::1]:2122",
			"0.0.0.0:2122":   "not a loopback address",
			"[::]:2122":      "not a loopback address",
			"192.0.2.1:2122": "not a loopback address",
			"example.com:22": "not a loopback address",
			"127.0.0.1":      "missing port",
			"127.0.0.1:ssh":  "must be a number",
			"127.0.0.1:2e5":  "must be a number",
		}
		for addr, want := range tests {
			if _, err := Load(options(addr)); err == nil || !strings.HasPrefix(err.Error(), setting+" ") || !strings.Contains(err.Error(), want) {
				t.Errorf("%s %s: error = %v, want %q about %s", setting, addr, err, want, setting)
			}
		}
	}
}

func TestLoadRejectsInvalidFiles(t *testing.T) {
	dir := t.TempDir()
	writeAuthorizedKeys(t, filepath.Join(dir, "optioned.pub"), `from="10.0.0.1" `)
	writeTestFile(t, filepath.Join(dir, "empty.pub"), "# no keys\n")
	writeTestFile(t, filepath.Join(dir, "broken.pub"), "\nnot-a-key AAAA\n")

	tests := []struct {
		name    string
		content string
		want    string
	}{
		{"empty file", "", "the file is empty"},
		{"no schema version", "server: {}\n", "schema_version is required"},
		{"future schema version", "schema_version: 2\n", "schema_version 2 is not supported"},
		{"unknown field", "schema_version: 1\nserver:\n  smtp_listen: \"127.0.0.1:1025\"\n", "field smtp_listen not found"},
		{"duplicate key", "schema_version: 1\nschema_version: 1\n", "already defined"},
		{"two documents", "schema_version: 1\n---\nschema_version: 1\n", "a single YAML document"},
		{"wrong type", "schema_version: \"1\"\n", "cannot unmarshal"},
		{"env_file mapping", "schema_version: 1\nenv_file: {a: b}\n", "a string or a list of strings"},
		{"non-loopback listen", "schema_version: 1\nserver:\n  sftp_listen: \"0.0.0.0:2122\"\n", "not a loopback address"},
		{"limit turned off", "schema_version: 1\nstorage:\n  max_files: 0\n", "max_files is 0; storage limits must be at least 1"},
		{"negative limit", "schema_version: 1\nstorage:\n  max_open_files: -1\n", "max_open_files is -1"},
		{"limit with a unit", "schema_version: 1\nstorage:\n  max_total_bytes: 64MiB\n", "cannot unmarshal"},
		{"user without a name", "schema_version: 1\nusers:\n  - password_env: P\n", "users[0]: name is required"},
		{"duplicate user", "schema_version: 1\nusers:\n  - {name: a, password_env: P}\n  - {name: a, password_env: P}\n", "users[1] (a): users[0] has the same name"},
		{"user without credentials", "schema_version: 1\nusers:\n  - name: a\n", "set password_env, authorized_keys or both"},
		{"invalid variable name", "schema_version: 1\nusers:\n  - {name: a, password_env: \"MY-PASSWORD\"}\n", "not a valid environment variable name"},
		{"relative home", "schema_version: 1\nusers:\n  - {name: a, password_env: P, home: in}\n", `home "in" must be an absolute SFTP path`},
		{"missing key file", "schema_version: 1\nusers:\n  - {name: a, authorized_keys: missing.pub}\n", "no such file"},
		{"key options", "schema_version: 1\nusers:\n  - {name: a, authorized_keys: optioned.pub}\n", "optioned.pub:2: key options"},
		{"no keys", "schema_version: 1\nusers:\n  - {name: a, authorized_keys: empty.pub}\n", "empty.pub: no keys found"},
		{"bad key", "schema_version: 1\nusers:\n  - {name: a, authorized_keys: broken.pub}\n", "broken.pub:2: "},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			config := writeTestFile(t, filepath.Join(dir, "sftpit.yaml"), tt.content)
			_, err := Load(Options{ConfigFile: config, LookupEnv: fakeEnv{"P": "password"}.lookup})
			if err == nil || !strings.Contains(err.Error(), tt.want) {
				t.Errorf("error = %v, want %q", err, tt.want)
			}
		})
	}
}

func TestLookupSecretsPrefersTheEnvironmentThenLaterFiles(t *testing.T) {
	dir := t.TempDir()
	first := writeTestFile(t, filepath.Join(dir, "first.env"), "FROM_ENV=file\nFIRST=first\nLATER=first\n")
	second := writeTestFile(t, filepath.Join(dir, "second.env"), "LATER=second\nUNUSED=unused\n")
	env := fakeEnv{"FROM_ENV": "environment"}

	names := map[string]bool{"FROM_ENV": true, "FIRST": true, "LATER": true}
	l, err := lookupSecrets(names, []string{first, second}, env.lookup)
	if err != nil {
		t.Fatalf("lookupSecrets: %v", err)
	}
	if err := l.check(); err != nil {
		t.Errorf("check: %v", err)
	}
	want := map[string]string{"FROM_ENV": "environment", "FIRST": "first", "LATER": "second"}
	if !maps.Equal(l.values, want) {
		t.Errorf("values = %v, want only the referenced variables, %v", l.values, want)
	}
	if want := map[string]string{"FROM_ENV": "the environment", "FIRST": first, "LATER": second}; !maps.Equal(l.sources, want) {
		t.Errorf("sources = %v, want %v", l.sources, want)
	}
}

func TestLookupSecretsNeverSetsTheProcessEnvironment(t *testing.T) {
	const name = "SFTPIT_CONFIG_TEST_SECRET"
	file := writeTestFile(t, filepath.Join(t.TempDir(), "test.env"), name+"=value\n")
	if _, err := lookupSecrets(map[string]bool{name: true}, []string{file}, os.LookupEnv); err != nil {
		t.Fatalf("lookupSecrets: %v", err)
	}
	if _, ok := os.LookupEnv(name); ok {
		t.Errorf("%s was added to the process environment", name)
	}
}

func TestLookupSecretsReportsWhereItLooked(t *testing.T) {
	dir := t.TempDir()
	present := writeTestFile(t, filepath.Join(dir, "present.env"), "OTHER=1\n")
	absent := filepath.Join(dir, "absent.env")

	l, err := lookupSecrets(map[string]bool{"SECRET": true}, []string{absent, present}, noEnv)
	if err != nil {
		t.Fatalf("lookupSecrets: %v", err)
	}
	if !slices.Equal(l.missing, []string{"SECRET"}) {
		t.Errorf("missing = %v, want SECRET", l.missing)
	}
	want := "SECRET is not set in the environment or " + absent + " (not found), " + present
	if err := l.check(); err == nil || err.Error() != want {
		t.Errorf("check = %v, want %q", err, want)
	}

	empty := writeTestFile(t, filepath.Join(dir, "empty.env"), "SECRET=\n")
	if l, err = lookupSecrets(map[string]bool{"SECRET": true}, []string{empty}, noEnv); err != nil {
		t.Fatalf("lookupSecrets: %v", err)
	}
	if err := l.check(); err == nil || err.Error() != "SECRET is set but empty" {
		t.Errorf("check = %v, want an empty value rejected", err)
	}
}

func TestLookupSecretsChecksEveryDeclaredFile(t *testing.T) {
	malformed := writeTestFile(t, filepath.Join(t.TempDir(), "bad.env"), "NOT A LINE\n")
	_, err := lookupSecrets(map[string]bool{}, []string{malformed}, noEnv)
	if err == nil || !strings.Contains(err.Error(), "bad.env:1: expected KEY=value") {
		t.Errorf("error = %v, want the malformed file reported", err)
	}
}

func TestLoadReadsEnvFilesFromTheCommandLineLast(t *testing.T) {
	dir := t.TempDir()
	writeTestFile(t, filepath.Join(dir, "config.env"), "P=from-config-env-file\n")
	flagFile := writeTestFile(t, filepath.Join(dir, "flag.env"), "P=from-flag-env-file\n")
	config := writeTestFile(t, filepath.Join(dir, "sftpit.yaml"),
		"schema_version: 1\nenv_file: [config.env]\nusers:\n  - {name: a, password_env: P}\n")

	cfg, err := Load(Options{ConfigFile: config, EnvFiles: []string{flagFile}, LookupEnv: noEnv})
	if err != nil {
		t.Fatalf("Load: %v", err)
	}
	if got := cfg.Users[0].Password; got != "from-flag-env-file" {
		t.Errorf("password = %q, want the --env-file value", got)
	}
}

func TestLoadReadsTheReplyOrder(t *testing.T) {
	config := filepath.Join(t.TempDir(), "sftpit.yaml")
	tests := []struct {
		setting string
		want    sftpproxy.ReplyOrder
	}{
		{"", sftpproxy.RequestOrder},
		{"server:\n  reply_order: request\n", sftpproxy.RequestOrder},
		{"server:\n  reply_order: completion\n", sftpproxy.CompletionOrder},
	}
	for _, tt := range tests {
		writeTestFile(t, config, "schema_version: 1\n"+tt.setting)
		cfg, err := Load(Options{ConfigFile: config, LookupEnv: noEnv})
		if err != nil {
			t.Fatalf("Load with %q: %v", tt.setting, err)
		}
		if cfg.ReplyOrder != tt.want {
			t.Errorf("with %q, ReplyOrder = %v, want %v", tt.setting, cfg.ReplyOrder, tt.want)
		}
	}

	writeTestFile(t, config, "schema_version: 1\nserver:\n  reply_order: random\n")
	if _, err := Load(Options{ConfigFile: config, LookupEnv: noEnv}); err == nil || !strings.Contains(err.Error(), `reply_order "random" is not request or completion`) {
		t.Errorf("Load of an unknown reply order = %v, want it refused", err)
	}
}
