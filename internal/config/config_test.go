package config

import (
	"crypto/ed25519"
	"crypto/rand"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"golang.org/x/crypto/ssh"
)

func TestLoadWithoutAConfigFileUsesTheDefaults(t *testing.T) {
	cfg, err := Load(Options{LookupEnv: noEnv})
	if err != nil {
		t.Fatalf("Load: %v", err)
	}
	if cfg.SFTPListen != DefaultSFTPListen || cfg.HostKeyDir != "" || !cfg.DefaultCredentials {
		t.Errorf("Load = %+v, want the defaults", cfg)
	}
	if len(cfg.Users) != 1 || cfg.Users[0].Name != "test" || cfg.Users[0].Password != "test" || cfg.Users[0].Home != "/" {
		t.Errorf("users = %+v, want test/test", cfg.Users)
	}
}

func TestLoadReadsAFullConfig(t *testing.T) {
	dir := t.TempDir()
	key := writeAuthorizedKeys(t, filepath.Join(dir, "keys", "partner-b.pub"), "")
	writeTestFile(t, filepath.Join(dir, ".env"), "SFTPIT_TEST_PASSWORD='from the env file'\n", 0o600)
	config := writeTestFile(t, filepath.Join(dir, "sftpit.yaml"), `
schema_version: 1
env_file: ".env"
server:
  sftp_listen: "127.0.0.1:2200"
  host_key: "./hostkeys"
users:
  - name: "test"
    password_env: "SFTPIT_TEST_PASSWORD"
  - name: "partner-b"
    authorized_keys: "./keys/partner-b.pub"
    home: "/partner-b/./in/.."
`, 0o600)

	cfg, err := Load(Options{ConfigFile: config, LookupEnv: noEnv})
	if err != nil {
		t.Fatalf("Load: %v", err)
	}
	if cfg.SFTPListen != "127.0.0.1:2200" {
		t.Errorf("SFTPListen = %q", cfg.SFTPListen)
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

func TestLoadAppliesTheFlagOverride(t *testing.T) {
	config := writeTestFile(t, filepath.Join(t.TempDir(), "sftpit.yaml"), "schema_version: 1\nserver:\n  sftp_listen: \"127.0.0.1:2200\"\n", 0o600)
	cfg, err := Load(Options{ConfigFile: config, SFTPListen: "[::1]:0", LookupEnv: noEnv})
	if err != nil {
		t.Fatalf("Load: %v", err)
	}
	if cfg.SFTPListen != "[::1]:0" {
		t.Errorf("SFTPListen = %q, want the flag's value", cfg.SFTPListen)
	}
}

func TestLoadResolvesTheSeedDirectory(t *testing.T) {
	dir := t.TempDir()
	if err := os.MkdirAll(filepath.Join(dir, "fixtures", "seed"), 0o755); err != nil {
		t.Fatal(err)
	}
	config := writeTestFile(t, filepath.Join(dir, "sftpit.yaml"), "schema_version: 1\nstorage:\n  seed_dir: fixtures/seed\n", 0o600)

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
	file := writeTestFile(t, filepath.Join(t.TempDir(), "orders.csv"), "data", 0o600)
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
	config := writeTestFile(t, filepath.Join(dir, "sftpit.yaml"), "schema_version: 1\nstorage:\n  data_dir: sandbox-data\n", 0o600)

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
	for _, addr := range []string{"127.0.0.1:2122", "127.0.0.2:22", "[::1]:0", "localhost:2122"} {
		if _, err := Load(Options{SFTPListen: addr, LookupEnv: noEnv}); err != nil {
			t.Errorf("%s: %v", addr, err)
		}
	}
	tests := map[string]string{
		":2122":          "not a loopback address",
		"0.0.0.0:2122":   "not a loopback address",
		"[::]:2122":      "not a loopback address",
		"192.0.2.1:2122": "not a loopback address",
		"example.com:22": "not a loopback address",
		"127.0.0.1":      "missing port",
		"127.0.0.1:ssh":  "must be a number",
		"127.0.0.1:2e5":  "must be a number",
	}
	for addr, want := range tests {
		if _, err := Load(Options{SFTPListen: addr, LookupEnv: noEnv}); err == nil || !strings.Contains(err.Error(), want) {
			t.Errorf("%s: error = %v, want %q", addr, err, want)
		}
	}
}

func TestLoadRejectsInvalidFiles(t *testing.T) {
	dir := t.TempDir()
	writeAuthorizedKeys(t, filepath.Join(dir, "optioned.pub"), `from="10.0.0.1" `)
	writeTestFile(t, filepath.Join(dir, "empty.pub"), "# no keys\n", 0o600)
	writeTestFile(t, filepath.Join(dir, "broken.pub"), "\nnot-a-key AAAA\n", 0o600)

	tests := []struct {
		name    string
		content string
		want    string
	}{
		{"empty file", "", "the file is empty"},
		{"no schema version", "server: {}\n", "schema_version is required"},
		{"future schema version", "schema_version: 2\n", "schema_version 2 is not supported"},
		{"unknown field", "schema_version: 1\nserver:\n  http_listen: \"127.0.0.1:8122\"\n", "field http_listen not found"},
		{"duplicate key", "schema_version: 1\nschema_version: 1\n", "already defined"},
		{"two documents", "schema_version: 1\n---\nschema_version: 1\n", "a single YAML document"},
		{"wrong type", "schema_version: \"1\"\n", "cannot unmarshal"},
		{"env_file mapping", "schema_version: 1\nenv_file: {a: b}\n", "a path or a list of paths"},
		{"non-loopback listen", "schema_version: 1\nserver:\n  sftp_listen: \"0.0.0.0:2122\"\n", "not a loopback address"},
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
			config := writeTestFile(t, filepath.Join(dir, "sftpit.yaml"), tt.content, 0o600)
			_, err := Load(Options{ConfigFile: config, LookupEnv: fakeEnv{"P": "password"}.lookup})
			if err == nil || !strings.Contains(err.Error(), tt.want) {
				t.Errorf("error = %v, want %q", err, tt.want)
			}
		})
	}
}

func TestResolveSecretsPrefersTheEnvironmentThenLaterFiles(t *testing.T) {
	dir := t.TempDir()
	first := writeTestFile(t, filepath.Join(dir, "first.env"), "FROM_ENV=file\nFIRST=first\nLATER=first\n", 0o600)
	second := writeTestFile(t, filepath.Join(dir, "second.env"), "LATER=second\nUNUSED=unused\n", 0o600)
	env := fakeEnv{"FROM_ENV": "environment"}

	names := map[string]bool{"FROM_ENV": true, "FIRST": true, "LATER": true}
	secrets, _, err := resolveSecrets(names, []string{first, second}, env.lookup)
	if err != nil {
		t.Fatalf("resolveSecrets: %v", err)
	}
	want := map[string]string{"FROM_ENV": "environment", "FIRST": "first", "LATER": "second"}
	for name, value := range want {
		if secrets[name] != value {
			t.Errorf("%s = %q, want %q", name, secrets[name], value)
		}
	}
	if len(secrets) != len(want) {
		t.Errorf("secrets = %v, want only the referenced variables", secrets)
	}
}

func TestResolveSecretsNeverSetsTheProcessEnvironment(t *testing.T) {
	const name = "SFTPIT_CONFIG_TEST_SECRET"
	file := writeTestFile(t, filepath.Join(t.TempDir(), "test.env"), name+"=value\n", 0o600)
	if _, _, err := resolveSecrets(map[string]bool{name: true}, []string{file}, os.LookupEnv); err != nil {
		t.Fatalf("resolveSecrets: %v", err)
	}
	if _, ok := os.LookupEnv(name); ok {
		t.Errorf("%s was added to the process environment", name)
	}
}

func TestResolveSecretsReportsWhereItLooked(t *testing.T) {
	dir := t.TempDir()
	present := writeTestFile(t, filepath.Join(dir, "present.env"), "OTHER=1\n", 0o600)
	absent := filepath.Join(dir, "absent.env")

	_, _, err := resolveSecrets(map[string]bool{"SECRET": true}, []string{absent, present}, noEnv)
	want := "SECRET is not set in the environment or " + absent + " (not found), " + present
	if err == nil || err.Error() != want {
		t.Errorf("error = %v, want %q", err, want)
	}

	empty := writeTestFile(t, filepath.Join(dir, "empty.env"), "SECRET=\n", 0o600)
	_, _, err = resolveSecrets(map[string]bool{"SECRET": true}, []string{empty}, noEnv)
	if err == nil || err.Error() != "SECRET is set but empty" {
		t.Errorf("error = %v, want an empty value rejected", err)
	}
}

func TestResolveSecretsChecksEveryDeclaredFile(t *testing.T) {
	malformed := writeTestFile(t, filepath.Join(t.TempDir(), "bad.env"), "NOT A LINE\n", 0o600)
	_, _, err := resolveSecrets(map[string]bool{}, []string{malformed}, noEnv)
	if err == nil || !strings.Contains(err.Error(), "bad.env:1: expected KEY=value") {
		t.Errorf("error = %v, want the malformed file reported", err)
	}
}

func TestLoadReadsEnvFilesFromTheCommandLineLast(t *testing.T) {
	dir := t.TempDir()
	writeTestFile(t, filepath.Join(dir, "config.env"), "P=from-config-env-file\n", 0o600)
	flagFile := writeTestFile(t, filepath.Join(dir, "flag.env"), "P=from-flag-env-file\n", 0o600)
	config := writeTestFile(t, filepath.Join(dir, "sftpit.yaml"),
		"schema_version: 1\nenv_file: [config.env]\nusers:\n  - {name: a, password_env: P}\n", 0o600)

	cfg, err := Load(Options{ConfigFile: config, EnvFiles: []string{flagFile}, LookupEnv: noEnv})
	if err != nil {
		t.Fatalf("Load: %v", err)
	}
	if got := cfg.Users[0].Password; got != "from-flag-env-file" {
		t.Errorf("password = %q, want the --env-file value", got)
	}
}

type fakeEnv map[string]string

func (e fakeEnv) lookup(name string) (string, bool) {
	v, ok := e[name]
	return v, ok
}

func noEnv(string) (string, bool) { return "", false }

func writeTestFile(t *testing.T, name, content string, mode os.FileMode) string {
	t.Helper()
	if err := os.MkdirAll(filepath.Dir(name), 0o755); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(name, []byte(content), mode); err != nil {
		t.Fatal(err)
	}
	return name
}

func writeAuthorizedKeys(t *testing.T, name, options string) ssh.PublicKey {
	t.Helper()
	pub, _, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	key, err := ssh.NewPublicKey(pub)
	if err != nil {
		t.Fatal(err)
	}
	line := options + strings.TrimSpace(string(ssh.MarshalAuthorizedKey(key))) + " partner-b@example\n"
	writeTestFile(t, name, "# test key\n"+line, 0o600)
	return key
}
