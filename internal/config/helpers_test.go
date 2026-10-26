package config

import (
	"crypto/ed25519"
	"crypto/rand"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"golang.org/x/crypto/ssh"

	"github.com/nebarg/sftpit/internal/sshfront"
)

// withScenarios is a configuration with two users, followed by scenarios.
const withScenarios = `schema_version: 1
users:
  - name: test
    password_env: P
  - name: partner-b
    authorized_keys: partner-b.pub
scenarios:
`

var testUsers = []sshfront.User{{Name: "test", Password: "test", Home: "/"}}

type fakeEnv map[string]string

func (e fakeEnv) lookup(name string) (string, bool) {
	v, ok := e[name]
	return v, ok
}

func noEnv(string) (string, bool) { return "", false }

// writeTestFile writes content to the file name, which only its owner can
// read, making its directory if need be, and returns name.
func writeTestFile(t *testing.T, name, content string) string {
	t.Helper()
	if err := os.MkdirAll(filepath.Dir(name), 0o755); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(name, []byte(content), 0o600); err != nil {
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
	writeTestFile(t, name, "# test key\n"+line)
	return key
}

// loadScenarios loads scenarios, written as they follow withScenarios, from
// a configuration in dir, which holds partner-b.pub, with P set, choosing the
// scenario selected.
func loadScenarios(t *testing.T, dir, scenarios, selected string) (*Config, error) {
	t.Helper()
	config := writeTestFile(t, filepath.Join(dir, "sftpit.yaml"), withScenarios+scenarios)
	return Load(Options{ConfigFile: config, Scenario: selected, LookupEnv: fakeEnv{"P": "password"}.lookup})
}

// oneRule returns the scenario s, whose only rule is r with the fields
// rule gives.
func oneRule(rule string) string {
	return "  s:\n    faults:\n      - id: r\n        " + rule + "\n"
}
