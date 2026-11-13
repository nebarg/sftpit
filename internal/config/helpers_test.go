package config

import (
	"crypto/ed25519"
	"crypto/rand"
	"fmt"
	"maps"
	"path/filepath"
	"slices"
	"strings"
	"testing"

	"go.yaml.in/yaml/v3"
	"golang.org/x/crypto/ssh"

	"github.com/nebarg/sftpit/internal/faults"
	"github.com/nebarg/sftpit/internal/sshfront"
	"github.com/nebarg/sftpit/internal/testutil"
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
	testutil.WriteFile(t, name, "# test key\n"+line)
	return key
}

// loadScenarios loads scenarios, written as they follow withScenarios, from
// a configuration in dir, which holds partner-b.pub, with P set, turning on
// the scenario selected at startup.
func loadScenarios(t *testing.T, dir, scenarios, selected string) (*Config, error) {
	t.Helper()
	config := testutil.WriteFile(t, filepath.Join(dir, "sftpit.yaml"), withScenarios+scenarios)
	return Load(Options{ConfigFile: config, Scenario: selected, LookupEnv: fakeEnv{"P": "password"}.lookup})
}

// compileLongForm compiles scenarios of rules in the long form, written as
// they follow withScenarios, with the users of a configuration in dir,
// which holds partner-b.pub, and returns each scenario's rules by name.
// Errors name each rule as the configuration's scenarios once did.
func compileLongForm(t *testing.T, dir, scenarios string) (map[string][]faults.Rule, error) {
	t.Helper()
	cfg := loadUsers(t, dir)
	var defined struct {
		Scenarios map[string]struct {
			Faults []ruleConfig `yaml:"faults"`
		} `yaml:"scenarios"`
	}
	dec := yaml.NewDecoder(strings.NewReader("scenarios:\n" + scenarios))
	dec.KnownFields(true)
	if err := dec.Decode(&defined); err != nil {
		return nil, err
	}
	compiled := make(map[string][]faults.Rule)
	for _, name := range slices.Sorted(maps.Keys(defined.Scenarios)) {
		field := "scenarios." + name
		rules, err := parseRules(field+".", defined.Scenarios[name].Faults, cfg.Users)
		if err != nil {
			return nil, err
		}
		if err := faults.Check(rules); err != nil {
			return nil, fmt.Errorf("%s: %w", field, err)
		}
		compiled[name] = rules
	}
	return compiled, nil
}

// loadUsers loads the configuration withScenarios, without scenarios, from
// dir, which holds partner-b.pub, with P set.
func loadUsers(t *testing.T, dir string) *Config {
	t.Helper()
	config := testutil.WriteFile(t, filepath.Join(dir, "sftpit.yaml"), strings.TrimSuffix(withScenarios, "scenarios:\n"))
	cfg, err := Load(Options{ConfigFile: config, LookupEnv: fakeEnv{"P": "password"}.lookup})
	if err != nil {
		t.Fatalf("Load: %v", err)
	}
	return cfg
}

// parseRules returns the rules that rcs give, naming each in errors as
// prefix followed by faults and its index.
func parseRules(prefix string, rcs []ruleConfig, users []sshfront.User) ([]faults.Rule, error) {
	var rules []faults.Rule
	for i, rc := range rcs {
		field := fmt.Sprintf("%sfaults[%d]", prefix, i)
		if rc.ID == "" {
			return nil, fmt.Errorf("%s: id is required", field)
		}
		if !namePattern.MatchString(rc.ID) {
			return nil, fmt.Errorf("%s: id %q must hold only lowercase letters, digits and -, starting with a letter or digit", field, rc.ID)
		}
		field += " (" + rc.ID + ")"
		r, err := rc.rule(users)
		if err != nil {
			return nil, fmt.Errorf("%s: %w", field, err)
		}
		rules = append(rules, r)
	}
	return rules, nil
}

// oneRule returns the scenario s, whose only rule is r with the fields
// rule gives.
func oneRule(rule string) string {
	return "  s:\n    faults:\n      - id: r\n        " + rule + "\n"
}
