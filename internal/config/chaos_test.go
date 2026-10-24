package config

import (
	"path/filepath"
	"reflect"
	"strings"
	"testing"

	"golang.org/x/crypto/ssh"

	"github.com/nebarg/sftpit/internal/faults"
)

func TestLoadReadsAScenariosChaos(t *testing.T) {
	dir := t.TempDir()
	key := writeAuthorizedKeys(t, filepath.Join(dir, "partner-b.pub"), "")
	config := writeTestFile(t, filepath.Join(dir, "sftpit.yaml"), withScenarios+`  dev-chaos:
    chaos:
      preset: moderate
      scope: {user: partner-b, key_fingerprint: "`+ssh.FingerprintSHA256(key)+`", path_prefix: /incoming}
      extras: [corrupt_download, wrong_size]
      paused: true
    faults:
      - {id: deny, match: {operation: remove}, action: {type: fail, when: before, status: permission_denied}}
  light-chaos:
    chaos: {preset: light}
`, 0o600)
	cfg, err := Load(Options{ConfigFile: config, LookupEnv: fakeEnv{"P": "password"}.lookup})
	if err != nil {
		t.Fatalf("Load: %v", err)
	}
	want := &faults.Chaos{
		Preset: faults.Moderate,
		Scope:  faults.Scope{User: "partner-b", KeyFingerprint: ssh.FingerprintSHA256(key), Path: faults.Location{Kind: faults.Under, Pattern: "/incoming"}},
		Extras: []faults.Extra{faults.CorruptDownloads, faults.WrongSizes},
		Paused: true,
	}
	if s := cfg.Scenarios["dev-chaos"]; !reflect.DeepEqual(s.Chaos, want) || len(s.Rules) != 1 || s.Rules[0].ID != "deny" {
		t.Errorf("dev-chaos has chaos %+v and rules %+v, want chaos %+v and its rule", s.Chaos, s.Rules, want)
	}
	if s := cfg.Scenarios["light-chaos"]; !reflect.DeepEqual(s.Chaos, &faults.Chaos{Preset: faults.Light}) || s.Rules != nil {
		t.Errorf("light-chaos has chaos %+v and rules %+v, want light chaos everywhere and no rules", s.Chaos, s.Rules)
	}
	if s := cfg.Scenarios["light-chaos"]; s.Chaos.Paused {
		t.Error("light-chaos is paused, want chaos running unless paused is set")
	}
}

func TestLoadRejectsInvalidChaos(t *testing.T) {
	dir := t.TempDir()
	writeAuthorizedKeys(t, filepath.Join(dir, "partner-b.pub"), "")
	chaos := func(block string) string {
		return "  s:\n    chaos: " + block + "\n"
	}
	tests := []struct {
		name, scenarios, want string
	}{
		{"no preset", chaos("{scope: {user: test}}"), "scenarios.s.chaos: faults: chaos needs a preset: light, moderate or heavy"},
		{"an unknown preset", chaos("{preset: wild}"), `scenarios.s.chaos: faults: chaos preset "wild" is not light, moderate or heavy`},
		{"an unknown extra", chaos("{preset: light, extras: [corrupt_upload]}"), `scenarios.s.chaos: faults: chaos extra "corrupt_upload" is not corrupt_download or wrong_size`},
		{"an extra listed twice", chaos("{preset: light, extras: [wrong_size, wrong_size]}"), `chaos extra "wrong_size" is listed twice`},
		{"an unknown field", chaos("{preset: light, level: 3}"), "field level not found"},
		{"an operation in its scope", chaos("{preset: light, scope: {operation: stat}}"), "field operation not found"},
		{"an unknown user", chaos("{preset: light, scope: {user: nobody}}"), `scenarios.s.chaos: scope: user "nobody" is not a configured user`},
		{"an unknown key", chaos(`{preset: light, scope: {key_fingerprint: "SHA256:abc"}}`), `scenarios.s.chaos: scope: key_fingerprint "SHA256:abc" is not one of the configured users' authorized keys`},
		{"two locations", chaos("{preset: light, scope: {path: /a, filename: a}}"), "scenarios.s.chaos: scope: path and filename cannot both be set"},
		{"an unclean location", chaos("{preset: light, scope: {path_prefix: /in/}}"), `scenarios.s.chaos: faults: chaos scope: path: "/in/" is not a clean absolute path`},
		{"a rule named as chaos's are", "  s:\n    chaos: {preset: light}\n    faults:\n      - {id: chaos-delay, match: {operation: stat}, action: {type: fail, when: before, status: failure}}\n", `scenarios.s: faults: rule ID "chaos-delay" starts with chaos-`},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			config := writeTestFile(t, filepath.Join(dir, "sftpit.yaml"), withScenarios+tt.scenarios, 0o600)
			_, err := Load(Options{ConfigFile: config, LookupEnv: fakeEnv{"P": "password"}.lookup})
			if err == nil || !strings.Contains(err.Error(), tt.want) {
				t.Errorf("error = %v, want %q", err, tt.want)
			}
		})
	}
}

func TestChaosInJSONParsesAsTheSameChaos(t *testing.T) {
	got, err := ParseChaos([]byte(`{"preset": "heavy", "scope": {"user": "test", "filename_glob": "*.csv"}, "extras": ["wrong_size"]}`), testUsers)
	want := &faults.Chaos{Preset: faults.Heavy, Scope: faults.Scope{User: "test", Path: faults.Location{Kind: faults.NamedGlob, Pattern: "*.csv"}}, Extras: []faults.Extra{faults.WrongSizes}}
	if err != nil || !reflect.DeepEqual(got, want) {
		t.Fatalf("ParseChaos = %+v, %v; want %+v", got, err, want)
	}
	tests := []struct {
		chaos *faults.Chaos
		json  string
	}{
		{want, `{"preset":"heavy","scope":{"user":"test","filename_glob":"*.csv"},"extras":["wrong_size"],"paused":false}`},
		{&faults.Chaos{Preset: faults.Light, Paused: true}, `{"preset":"light","scope":{},"extras":[],"paused":true}`},
	}
	for _, tt := range tests {
		b, err := ChaosJSON(tt.chaos)
		if err != nil || string(b) != tt.json {
			t.Errorf("ChaosJSON(%+v) = %s, %v; want %s", tt.chaos, b, err, tt.json)
		}
		if got, err := ParseChaos(b, testUsers); err != nil || !reflect.DeepEqual(got, tt.chaos) {
			t.Errorf("ParseChaos(%s) = %+v, %v; want %+v", b, got, err, tt.chaos)
		}
	}
}

func TestParseChaosRejectsWhatLoadRejects(t *testing.T) {
	tests := []struct {
		name, chaos, want string
	}{
		{"not an object", `["light"]`, "chaos: json: cannot unmarshal array"},
		{"an unknown field", `{"preset": "light", "level": 3}`, `chaos: json: unknown field "level"`},
		{"an unknown preset", `{"preset": "wild"}`, `chaos: faults: chaos preset "wild" is not light, moderate or heavy`},
		{"an unknown user", `{"preset": "light", "scope": {"user": "nobody"}}`, `chaos: scope: user "nobody" is not a configured user`},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			chaos, err := ParseChaos([]byte(tt.chaos), testUsers)
			if err == nil || !strings.HasPrefix(err.Error(), tt.want) {
				t.Errorf("ParseChaos = %+v, %v; want an error starting %q", chaos, err, tt.want)
			}
		})
	}
}
