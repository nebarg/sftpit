package config

import (
	"path/filepath"
	"reflect"
	"slices"
	"strings"
	"testing"

	"github.com/nebarg/sftpit/internal/testutil"
)

// withPolicy is a configuration with two users, followed by a policy.
const withPolicy = `schema_version: 1
users:
  - name: test
    password_env: P
  - name: partner-b
    password_env: P
policy:
`

func loadPolicy(t *testing.T, policy string) (*Config, error) {
	t.Helper()
	config := testutil.WriteFile(t, filepath.Join(t.TempDir(), "sftpit.yaml"), withPolicy+policy)
	return Load(Options{ConfigFile: config, LookupEnv: fakeEnv{"P": "password"}.lookup})
}

func TestLoadReadsTheReadOnlyPaths(t *testing.T) {
	cfg, err := loadPolicy(t, `  read_only:
    - path_prefix: /reference
    - path_prefix: /outgoing
      users: partner-b
    - {path_prefix: /, users: [test]}
`)
	if err != nil {
		t.Fatalf("Load: %v", err)
	}
	want := Policy{ReadOnly: []ReadOnly{
		{PathPrefix: "/reference"},
		{PathPrefix: "/outgoing", Users: []string{"partner-b"}},
		{PathPrefix: "/", Users: []string{"test"}},
	}}
	if !reflect.DeepEqual(cfg.Policy, want) {
		t.Errorf("Policy = %+v, want %+v", cfg.Policy, want)
	}
	for user, paths := range map[string][]string{
		"test":      {"/reference", "/"},
		"partner-b": {"/reference", "/outgoing"},
		"other":     {"/reference"},
	} {
		if got := cfg.Policy.ReadOnlyFor(user); !slices.Equal(got, paths) {
			t.Errorf("ReadOnlyFor(%s) = %q, want %q", user, got, paths)
		}
	}
}

func TestLoadRejectsInvalidReadOnlyPaths(t *testing.T) {
	tests := []struct {
		name, policy, want string
	}{
		{"no path", "  read_only:\n    - users: [test]\n", "policy.read_only[0]: path_prefix is required"},
		{"a relative path", "  read_only:\n    - path_prefix: reference\n", `path_prefix "reference" is not a clean absolute path`},
		{"an unclean path", "  read_only:\n    - path_prefix: /reference/\n", `path_prefix "/reference/" is not a clean absolute path`},
		{"an unknown user", "  read_only:\n    - {path_prefix: /a}\n    - {path_prefix: /b, users: [nobody]}\n", `policy.read_only[1]: user "nobody" is not a configured user`},
		{"no users", "  read_only:\n    - {path_prefix: /a, users: []}\n", "users needs at least one user; leave it out for every user"},
		{"an unknown field", "  read_only:\n    - {path: /a}\n", "field path not found"},
		{"an unknown policy", "  deny: [remove]\n", "field deny not found"},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			_, err := loadPolicy(t, tt.policy)
			if err == nil || !strings.Contains(err.Error(), tt.want) {
				t.Errorf("error = %v, want %q", err, tt.want)
			}
		})
	}
}

func TestExplainWritesThePolicy(t *testing.T) {
	config := testutil.WriteFile(t, filepath.Join(t.TempDir(), "sftpit.yaml"), withPolicy+`  read_only:
    - path_prefix: /reference
    - path_prefix: /outgoing
      users: partner-b
`)
	explained, err := Explain(Options{ConfigFile: config, LookupEnv: fakeEnv{"P": "password"}.lookup})
	if err != nil {
		t.Fatalf("Explain: %v", err)
	}
	want := `policy:
  read_only:
    - path_prefix: /reference
    - path_prefix: /outgoing
      users: partner-b
`
	if !strings.Contains(string(explained), want) {
		t.Errorf("Explain wrote\n%s\nwant it to hold\n%s", explained, want)
	}
}
