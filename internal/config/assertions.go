package config

import (
	"bytes"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"io/fs"
	"os"
	"path"
	"path/filepath"
	"slices"
	"strings"

	"github.com/nebarg/sftpit/internal/faults"
)

// AssertionType says what an Assertion checks.
type AssertionType string

const (
	// RuleFired checks how many times the rule Rule fired.
	RuleFired AssertionType = "rule_fired"

	// SuccessfulOperation checks how many requests of Operation on Path, or
	// a rename from Source to Target, got a successful reply.
	SuccessfulOperation AssertionType = "successful_operation"

	// FileEqualsFixture checks that the file Path holds the content of the
	// expected fixture Fixture.
	FileEqualsFixture AssertionType = "file_equals_fixture"

	// FileHash checks that the file Path has the hash SHA256.
	FileHash AssertionType = "file_hash"

	// PathAbsent checks that nothing is left at Path.
	PathAbsent AssertionType = "path_absent"
)

// Assertion is something that a run of a scenario must have done, or left
// behind, once it is over. Which fields are set depends on its Type.
type Assertion struct {
	Type AssertionType

	// Rule is the ID of a rule of the scenario or its chaos.
	Rule string

	// Operation is the kind of request to count, and Path, or Source and
	// Target, the clean absolute paths it acted on. A rename may give only
	// one of Source and Target.
	Operation faults.Operation
	Path      string
	Source    string
	Target    string

	// Fixture is the slash-separated path of a file under the expected
	// directory, and SHA256 a hash in lowercase hex.
	Fixture string
	SHA256  string

	// Count is the number of firings or requests allowed.
	Count Count
}

// Count bounds a number: at least Min, and at most Max if it is set.
type Count struct {
	Min uint64
	Max *uint64
}

// Allows reports whether n is within the bounds.
func (c Count) Allows(n uint64) bool {
	return n >= c.Min && (c.Max == nil || n <= *c.Max)
}

type assertionConfig struct {
	Type      string  `yaml:"type" json:"type"`
	RuleID    string  `yaml:"rule_id,omitempty" json:"rule_id,omitempty"`
	Operation string  `yaml:"operation,omitempty" json:"operation,omitempty"`
	Path      string  `yaml:"path,omitempty" json:"path,omitempty"`
	Source    string  `yaml:"source,omitempty" json:"source,omitempty"`
	Target    string  `yaml:"target,omitempty" json:"target,omitempty"`
	Fixture   string  `yaml:"fixture,omitempty" json:"fixture,omitempty"`
	SHA256    string  `yaml:"sha256,omitempty" json:"sha256,omitempty"`
	Exactly   *uint64 `yaml:"exactly,omitempty" json:"exactly,omitempty"`
	AtLeast   *uint64 `yaml:"at_least,omitempty" json:"at_least,omitempty"`
	AtMost    *uint64 `yaml:"at_most,omitempty" json:"at_most,omitempty"`
}

// assertedOperations are the operations that SuccessfulOperation can count:
// those recorded as an event of their own. A run sums its reads and writes
// by file handle instead, and does not record which way a handle was opened
// until it closes.
var assertedOperations = []faults.Operation{faults.Rename, faults.Remove, faults.Mkdir, faults.Rmdir, faults.SetStat, faults.Stat, faults.LStat}

// assertion returns the assertion that ac gives. It may refer only to the
// rules ruleIDs, and to fixtures under expectedDir, or to none if that is "".
func (ac assertionConfig) assertion(ruleIDs []string, expectedDir string) (Assertion, error) {
	a := Assertion{Type: AssertionType(ac.Type)}
	var err error
	switch a.Type {
	case RuleFired:
		err = ac.ruleFired(&a, ruleIDs)
	case SuccessfulOperation:
		err = ac.successfulOperation(&a)
	case FileEqualsFixture:
		err = ac.fileEqualsFixture(&a, expectedDir)
	case FileHash:
		err = ac.fileHash(&a)
	case PathAbsent:
		if err = ac.only("path"); err == nil {
			a.Path, err = assertedPath("path", ac.Path)
		}
	default:
		err = fmt.Errorf("type %q is not rule_fired, successful_operation, file_equals_fixture, file_hash or path_absent", ac.Type)
	}
	if err != nil {
		return Assertion{}, err
	}
	return a, nil
}

func (ac assertionConfig) ruleFired(a *Assertion, ruleIDs []string) error {
	if err := ac.only("rule_id", "exactly", "at_least", "at_most"); err != nil {
		return err
	}
	if ac.RuleID == "" {
		return errors.New("rule_id is required")
	}
	if !slices.Contains(ruleIDs, ac.RuleID) {
		return fmt.Errorf("rule_id %q is not a rule of this scenario or its chaos", ac.RuleID)
	}
	a.Rule = ac.RuleID
	var err error
	a.Count, err = ac.count()
	return err
}

func (ac assertionConfig) successfulOperation(a *Assertion) error {
	if err := ac.only("operation", "path", "source", "target", "exactly", "at_least", "at_most"); err != nil {
		return err
	}
	if ac.Operation == "" {
		return errors.New("operation is required")
	}
	a.Operation = faults.Operation(ac.Operation)
	if !slices.Contains(assertedOperations, a.Operation) {
		return fmt.Errorf("operation %q is not rename, remove, mkdir, rmdir, setstat, stat or lstat; for what a transfer stored, assert on the file", ac.Operation)
	}
	var err error
	if a.Operation == faults.Rename {
		if ac.Path != "" {
			return errors.New("a rename gives source and target, not path")
		}
		if ac.Source == "" && ac.Target == "" {
			return errors.New("a rename gives source, target or both")
		}
		if ac.Source != "" {
			if a.Source, err = assertedPath("source", ac.Source); err != nil {
				return err
			}
		}
		if ac.Target != "" {
			if a.Target, err = assertedPath("target", ac.Target); err != nil {
				return err
			}
		}
	} else {
		if ac.Source != "" || ac.Target != "" {
			return fmt.Errorf("%s gives path, not source or target", ac.Operation)
		}
		if a.Path, err = assertedPath("path", ac.Path); err != nil {
			return err
		}
	}
	a.Count, err = ac.count()
	return err
}

func (ac assertionConfig) fileEqualsFixture(a *Assertion, expectedDir string) error {
	if err := ac.only("path", "fixture"); err != nil {
		return err
	}
	var err error
	if a.Path, err = assertedPath("path", ac.Path); err != nil {
		return err
	}
	if ac.Fixture == "" {
		return errors.New("fixture is required")
	}
	if expectedDir == "" {
		return fmt.Errorf("fixture %q needs storage.expected_dir, which is not set", ac.Fixture)
	}
	if err := checkFixture(expectedDir, ac.Fixture); err != nil {
		return err
	}
	a.Fixture = ac.Fixture
	return nil
}

func (ac assertionConfig) fileHash(a *Assertion) error {
	if err := ac.only("path", "sha256"); err != nil {
		return err
	}
	var err error
	if a.Path, err = assertedPath("path", ac.Path); err != nil {
		return err
	}
	a.SHA256 = strings.ToLower(ac.SHA256)
	if decoded, err := hex.DecodeString(a.SHA256); err != nil || len(decoded) != 32 {
		return fmt.Errorf("sha256 %q is not a SHA-256 in hex", ac.SHA256)
	}
	return nil
}

// only reports a field set that an assertion of ac's type does not have.
func (ac assertionConfig) only(allowed ...string) error {
	for _, field := range []struct {
		name string
		set  bool
	}{
		{"rule_id", ac.RuleID != ""},
		{"operation", ac.Operation != ""},
		{"path", ac.Path != ""},
		{"source", ac.Source != ""},
		{"target", ac.Target != ""},
		{"fixture", ac.Fixture != ""},
		{"sha256", ac.SHA256 != ""},
		{"exactly", ac.Exactly != nil},
		{"at_least", ac.AtLeast != nil},
		{"at_most", ac.AtMost != nil},
	} {
		if field.set && !slices.Contains(allowed, field.name) {
			return fmt.Errorf("%s has no %s", ac.Type, field.name)
		}
	}
	return nil
}

// count returns the bounds that ac gives: exactly a number, or at least,
// at most or both, or else at least 1.
func (ac assertionConfig) count() (Count, error) {
	switch {
	case ac.Exactly != nil && (ac.AtLeast != nil || ac.AtMost != nil):
		return Count{}, errors.New("exactly cannot be set with at_least or at_most")
	case ac.Exactly != nil:
		return Count{Min: *ac.Exactly, Max: ac.Exactly}, nil
	case ac.AtLeast == nil && ac.AtMost == nil:
		return Count{Min: 1}, nil
	}
	c := Count{Max: ac.AtMost}
	if ac.AtLeast != nil {
		c.Min = *ac.AtLeast
	}
	if c.Max != nil && c.Min > *c.Max {
		return Count{}, fmt.Errorf("at_least %d is more than at_most %d", c.Min, *c.Max)
	}
	return c, nil
}

// assertedPath returns name, an SFTP path, cleaned, as the events and a
// run's files give paths, or else says that field must be absolute.
func assertedPath(field, name string) (string, error) {
	if !path.IsAbs(name) || strings.ContainsRune(name, 0) {
		return "", fmt.Errorf("%s %q must be an absolute SFTP path", field, name)
	}
	return path.Clean(name), nil
}

// checkFixture reports a fixture that is not a regular file under dir.
func checkFixture(dir, fixture string) error {
	if !fs.ValidPath(fixture) || fixture == "." {
		return fmt.Errorf("fixture %q must be a clean path relative to storage.expected_dir", fixture)
	}
	root, err := os.OpenRoot(dir)
	if err != nil {
		return fmt.Errorf("storage.expected_dir: %w", err)
	}
	defer root.Close()
	info, err := root.Lstat(filepath.FromSlash(fixture))
	if err != nil {
		return fmt.Errorf("fixture %q: %w", fixture, err)
	}
	if !info.Mode().IsRegular() {
		return fmt.Errorf("fixture %q is not a regular file in %s", fixture, dir)
	}
	return nil
}

// parseAssertions returns the assertions that acs give, naming each in
// errors as prefix followed by assertions and its index. They may refer only
// to rules of rules and chaos, and to fixtures under expectedDir.
func parseAssertions(prefix string, acs []assertionConfig, rules []faults.Rule, chaos *faults.Chaos, expectedDir string) ([]Assertion, error) {
	if len(acs) == 0 {
		return nil, nil
	}
	ruleIDs := make([]string, 0, len(rules))
	for _, r := range rules {
		ruleIDs = append(ruleIDs, r.ID)
	}
	if chaos != nil {
		for _, r := range chaos.Rules() {
			ruleIDs = append(ruleIDs, r.ID)
		}
	}
	assertions := make([]Assertion, 0, len(acs))
	for i, ac := range acs {
		a, err := ac.assertion(ruleIDs, expectedDir)
		if err != nil {
			return nil, fmt.Errorf("%sassertions[%d]: %w", prefix, i, err)
		}
		assertions = append(assertions, a)
	}
	return assertions, nil
}

// ParseAssertions returns the assertions in data, a JSON list as a
// scenario's assertions gives them, validated as Load validates them. They
// may refer only to rules of rules and chaos, and to fixtures under
// expectedDir.
func ParseAssertions(data []byte, rules []faults.Rule, chaos *faults.Chaos, expectedDir string) ([]Assertion, error) {
	var list []json.RawMessage
	if err := json.Unmarshal(data, &list); err != nil {
		return nil, fmt.Errorf("assertions: %w", err)
	}
	acs := make([]assertionConfig, len(list))
	for i, raw := range list {
		dec := json.NewDecoder(bytes.NewReader(raw))
		dec.DisallowUnknownFields()
		if err := dec.Decode(&acs[i]); err != nil {
			return nil, fmt.Errorf("assertions[%d]: %w", i, err)
		}
	}
	return parseAssertions("", acs, rules, chaos, expectedDir)
}

// AssertionsJSON returns assertions as a JSON list, with every default
// spelled out, which ParseAssertions reads as the same assertions.
func AssertionsJSON(assertions []Assertion) (json.RawMessage, error) {
	acs := longAssertions(assertions)
	if acs == nil {
		acs = []assertionConfig{}
	}
	b, err := json.Marshal(acs)
	if err != nil {
		return nil, fmt.Errorf("config: write the assertions: %w", err)
	}
	return b, nil
}

// longAssertions returns assertions as they are written, with their counts
// spelled out.
func longAssertions(assertions []Assertion) []assertionConfig {
	var acs []assertionConfig
	for _, a := range assertions {
		ac := assertionConfig{Type: string(a.Type), RuleID: a.Rule, Operation: string(a.Operation), Path: a.Path, Source: a.Source, Target: a.Target, Fixture: a.Fixture, SHA256: a.SHA256}
		if a.Type == RuleFired || a.Type == SuccessfulOperation {
			switch {
			case a.Count.Max != nil && *a.Count.Max == a.Count.Min:
				ac.Exactly = a.Count.Max
			case a.Count.Max != nil && a.Count.Min == 0:
				ac.AtMost = a.Count.Max
			default:
				ac.AtLeast, ac.AtMost = &a.Count.Min, a.Count.Max
			}
		}
		acs = append(acs, ac)
	}
	return acs
}
