package config

import (
	"errors"
	"fmt"
	"maps"
	"regexp"
	"slices"
	"strings"
	"time"

	"golang.org/x/crypto/ssh"

	"github.com/nebarg/sftpit/internal/faults"
	"github.com/nebarg/sftpit/internal/sftpproxy"
	"github.com/nebarg/sftpit/internal/sftpwire"
	"github.com/nebarg/sftpit/internal/sshfront"
)

// namePattern constrains scenario names and rule IDs, which name files and
// appear in logs and URLs.
var namePattern = regexp.MustCompile(`^[a-z0-9][a-z0-9-]*$`)

type scenarioConfig struct {
	Faults []ruleConfig `yaml:"faults"`
}

type ruleConfig struct {
	ID          string       `yaml:"id"`
	Priority    int          `yaml:"priority"`
	MaxTriggers int          `yaml:"max_triggers"`
	Match       matchConfig  `yaml:"match"`
	Action      actionConfig `yaml:"action"`
}

type matchConfig struct {
	User           string     `yaml:"user"`
	KeyFingerprint string     `yaml:"key_fingerprint"`
	Operation      stringList `yaml:"operation"`

	Path         string `yaml:"path"`
	PathPrefix   string `yaml:"path_prefix"`
	PathGlob     string `yaml:"path_glob"`
	Filename     string `yaml:"filename"`
	FilenameGlob string `yaml:"filename_glob"`

	Source             string `yaml:"source"`
	SourcePrefix       string `yaml:"source_prefix"`
	SourceGlob         string `yaml:"source_glob"`
	SourceFilename     string `yaml:"source_filename"`
	SourceFilenameGlob string `yaml:"source_filename_glob"`

	Target             string `yaml:"target"`
	TargetPrefix       string `yaml:"target_prefix"`
	TargetGlob         string `yaml:"target_glob"`
	TargetFilename     string `yaml:"target_filename"`
	TargetFilenameGlob string `yaml:"target_filename_glob"`

	Attempt    *attemptConfig `yaml:"attempt"`
	Occurrence []uint64       `yaml:"occurrence"`
}

type attemptConfig struct {
	Per     []string `yaml:"per"`
	Numbers []uint64 `yaml:"numbers"`
}

// actionConfig holds the fields of every action type. Each type allows only
// its own fields.
type actionConfig struct {
	Type         string  `yaml:"type"`
	When         string  `yaml:"when"`
	Duration     string  `yaml:"duration"`
	Status       string  `yaml:"status"`
	Mode         string  `yaml:"mode"`
	MaxFreeze    string  `yaml:"max_freeze"`
	CutoffOffset *uint64 `yaml:"cutoff_offset"`
	Result       string  `yaml:"result"`
	Transform    string  `yaml:"transform"`
	Offset       *uint64 `yaml:"offset"`
	Length       *uint64 `yaml:"length"`
	Size         *uint64 `yaml:"size"`
	SizeDelta    *int64  `yaml:"size_delta"`
}

// statuses are the statuses a fault can answer with. OK would fake success,
// and NO_CONNECTION and CONNECTION_LOST only ever come from a client itself.
var statuses = map[string]sftpwire.StatusCode{
	"eof":               sftpwire.StatusEOF,
	"no_such_file":      sftpwire.StatusNoSuchFile,
	"permission_denied": sftpwire.StatusPermissionDenied,
	"failure":           sftpwire.StatusFailure,
	"bad_message":       sftpwire.StatusBadMessage,
	"op_unsupported":    sftpwire.StatusOpUnsupported,
}

var corruptions = map[string]sftpproxy.Corruption{
	"truncate":   sftpproxy.Truncate,
	"omit_range": sftpproxy.OmitRange,
	"flip_bytes": sftpproxy.FlipBytes,
}

// scenarios validates every scenario and returns the rules of the one named
// selected, or none if selected is "". Rules may refer only to users, and
// keys, that the configuration defines.
func scenarios(defined map[string]scenarioConfig, selected string, users []sshfront.User) ([]faults.Rule, error) {
	if _, ok := defined[selected]; selected != "" && !ok {
		names := slices.Sorted(maps.Keys(defined))
		if len(names) == 0 {
			return nil, fmt.Errorf("scenario %q is not defined; the configuration defines no scenarios", selected)
		}
		return nil, fmt.Errorf("scenario %q is not defined; the configuration defines %s", selected, strings.Join(names, ", "))
	}
	var rules []faults.Rule
	for _, name := range slices.Sorted(maps.Keys(defined)) {
		field := "scenarios." + name
		if !namePattern.MatchString(name) {
			return nil, fmt.Errorf("%s: a scenario name may hold only lowercase letters, digits and -, starting with a letter or digit", field)
		}
		scenario, err := defined[name].rules(field, users)
		if err != nil {
			return nil, err
		}
		if name == selected {
			rules = scenario
		}
	}
	return rules, nil
}

func (s scenarioConfig) rules(field string, users []sshfront.User) ([]faults.Rule, error) {
	var rules []faults.Rule
	for i, rc := range s.Faults {
		field := fmt.Sprintf("%s.faults[%d]", field, i)
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
	if err := faults.Check(rules); err != nil {
		return nil, fmt.Errorf("%s: %w", field, err)
	}
	return rules, nil
}

func (rc ruleConfig) rule(users []sshfront.User) (faults.Rule, error) {
	m, err := rc.Match.match(users)
	if err != nil {
		return faults.Rule{}, fmt.Errorf("match: %w", err)
	}
	a, err := rc.Action.action()
	if err != nil {
		return faults.Rule{}, fmt.Errorf("action: %w", err)
	}
	return faults.Rule{ID: rc.ID, Priority: rc.Priority, MaxTriggers: rc.MaxTriggers, Match: m, Action: a}, nil
}

func (mc matchConfig) match(users []sshfront.User) (faults.Match, error) {
	m := faults.Match{User: mc.User, KeyFingerprint: mc.KeyFingerprint, Occurrence: mc.Occurrence}
	if len(mc.Operation) == 0 {
		return m, errors.New("operation is required")
	}
	for _, op := range mc.Operation {
		m.Operations = append(m.Operations, faults.Operation(op))
	}
	if err := checkCredentials(mc.User, mc.KeyFingerprint, users); err != nil {
		return m, err
	}

	paths, err := location([]locationField{
		{"path", faults.Exactly, mc.Path},
		{"path_prefix", faults.Under, mc.PathPrefix},
		{"path_glob", faults.Glob, mc.PathGlob},
		{"filename", faults.Named, mc.Filename},
		{"filename_glob", faults.NamedGlob, mc.FilenameGlob},
	})
	if err != nil {
		return m, err
	}
	sources, err := location([]locationField{
		{"source", faults.Exactly, mc.Source},
		{"source_prefix", faults.Under, mc.SourcePrefix},
		{"source_glob", faults.Glob, mc.SourceGlob},
		{"source_filename", faults.Named, mc.SourceFilename},
		{"source_filename_glob", faults.NamedGlob, mc.SourceFilenameGlob},
	})
	if err != nil {
		return m, err
	}
	m.Target, err = location([]locationField{
		{"target", faults.Exactly, mc.Target},
		{"target_prefix", faults.Under, mc.TargetPrefix},
		{"target_glob", faults.Glob, mc.TargetGlob},
		{"target_filename", faults.Named, mc.TargetFilename},
		{"target_filename_glob", faults.NamedGlob, mc.TargetFilenameGlob},
	})
	if err != nil {
		return m, err
	}
	// A rename's source is the path it acts on, so the source fields are
	// the path fields under the names that suit a rename.
	switch renames := slices.Equal(m.Operations, []faults.Operation{faults.Rename}); {
	case sources.Kind != faults.Anywhere && !renames:
		return m, errors.New("the source fields need operation rename; match other operations with the path fields")
	case sources.Kind != faults.Anywhere && paths.Kind != faults.Anywhere:
		return m, errors.New("set the source fields or the path fields, not both")
	case sources.Kind != faults.Anywhere:
		m.Path = sources
	default:
		m.Path = paths
	}

	if mc.Attempt != nil {
		m.Attempt = &faults.Attempt{Numbers: mc.Attempt.Numbers}
		per := mc.Attempt.Per
		if per == nil {
			per = []string{"user", "path"}
		}
		if len(per) == 0 {
			return m, errors.New("attempt per needs user, path or both")
		}
		for _, p := range per {
			switch p {
			case "user":
				m.Attempt.PerUser = true
			case "path":
				m.Attempt.PerPath = true
			default:
				return m, fmt.Errorf("attempt per %q is not user or path", p)
			}
		}
	}
	return m, nil
}

// checkCredentials reports a user or key fingerprint that no configured
// user has, which would never match.
func checkCredentials(user, keyFingerprint string, users []sshfront.User) error {
	if user != "" && !slices.ContainsFunc(users, func(u sshfront.User) bool { return u.Name == user }) {
		return fmt.Errorf("user %q is not a configured user", user)
	}
	if keyFingerprint == "" {
		return nil
	}
	for _, u := range users {
		if user != "" && u.Name != user {
			continue
		}
		for _, key := range u.AuthorizedKeys {
			if ssh.FingerprintSHA256(key) == keyFingerprint {
				return nil
			}
		}
	}
	if user != "" {
		return fmt.Errorf("key_fingerprint %q is not one of %s's authorized keys", keyFingerprint, user)
	}
	return fmt.Errorf("key_fingerprint %q is not one of the configured users' authorized keys", keyFingerprint)
}

type locationField struct {
	name    string
	kind    faults.LocationKind
	pattern string
}

// location returns the one location among fields that is set, if any.
func location(fields []locationField) (faults.Location, error) {
	var l faults.Location
	var set string
	for _, f := range fields {
		if f.pattern == "" {
			continue
		}
		if set != "" {
			return l, fmt.Errorf("%s and %s cannot both be set", set, f.name)
		}
		set, l = f.name, faults.Location{Kind: f.kind, Pattern: f.pattern}
	}
	return l, nil
}

// actionFields are the fields each action type allows, besides type.
var actionFields = map[string][]string{
	"delay":            {"when", "duration"},
	"fail":             {"when", "status"},
	"drop":             {"when", "mode", "max_freeze"},
	"partial_upload":   {"cutoff_offset", "result", "status", "mode", "max_freeze"},
	"corrupt_download": {"transform", "offset", "length"},
	"wrong_size":       {"size", "size_delta"},
}

func (ac actionConfig) action() (sftpproxy.Action, error) {
	allowed, ok := actionFields[ac.Type]
	if !ok {
		return nil, fmt.Errorf("type %q is not one of %s", ac.Type, strings.Join(slices.Sorted(maps.Keys(actionFields)), ", "))
	}
	for _, f := range ac.set() {
		if !slices.Contains(allowed, f) {
			return nil, fmt.Errorf("%s does not apply to a %s", f, ac.Type)
		}
	}
	switch ac.Type {
	case "delay":
		when, err := ac.when()
		if err != nil {
			return nil, err
		}
		d, err := positiveDuration("duration", ac.Duration)
		if err != nil {
			return nil, err
		}
		return sftpproxy.Delay{When: when, Duration: d}, nil
	case "fail":
		when, err := ac.when()
		if err != nil {
			return nil, err
		}
		code, err := status(ac.Status)
		if err != nil {
			return nil, err
		}
		return sftpproxy.Fail{When: when, Status: code}, nil
	case "drop":
		when, err := ac.when()
		if err != nil {
			return nil, err
		}
		return ac.drop(when)
	case "partial_upload":
		return ac.partialUpload()
	case "corrupt_download":
		return ac.corruptDownload()
	}
	return ac.wrongSize()
}

// set returns the names of the fields that are set, besides type.
func (ac actionConfig) set() []string {
	var names []string
	for name, set := range map[string]bool{
		"when":          ac.When != "",
		"duration":      ac.Duration != "",
		"status":        ac.Status != "",
		"mode":          ac.Mode != "",
		"max_freeze":    ac.MaxFreeze != "",
		"cutoff_offset": ac.CutoffOffset != nil,
		"result":        ac.Result != "",
		"transform":     ac.Transform != "",
		"offset":        ac.Offset != nil,
		"length":        ac.Length != nil,
		"size":          ac.Size != nil,
		"size_delta":    ac.SizeDelta != nil,
	} {
		if set {
			names = append(names, name)
		}
	}
	slices.Sort(names)
	return names
}

func (ac actionConfig) when() (sftpproxy.When, error) {
	switch ac.When {
	case "before":
		return sftpproxy.Before, nil
	case "after":
		return sftpproxy.After, nil
	case "":
		return 0, errors.New("when is required: before the server acts, or after")
	}
	return 0, fmt.Errorf("when %q is not before or after", ac.When)
}

// drop returns the Drop or Freeze that ac's mode chooses, taking effect
// when. The mode is fin unless set.
func (ac actionConfig) drop(when sftpproxy.When) (sftpproxy.Action, error) {
	if ac.Mode != "freeze" && ac.MaxFreeze != "" {
		return nil, errors.New("max_freeze applies only to mode freeze")
	}
	switch ac.Mode {
	case "", "fin":
		return sftpproxy.Drop{When: when}, nil
	case "rst":
		return sftpproxy.Drop{When: when, Reset: true}, nil
	case "freeze":
		limit, err := positiveDuration("max_freeze", ac.MaxFreeze)
		if err != nil {
			return nil, err
		}
		return sftpproxy.Freeze{When: when, Limit: limit}, nil
	}
	return nil, fmt.Errorf("mode %q is not fin, rst or freeze", ac.Mode)
}

func (ac actionConfig) partialUpload() (sftpproxy.Action, error) {
	if ac.CutoffOffset == nil {
		return nil, errors.New("cutoff_offset is required")
	}
	u := sftpproxy.PartialUpload{Cutoff: *ac.CutoffOffset}
	if ac.Status != "" && ac.Result != "status" {
		return nil, errors.New("status applies only to result status")
	}
	switch ac.Result {
	case "status":
		if ac.Mode != "" || ac.MaxFreeze != "" {
			return nil, errors.New("mode and max_freeze apply only to result close_connection or freeze_connection")
		}
		code, err := status(ac.Status)
		if err != nil {
			return nil, err
		}
		u.Result = sftpproxy.Fail{Status: code}
	case "close_connection":
		if ac.MaxFreeze != "" {
			return nil, errors.New("max_freeze applies only to result freeze_connection")
		}
		switch ac.Mode {
		case "", "fin":
			u.Result = sftpproxy.Drop{}
		case "rst":
			u.Result = sftpproxy.Drop{Reset: true}
		default:
			return nil, fmt.Errorf("mode %q is not fin or rst", ac.Mode)
		}
	case "freeze_connection":
		if ac.Mode != "" {
			return nil, errors.New("mode applies only to result close_connection")
		}
		limit, err := positiveDuration("max_freeze", ac.MaxFreeze)
		if err != nil {
			return nil, err
		}
		u.Result = sftpproxy.Freeze{Limit: limit}
	case "":
		return nil, errors.New("result is required: status, close_connection or freeze_connection")
	default:
		return nil, fmt.Errorf("result %q is not status, close_connection or freeze_connection", ac.Result)
	}
	return u, nil
}

func (ac actionConfig) corruptDownload() (sftpproxy.Action, error) {
	corruption, ok := corruptions[ac.Transform]
	if !ok {
		return nil, fmt.Errorf("transform %q is not one of %s", ac.Transform, strings.Join(slices.Sorted(maps.Keys(corruptions)), ", "))
	}
	if ac.Offset == nil {
		return nil, errors.New("offset is required")
	}
	d := sftpproxy.CorruptDownload{Corruption: corruption, Offset: *ac.Offset}
	switch {
	case corruption == sftpproxy.Truncate && ac.Length != nil:
		return nil, errors.New("length does not apply to truncate")
	case corruption != sftpproxy.Truncate && (ac.Length == nil || *ac.Length == 0):
		return nil, fmt.Errorf("%s needs a length of at least 1", ac.Transform)
	case corruption != sftpproxy.Truncate:
		d.Length = *ac.Length
	}
	return d, nil
}

func (ac actionConfig) wrongSize() (sftpproxy.Action, error) {
	switch {
	case ac.Size != nil && ac.SizeDelta != nil:
		return nil, errors.New("set size or size_delta, not both")
	case ac.Size != nil:
		return sftpproxy.WrongSize{Size: *ac.Size}, nil
	case ac.SizeDelta != nil && *ac.SizeDelta != 0:
		return sftpproxy.WrongSize{Delta: *ac.SizeDelta}, nil
	}
	return nil, errors.New("size or a size_delta other than 0 is required")
}

func status(name string) (sftpwire.StatusCode, error) {
	if name == "" {
		return 0, errors.New("status is required")
	}
	code, ok := statuses[name]
	if !ok {
		return 0, fmt.Errorf("status %q is not one of %s", name, strings.Join(slices.Sorted(maps.Keys(statuses)), ", "))
	}
	return code, nil
}

func positiveDuration(field, value string) (time.Duration, error) {
	if value == "" {
		return 0, fmt.Errorf("%s is required", field)
	}
	d, err := time.ParseDuration(value)
	if err != nil || d <= 0 {
		return 0, fmt.Errorf("%s %q is not a positive duration, such as 500ms or 2s", field, value)
	}
	return d, nil
}
