package config

import (
	"bytes"
	"encoding/json"
	"errors"
	"fmt"
	"maps"
	"regexp"
	"slices"
	"strings"
	"time"

	"go.yaml.in/yaml/v3"
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
	Seed   *faults.Seed `yaml:"seed,omitempty"`
	Faults []ruleConfig `yaml:"faults"`
}

type ruleConfig struct {
	ID          string          `yaml:"id" json:"id"`
	Priority    int             `yaml:"priority" json:"priority"`
	MaxTriggers int             `yaml:"max_triggers" json:"max_triggers"`
	Match       matchConfig     `yaml:"match" json:"match"`
	Trigger     *triggerConfig  `yaml:"trigger,omitempty" json:"trigger,omitempty"`
	Decision    *decisionConfig `yaml:"decision,omitempty" json:"decision,omitempty"`
	Action      actionConfig    `yaml:"action" json:"action"`

	// A rule gives either a match and an action, or one recipe.
	FailUpload      *failUploadConfig      `yaml:"fail_upload,omitempty" json:"fail_upload,omitempty"`
	FailRandomly    *failRandomlyConfig    `yaml:"fail_randomly,omitempty" json:"fail_randomly,omitempty"`
	CorruptDownload *corruptDownloadConfig `yaml:"corrupt_download,omitempty" json:"corrupt_download,omitempty"`
}

type triggerConfig struct {
	At     *valueRange[string] `yaml:"at,omitempty" json:"at,omitempty"`
	Window *windowConfig       `yaml:"window,flow,omitempty" json:"window,omitempty"`
	Anchor string              `yaml:"anchor" json:"anchor"`
}

type windowConfig struct {
	From  string `yaml:"from" json:"from"`
	Until string `yaml:"until" json:"until"`
}

var anchors = map[string]faults.Anchor{
	"run":        faults.Run,
	"connection": faults.Connection,
	"transfer":   faults.Transfer,
}

// connectionActions are the action types that act on the client's
// connection or session, and so can fire at a moment.
var connectionActions = []string{"close_connection", "freeze_connection", "close_subsystem", "listener_down"}

// eventActions are the action types that apply to the connection events,
// connect and authenticate.
var eventActions = []string{"delay", "close_connection", "freeze_connection", "listener_down"}

type decisionConfig struct {
	Probability *float64 `yaml:"probability,omitempty" json:"probability,omitempty"`
	Scope       string   `yaml:"scope,omitempty" json:"scope,omitempty"`
}

type matchConfig struct {
	User           string     `yaml:"user,omitempty" json:"user,omitempty"`
	KeyFingerprint string     `yaml:"key_fingerprint,omitempty" json:"key_fingerprint,omitempty"`
	Operation      stringList `yaml:"operation,omitempty" json:"operation,omitempty"`

	Path         string `yaml:"path,omitempty" json:"path,omitempty"`
	PathPrefix   string `yaml:"path_prefix,omitempty" json:"path_prefix,omitempty"`
	PathGlob     string `yaml:"path_glob,omitempty" json:"path_glob,omitempty"`
	Filename     string `yaml:"filename,omitempty" json:"filename,omitempty"`
	FilenameGlob string `yaml:"filename_glob,omitempty" json:"filename_glob,omitempty"`

	Source             string `yaml:"source,omitempty" json:"source,omitempty"`
	SourcePrefix       string `yaml:"source_prefix,omitempty" json:"source_prefix,omitempty"`
	SourceGlob         string `yaml:"source_glob,omitempty" json:"source_glob,omitempty"`
	SourceFilename     string `yaml:"source_filename,omitempty" json:"source_filename,omitempty"`
	SourceFilenameGlob string `yaml:"source_filename_glob,omitempty" json:"source_filename_glob,omitempty"`

	Target             string `yaml:"target,omitempty" json:"target,omitempty"`
	TargetPrefix       string `yaml:"target_prefix,omitempty" json:"target_prefix,omitempty"`
	TargetGlob         string `yaml:"target_glob,omitempty" json:"target_glob,omitempty"`
	TargetFilename     string `yaml:"target_filename,omitempty" json:"target_filename,omitempty"`
	TargetFilenameGlob string `yaml:"target_filename_glob,omitempty" json:"target_filename_glob,omitempty"`

	Attempt    *attemptConfig `yaml:"attempt,omitempty" json:"attempt,omitempty"`
	Occurrence []uint64       `yaml:"occurrence,flow,omitempty" json:"occurrence,omitempty"`
}

type attemptConfig struct {
	Per     []string `yaml:"per,flow,omitempty" json:"per,omitempty"`
	Numbers []uint64 `yaml:"numbers,flow,omitempty" json:"numbers,omitempty"`
}

// actionConfig holds the fields of every action type. Each type allows only
// its own fields.
type actionConfig struct {
	Type          string              `yaml:"type" json:"type"`
	When          string              `yaml:"when,omitempty" json:"when,omitempty"`
	Duration      *valueRange[string] `yaml:"duration,omitempty" json:"duration,omitempty"`
	CutoffOffset  *valueRange[uint64] `yaml:"cutoff_offset,omitempty" json:"cutoff_offset,omitempty"`
	Result        string              `yaml:"result,omitempty" json:"result,omitempty"`
	Status        string              `yaml:"status,omitempty" json:"status,omitempty"`
	Mode          string              `yaml:"mode,omitempty" json:"mode,omitempty"`
	MaxFreeze     string              `yaml:"max_freeze,omitempty" json:"max_freeze,omitempty"`
	Transform     string              `yaml:"transform,omitempty" json:"transform,omitempty"`
	Offset        *uint64             `yaml:"offset,omitempty" json:"offset,omitempty"`
	Length        *uint64             `yaml:"length,omitempty" json:"length,omitempty"`
	Size          *uint64             `yaml:"size,omitempty" json:"size,omitempty"`
	SizeDelta     *int64              `yaml:"size_delta,omitempty" json:"size_delta,omitempty"`
	CloseExisting *bool               `yaml:"close_existing,omitempty" json:"close_existing,omitempty"`
}

// valueRange is a value, such as 2s, or a range to draw one from for each
// decision, such as {min: 1s, max: 5s}.
type valueRange[T any] struct {
	Min, Max T
	ranged   bool
}

func (r *valueRange[T]) UnmarshalYAML(n *yaml.Node) error {
	if n.Kind != yaml.MappingNode {
		var v T
		if err := n.Decode(&v); err != nil {
			return err
		}
		*r = valueRange[T]{Min: v, Max: v}
		return nil
	}
	// A node decodes without the file's KnownFields, so a misspelt bound
	// would go unnoticed if the mapping were decoded into a struct.
	var hasMin, hasMax bool
	for i := 0; i+1 < len(n.Content); i += 2 {
		key, value := n.Content[i], n.Content[i+1]
		var err error
		switch {
		case key.Value == "min" && !hasMin:
			hasMin, err = true, value.Decode(&r.Min)
		case key.Value == "max" && !hasMax:
			hasMax, err = true, value.Decode(&r.Max)
		case key.Value == "min" || key.Value == "max":
			return fmt.Errorf("line %d: a range's %s is set twice", key.Line, key.Value)
		default:
			return fmt.Errorf("line %d: a range has min and max, not %s", key.Line, key.Value)
		}
		if err != nil {
			return err
		}
	}
	if !hasMin || !hasMax {
		return fmt.Errorf("line %d: a range needs both min and max", n.Line)
	}
	r.ranged = true
	return nil
}

func (r *valueRange[T]) UnmarshalJSON(b []byte) error {
	if !bytes.HasPrefix(b, []byte("{")) {
		var v T
		if err := json.Unmarshal(b, &v); err != nil {
			return err
		}
		*r = valueRange[T]{Min: v, Max: v}
		return nil
	}
	var bounds map[string]json.RawMessage
	if err := json.Unmarshal(b, &bounds); err != nil {
		return err
	}
	for _, key := range slices.Sorted(maps.Keys(bounds)) {
		if key != "min" && key != "max" {
			return fmt.Errorf("a range has min and max, not %s", key)
		}
	}
	lo, hasMin := bounds["min"]
	hi, hasMax := bounds["max"]
	if !hasMin || !hasMax {
		return errors.New("a range needs both min and max")
	}
	if err := json.Unmarshal(lo, &r.Min); err != nil {
		return err
	}
	if err := json.Unmarshal(hi, &r.Max); err != nil {
		return err
	}
	r.ranged = true
	return nil
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

// scenarios validates every scenario, and checks that selected names one
// unless it is "". Rules may refer only to users, and keys, that the
// configuration defines.
func scenarios(defined map[string]scenarioConfig, selected string, users []sshfront.User) (map[string]Scenario, error) {
	if _, ok := defined[selected]; selected != "" && !ok {
		names := slices.Sorted(maps.Keys(defined))
		if len(names) == 0 {
			return nil, fmt.Errorf("scenario %q is not defined; the configuration defines no scenarios", selected)
		}
		return nil, fmt.Errorf("scenario %q is not defined; the configuration defines %s", selected, strings.Join(names, ", "))
	}
	valid := make(map[string]Scenario, len(defined))
	for _, name := range slices.Sorted(maps.Keys(defined)) {
		field := "scenarios." + name
		if !namePattern.MatchString(name) {
			return nil, fmt.Errorf("%s: a scenario name may hold only lowercase letters, digits and -, starting with a letter or digit", field)
		}
		rules, err := defined[name].rules(field, users)
		if err != nil {
			return nil, err
		}
		valid[name] = Scenario{Seed: defined[name].Seed, Rules: rules}
	}
	return valid, nil
}

func (s scenarioConfig) rules(field string, users []sshfront.User) ([]faults.Rule, error) {
	rules, err := parseRules(field+".", s.Faults, users)
	if err != nil {
		return nil, err
	}
	if err := faults.Check(rules); err != nil {
		return nil, fmt.Errorf("%s: %w", field, err)
	}
	return rules, nil
}

// parseRules returns the rules that rcs give, naming each in errors as
// prefix followed by faults and its index.
func parseRules(prefix string, rcs []ruleConfig, users []sshfront.User) ([]faults.Rule, error) {
	var rules []faults.Rule
	for i, rc := range rcs {
		field := fmt.Sprintf("%sfaults[%d]", prefix, i)
		if !namePattern.MatchString(rc.ID) {
			return nil, fmt.Errorf("%s: id %q must hold only lowercase letters, digits and -, starting with a letter or digit", field, rc.ID)
		}
		field += " (" + rc.ID + ")"
		long, recipe, err := rc.expand()
		if err != nil {
			return nil, fmt.Errorf("%s: %w", field, err)
		}
		if recipe != "" {
			field += ": " + recipe
		}
		r, err := long.rule(users)
		if err != nil {
			return nil, fmt.Errorf("%s: %w", field, err)
		}
		rules = append(rules, r)
	}
	return rules, nil
}

func (rc ruleConfig) rule(users []sshfront.User) (faults.Rule, error) {
	r := faults.Rule{ID: rc.ID, Priority: rc.Priority, MaxTriggers: rc.MaxTriggers}
	var err error
	// A connection action at a moment of the run or the connection matches
	// connections, not requests, so it has no operation.
	moment := rc.atMoment()
	if r.Match, err = rc.Match.match(users, !moment || rc.Trigger.Anchor == "transfer"); err != nil {
		return r, fmt.Errorf("match: %w", err)
	}
	if rc.Trigger != nil {
		if r.Trigger, err = rc.Trigger.trigger(); err != nil {
			return r, fmt.Errorf("trigger: %w", err)
		}
	}
	var noWhen string
	switch {
	case moment:
		noWhen = "at a moment, which acts whatever the client is doing"
	case rc.Match.hasEvent():
		if !slices.Contains(eventActions, rc.Action.Type) {
			return r, fmt.Errorf("action: connect and authenticate take a delay, close_connection, freeze_connection or listener_down, not a %s", rc.Action.Type)
		}
		noWhen = "at connect or authenticate, which have no request to act before or after"
	}
	if err := rc.Action.apply(&r, noWhen); err != nil {
		return r, fmt.Errorf("action: %w", err)
	}
	if d := rc.Decision; d != nil {
		if d.Probability == nil {
			return r, errors.New("decision: probability is required")
		}
		if err := rc.checkScope(d.Scope); err != nil {
			return r, fmt.Errorf("decision: %w", err)
		}
		r.Probability = d.Probability
	}
	return r, nil
}

// checkScope reports a decision scope that the rule cannot have. A partial
// upload or corrupt download is decided once for each transfer, at its
// open, and any other fault for each request, which for an open is the same
// as for its transfer. The scope defaults to the one the action has.
func (rc ruleConfig) checkScope(scope string) error {
	transfer := rc.Action.Type == "partial_upload" || rc.Action.Type == "corrupt_download" ||
		(rc.atMoment() && rc.Trigger.Anchor == "transfer")
	switch scope {
	case "":
	case "transfer":
		opens := !slices.ContainsFunc(rc.Match.Operation, func(op string) bool {
			return op != string(faults.OpenRead) && op != string(faults.OpenWrite)
		})
		if !transfer && !opens {
			return fmt.Errorf("scope transfer needs a partial_upload, a corrupt_download or the open_read and open_write operations; a %s on every request of a chosen transfer is not supported", rc.Action.Type)
		}
	case "operation":
		if transfer {
			return fmt.Errorf("a %s is decided once for each transfer, at its open, so its scope is transfer", rc.Action.Type)
		}
	default:
		return fmt.Errorf("scope %q is not operation or transfer", scope)
	}
	return nil
}

// atMoment reports whether the rule is a connection action that fires at a
// moment rather than at a request.
func (rc ruleConfig) atMoment() bool {
	return rc.Trigger != nil && rc.Trigger.At != nil && slices.Contains(connectionActions, rc.Action.Type)
}

func (tc triggerConfig) trigger() (*faults.Trigger, error) {
	anchor, ok := anchors[tc.Anchor]
	names := strings.Join(slices.Sorted(maps.Keys(anchors)), ", ")
	switch {
	case tc.Anchor == "":
		return nil, fmt.Errorf("anchor is required: one of %s", names)
	case !ok:
		return nil, fmt.Errorf("anchor %q is not one of %s", tc.Anchor, names)
	}
	t := &faults.Trigger{Anchor: anchor}
	switch {
	case tc.At != nil && tc.Window != nil:
		return nil, errors.New("set at or window, not both")
	case tc.At != nil:
		lo, err := nonNegativeDuration("at", tc.At.Min)
		if err != nil {
			return nil, err
		}
		hi := lo
		if tc.At.ranged {
			if hi, err = nonNegativeDuration("at", tc.At.Max); err != nil {
				return nil, err
			}
		}
		t.At = &faults.Range[time.Duration]{Min: lo, Max: hi}
	case tc.Window != nil:
		from, err := nonNegativeDuration("window from", tc.Window.From)
		if err != nil {
			return nil, err
		}
		until, err := nonNegativeDuration("window until", tc.Window.Until)
		if err != nil {
			return nil, err
		}
		t.Window = &faults.Window{From: from, Until: until}
	default:
		return nil, errors.New("at or window is required")
	}
	return t, nil
}

// hasEvent reports whether mc matches a connection event, connect or
// authenticate.
func (mc matchConfig) hasEvent() bool {
	return slices.ContainsFunc(mc.Operation, func(op string) bool {
		return op == string(faults.Connect) || op == string(faults.Authenticate)
	})
}

func (mc matchConfig) match(users []sshfront.User, needsOperation bool) (faults.Match, error) {
	m := faults.Match{User: mc.User, KeyFingerprint: mc.KeyFingerprint, Occurrence: mc.Occurrence}
	if len(mc.Operation) == 0 && needsOperation {
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
	"delay":             {"when", "duration"},
	"fail":              {"when", "status"},
	"close_connection":  {"when", "mode"},
	"freeze_connection": {"when", "max_freeze"},
	"close_subsystem":   {"when"},
	"listener_down":     {"when", "duration", "close_existing"},
	"partial_upload":    {"cutoff_offset", "result", "status", "mode", "max_freeze"},
	"corrupt_download":  {"transform", "offset", "length"},
	"wrong_size":        {"size", "size_delta"},
}

// apply sets the action of r, and the ranges it draws values from. If noWhen
// is set, the action takes no when, for the reason it gives.
func (ac actionConfig) apply(r *faults.Rule, noWhen string) error {
	allowed, ok := actionFields[ac.Type]
	if !ok {
		return fmt.Errorf("type %q is not one of %s", ac.Type, strings.Join(slices.Sorted(maps.Keys(actionFields)), ", "))
	}
	for _, f := range ac.set() {
		if !slices.Contains(allowed, f) {
			return fmt.Errorf("%s does not apply to a %s", f, ac.Type)
		}
	}
	var err error
	switch ac.Type {
	case "delay":
		r.Action, r.Duration, err = ac.delay(noWhen)
	case "fail":
		r.Action, err = ac.fail()
	case "close_connection":
		r.Action, err = ac.closeConnection(noWhen)
	case "freeze_connection":
		r.Action, err = ac.freezeConnection(noWhen)
	case "close_subsystem":
		var when sftpproxy.When
		when, err = ac.whenUnless(noWhen)
		r.Action = sftpproxy.EndSession{When: when}
	case "listener_down":
		r.Action, r.Duration, err = ac.listenerDown(noWhen)
	case "partial_upload":
		r.Action, r.Cutoff, err = ac.partialUpload()
	case "corrupt_download":
		r.Action, err = ac.corruptDownload()
	case "wrong_size":
		r.Action, err = ac.wrongSize()
	}
	return err
}

// set returns the names of the fields that are set, besides type.
func (ac actionConfig) set() []string {
	var names []string
	for name, set := range map[string]bool{
		"when":           ac.When != "",
		"duration":       ac.Duration != nil,
		"status":         ac.Status != "",
		"mode":           ac.Mode != "",
		"max_freeze":     ac.MaxFreeze != "",
		"cutoff_offset":  ac.CutoffOffset != nil,
		"result":         ac.Result != "",
		"transform":      ac.Transform != "",
		"offset":         ac.Offset != nil,
		"length":         ac.Length != nil,
		"size":           ac.Size != nil,
		"size_delta":     ac.SizeDelta != nil,
		"close_existing": ac.CloseExisting != nil,
	} {
		if set {
			names = append(names, name)
		}
	}
	slices.Sort(names)
	return names
}

// delay returns the delay of ac, and the range it draws its duration from
// if ac gives one.
func (ac actionConfig) delay(noWhen string) (sftpproxy.Action, *faults.Range[time.Duration], error) {
	when, err := ac.whenUnless(noWhen)
	if err != nil {
		return nil, nil, err
	}
	d, drawn, err := ac.duration()
	if err != nil {
		return nil, nil, err
	}
	return sftpproxy.Delay{When: when, Duration: d}, drawn, nil
}

// listenerDown returns the outage of ac, which leaves existing connections
// open unless close_existing is true, and the range it draws its duration
// from if ac gives one.
func (ac actionConfig) listenerDown(noWhen string) (sftpproxy.Action, *faults.Range[time.Duration], error) {
	when, err := ac.whenUnless(noWhen)
	if err != nil {
		return nil, nil, err
	}
	d, drawn, err := ac.duration()
	if err != nil {
		return nil, nil, err
	}
	closeExisting := ac.CloseExisting != nil && *ac.CloseExisting
	return sftpproxy.ListenerDown{When: when, Duration: d, CloseExisting: closeExisting}, drawn, nil
}

// duration returns ac's duration, or the range to draw it from if ac gives
// one.
func (ac actionConfig) duration() (time.Duration, *faults.Range[time.Duration], error) {
	if ac.Duration == nil {
		return 0, nil, errors.New("duration is required")
	}
	lo, err := positiveDuration("duration", ac.Duration.Min)
	if err != nil {
		return 0, nil, err
	}
	if !ac.Duration.ranged {
		return lo, nil, nil
	}
	hi, err := positiveDuration("duration", ac.Duration.Max)
	if err != nil {
		return 0, nil, err
	}
	return 0, &faults.Range[time.Duration]{Min: lo, Max: hi}, nil
}

func (ac actionConfig) fail() (sftpproxy.Action, error) {
	when, err := ac.when()
	if err != nil {
		return nil, err
	}
	code, err := status(ac.Status)
	if err != nil {
		return nil, err
	}
	return sftpproxy.Fail{When: when, Status: code}, nil
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

// whenUnless returns when ac acts, or Before, which is ignored, if noWhen
// gives a reason it takes no when.
func (ac actionConfig) whenUnless(noWhen string) (sftpproxy.When, error) {
	if noWhen == "" {
		return ac.when()
	}
	if ac.When != "" {
		return 0, fmt.Errorf("when does not apply to a %s %s", ac.Type, noWhen)
	}
	return sftpproxy.Before, nil
}

// closeConnection returns the Drop that ac's mode chooses, fin unless set.
func (ac actionConfig) closeConnection(noWhen string) (sftpproxy.Action, error) {
	when, err := ac.whenUnless(noWhen)
	if err != nil {
		return nil, err
	}
	switch ac.Mode {
	case "", "fin":
		return sftpproxy.Drop{When: when}, nil
	case "rst":
		return sftpproxy.Drop{When: when, Reset: true}, nil
	}
	return nil, fmt.Errorf("mode %q is not fin or rst", ac.Mode)
}

func (ac actionConfig) freezeConnection(noWhen string) (sftpproxy.Action, error) {
	when, err := ac.whenUnless(noWhen)
	if err != nil {
		return nil, err
	}
	limit, err := positiveDuration("max_freeze", ac.MaxFreeze)
	if err != nil {
		return nil, err
	}
	return sftpproxy.Freeze{When: when, Limit: limit}, nil
}

// partialUpload returns the partial upload of ac, and the range it draws
// its cutoff from if ac gives one.
func (ac actionConfig) partialUpload() (sftpproxy.Action, *faults.Range[uint64], error) {
	if ac.CutoffOffset == nil {
		return nil, nil, errors.New("cutoff_offset is required")
	}
	var u sftpproxy.PartialUpload
	var cutoffs *faults.Range[uint64]
	if ac.CutoffOffset.ranged {
		cutoffs = &faults.Range[uint64]{Min: ac.CutoffOffset.Min, Max: ac.CutoffOffset.Max}
	} else {
		u.Cutoff = ac.CutoffOffset.Min
	}
	result, err := ac.uploadResult()
	if err != nil {
		return nil, nil, err
	}
	u.Result = result
	return u, cutoffs, nil
}

// uploadResult returns what a partial upload of ac does at its cutoff.
func (ac actionConfig) uploadResult() (sftpproxy.Action, error) {
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
		return sftpproxy.Fail{Status: code}, nil
	case "close_connection":
		if ac.MaxFreeze != "" {
			return nil, errors.New("max_freeze applies only to result freeze_connection")
		}
		switch ac.Mode {
		case "", "fin":
			return sftpproxy.Drop{}, nil
		case "rst":
			return sftpproxy.Drop{Reset: true}, nil
		}
		return nil, fmt.Errorf("mode %q is not fin or rst", ac.Mode)
	case "freeze_connection":
		if ac.Mode != "" {
			return nil, errors.New("mode applies only to result close_connection")
		}
		limit, err := positiveDuration("max_freeze", ac.MaxFreeze)
		if err != nil {
			return nil, err
		}
		return sftpproxy.Freeze{Limit: limit}, nil
	case "":
		return nil, errors.New("result is required: status, close_connection or freeze_connection")
	}
	return nil, fmt.Errorf("result %q is not status, close_connection or freeze_connection", ac.Result)
}

func (ac actionConfig) corruptDownload() (sftpproxy.Action, error) {
	names := strings.Join(slices.Sorted(maps.Keys(corruptions)), ", ")
	corruption, ok := corruptions[ac.Transform]
	switch {
	case ac.Transform == "":
		return nil, fmt.Errorf("transform is required: one of %s", names)
	case !ok:
		return nil, fmt.Errorf("transform %q is not one of %s", ac.Transform, names)
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

func nonNegativeDuration(field, value string) (time.Duration, error) {
	if value == "" {
		return 0, fmt.Errorf("%s is required", field)
	}
	d, err := time.ParseDuration(value)
	if err != nil || d < 0 {
		return 0, fmt.Errorf("%s %q is not a duration of 0 or more, such as 0s or 2s", field, value)
	}
	return d, nil
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
