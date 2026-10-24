package config

import (
	"bytes"
	"cmp"
	"encoding/json"
	"fmt"
	"maps"
	"slices"
	"time"

	"go.yaml.in/yaml/v3"

	"github.com/nebarg/sftpit/internal/faults"
	"github.com/nebarg/sftpit/internal/sftpproxy"
	"github.com/nebarg/sftpit/internal/sftpwire"
)

// Explain returns the configuration that Load reads for opts, written as a
// configuration file: every default filled in, every path absolute, recipes
// in the long form and each scenario's rules in the order they are tried.
// Comments say where each secret comes from, without its value. Loading the
// result gives the same configuration. Unlike Load, Explain reports a
// missing or empty secret in a comment rather than as an error.
func Explain(opts Options) ([]byte, error) {
	r, err := read(opts, false)
	if err != nil {
		return nil, err
	}
	cfg := r.cfg
	f := fileConfig{
		SchemaVersion: SchemaVersion,
		EnvFile:       r.envFiles,
		Server:        serverConfig{SFTPListen: cfg.SFTPListen, HTTPListen: cfg.HTTPListen, HostKey: cmp.Or(cfg.HostKeyDir, hostKeyWorkspace)},
		Storage: storageConfig{
			DataDir:       cfg.DataDir,
			SeedDir:       cfg.SeedDir,
			MaxFileBytes:  &cfg.Limits.MaxFileBytes,
			MaxTotalBytes: &cfg.Limits.MaxTotalBytes,
			MaxFiles:      &cfg.Limits.MaxFiles,
			MaxOpenFiles:  &cfg.Limits.MaxOpenFiles,
		},
	}
	for i, u := range r.file.Users {
		f.Users = append(f.Users, userConfig{Name: u.Name, PasswordEnv: u.PasswordEnv, Home: cfg.Users[i].Home})
		if u.AuthorizedKeys != "" {
			f.Users[i].AuthorizedKeys = resolvePath(r.dir, u.AuthorizedKeys)
		}
	}
	if len(cfg.Scenarios) > 0 {
		f.Scenarios = make(map[string]scenarioConfig, len(cfg.Scenarios))
	}
	for name, s := range cfg.Scenarios {
		rules := slices.Clone(s.Rules)
		slices.SortStableFunc(rules, func(a, b faults.Rule) int { return cmp.Compare(a.Priority, b.Priority) })
		sc := scenarioConfig{Seed: s.Seed, Faults: []ruleConfig{}}
		for _, rule := range rules {
			sc.Faults = append(sc.Faults, longForm(rule))
		}
		f.Scenarios[name] = sc
	}

	var b bytes.Buffer
	b.WriteString(r.header(opts.ConfigFile))
	enc := yaml.NewEncoder(&b)
	enc.SetIndent(2)
	if err := enc.Encode(f); err != nil {
		return nil, fmt.Errorf("config: write the configuration: %w", err)
	}
	if err := enc.Close(); err != nil {
		return nil, fmt.Errorf("config: write the configuration: %w", err)
	}
	return b.Bytes(), nil
}

// header returns the comments that open an explained configuration.
func (r *reading) header(configFile string) string {
	var b bytes.Buffer
	if configFile == "" {
		b.WriteString("# The configuration sftpit uses without a config file.\n")
	} else {
		fmt.Fprintf(&b, "# The configuration sftpit reads from %s.\n", configFile)
	}
	b.WriteString("# Every default is filled in, every path is absolute, recipes are in the\n# long form and each scenario's rules are in the order they are tried.\n")
	if r.cfg.DefaultCredentials {
		fmt.Fprintf(&b, "#\n# No users are configured, so sftpit accepts the user %s with the password %s.\n", DefaultUser, DefaultPassword)
	}
	names := slices.Sorted(maps.Keys(referencedSecrets(r.file.Users)))
	if len(names) > 0 {
		b.WriteString("#\n# Secrets, whose values are never shown:\n")
	}
	for _, name := range names {
		value, found := r.secrets.values[name]
		switch {
		case !found:
			fmt.Fprintf(&b, "#   %s: missing; it is not in %s\n", name, r.secrets.searched)
		case value == "":
			fmt.Fprintf(&b, "#   %s: empty, in %s\n", name, r.secrets.sources[name])
		default:
			fmt.Fprintf(&b, "#   %s: from %s\n", name, r.secrets.sources[name])
		}
	}
	return b.String()
}

// MarshalYAML writes a value as itself, and a range as {min, max}.
func (r valueRange[T]) MarshalYAML() (any, error) {
	if !r.ranged {
		return r.Min, nil
	}
	return flowNode(struct {
		Min T `yaml:"min"`
		Max T `yaml:"max"`
	}{r.Min, r.Max})
}

// MarshalJSON writes a value as itself, and a range as {"min", "max"}.
func (r valueRange[T]) MarshalJSON() ([]byte, error) {
	if !r.ranged {
		return json.Marshal(r.Min)
	}
	return json.Marshal(struct {
		Min T `json:"min"`
		Max T `json:"max"`
	}{r.Min, r.Max})
}

// longForm returns r as a rule in the long form, with every default
// spelled out.
func longForm(r faults.Rule) ruleConfig {
	rc := ruleConfig{ID: r.ID, Priority: r.Priority, MaxTriggers: r.MaxTriggers, Match: longMatch(r.Match), Trigger: longTrigger(r.Trigger), Action: longAction(r)}
	if r.Probability != nil {
		scope := "operation"
		switch r.Action.(type) {
		case sftpproxy.PartialUpload, sftpproxy.CorruptDownload:
			scope = "transfer"
		}
		if r.Trigger != nil && r.Trigger.Anchor == faults.Transfer {
			scope = "transfer"
		}
		rc.Decision = &decisionConfig{Probability: r.Probability, Scope: scope}
	}
	return rc
}

func longTrigger(t *faults.Trigger) *triggerConfig {
	if t == nil {
		return nil
	}
	tc := &triggerConfig{Anchor: t.Anchor.String()}
	if at := t.At; at != nil {
		tc.At = &valueRange[string]{Min: at.Min.String(), Max: at.Max.String(), ranged: at.Min != at.Max}
	}
	if w := t.Window; w != nil {
		tc.Window = &windowConfig{From: w.From.String(), Until: w.Until.String()}
	}
	return tc
}

func longMatch(m faults.Match) matchConfig {
	mc := matchConfig{User: m.User, KeyFingerprint: m.KeyFingerprint, Occurrence: m.Occurrence}
	for _, op := range m.Operations {
		mc.Operation = append(mc.Operation, string(op))
	}
	if slices.Equal(m.Operations, []faults.Operation{faults.Rename}) {
		setLocation(m.Path, &mc.Source, &mc.SourcePrefix, &mc.SourceGlob, &mc.SourceFilename, &mc.SourceFilenameGlob)
	} else {
		setLocation(m.Path, &mc.Path, &mc.PathPrefix, &mc.PathGlob, &mc.Filename, &mc.FilenameGlob)
	}
	setLocation(m.Target, &mc.Target, &mc.TargetPrefix, &mc.TargetGlob, &mc.TargetFilename, &mc.TargetFilenameGlob)
	if a := m.Attempt; a != nil {
		mc.Attempt = &attemptConfig{Numbers: a.Numbers}
		if a.PerUser {
			mc.Attempt.Per = append(mc.Attempt.Per, "user")
		}
		if a.PerPath {
			mc.Attempt.Per = append(mc.Attempt.Per, "path")
		}
	}
	return mc
}

// setLocation sets the one of the fields that matches as l does.
func setLocation(l faults.Location, exactly, under, glob, named, namedGlob *string) {
	field := map[faults.LocationKind]*string{
		faults.Exactly:   exactly,
		faults.Under:     under,
		faults.Glob:      glob,
		faults.Named:     named,
		faults.NamedGlob: namedGlob,
	}[l.Kind]
	if field != nil {
		*field = l.Pattern
	}
}

func longAction(r faults.Rule) actionConfig {
	switch a := r.Action.(type) {
	case sftpproxy.Delay:
		return actionConfig{Type: "delay", When: actionWhen(r, a.When), Duration: longDuration(r, a.Duration)}
	case sftpproxy.Fail:
		return actionConfig{Type: "fail", When: whenName(a.When), Status: statusName(a.Status)}
	case sftpproxy.Drop:
		return actionConfig{Type: "close_connection", When: connectionWhen(r, a.When), Mode: dropMode(a)}
	case sftpproxy.Freeze:
		return actionConfig{Type: "freeze_connection", When: connectionWhen(r, a.When), MaxFreeze: a.Limit.String()}
	case sftpproxy.EndSession:
		return actionConfig{Type: "close_subsystem", When: connectionWhen(r, a.When)}
	case sftpproxy.ListenerDown:
		return actionConfig{Type: "listener_down", When: connectionWhen(r, a.When), Duration: longDuration(r, a.Duration), CloseExisting: &a.CloseExisting}
	case sftpproxy.PartialUpload:
		ac := actionConfig{Type: "partial_upload", CutoffOffset: &valueRange[uint64]{Min: a.Cutoff, Max: a.Cutoff}}
		if c := r.Cutoff; c != nil {
			ac.CutoffOffset = &valueRange[uint64]{Min: c.Min, Max: c.Max, ranged: true}
		}
		switch result := a.Result.(type) {
		case sftpproxy.Fail:
			ac.Result, ac.Status = "status", statusName(result.Status)
		case sftpproxy.Drop:
			ac.Result, ac.Mode = "close_connection", dropMode(result)
		case sftpproxy.Freeze:
			ac.Result, ac.MaxFreeze = "freeze_connection", result.Limit.String()
		}
		return ac
	case sftpproxy.CorruptDownload:
		ac := actionConfig{Type: "corrupt_download", Offset: &a.Offset}
		for name, c := range corruptions {
			if c == a.Corruption {
				ac.Transform = name
			}
		}
		if a.Corruption != sftpproxy.Truncate {
			ac.Length = &a.Length
		}
		return ac
	case sftpproxy.WrongSize:
		if a.Delta != 0 {
			return actionConfig{Type: "wrong_size", SizeDelta: &a.Delta}
		}
		return actionConfig{Type: "wrong_size", Size: &a.Size}
	}
	// The configuration makes no other action, and faults.Check refuses any
	// other.
	panic(fmt.Sprintf("config: no long form for %T", r.Action))
}

// longDuration returns d, or the range that r draws a duration from.
func longDuration(r faults.Rule, d time.Duration) *valueRange[string] {
	if rd := r.Duration; rd != nil {
		return &valueRange[string]{Min: rd.Min.String(), Max: rd.Max.String(), ranged: true}
	}
	return &valueRange[string]{Min: d.String(), Max: d.String()}
}

// actionWhen returns the when of r's action, which has none at connect or
// authenticate.
func actionWhen(r faults.Rule, w sftpproxy.When) string {
	if slices.ContainsFunc(r.Match.Operations, func(op faults.Operation) bool { return op == faults.Connect || op == faults.Authenticate }) {
		return ""
	}
	return whenName(w)
}

// connectionWhen returns the when of r's connection action, which has none
// at a moment either.
func connectionWhen(r faults.Rule, w sftpproxy.When) string {
	if r.Trigger != nil && r.Trigger.At != nil {
		return ""
	}
	return actionWhen(r, w)
}

func whenName(w sftpproxy.When) string {
	if w == sftpproxy.After {
		return "after"
	}
	return "before"
}

func dropMode(d sftpproxy.Drop) string {
	if d.Reset {
		return "rst"
	}
	return "fin"
}

func statusName(code sftpwire.StatusCode) string {
	for name, c := range statuses {
		if c == code {
			return name
		}
	}
	return code.String()
}
