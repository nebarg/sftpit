package config

import (
	"errors"
	"fmt"
	"slices"
	"strings"
	"time"

	"github.com/nebarg/sftpit/internal/faults"
	"github.com/nebarg/sftpit/internal/sshfront"
)

// Fault is a fault in plain terms, as the dashboard and a test's HTTP calls
// give it: a preset, or the steps of a client's work it acts on and what it
// does there, narrowed to some files or a user and to how often it happens.
// Rule compiles it to one of the engine's rules.
type Fault struct {
	// Name is what the dashboard calls the fault; a preset's own name, or
	// "Custom fault", if empty.
	Name string `json:"name,omitempty"`

	// Preset names one of Presets, which sets Steps and Do and the
	// defaults of the settings, which the fault may still change.
	Preset string `json:"preset,omitempty"`

	// Steps are the ids of the Steps the fault acts on, and Do the id of
	// one of Actions, what it does there.
	Steps []string `json:"steps,omitempty"`
	Do    string   `json:"do,omitempty"`

	// The settings of what it does: the Error a refusal answers with,
	// the Seconds of a wait or outage, or the longest a hold or freeze
	// lasts, the KB a transfer stops
	// after, how far a reported size is off by, whether a dropped
	// connection is reset rather than closed, and whether the fault acts
	// after the server has done what was asked rather than before.
	Error     string   `json:"error,omitempty"`
	Seconds   *float64 `json:"seconds,omitempty"`
	KB        *uint64  `json:"kb,omitempty"`
	SizeOffBy *int64   `json:"size_off_by,omitempty"`
	Abrupt    bool     `json:"abrupt,omitempty"`
	After     bool     `json:"after,omitempty"`

	// At most one of Folder, everything beneath a directory, File, one
	// path, and Names, a pattern for the last part of a path, such as
	// *.csv, narrows the files. User narrows it to one user's requests.
	Folder string `json:"folder,omitempty"`
	File   string `json:"file,omitempty"`
	Names  string `json:"names,omitempty"`
	User   string `json:"user,omitempty"`

	// At most one of these says how often it happens, every time if none:
	// the First times only, Only the time numbered so, a Percent of the
	// times, or for the next Minutes.
	First   *uint64  `json:"first,omitempty"`
	Only    *uint64  `json:"only,omitempty"`
	Percent *float64 `json:"percent,omitempty"`
	Minutes *float64 `json:"minutes,omitempty"`
}

// Step is a step of a client's work that a fault can act on.
type Step struct {
	ID   string `json:"id"`
	Name string `json:"name"`
}

// Steps are what a fault can act on, in the order the dashboard offers
// them. Their ids are the engine's operations, with stat standing for
// every way of checking a file.
var Steps = []Step{
	{"connect", "Connecting"},
	{"authenticate", "Logging in"},
	{"list", "Listing a folder"},
	{"stat", "Checking a file"},
	{"open_read", "Starting a download"},
	{"read", "Reading file data"},
	{"open_write", "Starting an upload"},
	{"write", "Writing file data"},
	{"close", "Finishing a file"},
	{"rename", "Renaming or moving"},
	{"remove", "Deleting a file"},
	{"mkdir", "Making a folder"},
	{"rmdir", "Deleting a folder"},
	{"setstat", "Changing permissions or times"},
}

// Action is something a fault can do.
type Action struct {
	ID   string `json:"id"`
	Name string `json:"name"`
}

// Actions are what a fault can do, in the order the dashboard offers them.
var Actions = []Action{
	{"refuse", "Refuse with an error"},
	{"wait", "Wait"},
	{"hold", "Hold until released"},
	{"drop", "Drop the connection"},
	{"freeze", "Freeze the connection"},
	{"stop_partway", "Stop the transfer partway"},
	{"corrupt", "Corrupt the data"},
	{"wrong_size", "Report the wrong size"},
	{"hide", "Pretend the file isn't there"},
	{"down", "Take the server down"},
}

// Preset is a ready-made fault.
type Preset struct {
	ID    string `json:"id"`
	Name  string `json:"name"`
	Hint  string `json:"hint"`
	Fault Fault  `json:"fault"`
}

// commandSteps are every step but connecting, logging in and moving file
// data, so that a preset slows or drops commands without holding each
// piece of a transfer.
var commandSteps = []string{"list", "stat", "open_read", "open_write", "close", "rename", "remove", "mkdir", "rmdir", "setstat"}

// Presets are the ready-made faults, in the order the dashboard offers
// them.
var Presets = []Preset{
	{"deletes_fail", "Deletes fail", "The server refuses to delete", Fault{Steps: []string{"remove"}, Do: "refuse", Error: "permission_denied"}},
	{"renames_fail", "Renames fail", "Moving or publishing a file is refused", Fault{Steps: []string{"rename"}, Do: "refuse", Error: "permission_denied"}},
	{"upload_stops_partway", "Upload stops partway", "The connection drops mid-upload", Fault{Steps: []string{"write"}, Do: "stop_partway", KB: new(uint64(32))}},
	{"download_stops_partway", "Download stops partway", "The connection drops mid-download", Fault{Steps: []string{"read"}, Do: "stop_partway", KB: new(uint64(32))}},
	{"download_corrupted", "Download is corrupted", "Bytes change, and nobody says so", Fault{Steps: []string{"read"}, Do: "corrupt"}},
	{"file_goes_missing", "File goes missing", "Listed, but can't be fetched", Fault{Steps: []string{"open_read", "stat"}, Do: "hide"}},
	{"slow_responses", "Slow responses", "Each command takes longer", Fault{Steps: commandSteps, Do: "wait", Seconds: new(3.0)}},
	{"connection_drops", "Connection drops", "Mid-command, without warning", Fault{Steps: commandSteps, Do: "drop"}},
	{"server_goes_down", "Server goes down", "Refuses connections for a while", Fault{Do: "down", Seconds: new(30.0)}},
	{"logins_fail", "Logins fail", "The connection closes as the login succeeds", Fault{Steps: []string{"authenticate"}, Do: "drop"}},
}

//go:fix inline

// errorStatuses are the errors a refusal can answer with, by their plain
// names, and the statuses they are.
var errorStatuses = map[string]string{
	"permission_denied": "permission_denied",
	"no_such_file":      "no_such_file",
	"failure":           "failure",
	"unsupported":       "op_unsupported",
}

// Resolve returns f with its preset's steps, action and defaults filled in,
// and every setting its action needs, or an error saying what is wrong
// with it.
func (f Fault) Resolve() (Fault, error) {
	if f.Preset != "" {
		i := slices.IndexFunc(Presets, func(p Preset) bool { return p.ID == f.Preset })
		if i < 0 {
			return f, fmt.Errorf("there is no preset %q", f.Preset)
		}
		p := Presets[i]
		// A fault resolved already has its preset's steps and action.
		if (f.Steps != nil && !slices.Equal(f.Steps, p.Fault.Steps)) || (f.Do != "" && f.Do != p.Fault.Do) {
			return f, fmt.Errorf("the preset %s sets the steps and what to do; leave them out, or give them without a preset", f.Preset)
		}
		f.Steps, f.Do = p.Fault.Steps, p.Fault.Do
		f.Name = orDefault(f.Name, p.Name)
		f.Error = orDefault(f.Error, p.Fault.Error)
		f.Seconds = orPointer(f.Seconds, p.Fault.Seconds)
		f.KB = orPointer(f.KB, p.Fault.KB)
	}
	f.Name = orDefault(f.Name, "Custom fault")
	switch f.Do {
	case "refuse":
		f.Error = orDefault(f.Error, "failure")
	case "wait":
		f.Seconds = orPointer(f.Seconds, new(3.0))
	case "freeze":
		f.Seconds = orPointer(f.Seconds, new(60.0))
	case "hold":
		f.Seconds = orPointer(f.Seconds, new(600.0))
	case "down":
		f.Seconds = orPointer(f.Seconds, new(30.0))
	case "stop_partway":
		f.KB = orPointer(f.KB, new(uint64(32)))
	case "wrong_size":
		f.SizeOffBy = orPointer(f.SizeOffBy, new(int64(-1024)))
	}
	if _, err := f.ruleConfig("check"); err != nil {
		return f, err
	}
	return f, nil
}

func orDefault(s, def string) string {
	if s == "" {
		return def
	}
	return s
}

func orPointer[T any](p, def *T) *T {
	if p == nil {
		return def
	}
	return p
}

// Rule returns the engine's rule for f, with id, checked against users as
// a configured rule is.
func (f Fault) Rule(id string, users []sshfront.User) (faults.Rule, error) {
	resolved, err := f.Resolve()
	if err != nil {
		return faults.Rule{}, err
	}
	rc, err := resolved.ruleConfig(id)
	if err != nil {
		return faults.Rule{}, err
	}
	return rc.rule(users)
}

// ruleConfig returns f, resolved, as a rule in the long form.
func (f Fault) ruleConfig(id string) (ruleConfig, error) {
	rc := ruleConfig{ID: id, Match: matchConfig{User: f.User, PathPrefix: f.Folder, Path: f.File, FilenameGlob: f.Names}}
	if n := countSet(f.Folder != "", f.File != "", f.Names != ""); n > 1 {
		return rc, errors.New("choose one of folder, file and names")
	}
	events := slices.Contains(f.Steps, "connect") || slices.Contains(f.Steps, "authenticate")
	if events && len(f.Steps) > 1 {
		return rc, errors.New("connecting and logging in can't be combined with other steps")
	}
	if events && (f.Folder != "" || f.File != "" || f.Names != "") {
		return rc, errors.New("connecting and logging in have no file, so leave out folder, file and names")
	}
	if f.Do == "" {
		return rc, errors.New("say what to do, or choose a preset")
	}
	if len(f.Steps) == 0 && f.Do != "down" {
		return rc, errors.New("choose at least one step")
	}
	ops, err := operations(f.Steps, f.Do)
	if err != nil {
		return rc, err
	}
	rc.Match.Operation = ops

	when := "before"
	if f.After {
		when = "after"
	}
	if events {
		when = ""
	}
	if f.After && !slices.Contains([]string{"refuse", "wait", "hold", "drop", "freeze", "down"}, f.Do) {
		return rc, fmt.Errorf("%s can't act after the server has done what was asked", f.Do)
	}
	if events && f.After {
		return rc, errors.New("connecting and logging in have no before or after")
	}
	mode := "fin"
	if f.Abrupt {
		mode = "rst"
	}
	transfer := f.Do == "stop_partway" || f.Do == "corrupt"

	switch f.Do {
	case "refuse":
		if events {
			return rc, errors.New("connecting and logging in can't be refused with an error; drop the connection instead")
		}
		status, ok := errorStatuses[f.Error]
		if !ok {
			return rc, fmt.Errorf("error %q is not one of %s", f.Error, strings.Join(sortedKeys(errorStatuses), ", "))
		}
		rc.Action = actionConfig{Type: "fail", When: when, Status: status}
	case "wait":
		d, err := seconds(f.Seconds)
		if err != nil {
			return rc, err
		}
		rc.Action = actionConfig{Type: "delay", When: when, Duration: &valueRange[string]{Min: d, Max: d}}
	case "hold":
		if events {
			return rc, errors.New("connecting and logging in can't be held; wait or freeze instead")
		}
		d, err := seconds(f.Seconds)
		if err != nil {
			return rc, err
		}
		rc.Action = actionConfig{Type: "stall", When: when, MaxStall: d}
	case "drop":
		rc.Action = actionConfig{Type: "close_connection", When: when, Mode: mode}
	case "freeze":
		d, err := seconds(f.Seconds)
		if err != nil {
			return rc, err
		}
		rc.Action = actionConfig{Type: "freeze_connection", When: when, MaxFreeze: d}
	case "stop_partway":
		action, err := transferAction(f.Steps, "partial_upload", "partial_download", "stopping partway")
		if err != nil {
			return rc, err
		}
		cutoff := *f.KB * 1024
		rc.Action = actionConfig{Type: action, CutoffOffset: &valueRange[uint64]{Min: cutoff, Max: cutoff}, Result: "close_connection", Mode: mode}
	case "corrupt":
		action, err := transferAction(f.Steps, "corrupt_upload", "corrupt_download", "corrupting data")
		if err != nil {
			return rc, err
		}
		rc.Action = actionConfig{Type: action, Transform: "flip_bytes", Offset: new(uint64(0)), Length: new(uint64(64))}
	case "wrong_size":
		if err := onlySteps(f.Steps, "a wrong size", "stat", "list"); err != nil {
			return rc, err
		}
		rc.Action = actionConfig{Type: "wrong_size", SizeDelta: f.SizeOffBy}
	case "hide":
		if err := onlySteps(f.Steps, "hiding a file", "open_read", "stat", "list", "remove", "rename"); err != nil {
			return rc, err
		}
		rc.Action = actionConfig{Type: "hide"}
	case "down":
		d, err := seconds(f.Seconds)
		if err != nil {
			return rc, err
		}
		rc.Action = actionConfig{Type: "listener_down", Duration: &valueRange[string]{Min: d, Max: d}, CloseExisting: new(true)}
		if len(f.Steps) == 0 {
			if f.After || f.Folder != "" || f.File != "" || f.Names != "" {
				return rc, errors.New("a server that goes down at once has no files or before and after; choose steps to take it down at one of them")
			}
			rc.Trigger = &triggerConfig{At: &valueRange[string]{Min: "0s", Max: "0s"}, Anchor: "run"}
		} else {
			rc.Action.When = when
		}
	default:
		return rc, fmt.Errorf("there is nothing to do called %q", f.Do)
	}

	if n := countSet(f.First != nil, f.Only != nil, f.Percent != nil, f.Minutes != nil); n > 1 {
		return rc, errors.New("choose one of first, only, percent and minutes")
	}
	switch {
	case f.First != nil:
		if *f.First == 0 {
			return rc, errors.New("first must be at least 1")
		}
		rc.MaxTriggers = int(*f.First)
	case f.Only != nil:
		if *f.Only == 0 {
			return rc, errors.New("only must be at least 1")
		}
		// A transfer is decided as its file opens, so its times count the
		// opens of each file rather than each piece of data.
		if transfer {
			rc.Match.Attempt = &attemptConfig{Per: []string{"path"}, Numbers: []uint64{*f.Only}}
		} else {
			rc.Match.Occurrence = []uint64{*f.Only}
		}
	case f.Percent != nil:
		if *f.Percent <= 0 || *f.Percent > 100 {
			return rc, errors.New("percent must be above 0 and at most 100")
		}
		rc.Decision = &decisionConfig{Probability: new(*f.Percent / 100)}
	case f.Minutes != nil:
		if *f.Minutes <= 0 {
			return rc, errors.New("minutes must be above 0")
		}
		if rc.Trigger != nil {
			return rc, errors.New("a server that goes down at once can't also last for some minutes; give its seconds instead")
		}
		until := time.Duration(*f.Minutes * float64(time.Minute)).String()
		rc.Trigger = &triggerConfig{Window: &windowConfig{From: "0s", Until: until}, Anchor: "run"}
	}
	return rc, nil
}

// operations returns the engine's operations for steps, given what the
// fault does there, or an error naming a step that is not one of Steps.
func operations(steps []string, do string) (stringList, error) {
	var ops stringList
	for _, step := range steps {
		if !slices.ContainsFunc(Steps, func(s Step) bool { return s.ID == step }) {
			ids := make([]string, len(Steps))
			for i, s := range Steps {
				ids[i] = s.ID
			}
			return nil, fmt.Errorf("there is no step %q; the steps are %s", step, strings.Join(ids, ", "))
		}
		switch {
		case step == "stat" && do == "hide":
			ops = append(ops, "stat", "lstat")
		case step == "stat":
			ops = append(ops, "stat", "lstat", "fstat")
		default:
			ops = append(ops, step)
		}
	}
	return ops, nil
}

// transferAction returns upload's action for the step write, and
// download's for read, which must be the only step.
func transferAction(steps []string, upload, download, what string) (string, error) {
	switch {
	case slices.Equal(steps, []string{"write"}):
		return upload, nil
	case slices.Equal(steps, []string{"read"}):
		return download, nil
	}
	return "", fmt.Errorf("%s applies to writing file data or reading it; choose one of them", what)
}

// onlySteps reports a step outside allowed.
func onlySteps(steps []string, what string, allowed ...string) error {
	for _, s := range steps {
		if !slices.Contains(allowed, s) {
			return fmt.Errorf("%s applies only to the steps %s", what, strings.Join(allowed, ", "))
		}
	}
	return nil
}

// seconds returns s seconds as a duration the long form reads.
func seconds(s *float64) (string, error) {
	if s == nil || *s <= 0 {
		return "", errors.New("seconds must be above 0")
	}
	return time.Duration(*s * float64(time.Second)).String(), nil
}

func countSet(set ...bool) int {
	n := 0
	for _, s := range set {
		if s {
			n++
		}
	}
	return n
}

// ErrorNames returns the errors a refusal can answer with, sorted.
func ErrorNames() []string { return sortedKeys(errorStatuses) }

func sortedKeys(m map[string]string) []string {
	keys := make([]string, 0, len(m))
	for k := range m {
		keys = append(keys, k)
	}
	slices.Sort(keys)
	return keys
}
