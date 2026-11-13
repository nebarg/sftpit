package config

import (
	"errors"
	"fmt"
	"maps"
	"slices"
	"strings"
	"time"

	"github.com/nebarg/sftpit/internal/faults"
	"github.com/nebarg/sftpit/internal/sftpproxy"
	"github.com/nebarg/sftpit/internal/sftpwire"
	"github.com/nebarg/sftpit/internal/sshfront"
)

// Fault is a fault in plain terms, as the dashboard and a test's HTTP calls
// give it: a preset, or the steps of a client's work it acts on and what it
// does there, narrowed to some files or a user and to how often it happens.
// Rule compiles it to one of the engine's rules.
type Fault struct {
	// Name is what the dashboard calls the fault; a preset's own name, or
	// "Custom fault", if empty.
	Name string `json:"name,omitempty" yaml:"name,omitempty"`

	// Preset names one of Presets, which sets Steps and Do and the
	// defaults of the settings, which the fault may still change.
	Preset string `json:"preset,omitempty" yaml:"preset,omitempty"`

	// Steps are the ids of the Steps the fault acts on, and Do the id of
	// one of Actions, what it does there.
	Steps []string `json:"steps,omitempty" yaml:"steps,flow,omitempty"`
	Do    string   `json:"do,omitempty" yaml:"do,omitempty"`

	// The settings of what it does: the Error a refusal answers with, or a
	// transfer stopped partway instead of closing the connection, the
	// Seconds of a wait or outage, or the longest a hold or freeze lasts,
	// the KB a transfer stops or is cut short after, how far a reported
	// size is off by, whether a dropped connection is reset rather than
	// closed, and whether the fault acts after the server has done what was
	// asked rather than before.
	Error     string   `json:"error,omitempty" yaml:"error,omitempty"`
	Seconds   *float64 `json:"seconds,omitempty" yaml:"seconds,omitempty"`
	KB        *uint64  `json:"kb,omitempty" yaml:"kb,omitempty"`
	SizeOffBy *int64   `json:"size_off_by,omitempty" yaml:"size_off_by,omitempty"`
	Abrupt    bool     `json:"abrupt,omitempty" yaml:"abrupt,omitempty"`
	After     bool     `json:"after,omitempty" yaml:"after,omitempty"`

	// At most one of Folder, everything beneath a directory, File, one
	// path, and Names, a pattern for the last part of a path, such as
	// *.csv, narrows the files. User narrows it to one user's requests.
	Folder string `json:"folder,omitempty" yaml:"folder,omitempty"`
	File   string `json:"file,omitempty" yaml:"file,omitempty"`
	Names  string `json:"names,omitempty" yaml:"names,omitempty"`
	User   string `json:"user,omitempty" yaml:"user,omitempty"`

	// At most one of these says how often it happens, every time if none:
	// the First times only, Only the time numbered so, a Percent of the
	// times, or for the next Minutes.
	First   *uint64  `json:"first,omitempty" yaml:"first,omitempty"`
	Only    *uint64  `json:"only,omitempty" yaml:"only,omitempty"`
	Percent *float64 `json:"percent,omitempty" yaml:"percent,omitempty"`
	Minutes *float64 `json:"minutes,omitempty" yaml:"minutes,omitempty"`
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
	{"wait", "Delay the reply"},
	{"hold", "Hold the request until released"},
	{"drop", "Close the connection"},
	{"freeze", "Stop responding, keeping the connection open"},
	{"stop_partway", "Stop a transfer partway"},
	{"corrupt", "Change the data"},
	{"truncate", "Cut the file short, without an error"},
	{"wrong_size", "Report the wrong file size"},
	{"hide", "Answer “no such file”"},
	{"down", "Take the server offline"},
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
	{"deletes_fail", "Deletes fail", "Delete requests are refused with “permission denied”.", Fault{Steps: []string{"remove"}, Do: "refuse", Error: "permission_denied"}},
	{"renames_fail", "Renames fail", "Rename requests are refused with “permission denied”.", Fault{Steps: []string{"rename"}, Do: "refuse", Error: "permission_denied"}},
	{"upload_stops_partway", "Uploads stop partway", "The connection closes once an upload reaches 32 KB.", Fault{Steps: []string{"write"}, Do: "stop_partway", KB: new(uint64(32))}},
	{"download_stops_partway", "Downloads stop partway", "The connection closes once a download reaches 32 KB.", Fault{Steps: []string{"read"}, Do: "stop_partway", KB: new(uint64(32))}},
	{"download_corrupted", "Downloads are corrupted", "The first 64 bytes of each download are changed. The client gets no error.", Fault{Steps: []string{"read"}, Do: "corrupt"}},
	{"file_goes_missing", "Files can't be opened", "Files still appear in listings, but opening one returns “no such file”.", Fault{Steps: []string{"open_read", "stat"}, Do: "hide"}},
	{"slow_responses", "Slow responses", "Every request except reading and writing data waits 3 seconds.", Fault{Steps: commandSteps, Do: "wait", Seconds: new(3.0)}},
	{"connection_drops", "Connections close", "The connection closes when a request arrives.", Fault{Steps: commandSteps, Do: "drop"}},
	{"server_goes_down", "Server goes down", "Open connections close, and new ones are refused for 30 seconds.", Fault{Do: "down", Seconds: new(30.0)}},
	{"logins_fail", "Logins fail", "The connection closes just after a successful login.", Fault{Steps: []string{"authenticate"}, Do: "drop"}},
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
	case "stop_partway", "truncate":
		f.KB = orPointer(f.KB, new(uint64(32)))
	case "wrong_size":
		f.SizeOffBy = orPointer(f.SizeOffBy, new(int64(-1024)))
	}
	if _, err := f.compile("check"); err != nil {
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

// Rule returns the engine's rule for f, with id. Its user, if it has one,
// must be one of users.
func (f Fault) Rule(id string, users []sshfront.User) (faults.Rule, error) {
	resolved, err := f.Resolve()
	if err != nil {
		return faults.Rule{}, err
	}
	if f.User != "" {
		if err := checkUser(f.User, users); err != nil {
			return faults.Rule{}, err
		}
	}
	return resolved.compile(id)
}

// operations returns the engine's operations for steps, given what the
// fault does there, or an error naming a step that is not one of Steps.
func operations(steps []string, do string) ([]faults.Operation, error) {
	var ops []faults.Operation
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
			ops = append(ops, faults.Stat, faults.LStat)
		case step == "stat":
			ops = append(ops, faults.Stat, faults.LStat, faults.FStat)
		default:
			ops = append(ops, faults.Operation(step))
		}
	}
	return ops, nil
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
func ErrorNames() []string { return slices.Sorted(maps.Keys(errorCodes)) }

// errorCodes are the statuses of the errors a refusal can answer with, by
// their plain names.
var errorCodes = map[string]sftpwire.StatusCode{
	"permission_denied": sftpwire.StatusPermissionDenied,
	"no_such_file":      sftpwire.StatusNoSuchFile,
	"failure":           sftpwire.StatusFailure,
	"unsupported":       sftpwire.StatusOpUnsupported,
}

// compile returns f, resolved, as the engine's rule with id, or an error
// saying what is wrong with it.
func (f Fault) compile(id string) (faults.Rule, error) {
	r := faults.Rule{ID: id, Match: faults.Match{User: f.User}}
	switch n := countSet(f.Folder != "", f.File != "", f.Names != ""); {
	case n > 1:
		return r, errors.New("choose one of folder, file and names")
	case f.Folder != "":
		r.Match.Path = faults.Location{Kind: faults.Under, Pattern: f.Folder}
	case f.File != "":
		r.Match.Path = faults.Location{Kind: faults.Exactly, Pattern: f.File}
	case f.Names != "":
		r.Match.Path = faults.Location{Kind: faults.NamedGlob, Pattern: f.Names}
	}
	events := slices.Contains(f.Steps, "connect") || slices.Contains(f.Steps, "authenticate")
	if events && len(f.Steps) > 1 {
		return r, errors.New("connecting and logging in can't be combined with other steps")
	}
	if events && (f.Folder != "" || f.File != "" || f.Names != "") {
		return r, errors.New("connecting and logging in have no file, so leave out folder, file and names")
	}
	if f.Do == "" {
		return r, errors.New("say what to do, or choose a preset")
	}
	if len(f.Steps) == 0 && f.Do != "down" {
		return r, errors.New("choose at least one step")
	}
	var err error
	if r.Match.Operations, err = operations(f.Steps, f.Do); err != nil {
		return r, err
	}
	if f.After && !slices.Contains([]string{"refuse", "wait", "hold", "drop", "freeze", "down"}, f.Do) {
		return r, fmt.Errorf("%s can't act after the server has done what was asked", f.Do)
	}
	if events && f.After {
		return r, errors.New("connecting and logging in have no before or after")
	}
	if r.Action, err = f.action(events); err != nil {
		return r, err
	}
	if f.Do == "down" && len(f.Steps) == 0 {
		if f.After || f.Folder != "" || f.File != "" || f.Names != "" {
			return r, errors.New("a server that goes down at once has no files or before and after; choose steps to take it down at one of them")
		}
		r.Trigger = &faults.Trigger{Anchor: faults.Run, At: &faults.Range[time.Duration]{}}
	}
	if err := f.often(&r); err != nil {
		return r, err
	}
	return r, nil
}

// action returns what f does, at connecting or logging in if events is
// set, which have no before or after.
func (f Fault) action(events bool) (sftpproxy.Action, error) {
	when := sftpproxy.Before
	if f.After {
		when = sftpproxy.After
	}
	switch f.Do {
	case "refuse":
		if events {
			return nil, errors.New("connecting and logging in can't be refused with an error; drop the connection instead")
		}
		code, err := errorCode(f.Error)
		return sftpproxy.Fail{When: when, Status: code}, err
	case "wait":
		d, err := seconds(f.Seconds)
		return sftpproxy.Delay{When: when, Duration: d}, err
	case "hold":
		if events {
			return nil, errors.New("connecting and logging in can't be held; wait or freeze instead")
		}
		d, err := seconds(f.Seconds)
		return sftpproxy.Stall{When: when, Limit: d}, err
	case "drop":
		return sftpproxy.Drop{When: when, Reset: f.Abrupt}, nil
	case "freeze":
		d, err := seconds(f.Seconds)
		return sftpproxy.Freeze{When: when, Limit: d}, err
	case "stop_partway":
		if err := transferStep(f.Steps, "stopping partway"); err != nil {
			return nil, err
		}
		cutoff := *f.KB * 1024
		var result sftpproxy.Action = sftpproxy.Drop{Reset: f.Abrupt}
		if f.Error != "" {
			if f.Abrupt {
				return nil, errors.New("a transfer stopped partway either answers with an error or closes the connection abruptly, not both")
			}
			code, err := errorCode(f.Error)
			if err != nil {
				return nil, err
			}
			result = sftpproxy.Fail{Status: code}
		}
		if f.Steps[0] == "write" {
			return sftpproxy.PartialUpload{Cutoff: cutoff, Result: result}, nil
		}
		return sftpproxy.PartialDownload{Cutoff: cutoff, Result: result}, nil
	case "corrupt":
		if err := transferStep(f.Steps, "corrupting data"); err != nil {
			return nil, err
		}
		if f.Steps[0] == "write" {
			return sftpproxy.CorruptUpload{Corruption: sftpproxy.FlipBytes, Length: 64}, nil
		}
		return sftpproxy.CorruptDownload{Corruption: sftpproxy.FlipBytes, Length: 64}, nil
	case "truncate":
		if err := transferStep(f.Steps, "cutting a file short"); err != nil {
			return nil, err
		}
		if f.Steps[0] == "write" {
			return sftpproxy.CorruptUpload{Corruption: sftpproxy.Truncate, Offset: *f.KB * 1024}, nil
		}
		return sftpproxy.CorruptDownload{Corruption: sftpproxy.Truncate, Offset: *f.KB * 1024}, nil
	case "wrong_size":
		if err := onlySteps(f.Steps, "a wrong size", "stat", "list"); err != nil {
			return nil, err
		}
		if *f.SizeOffBy == 0 {
			return nil, errors.New("size_off_by can't be 0")
		}
		return sftpproxy.WrongSize{Delta: *f.SizeOffBy}, nil
	case "hide":
		if err := onlySteps(f.Steps, "hiding a file", "open_read", "stat", "list", "remove", "rename"); err != nil {
			return nil, err
		}
		return sftpproxy.Hide{}, nil
	case "down":
		d, err := seconds(f.Seconds)
		return sftpproxy.ListenerDown{When: when, Duration: d, CloseExisting: true}, err
	}
	return nil, fmt.Errorf("there is nothing to do called %q", f.Do)
}

// often narrows r to how often f happens.
func (f Fault) often(r *faults.Rule) error {
	if n := countSet(f.First != nil, f.Only != nil, f.Percent != nil, f.Minutes != nil); n > 1 {
		return errors.New("choose one of first, only, percent and minutes")
	}
	switch {
	case f.First != nil:
		if *f.First == 0 {
			return errors.New("first must be at least 1")
		}
		r.MaxTriggers = int(*f.First)
	case f.Only != nil:
		if *f.Only == 0 {
			return errors.New("only must be at least 1")
		}
		// A transfer is decided as its file opens, so its times count the
		// opens of each file rather than each piece of data.
		if r.IsTransfer() {
			r.Match.Attempt = &faults.Attempt{PerPath: true, Numbers: []uint64{*f.Only}}
		} else {
			r.Match.Occurrence = []uint64{*f.Only}
		}
	case f.Percent != nil:
		if *f.Percent <= 0 || *f.Percent > 100 {
			return errors.New("percent must be above 0 and at most 100")
		}
		r.Probability = new(*f.Percent / 100)
	case f.Minutes != nil:
		if *f.Minutes <= 0 {
			return errors.New("minutes must be above 0")
		}
		if r.Trigger != nil {
			return errors.New("a server that goes down at once can't also last for some minutes; give its seconds instead")
		}
		r.Trigger = &faults.Trigger{Anchor: faults.Run, Window: &faults.Window{Until: time.Duration(*f.Minutes * float64(time.Minute))}}
	}
	return nil
}

// errorCode returns the status of the error named name.
func errorCode(name string) (sftpwire.StatusCode, error) {
	code, ok := errorCodes[name]
	if !ok {
		return 0, fmt.Errorf("error %q is not one of %s", name, strings.Join(ErrorNames(), ", "))
	}
	return code, nil
}

// transferStep reports steps other than writing or reading file data alone.
func transferStep(steps []string, what string) error {
	if slices.Equal(steps, []string{"write"}) || slices.Equal(steps, []string{"read"}) {
		return nil
	}
	return fmt.Errorf("%s applies to writing file data or reading it; choose one of them", what)
}

// seconds returns s seconds as a duration, which must be above 0.
func seconds(s *float64) (time.Duration, error) {
	if s == nil || *s <= 0 || time.Duration(*s*float64(time.Second)) <= 0 {
		return 0, errors.New("seconds must be above 0")
	}
	return time.Duration(*s * float64(time.Second)), nil
}
