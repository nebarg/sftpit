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
var Actions = actionList()

// actionDef is one of Actions with what a fault that does it needs: the
// settings filled in when it leaves them out, what it can act on, and how
// it becomes the engine's action.
type actionDef struct {
	Action

	// defaults are the settings a fault that does it is given when it
	// leaves them out.
	defaults Fault

	// after is set if it can act after the server has done what was asked.
	after bool

	// atOnce is set if it may have no steps, and then happens at once.
	atOnce bool

	// stat, if set, are the operations that the step stat stands for, in
	// place of every way of checking a file.
	stat []faults.Operation

	// build returns the engine's action for f, which happens at when, at
	// connecting or logging in if events is set.
	build func(f Fault, events bool, when sftpproxy.When) (sftpproxy.Action, error)
}

// actions are the definitions of Actions, in the same order.
var actions = []actionDef{
	{Action: Action{"refuse", "Refuse with an error"}, defaults: Fault{Error: "failure"}, after: true, build: Fault.refuse},
	{Action: Action{"wait", "Delay the reply"}, defaults: Fault{Seconds: new(3.0)}, after: true, build: Fault.wait},
	{Action: Action{"hold", "Hold the request until released"}, defaults: Fault{Seconds: new(600.0)}, after: true, build: Fault.hold},
	{Action: Action{"drop", "Close the connection"}, after: true, build: Fault.drop},
	{Action: Action{"freeze", "Stop responding, keeping the connection open"}, defaults: Fault{Seconds: new(60.0)}, after: true, build: Fault.freeze},
	{Action: Action{"stop_partway", "Stop a transfer partway"}, defaults: Fault{KB: new(uint64(32))}, build: Fault.stopPartway},
	{Action: Action{"corrupt", "Change the data"}, build: Fault.corrupt},
	{Action: Action{"truncate", "Cut the file short, without an error"}, defaults: Fault{KB: new(uint64(32))}, build: Fault.truncate},
	{Action: Action{"wrong_size", "Report the wrong file size"}, defaults: Fault{SizeOffBy: new(int64(-1024))}, build: Fault.wrongSize},
	// The proxy hides no file from FSTAT, which checks a file already open.
	{Action: Action{"hide", "Answer “no such file”"}, stat: []faults.Operation{faults.Stat, faults.LStat}, build: Fault.hide},
	{Action: Action{"down", "Take the server offline"}, defaults: Fault{Seconds: new(30.0)}, after: true, atOnce: true, build: Fault.down},
}

func actionList() []Action {
	list := make([]Action, len(actions))
	for i, a := range actions {
		list[i] = a.Action
	}
	return list
}

// actionFor returns the definition of the action do, and whether there is
// one.
func actionFor(do string) (actionDef, bool) {
	i := slices.IndexFunc(actions, func(a actionDef) bool { return a.ID == do })
	if i < 0 {
		return actionDef{}, false
	}
	return actions[i], true
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

// ErrInvalidFault reports a fault that sftpit cannot inject.
var ErrInvalidFault = errors.New("invalid fault")

// invalidFaultError says what is wrong with a fault. It is ErrInvalidFault
// without that sentinel's text, which the dashboard would show.
type invalidFaultError struct{ error }

func (invalidFaultError) Is(target error) bool { return target == ErrInvalidFault }

// Resolve returns f with its preset's steps, action and defaults filled in,
// and every setting its action needs, or an error, which is
// ErrInvalidFault, saying what is wrong with it.
func (f Fault) Resolve() (Fault, error) {
	resolved, _, err := f.resolve()
	return resolved, err
}

// Compile returns f resolved, as Resolve gives it, and the engine's rule
// for it, without an ID. Its user, if it has one, must be one of users. An
// error, which is ErrInvalidFault, says what is wrong with f.
func (f Fault) Compile(users []sshfront.User) (Fault, faults.Rule, error) {
	resolved, r, err := f.resolve()
	if err != nil {
		return Fault{}, faults.Rule{}, err
	}
	if f.User != "" {
		if err := checkUser(f.User, users); err != nil {
			return Fault{}, faults.Rule{}, invalidFaultError{err}
		}
	}
	return resolved, r, nil
}

// Rule returns the engine's rule for f, with id, as Compile does.
func (f Fault) Rule(id string, users []sshfront.User) (faults.Rule, error) {
	_, r, err := f.Compile(users)
	if err != nil {
		return faults.Rule{}, err
	}
	r.ID = id
	return r, nil
}

// resolve returns f resolved and the engine's rule for it, without an ID.
func (f Fault) resolve() (Fault, faults.Rule, error) {
	resolved, err := f.fillIn()
	if err != nil {
		return Fault{}, faults.Rule{}, invalidFaultError{err}
	}
	r, err := resolved.compile()
	if err != nil {
		return Fault{}, faults.Rule{}, invalidFaultError{err}
	}
	return resolved, r, nil
}

// fillIn returns f with its preset's steps, action and defaults, and its
// action's defaults, filled in.
func (f Fault) fillIn() (Fault, error) {
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
		f = f.withDefaults(p.Fault)
	}
	f.Name = orDefault(f.Name, "Custom fault")
	def, _ := actionFor(f.Do)
	return f.withDefaults(def.defaults), nil
}

// withDefaults returns f with the settings it leaves out taken from d.
func (f Fault) withDefaults(d Fault) Fault {
	f.Error = orDefault(f.Error, d.Error)
	f.Seconds = orPointer(f.Seconds, d.Seconds)
	f.KB = orPointer(f.KB, d.KB)
	f.SizeOffBy = orPointer(f.SizeOffBy, d.SizeOffBy)
	return f
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

// operations returns the engine's operations for steps, with stat standing
// for the operations stat, if set, or an error naming a step that is not
// one of Steps.
func operations(steps []string, stat []faults.Operation) ([]faults.Operation, error) {
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
		case step == "stat" && stat != nil:
			ops = append(ops, stat...)
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

// compile returns f, resolved, as the engine's rule, without an ID, or an
// error saying what is wrong with it.
func (f Fault) compile() (faults.Rule, error) {
	r := faults.Rule{Match: faults.Match{User: f.User}}
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
	def, known := actionFor(f.Do)
	if len(f.Steps) == 0 && !def.atOnce {
		return r, errors.New("choose at least one step")
	}
	var err error
	if r.Match.Operations, err = operations(f.Steps, def.stat); err != nil {
		return r, err
	}
	if f.After && !def.after {
		return r, fmt.Errorf("%s can't act after the server has done what was asked", f.Do)
	}
	if events && f.After {
		return r, errors.New("connecting and logging in have no before or after")
	}
	if !known {
		return r, fmt.Errorf("there is nothing to do called %q", f.Do)
	}
	when := sftpproxy.Before
	if f.After {
		when = sftpproxy.After
	}
	if r.Action, err = def.build(f, events, when); err != nil {
		return r, err
	}
	if def.atOnce && len(f.Steps) == 0 {
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

func (f Fault) refuse(events bool, when sftpproxy.When) (sftpproxy.Action, error) {
	if events {
		return nil, errors.New("connecting and logging in can't be refused with an error; drop the connection instead")
	}
	code, err := errorCode(f.Error)
	return sftpproxy.Fail{When: when, Status: code}, err
}

func (f Fault) wait(_ bool, when sftpproxy.When) (sftpproxy.Action, error) {
	d, err := seconds(f.Seconds)
	return sftpproxy.Delay{When: when, Duration: d}, err
}

func (f Fault) hold(events bool, when sftpproxy.When) (sftpproxy.Action, error) {
	if events {
		return nil, errors.New("connecting and logging in can't be held; wait or freeze instead")
	}
	d, err := seconds(f.Seconds)
	return sftpproxy.Stall{When: when, Limit: d}, err
}

func (f Fault) drop(_ bool, when sftpproxy.When) (sftpproxy.Action, error) {
	return sftpproxy.Drop{When: when, Reset: f.Abrupt}, nil
}

func (f Fault) freeze(_ bool, when sftpproxy.When) (sftpproxy.Action, error) {
	d, err := seconds(f.Seconds)
	return sftpproxy.Freeze{When: when, Limit: d}, err
}

func (f Fault) stopPartway(bool, sftpproxy.When) (sftpproxy.Action, error) {
	if err := transferStep(f.Steps, "stopping partway"); err != nil {
		return nil, err
	}
	cutoff, err := kbBytes(*f.KB)
	if err != nil {
		return nil, err
	}
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
}

func (f Fault) corrupt(bool, sftpproxy.When) (sftpproxy.Action, error) {
	if err := transferStep(f.Steps, "corrupting data"); err != nil {
		return nil, err
	}
	if f.Steps[0] == "write" {
		return sftpproxy.CorruptUpload{Corruption: sftpproxy.FlipBytes, Length: 64}, nil
	}
	return sftpproxy.CorruptDownload{Corruption: sftpproxy.FlipBytes, Length: 64}, nil
}

func (f Fault) truncate(bool, sftpproxy.When) (sftpproxy.Action, error) {
	if err := transferStep(f.Steps, "cutting a file short"); err != nil {
		return nil, err
	}
	offset, err := kbBytes(*f.KB)
	if err != nil {
		return nil, err
	}
	if f.Steps[0] == "write" {
		return sftpproxy.CorruptUpload{Corruption: sftpproxy.Truncate, Offset: offset}, nil
	}
	return sftpproxy.CorruptDownload{Corruption: sftpproxy.Truncate, Offset: offset}, nil
}

func (f Fault) wrongSize(bool, sftpproxy.When) (sftpproxy.Action, error) {
	if err := onlySteps(f.Steps, "a wrong size", "stat", "list"); err != nil {
		return nil, err
	}
	if *f.SizeOffBy == 0 {
		return nil, errors.New("size_off_by can't be 0")
	}
	return sftpproxy.WrongSize{Delta: *f.SizeOffBy}, nil
}

func (f Fault) hide(bool, sftpproxy.When) (sftpproxy.Action, error) {
	if err := onlySteps(f.Steps, "hiding a file", "open_read", "stat", "list", "remove", "rename"); err != nil {
		return nil, err
	}
	return sftpproxy.Hide{}, nil
}

func (f Fault) down(_ bool, when sftpproxy.When) (sftpproxy.Action, error) {
	d, err := seconds(f.Seconds)
	return sftpproxy.ListenerDown{When: when, Duration: d, CloseExisting: true}, err
}

// The most a fault's settings can be. Each is well beyond what a test
// needs, and small enough to be typed into the dashboard exactly.
const (
	// maxSeconds is a day.
	maxSeconds = 24 * 60 * 60

	// maxMinutes is a week.
	maxMinutes = 7 * 24 * 60

	// maxKB is a terabyte.
	maxKB = 1 << 30

	// maxTimes is the most first and only can be.
	maxTimes = 1_000_000
)

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
		if *f.First > maxTimes {
			return fmt.Errorf("first must be at most %d", maxTimes)
		}
		r.MaxTriggers = int(*f.First)
	case f.Only != nil:
		if *f.Only == 0 {
			return errors.New("only must be at least 1")
		}
		if *f.Only > maxTimes {
			return fmt.Errorf("only must be at most %d", maxTimes)
		}
		// A transfer is decided as its file opens, so its times count the
		// opens of each file rather than each piece of data.
		if r.IsTransfer() {
			r.Match.Attempt = &faults.Attempt{PerPath: true, Numbers: []uint64{*f.Only}}
		} else {
			r.Match.Occurrence = []uint64{*f.Only}
		}
	case f.Percent != nil:
		if !(*f.Percent > 0 && *f.Percent <= 100) {
			return errors.New("percent must be above 0 and at most 100")
		}
		r.Probability = new(*f.Percent / 100)
	case f.Minutes != nil:
		until, err := duration("minutes", *f.Minutes, time.Minute, maxMinutes)
		if err != nil {
			return err
		}
		if r.Trigger != nil {
			return errors.New("a server that goes down at once can't also last for some minutes; give its seconds instead")
		}
		r.Trigger = &faults.Trigger{Anchor: faults.Run, Window: &faults.Window{Until: until}}
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

// kbBytes returns kb kilobytes in bytes, or an error if kb is above maxKB.
func kbBytes(kb uint64) (uint64, error) {
	if kb > maxKB {
		return 0, fmt.Errorf("kb must be at most %d", maxKB)
	}
	return kb * 1024, nil
}

// seconds returns s seconds as a duration, which must be above 0.
func seconds(s *float64) (time.Duration, error) {
	if s == nil {
		return 0, errors.New("seconds must be above 0")
	}
	return duration("seconds", *s, time.Second, maxSeconds)
}

// duration returns v units as a duration, or an error, naming the setting
// name, if that is not at least a nanosecond or v is above most.
func duration(name string, v float64, unit time.Duration, most int) (time.Duration, error) {
	n := v * float64(unit)
	switch {
	// Written so that a v that is not a number fails it.
	case !(n >= 1):
		return 0, fmt.Errorf("%s must be above 0", name)
	case v > float64(most):
		return 0, fmt.Errorf("%s must be at most %d", name, most)
	}
	return time.Duration(n), nil
}
