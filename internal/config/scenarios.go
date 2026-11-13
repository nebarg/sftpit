package config

import (
	"bytes"
	"errors"
	"fmt"
	"io/fs"
	"maps"
	"os"
	"path/filepath"
	"slices"
	"strings"

	"github.com/nebarg/sftpit/internal/sshfront"
)

// Scenario is a named group of faults that are turned on and off together.
// Its faults are kept as given, without their presets and defaults filled
// in.
type Scenario struct {
	Description string  `json:"description,omitempty" yaml:"description,omitempty"`
	Faults      []Fault `json:"faults" yaml:"faults"`
}

// Source says where a scenario is defined.
type Source string

const (
	// BuiltIn is a scenario that sftpit itself defines.
	BuiltIn Source = "built_in"

	// Configured is a scenario of the configuration file.
	Configured Source = "config"

	// Saved is a scenario saved as a file in the scenarios directory.
	Saved Source = "file"
)

// NamedScenario is a scenario with its name and where it is defined.
type NamedScenario struct {
	Name     string
	Source   Source
	Scenario Scenario

	// Path is the absolute path of a saved scenario's file.
	Path string

	// Err, if set, says why a saved scenario's file holds no valid
	// scenario, which leaves Scenario unset.
	Err error
}

var (
	// ErrUnknownScenario reports a name that no scenario has.
	ErrUnknownScenario = errors.New("unknown scenario")

	// ErrInvalidScenario reports a scenario, or a scenario file, that sftpit
	// cannot turn on.
	ErrInvalidScenario = errors.New("invalid scenario")

	// ErrFixedScenario reports a change to a built-in or configured
	// scenario, which only saved scenarios allow.
	ErrFixedScenario = errors.New("can't be changed or deleted")
)

// The scenarios directory, relative to the configuration file's directory,
// or to the working directory when there is no configuration file, unless
// the configuration sets scenarios_dir.
const (
	defaultScenariosDir              = "scenarios"
	defaultScenariosDirWithoutConfig = "sftpit-scenarios"
)

// scenarioFileExt is the extension of a scenario file, whose name before it
// is the scenario's.
const scenarioFileExt = ".yaml"

// builtIn are the scenarios that sftpit defines, by name.
var builtIn = map[string]Scenario{
	"unreliable-light": {
		Description: "5% of commands wait 2 seconds, and 1% fail.",
		Faults: []Fault{
			{Name: "Slow commands", Steps: commandSteps, Do: "wait", Seconds: new(2.0), Percent: new(5.0)},
			{Name: "Commands fail", Steps: commandSteps, Do: "refuse", Error: "failure", Percent: new(1.0)},
		},
	},
	"unreliable-moderate": {
		Description: "10% of commands wait 2 seconds, 3% fail, and 2% of uploads and downloads stop partway.",
		Faults: []Fault{
			{Name: "Slow commands", Steps: commandSteps, Do: "wait", Seconds: new(2.0), Percent: new(10.0)},
			{Name: "Commands fail", Steps: commandSteps, Do: "refuse", Error: "failure", Percent: new(3.0)},
			{Preset: "upload_stops_partway", Percent: new(2.0)},
			{Preset: "download_stops_partway", Percent: new(2.0)},
		},
	},
	"unreliable-heavy": {
		Description: "20% of commands wait 2 seconds, 8% fail, 5% of uploads and downloads stop partway, and 0.5% of commands stop responding for 15 seconds.",
		Faults: []Fault{
			{Name: "Slow commands", Steps: commandSteps, Do: "wait", Seconds: new(2.0), Percent: new(20.0)},
			{Name: "Commands fail", Steps: commandSteps, Do: "refuse", Error: "failure", Percent: new(8.0)},
			{Preset: "upload_stops_partway", Percent: new(5.0)},
			{Preset: "download_stops_partway", Percent: new(5.0)},
			{Name: "Connection stops responding", Steps: commandSteps, Do: "freeze", Seconds: new(15.0), Percent: new(0.5)},
		},
	},
}

// Scenarios are the scenarios that can be turned on: the built-in ones, the
// configuration's, and those saved as files in a directory, one YAML file
// for each, named after the scenario. Saved scenarios are read again each
// time they are used. Its methods are safe for concurrent use.
type Scenarios struct {
	dir        string
	users      []sshfront.User
	configured map[string]Scenario
}

// NewScenarios returns the scenarios of a configuration that defines
// configured, and saves scenarios in dir, an absolute path. Faults may
// refer only to users that users has.
func NewScenarios(dir string, configured map[string]Scenario, users []sshfront.User) (*Scenarios, error) {
	for _, name := range slices.Sorted(maps.Keys(configured)) {
		field := "scenarios." + name
		if err := checkScenarioName(name); err != nil {
			return nil, fmt.Errorf("%s: %w", field, err)
		}
		if _, ok := builtIn[name]; ok {
			return nil, fmt.Errorf("%s: sftpit has a built-in scenario named %s; choose another name", field, name)
		}
		if err := configured[name].check(users); err != nil {
			return nil, fmt.Errorf("%s: %w", field, err)
		}
	}
	return &Scenarios{dir: dir, users: users, configured: configured}, nil
}

// Dir returns the absolute path of the directory of saved scenarios, which
// need not exist until a scenario is saved.
func (s *Scenarios) Dir() string {
	return s.dir
}

// List returns every scenario: the built-in ones, then the configuration's,
// then the saved ones, each sorted by name. A saved scenario's file that
// holds no valid scenario is listed with Err set.
func (s *Scenarios) List() ([]NamedScenario, error) {
	var list []NamedScenario
	for _, name := range slices.Sorted(maps.Keys(builtIn)) {
		list = append(list, NamedScenario{Name: name, Source: BuiltIn, Scenario: builtIn[name]})
	}
	for _, name := range slices.Sorted(maps.Keys(s.configured)) {
		list = append(list, NamedScenario{Name: name, Source: Configured, Scenario: s.configured[name]})
	}
	names, err := s.fileNames()
	if err != nil {
		return nil, err
	}
	for _, name := range names {
		list = append(list, s.read(name))
	}
	return list, nil
}

// Get returns the scenario name. A name that no scenario has fails with
// ErrUnknownScenario, and a file that holds no valid scenario with
// ErrInvalidScenario.
func (s *Scenarios) Get(name string) (NamedScenario, error) {
	if sc, ok := builtIn[name]; ok {
		return NamedScenario{Name: name, Source: BuiltIn, Scenario: sc}, nil
	}
	if sc, ok := s.configured[name]; ok {
		return NamedScenario{Name: name, Source: Configured, Scenario: sc}, nil
	}
	if checkScenarioName(name) == nil {
		file := s.read(name)
		if !errors.Is(file.Err, fs.ErrNotExist) {
			return file, file.Err
		}
	}
	return NamedScenario{}, s.unknown(name)
}

// Save saves sc as the scenario name, replacing the file of a scenario
// saved with that name. It fails with ErrInvalidScenario if sc is not a
// scenario sftpit can turn on, and with ErrFixedScenario for the name of a
// built-in or configured scenario.
func (s *Scenarios) Save(name string, sc Scenario) (NamedScenario, error) {
	if err := s.checkSavedName(name); err != nil {
		return NamedScenario{}, err
	}
	if err := sc.check(s.users); err != nil {
		return NamedScenario{}, fmt.Errorf("%w %s: %w", ErrInvalidScenario, name, err)
	}
	var b bytes.Buffer
	if err := encodeYAML(&b, scenarioFile{SchemaVersion: schemaVersion, Scenario: sc}); err != nil {
		return NamedScenario{}, fmt.Errorf("config: write scenario %s: %w", name, err)
	}
	if err := os.MkdirAll(s.dir, 0o755); err != nil {
		return NamedScenario{}, fmt.Errorf("config: scenarios_dir: %w", err)
	}
	if err := replaceFile(s.path(name), b.Bytes()); err != nil {
		return NamedScenario{}, fmt.Errorf("config: save scenario %s: %w", name, err)
	}
	return NamedScenario{Name: name, Source: Saved, Scenario: sc, Path: s.path(name)}, nil
}

// Delete deletes the file of the saved scenario name. It fails with
// ErrUnknownScenario if there is no such file, and with ErrFixedScenario
// for a built-in or configured scenario.
func (s *Scenarios) Delete(name string) error {
	if err := s.checkSavedName(name); err != nil {
		return err
	}
	err := os.Remove(s.path(name))
	if errors.Is(err, fs.ErrNotExist) {
		return s.unknown(name)
	}
	if err != nil {
		return fmt.Errorf("config: delete scenario %s: %w", name, err)
	}
	return nil
}

// checkFiles reports the first saved scenario's file that holds no valid
// scenario.
func (s *Scenarios) checkFiles() error {
	names, err := s.fileNames()
	if err != nil {
		return err
	}
	for _, name := range names {
		if file := s.read(name); file.Err != nil {
			return file.Err
		}
	}
	return nil
}

// checkSavedName reports a name that a saved scenario cannot have.
func (s *Scenarios) checkSavedName(name string) error {
	if err := checkScenarioName(name); err != nil {
		return fmt.Errorf("%w: %w", ErrInvalidScenario, err)
	}
	if _, ok := builtIn[name]; ok {
		return fmt.Errorf("%s is built in, so it %w", name, ErrFixedScenario)
	}
	if _, ok := s.configured[name]; ok {
		return fmt.Errorf("%s is defined in the configuration file, so it %w", name, ErrFixedScenario)
	}
	return nil
}

// fileNames returns the names of the saved scenarios, sorted: those of the
// files in the directory whose names end in .yaml and do not start with a
// dot. A directory that does not exist holds none.
func (s *Scenarios) fileNames() ([]string, error) {
	entries, err := os.ReadDir(s.dir)
	if errors.Is(err, fs.ErrNotExist) {
		return nil, nil
	}
	if err != nil {
		return nil, fmt.Errorf("config: scenarios_dir: %w", err)
	}
	var names []string
	for _, e := range entries {
		name, ok := strings.CutSuffix(e.Name(), scenarioFileExt)
		if ok && !strings.HasPrefix(name, ".") && !e.IsDir() {
			names = append(names, name)
		}
	}
	return names, nil
}

// read reads the saved scenario name. A name without a file has an Err
// wrapping fs.ErrNotExist, and a file that holds no valid scenario one
// wrapping ErrInvalidScenario.
func (s *Scenarios) read(name string) NamedScenario {
	file := NamedScenario{Name: name, Source: Saved, Path: s.path(name)}
	data, err := os.ReadFile(file.Path)
	if err != nil {
		file.Err = fmt.Errorf("config: %w", err)
		return file
	}
	invalid := func(err error) NamedScenario {
		file.Err = fmt.Errorf("config: %w %s: %w", ErrInvalidScenario, file.Path, err)
		return file
	}
	if err := checkScenarioName(name); err != nil {
		return invalid(err)
	}
	if _, ok := builtIn[name]; ok {
		return invalid(fmt.Errorf("sftpit has a built-in scenario named %s; rename the file", name))
	}
	if _, ok := s.configured[name]; ok {
		return invalid(fmt.Errorf("the configuration file defines a scenario %s too; rename one of them", name))
	}
	var sf scenarioFile
	if err := decodeStrict(data, &sf, &sf.SchemaVersion); err != nil {
		return invalid(err)
	}
	if err := sf.check(s.users); err != nil {
		return invalid(err)
	}
	file.Scenario = sf.Scenario
	return file
}

func (s *Scenarios) path(name string) string {
	return filepath.Join(s.dir, name+scenarioFileExt)
}

// unknown returns the error for name, which no scenario has, listing the
// names that scenarios do have.
func (s *Scenarios) unknown(name string) error {
	names := slices.Collect(maps.Keys(builtIn))
	names = append(names, slices.Collect(maps.Keys(s.configured))...)
	if files, err := s.fileNames(); err == nil {
		names = append(names, files...)
	}
	slices.Sort(names)
	return fmt.Errorf("%w %q; the scenarios are %s", ErrUnknownScenario, name, strings.Join(slices.Compact(names), ", "))
}

// check reports a scenario that sftpit cannot turn on: one without faults,
// or with a fault that is not valid for users.
func (sc Scenario) check(users []sshfront.User) error {
	if len(sc.Faults) == 0 {
		return errors.New("a scenario needs at least one fault")
	}
	for i, f := range sc.Faults {
		if _, err := f.Rule("check", users); err != nil {
			return fmt.Errorf("faults[%d]: %w", i, err)
		}
	}
	return nil
}

// Resolved returns sc with each fault's preset and defaults filled in, as
// Fault.Resolve gives them.
func (sc Scenario) Resolved() (Scenario, error) {
	resolved := Scenario{Description: sc.Description, Faults: make([]Fault, len(sc.Faults))}
	for i, f := range sc.Faults {
		var err error
		if resolved.Faults[i], err = f.Resolve(); err != nil {
			return Scenario{}, fmt.Errorf("faults[%d]: %w", i, err)
		}
	}
	return resolved, nil
}

// scenarioFile is a scenario file as written: a scenario with the schema
// version.
type scenarioFile struct {
	SchemaVersion int `yaml:"schema_version"`
	Scenario      `yaml:",inline"`
}

// checkScenarioName reports a name that a scenario cannot have, which
// keeps a scenario's file in the directory.
func checkScenarioName(name string) error {
	if !namePattern.MatchString(name) {
		return fmt.Errorf("scenario name %q may hold only lowercase letters, digits and -, starting with a letter or digit", name)
	}
	return nil
}

// replaceFile writes data to name through a temporary file beside it, so
// that a reader sees the old file or the new one, never part of one.
func replaceFile(name string, data []byte) error {
	f, err := os.CreateTemp(filepath.Dir(name), "."+filepath.Base(name)+".tmp-*")
	if err != nil {
		return err
	}
	tmpPath := f.Name()
	defer os.Remove(tmpPath)

	if _, err := f.Write(data); err != nil {
		f.Close()
		return err
	}
	if err := f.Chmod(0o644); err != nil {
		f.Close()
		return err
	}
	if err := f.Close(); err != nil {
		return err
	}
	return os.Rename(tmpPath, name)
}
