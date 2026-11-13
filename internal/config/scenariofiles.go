package config

import (
	"errors"
	"fmt"
	"io/fs"
	"os"
	"path/filepath"
	"strings"

	"github.com/nebarg/sftpit/internal/sshfront"
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

var (
	// ErrScenarioName reports a name that a scenario cannot have.
	ErrScenarioName = errors.New("invalid scenario name")

	// ErrInvalidScenarioFile reports a scenario file that does not hold a
	// valid scenario.
	ErrInvalidScenarioFile = errors.New("invalid scenario file")
)

// ScenarioFiles are the scenarios saved in a directory, one YAML file for
// each, named after the scenario. Its methods are safe for concurrent use.
type ScenarioFiles struct {
	dir   string
	users []sshfront.User

	// configured are the configuration file's scenarios, whose names no
	// file may have.
	configured map[string]Scenario
}

// NewScenarioFiles returns the scenarios saved in dir, an absolute path,
// whose rules may refer only to users, and keys, that users has, and which
// may not have the names of the scenarios configured.
func NewScenarioFiles(dir string, users []sshfront.User, configured map[string]Scenario) *ScenarioFiles {
	return &ScenarioFiles{dir: dir, users: users, configured: configured}
}

// ScenarioFile is a scenario saved as a file.
type ScenarioFile struct {
	Name string

	// Path is the file's absolute path.
	Path string

	Scenario Scenario

	// Err, if set, says why the file holds no valid scenario, which
	// leaves Scenario unset.
	Err error
}

// Dir returns the absolute path of the directory, which need not exist
// until a scenario is saved.
func (f *ScenarioFiles) Dir() string {
	return f.dir
}

// List reads every scenario file, sorted by name: each file in the
// directory whose name ends in .yaml and does not start with a dot. A file
// that holds no valid scenario is listed with Err set. A directory that
// does not exist holds none.
func (f *ScenarioFiles) List() ([]ScenarioFile, error) {
	entries, err := os.ReadDir(f.dir)
	if errors.Is(err, fs.ErrNotExist) {
		return nil, nil
	}
	if err != nil {
		return nil, fmt.Errorf("config: scenarios_dir: %w", err)
	}
	var files []ScenarioFile
	for _, e := range entries {
		name, ok := strings.CutSuffix(e.Name(), scenarioFileExt)
		if !ok || strings.HasPrefix(name, ".") || e.IsDir() {
			continue
		}
		file := f.read(name)
		if file.Err == nil {
			if _, ok := f.configured[name]; ok {
				file.Err = fmt.Errorf("%w %s: the configuration file defines a scenario %s too; rename one of them", ErrInvalidScenarioFile, file.Path, name)
			}
		}
		files = append(files, file)
	}
	return files, nil
}

// Load reads the scenario file of name. A name without a file fails with an
// error wrapping fs.ErrNotExist, and a file that holds no valid scenario
// with one wrapping ErrInvalidScenarioFile.
func (f *ScenarioFiles) Load(name string) (ScenarioFile, error) {
	if err := checkScenarioName(name); err != nil {
		return ScenarioFile{}, fmt.Errorf("config: scenario %q: %w", name, fs.ErrNotExist)
	}
	file := f.read(name)
	return file, file.Err
}

// read reads the scenario file of name, a valid scenario name.
func (f *ScenarioFiles) read(name string) ScenarioFile {
	file := ScenarioFile{Name: name, Path: f.path(name)}
	data, err := os.ReadFile(file.Path)
	if err != nil {
		file.Err = fmt.Errorf("config: %w", err)
		return file
	}
	if err := checkScenarioName(name); err != nil {
		file.Err = fmt.Errorf("%w %s: %w", ErrInvalidScenarioFile, file.Path, err)
		return file
	}
	var sf scenarioFile
	if err := decodeStrict(data, &sf, &sf.SchemaVersion); err != nil {
		file.Err = fmt.Errorf("%w %s: %w", ErrInvalidScenarioFile, file.Path, err)
		return file
	}
	if file.Scenario, err = sf.scenario("scenario "+name, f.users); err != nil {
		file.Err = fmt.Errorf("%w %s: %w", ErrInvalidScenarioFile, file.Path, err)
	}
	return file
}

func (f *ScenarioFiles) path(name string) string {
	return filepath.Join(f.dir, name+scenarioFileExt)
}

// scenarioFile is a scenario file as written: a scenario, as the
// configuration's scenarios give one, with the schema version.
type scenarioFile struct {
	SchemaVersion  int `yaml:"schema_version"`
	scenarioConfig `yaml:",inline"`
}

// checkScenarioName reports a name that a scenario cannot have, which
// keeps a scenario's file in the directory.
func checkScenarioName(name string) error {
	if !namePattern.MatchString(name) {
		return fmt.Errorf("%w %q: a scenario name may hold only lowercase letters, digits and -, starting with a letter or digit", ErrScenarioName, name)
	}
	return nil
}
