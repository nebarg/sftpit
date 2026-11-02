package config

import (
	"bytes"
	"crypto/sha256"
	"encoding/hex"
	"errors"
	"fmt"
	"io/fs"
	"os"
	"path/filepath"
	"strings"
	"sync"

	"github.com/nebarg/sftpit/internal/faults"
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

// scenarioFileHeader opens each scenario file that sftpit writes.
const scenarioFileHeader = `# A scenario saved by sftpit, which rewrites this file in full each time the
# scenario is saved again. Edit it by hand if you like, but keep notes in
# description, since comments are not kept.
`

var (
	// ErrScenarioName reports a name that a scenario cannot have.
	ErrScenarioName = errors.New("invalid scenario name")

	// ErrConfiguredScenario reports a save of a scenario that the
	// configuration file defines, which only an edit of that file changes.
	ErrConfiguredScenario = errors.New("the configuration file defines this scenario")

	// ErrScenarioChanged reports a save whose expected content hash does not
	// match the file it would replace, which has changed since it was read.
	ErrScenarioChanged = errors.New("the scenario file has changed")

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

	// saving serialises saves, so that each checks the file it replaces.
	saving sync.Mutex
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

	// Path is the file's absolute path, and Hash the SHA-256 of its
	// content, in hex.
	Path string
	Hash string

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

// Save writes s to the scenario file of name, which replaces the file that
// hash, the SHA-256 of its content, describes, or is a new file if hash is
// "". If the file holds other content, or hash describes a file that is
// gone, Save fails with ErrScenarioChanged. A name that the configuration
// file defines fails with ErrConfiguredScenario, and one that a scenario
// cannot have with ErrScenarioName. The directory is made if need be.
func (f *ScenarioFiles) Save(name string, s Scenario, hash string) (ScenarioFile, error) {
	if err := checkScenarioName(name); err != nil {
		return ScenarioFile{}, err
	}
	if _, ok := f.configured[name]; ok {
		return ScenarioFile{}, fmt.Errorf("config: scenario %s: %w; edit it there, or save a copy under another name", name, ErrConfiguredScenario)
	}
	data, err := renderScenario(s)
	if err != nil {
		return ScenarioFile{}, err
	}
	f.saving.Lock()
	defer f.saving.Unlock()
	file := f.path(name)
	current, err := os.ReadFile(file)
	switch {
	case errors.Is(err, fs.ErrNotExist):
		if hash != "" {
			return ScenarioFile{}, fmt.Errorf("config: %s: %w: it was removed", file, ErrScenarioChanged)
		}
	case err != nil:
		return ScenarioFile{}, fmt.Errorf("config: %w", err)
	case hash == "":
		return ScenarioFile{}, fmt.Errorf("config: %s: %w: it exists, so give its hash to replace it", file, ErrScenarioChanged)
	case hash != hashOf(current):
		return ScenarioFile{}, fmt.Errorf("config: %s: %w since it was read", file, ErrScenarioChanged)
	}
	if err := writeAtomically(f.dir, file, data); err != nil {
		return ScenarioFile{}, err
	}
	return ScenarioFile{Name: name, Path: file, Hash: hashOf(data), Scenario: s}, nil
}

// read reads the scenario file of name, a valid scenario name.
func (f *ScenarioFiles) read(name string) ScenarioFile {
	file := ScenarioFile{Name: name, Path: f.path(name)}
	data, err := os.ReadFile(file.Path)
	if err != nil {
		file.Err = fmt.Errorf("config: %w", err)
		return file
	}
	file.Hash = hashOf(data)
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

// renderScenario returns s as a scenario file, with its rules in the long
// form, in the order given.
func renderScenario(s Scenario) ([]byte, error) {
	if err := faults.Check(s.Rules); err != nil {
		return nil, fmt.Errorf("config: %w", err)
	}
	b := bytes.NewBufferString(scenarioFileHeader)
	if err := encodeYAML(b, scenarioFile{SchemaVersion: schemaVersion, scenarioConfig: longScenario(s)}); err != nil {
		return nil, fmt.Errorf("config: write the scenario: %w", err)
	}
	return b.Bytes(), nil
}

// writeAtomically replaces the file name, in dir, with data, through a
// temporary file renamed over it, so that a reader sees the old content or
// the new, never part of it.
func writeAtomically(dir, name string, data []byte) (err error) {
	if err := os.MkdirAll(dir, 0o755); err != nil {
		return fmt.Errorf("config: %w", err)
	}
	tmp, err := os.CreateTemp(dir, "."+filepath.Base(name)+".*.tmp")
	if err != nil {
		return fmt.Errorf("config: %w", err)
	}
	defer func() {
		if err != nil {
			tmp.Close()
			os.Remove(tmp.Name())
		}
	}()
	if _, err := tmp.Write(data); err != nil {
		return fmt.Errorf("config: %w", err)
	}
	// A scenario file is shared like any other file in the repository,
	// rather than kept private as CreateTemp makes it.
	if err := tmp.Chmod(0o644); err != nil {
		return fmt.Errorf("config: %w", err)
	}
	if err := tmp.Sync(); err != nil {
		return fmt.Errorf("config: %w", err)
	}
	if err := tmp.Close(); err != nil {
		return fmt.Errorf("config: %w", err)
	}
	if err := os.Rename(tmp.Name(), name); err != nil {
		return fmt.Errorf("config: %w", err)
	}
	return nil
}

func hashOf(data []byte) string {
	sum := sha256.Sum256(data)
	return hex.EncodeToString(sum[:])
}
