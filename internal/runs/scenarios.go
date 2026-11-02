package runs

import (
	"errors"
	"fmt"
	"io/fs"
	"maps"
	"slices"
	"strings"

	"github.com/nebarg/sftpit/internal/config"
)

// errNoScenarioFiles reports a save to a Manager without scenario files.
var errNoScenarioFiles = errors.New("runs: no scenarios directory is set")

// Scenarios are the scenarios a run can inject the faults of.
type Scenarios struct {
	// Configured are the configuration file's scenarios, by name.
	Configured map[string]config.Scenario

	// Dir is the directory of scenario files, or "" if there is none, and
	// Files are the files it holds, sorted by name, those that hold no
	// valid scenario included.
	Dir   string
	Files []config.ScenarioFile
}

// Scenarios returns the scenarios a run can inject the faults of, with each
// scenario file as it is now.
func (m *Manager) Scenarios() (Scenarios, error) {
	s := Scenarios{Configured: m.opts.Scenarios}
	if m.opts.ScenarioFiles == nil {
		return s, nil
	}
	s.Dir = m.opts.ScenarioFiles.Dir()
	files, err := m.opts.ScenarioFiles.List()
	if err != nil {
		return Scenarios{}, fmt.Errorf("runs: %w", err)
	}
	s.Files = files
	return s, nil
}

// SaveScenario saves s as the scenario file of name, as
// config.ScenarioFiles.Save does, replacing the file that hash describes,
// or none if hash is "". The next run of the scenario injects its faults.
func (m *Manager) SaveScenario(name string, s config.Scenario, hash string) (config.ScenarioFile, error) {
	if m.opts.ScenarioFiles == nil {
		return config.ScenarioFile{}, errNoScenarioFiles
	}
	file, err := m.opts.ScenarioFiles.Save(name, s, hash)
	if err != nil {
		return config.ScenarioFile{}, fmt.Errorf("runs: %w", err)
	}
	m.logger.Info("scenario saved", "scenario", name, "path", file.Path)
	return file, nil
}

// named returns the scenario name, from the configuration or else from its
// file as it is now. A name that neither defines fails with
// ErrUnknownScenario, and a file that holds no valid scenario with
// config.ErrInvalidScenarioFile.
func (m *Manager) named(name string) (config.Scenario, error) {
	if s, ok := m.opts.Scenarios[name]; ok {
		return s, nil
	}
	if m.opts.ScenarioFiles != nil {
		file, err := m.opts.ScenarioFiles.Load(name)
		if err == nil {
			return file.Scenario, nil
		}
		if !errors.Is(err, fs.ErrNotExist) {
			return config.Scenario{}, fmt.Errorf("runs: %w", err)
		}
	}
	defined := "no scenarios"
	if names := m.scenarioNames(); len(names) > 0 {
		defined = strings.Join(names, ", ")
	}
	return config.Scenario{}, fmt.Errorf("runs: %w %q; the configuration defines %s", ErrUnknownScenario, name, defined)
}

// scenarioNames returns the names of the scenarios a run can inject the
// faults of, sorted, as far as they can be listed.
func (m *Manager) scenarioNames() []string {
	names := slices.Collect(maps.Keys(m.opts.Scenarios))
	if m.opts.ScenarioFiles != nil {
		files, _ := m.opts.ScenarioFiles.List()
		for _, f := range files {
			if f.Err == nil {
				names = append(names, f.Name)
			}
		}
	}
	slices.Sort(names)
	return slices.Compact(names)
}
