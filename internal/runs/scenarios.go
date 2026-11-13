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
