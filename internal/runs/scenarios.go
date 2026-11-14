package runs

import (
	"fmt"
	"slices"

	"github.com/nebarg/sftpit/internal/config"
	"github.com/nebarg/sftpit/internal/sshfront"
)

// Scenario is a scenario that can be turned on, and whether it is on in the
// current run: whether the run has any of the faults it added.
type Scenario struct {
	config.NamedScenario
	On bool
}

// Scenarios returns every scenario, as config.Scenarios.List gives them,
// with whether each is on in the current run. It does not wait for a reset
// or a change of the run's rules.
func (m *Manager) Scenarios() ([]Scenario, error) {
	m.scenarioFiles.Lock()
	defer m.scenarioFiles.Unlock()
	listed, err := m.opts.Scenarios.List()
	if err != nil {
		return nil, err
	}
	m.mu.Lock()
	have := m.current.faults
	m.mu.Unlock()
	list := make([]Scenario, len(listed))
	for i, s := range listed {
		list[i] = Scenario{NamedScenario: s, On: isOn(have, s.Name)}
	}
	return list, nil
}

// SwitchScenario turns the scenario name on or off in the current run, and
// returns it. Turning it on adds its faults, switched on, after the run's
// other faults, in place of any it added before; turning it off removes
// them. It fails as config.Scenarios.Get does for a name that no valid
// scenario has, and once Close has returned.
func (m *Manager) SwitchScenario(name string, on bool) (Scenario, error) {
	m.resetting.Lock()
	defer m.resetting.Unlock()
	if m.closed {
		return Scenario{}, fmt.Errorf("runs: switch a scenario: %w", sshfront.ErrServerClosed)
	}
	current := m.active()
	named, err := m.opts.Scenarios.Get(name)
	// A scenario whose file has gone, or no longer holds a valid scenario,
	// can still be turned off.
	if err != nil && (on || !isOn(current.faults, name)) {
		return Scenario{}, err
	}
	named.Name = name
	var specs []config.Fault
	if on {
		specs = named.Scenario.Faults
	}
	if err := m.setScenarioFaults(current, name, specs); err != nil {
		return Scenario{}, err
	}
	return Scenario{NamedScenario: named, On: on}, nil
}

// SaveScenario saves sc as the scenario name, as config.Scenarios.Save
// does, and returns it. If it is on in the current run, its faults there are
// replaced with sc's.
func (m *Manager) SaveScenario(name string, sc config.Scenario) (Scenario, error) {
	m.resetting.Lock()
	defer m.resetting.Unlock()
	m.scenarioFiles.Lock()
	defer m.scenarioFiles.Unlock()
	saved, err := m.opts.Scenarios.Save(name, sc)
	if err != nil {
		return Scenario{}, err
	}
	current := m.active()
	on := isOn(current.faults, name)
	if on && !m.closed {
		if err := m.setScenarioFaults(current, name, sc.Faults); err != nil {
			return Scenario{}, err
		}
	}
	return Scenario{NamedScenario: saved, On: on}, nil
}

// DeleteScenario deletes the saved scenario name, as config.Scenarios.Delete
// does, and removes the faults it added to the current run.
func (m *Manager) DeleteScenario(name string) error {
	m.resetting.Lock()
	defer m.resetting.Unlock()
	m.scenarioFiles.Lock()
	defer m.scenarioFiles.Unlock()
	if err := m.opts.Scenarios.Delete(name); err != nil {
		return err
	}
	if m.closed {
		return nil
	}
	return m.setScenarioFaults(m.active(), name, nil)
}

// setScenarioFaults replaces the faults that the scenario name added to
// current with specs, each switched on, or leaves current's faults as they
// were if that fails. The caller holds resetting.
func (m *Manager) setScenarioFaults(current *activeRun, name string, specs []config.Fault) error {
	next := slices.DeleteFunc(slices.Clone(current.faults), func(f plainFault) bool { return f.scenario == name })
	for i, spec := range specs {
		resolved, rule, err := spec.Compile(m.opts.Server.Users)
		if err != nil {
			return fmt.Errorf("runs: scenario %s: faults[%d]: %w", name, i, err)
		}
		next = append(next, newPlainFault(m.faultID(current, next, resolved.Name), resolved, rule, name))
	}
	if _, err := m.replaceFaults(current, next); err != nil {
		return fmt.Errorf("runs: scenario %s: %w", name, err)
	}
	return nil
}

// isOn reports whether list has any of the faults that the scenario name
// added.
func isOn(list []plainFault, name string) bool {
	return slices.ContainsFunc(list, func(f plainFault) bool { return f.scenario == name })
}
