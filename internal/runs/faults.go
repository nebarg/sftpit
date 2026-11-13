package runs

import (
	"cmp"
	"errors"
	"fmt"
	"regexp"
	"slices"
	"strconv"
	"strings"

	"github.com/nebarg/sftpit/internal/config"
	"github.com/nebarg/sftpit/internal/faults"
	"github.com/nebarg/sftpit/internal/sshfront"
)

// ErrUnknownFault reports a fault that the current run does not have.
var ErrUnknownFault = errors.New("unknown fault")

// Fault is a fault added to the current run in plain terms: its ID, which
// its rule has too, the fault with its preset and defaults filled in,
// whether it is on, how many times it has happened since it was last
// switched on, and the scenario that added it, if any.
type Fault struct {
	ID       string
	Spec     config.Fault
	On       bool
	Happened uint64
	Scenario string
}

// plainFault is a fault of a run, as the run keeps it, with the rule it
// was compiled to once, as it was added.
type plainFault struct {
	id       string
	spec     config.Fault
	rule     faults.Rule
	on       bool
	scenario string
}

// Faults returns the faults added to the current run, in the order they
// were added.
func (m *Manager) Faults() []Fault {
	m.resetting.Lock()
	defer m.resetting.Unlock()
	current := m.active()
	counts := current.rules.Rules().Counts
	list := make([]Fault, len(current.faults))
	for i, f := range current.faults {
		list[i] = describeFault(f, counts)
	}
	return list
}

// Fault returns the current run's fault id, or fails with ErrUnknownFault.
func (m *Manager) Fault(id string) (Fault, error) {
	for _, f := range m.Faults() {
		if f.ID == id {
			return f, nil
		}
	}
	return Fault{}, fmt.Errorf("runs: fault %q: %w", id, ErrUnknownFault)
}

// AddFault adds spec to the current run, switched on, as a rule tried after
// the run's own rules, and returns it. Its ID comes from its name. It fails
// with spec's error, which is config.ErrInvalidFault, if spec is not a
// fault the run can inject, and once Close has returned.
func (m *Manager) AddFault(spec config.Fault) (Fault, error) {
	// A fault that can never work is the caller's mistake, whatever the
	// run is doing.
	resolved, rule, err := spec.Compile(m.opts.Server.Users)
	if err != nil {
		return Fault{}, err
	}
	m.resetting.Lock()
	defer m.resetting.Unlock()
	if m.closed {
		return Fault{}, fmt.Errorf("runs: add a fault: %w", sshfront.ErrServerClosed)
	}
	current := m.active()
	f := newPlainFault(m.faultID(current, resolved.Name), resolved, rule, "")
	current.faults = append(current.faults, f)
	set, err := m.applyFaults(current)
	if err != nil {
		current.faults = current.faults[:len(current.faults)-1]
		return Fault{}, err
	}
	return describeFault(f, set.Counts), nil
}

// SwitchFault switches the current run's fault id on or off, and returns
// it. A fault switched off is not tried until it is switched on again, and
// then counts its times from zero.
func (m *Manager) SwitchFault(id string, on bool) (Fault, error) {
	m.resetting.Lock()
	defer m.resetting.Unlock()
	current := m.active()
	i := slices.IndexFunc(current.faults, func(f plainFault) bool { return f.id == id })
	if i < 0 {
		return Fault{}, fmt.Errorf("runs: fault %q: %w", id, ErrUnknownFault)
	}
	was := current.faults[i].on
	current.faults[i].on = on
	set, err := m.applyFaults(current)
	if err != nil {
		current.faults[i].on = was
		return Fault{}, err
	}
	return describeFault(current.faults[i], set.Counts), nil
}

// RemoveFault removes the current run's fault id.
func (m *Manager) RemoveFault(id string) error {
	m.resetting.Lock()
	defer m.resetting.Unlock()
	current := m.active()
	i := slices.IndexFunc(current.faults, func(f plainFault) bool { return f.id == id })
	if i < 0 {
		return fmt.Errorf("runs: fault %q: %w", id, ErrUnknownFault)
	}
	was := current.faults
	current.faults = slices.Delete(slices.Clone(was), i, i+1)
	return m.removing(current, was)
}

// RemoveFaults removes every fault added to the current run.
func (m *Manager) RemoveFaults() error {
	m.resetting.Lock()
	defer m.resetting.Unlock()
	current := m.active()
	was := current.faults
	current.faults = nil
	return m.removing(current, was)
}

// removing applies current's faults once some of was are gone, putting was
// back if that fails.
func (m *Manager) removing(current *activeRun, was []plainFault) error {
	if _, err := m.replaceFaults(current, was); err != nil {
		current.faults = was
		return err
	}
	return nil
}

// applyFaults replaces the rules of current's faults with those its faults
// give now.
func (m *Manager) applyFaults(current *activeRun) (faults.RuleSet, error) {
	return m.replaceFaults(current, current.faults)
}

// replaceFaults replaces the rules of previous, current's faults before a
// change, with those of current's faults now, after the run's other rules.
// The caller holds resetting.
func (m *Manager) replaceFaults(current *activeRun, previous []plainFault) (faults.RuleSet, error) {
	set := current.rules.Rules()
	rules := slices.DeleteFunc(slices.Clone(set.Rules), func(r faults.Rule) bool {
		return slices.ContainsFunc(previous, func(f plainFault) bool { return f.id == r.ID })
	})
	for _, f := range current.faults {
		if f.on {
			rules = append(rules, f.rule)
		}
	}
	return m.replaceRules(current, set.Revision, rules)
}

// newPlainFault returns spec, resolved and compiled to rule, as the fault
// id, switched on, that the scenario added, if any.
func newPlainFault(id string, spec config.Fault, rule faults.Rule, scenario string) plainFault {
	rule.ID = id
	return plainFault{id: id, spec: spec, rule: rule, on: true, scenario: scenario}
}

var notID = regexp.MustCompile(`[^a-z0-9]+`)

// faultID returns an ID for a new fault of current named name: its name
// in lowercase letters, digits and -, numbered so that no rule of the run
// has it.
func (m *Manager) faultID(current *activeRun, name string) string {
	base := cmp.Or(strings.Trim(notID.ReplaceAllString(strings.ToLower(name), "-"), "-"), "fault")
	taken := current.rules.Rules().Counts
	for {
		current.lastFault++
		id := base + "-" + strconv.Itoa(current.lastFault)
		_, ruled := taken[id]
		if !ruled && !slices.ContainsFunc(current.faults, func(f plainFault) bool { return f.id == id }) {
			return id
		}
	}
}

func describeFault(f plainFault, counts map[string]faults.Counts) Fault {
	d := Fault{ID: f.id, Spec: f.spec, On: f.on, Scenario: f.scenario}
	if f.on {
		d.Happened = counts[f.id].Fired
	}
	return d
}
