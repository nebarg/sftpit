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
// were added. It does not wait for a reset or a change of the run's rules.
func (m *Manager) Faults() []Fault {
	m.mu.Lock()
	list, counts := m.current.faults, m.current.rules.Rules().Counts
	m.mu.Unlock()
	described := make([]Fault, len(list))
	for i, f := range list {
		described[i] = describeFault(f, counts)
	}
	return described
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
	f := newPlainFault(m.faultID(current, current.faults, resolved.Name), resolved, rule, "")
	set, err := m.replaceFaults(current, append(slices.Clone(current.faults), f))
	if err != nil {
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
	next := slices.Clone(current.faults)
	next[i].on = on
	set, err := m.replaceFaults(current, next)
	if err != nil {
		return Fault{}, err
	}
	return describeFault(next[i], set.Counts), nil
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
	_, err := m.replaceFaults(current, slices.Delete(slices.Clone(current.faults), i, i+1))
	return err
}

// RemoveFaults removes every fault added to the current run.
func (m *Manager) RemoveFaults() error {
	m.resetting.Lock()
	defer m.resetting.Unlock()
	_, err := m.replaceFaults(m.active(), nil)
	return err
}

// replaceFaults replaces current's faults with next, and their rules with
// those of next, after the run's other rules, and returns the new rules. If
// that fails, current keeps its faults. next must not be changed once
// passed, since readers may hold it. The caller holds resetting.
func (m *Manager) replaceFaults(current *activeRun, next []plainFault) (faults.RuleSet, error) {
	set := current.rules.Rules()
	rules := slices.DeleteFunc(slices.Clone(set.Rules), func(r faults.Rule) bool {
		return slices.ContainsFunc(current.faults, func(f plainFault) bool { return f.id == r.ID })
	})
	for _, f := range next {
		if f.on {
			rules = append(rules, f.rule)
		}
	}
	return m.replaceRules(current, set.Revision, rules, next)
}

// newPlainFault returns spec, resolved and compiled to rule, as the fault
// id, switched on, that the scenario added, if any.
func newPlainFault(id string, spec config.Fault, rule faults.Rule, scenario string) plainFault {
	rule.ID = id
	return plainFault{id: id, spec: spec, rule: rule, on: true, scenario: scenario}
}

var notID = regexp.MustCompile(`[^a-z0-9]+`)

// faultID returns an ID for a new fault of current named name, to join
// list: its name in lowercase letters, digits and -, numbered so that no
// rule of the run, and no fault of list, has it. The caller holds
// resetting.
func (m *Manager) faultID(current *activeRun, list []plainFault, name string) string {
	base := cmp.Or(strings.Trim(notID.ReplaceAllString(strings.ToLower(name), "-"), "-"), "fault")
	taken := current.rules.Rules().Counts
	for {
		current.lastFault++
		id := base + "-" + strconv.Itoa(current.lastFault)
		_, ruled := taken[id]
		if !ruled && !slices.ContainsFunc(list, func(f plainFault) bool { return f.id == id }) {
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
