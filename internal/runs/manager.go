package runs

import (
	"cmp"
	"context"
	"errors"
	"fmt"
	"io"
	"log/slog"
	"maps"
	"os"
	"slices"
	"strings"
	"sync"
	"time"

	"github.com/nebarg/sftpit/internal/backend"
	"github.com/nebarg/sftpit/internal/config"
	"github.com/nebarg/sftpit/internal/faults"
	"github.com/nebarg/sftpit/internal/sftpproxy"
	"github.com/nebarg/sftpit/internal/sshfront"
)

var (
	// ErrStaleRun reports a reset that expects to end a run that is no
	// longer current.
	ErrStaleRun = errors.New("stale run")

	// ErrUnknownScenario reports a reset to a scenario that the
	// configuration does not define.
	ErrUnknownScenario = errors.New("unknown scenario")

	// ErrSeedWithoutScenario reports a reset that pins a seed for a run
	// without a scenario.
	ErrSeedWithoutScenario = errors.New("a seed needs a scenario, whose random decisions it pins")

	// ErrTwoScenarios reports a reset that both names a scenario and gives
	// an inline one.
	ErrTwoScenarios = errors.New("a reset names a scenario or gives one inline, not both")
)

// Options configure a Manager.
type Options struct {
	// Server configures the SSH server that serves the runs. The Manager
	// sets its Handler and Hooks, and makes each user's home directory in
	// every run.
	Server sshfront.Config

	// SeedDir is the host directory whose files every run starts with, or
	// "" for none.
	SeedDir string

	// Limits bound each run's files and the handles open on them.
	Limits backend.Limits

	// Scenarios are the scenarios whose faults a run can inject, by name.
	Scenarios map[string]config.Scenario

	// Scenario names the first run's scenario, or is "" for a run without
	// faults. Seed, if set, pins its random decisions in place of the
	// scenario's own seed.
	Scenario string
	Seed     *faults.Seed

	// Logger receives what the runs log. Nil means slog.Default().
	Logger *slog.Logger
}

// Manager serves the runs of a workspace, one at a time, through an SSH
// server of its own. Each connection is served by the current run, and a
// reset ends that run and starts the next. Its methods are safe for
// concurrent use.
type Manager struct {
	workspace *Workspace
	fixtures  *seedSnapshot
	opts      Options
	logger    *slog.Logger
	srv       *sshfront.Server

	// resetting serialises each reset, each change of the current run's
	// rules, so that none arms timers on a run that a reset is ending, and
	// Close. It guards activeRun.stops.
	resetting sync.Mutex

	// mu guards current, inReset and failed. current also changes only
	// while resetting is held, so code holding resetting reads it without
	// mu.
	mu      sync.Mutex
	current *activeRun
	// inReset is set while a reset is under way, and failed once one has
	// failed, until another succeeds.
	inReset bool
	failed  error
}

// activeRun is a run that a Manager serves.
type activeRun struct {
	run     *Run
	root    *os.Root
	rules   *faults.Engine
	handler sshfront.Handler
	hooks   sshfront.Hooks

	// startRules and startChaos are the rules and chaos the run started
	// with, which a reset that repeats an inline scenario starts the next
	// run with.
	startRules []faults.Rule
	startChaos *faults.Chaos

	// stops stop the timers armed for the run: those it started with, and
	// those of each change of its rules. They are guarded by the Manager's
	// resetting.
	stops []func()
}

// stopTimers stops every timer armed for the run.
func (a *activeRun) stopTimers() {
	for _, stop := range a.stops {
		stop()
	}
}

// Start snapshots the seed in the workspace w and starts the first run,
// whose files are restored from the snapshot, and returns a Manager serving
// it. The caller serves the Manager's Server on its listeners, and closes
// the Manager to stop.
func Start(w *Workspace, opts Options) (*Manager, error) {
	logger := cmp.Or(opts.Logger, slog.Default())
	fixtures, err := w.snapshotSeed(opts.SeedDir)
	if err != nil {
		return nil, err
	}
	m := &Manager{workspace: w, fixtures: fixtures, opts: opts, logger: logger}
	cfg := opts.Server
	cfg.Handler, cfg.Hooks = m.handle, m.hooks()
	cfg.Logger = cmp.Or(cfg.Logger, logger)
	if m.srv, err = sshfront.New(cfg); err != nil {
		return nil, err
	}
	first, err := m.scenario(opts.Scenario, opts.Seed)
	if err != nil {
		return nil, err
	}
	if m.current, err = m.begin(first); err != nil {
		return nil, err
	}
	m.current.stops = append(m.current.stops, ArmTimers(m.current.rules, m.srv, logger))
	return m, nil
}

// Server returns the SSH server that serves the runs.
func (m *Manager) Server() *sshfront.Server { return m.srv }

// Close stops the server, as sshfront.Server.Close does, and ends the
// current run.
func (m *Manager) Close() error {
	err := m.srv.Close()
	m.resetting.Lock()
	defer m.resetting.Unlock()
	m.current.stopTimers()
	if closeErr := m.current.root.Close(); closeErr != nil {
		err = errors.Join(err, fmt.Errorf("runs: close the run's files: %w", closeErr))
	}
	return err
}

// ResetRequest chooses the run that a reset starts.
type ResetRequest struct {
	// Run, if set, is the run the reset expects to end. If another run is
	// current, the reset is refused with ErrStaleRun.
	Run string

	// Scenario, if set, names the next run's scenario, or is "" for a run
	// without faults. If neither Scenario nor Inline is set, the next run
	// repeats the current run's scenario, and its seed if that was pinned.
	Scenario *string

	// Inline, if set, is the next run's scenario, given in place of one the
	// configuration names.
	Inline *InlineScenario

	// Seed, if set, pins the next run's random decisions. Otherwise the
	// scenario's own seed does, or the run draws a fresh seed.
	Seed *faults.Seed
}

// InlineScenario is a scenario given at a reset rather than named in the
// configuration: its rules, and its chaos, or nil.
type InlineScenario struct {
	Rules []faults.Rule
	Chaos *faults.Chaos
}

// Reset ends the current run and starts the run that req chooses. It first
// closes admission and ends every connection, as sshfront.Server.Pause
// does, along with the run's timers, and waits until every session has
// finished, so that no client of the run can still change its files, or
// until ctx is done. The next run's files are restored from the seed
// snapshot, its counters start from zero and its timers count from its
// start. If anything fails once admission is closed, admission stays closed
// and Status reports the run unavailable until a reset succeeds.
func (m *Manager) Reset(ctx context.Context, req ResetRequest) (*Run, error) {
	m.resetting.Lock()
	defer m.resetting.Unlock()
	current := m.active()
	if req.Run != "" && req.Run != current.run.ID {
		return nil, staleRun(current, req.Run)
	}
	chosen, err := m.next(current, req)
	if err != nil {
		return nil, err
	}

	m.mu.Lock()
	m.inReset = true
	m.mu.Unlock()
	next, err := m.restart(ctx, current, chosen)
	m.mu.Lock()
	m.inReset = false
	if err != nil {
		m.failed = err
	} else {
		m.current, m.failed = next, nil
	}
	m.mu.Unlock()
	if err != nil {
		m.logger.Error("reset failed; admission stays closed until a reset succeeds", "run", current.run.ID, "err", err)
		return nil, err
	}

	if err := current.root.Close(); err != nil {
		m.logger.Warn("closing the files of the previous run failed", "run", current.run.ID, "err", err)
	}
	m.srv.Resume()
	next.stops = append(next.stops, ArmTimers(next.rules, m.srv, m.logger))
	m.logger.Info("reset", append([]any{"run", next.run.ID}, scenarioAttrs(chosen.scenario)...)...)
	return next.run, nil
}

// Rules returns the rules of run, which must be the current run, or else
// fails with ErrStaleRun.
func (m *Manager) Rules(run string) (faults.RuleSet, error) {
	current := m.active()
	if run != current.run.ID {
		return faults.RuleSet{}, staleRun(current, run)
	}
	return current.rules.Rules(), nil
}

// ChangeRules replaces the rules of run, which must be the current run, with
// rules, and its chaos with chaos, as faults.Engine.Replace does if revision
// is still the current revision, and returns the new rules. It fails with
// ErrStaleRun for another run, and with faults.ErrStaleRevision for another
// revision. The run takes the listener down at the moments of the rules
// that start afresh, as it does at those of the rules it started with.
func (m *Manager) ChangeRules(run string, revision uint64, rules []faults.Rule, chaos *faults.Chaos) (faults.RuleSet, error) {
	m.resetting.Lock()
	defer m.resetting.Unlock()
	current := m.active()
	if run != current.run.ID {
		return faults.RuleSet{}, staleRun(current, run)
	}
	timers, err := current.rules.Replace(revision, rules, chaos)
	if err != nil {
		return faults.RuleSet{}, err
	}
	current.stops = append(current.stops, armTimers(timers, m.srv, m.logger))
	return current.rules.Rules(), nil
}

// ReleaseStalls releases the stalls and freezes in progress in run, which
// must be the current run, as faults.Engine.ReleaseStalls does, or else
// fails with ErrStaleRun.
func (m *Manager) ReleaseStalls(run string) error {
	current := m.active()
	if run != current.run.ID {
		return staleRun(current, run)
	}
	current.rules.ReleaseStalls()
	return nil
}

// Users returns the users that the Manager's server accepts, which rules
// may refer to.
func (m *Manager) Users() []sshfront.User { return m.opts.Server.Users }

func staleRun(current *activeRun, run string) error {
	return fmt.Errorf("runs: %w: the current run is %s, not %s", ErrStaleRun, current.run.ID, run)
}

// restart ends current's timers and connections, and begins the chosen run
// once every session of current has finished.
func (m *Manager) restart(ctx context.Context, current *activeRun, chosen choice) (*activeRun, error) {
	current.stopTimers()
	if err := m.srv.Pause(ctx); err != nil {
		return nil, fmt.Errorf("runs: wait for the run's sessions to finish: %w", err)
	}
	return m.begin(chosen)
}

// State says whether clients can reach the current run.
type State string

const (
	// StateUp is a run that admits clients.
	StateUp State = "up"
	// StateDown is a run whose server is down for an outage.
	StateDown State = "down"
	// StateResetting is a run that a reset is ending.
	StateResetting State = "resetting"
	// StateUnavailable is a run that a failed reset has left without
	// admission.
	StateUnavailable State = "unavailable"
)

// Status describes the current run.
type Status struct {
	Run   Run
	State State

	// Revision is the revision of the run's rules, as faults.Engine.Revision
	// numbers them.
	Revision uint64

	// DownUntil is when an outage ends, in StateDown.
	DownUntil time.Time

	// Err is why the last reset failed, in StateUnavailable.
	Err error
}

// Status describes the current run.
func (m *Manager) Status() Status {
	m.mu.Lock()
	s := Status{Run: *m.current.run, State: StateUp, Revision: m.current.rules.Revision()}
	switch {
	case m.inReset:
		s.State = StateResetting
	case m.failed != nil:
		s.State, s.Err = StateUnavailable, m.failed
	}
	m.mu.Unlock()
	if s.State == StateUp {
		if until, down := m.srv.Outage(); down {
			s.State, s.DownUntil = StateDown, until
		}
	}
	return s
}

// choice is the scenario chosen for a run, with the rules and chaos it
// starts with.
type choice struct {
	scenario Scenario
	rules    []faults.Rule
	chaos    *faults.Chaos
}

// next chooses the scenario of the run after current, as req asks.
func (m *Manager) next(current *activeRun, req ResetRequest) (choice, error) {
	switch {
	case req.Scenario != nil && req.Inline != nil:
		return choice{}, fmt.Errorf("runs: %w", ErrTwoScenarios)
	case req.Scenario != nil:
		return m.scenario(*req.Scenario, req.Seed)
	case req.Inline != nil:
		return inline(*req.Inline, req.Seed)
	}
	last := current.run.Scenario
	seed := req.Seed
	if seed == nil && last.Pinned {
		seed = &last.Seed
	}
	if last.Inline {
		return inline(InlineScenario{Rules: current.startRules, Chaos: current.startChaos}, seed)
	}
	return m.scenario(last.Name, seed)
}

// scenario chooses a run of the scenario name, whose random decisions seed
// pins if set, or else the scenario's own seed or a fresh one.
func (m *Manager) scenario(name string, seed *faults.Seed) (choice, error) {
	if name == "" {
		if seed != nil {
			return choice{}, fmt.Errorf("runs: %w", ErrSeedWithoutScenario)
		}
		return choice{scenario: withSeed(Scenario{}, nil)}, nil
	}
	s, ok := m.opts.Scenarios[name]
	if !ok {
		defined := "no scenarios"
		if len(m.opts.Scenarios) > 0 {
			defined = strings.Join(slices.Sorted(maps.Keys(m.opts.Scenarios)), ", ")
		}
		return choice{}, fmt.Errorf("runs: %w %q; the configuration defines %s", ErrUnknownScenario, name, defined)
	}
	return choice{scenario: withSeed(Scenario{Name: name}, cmp.Or(seed, s.Seed)), rules: s.Rules, chaos: s.Chaos}, nil
}

// inline chooses a run of the inline scenario s, whose random decisions
// seed pins if set, or else a fresh seed.
func inline(s InlineScenario, seed *faults.Seed) (choice, error) {
	if err := faults.Check(s.Rules); err != nil {
		return choice{}, fmt.Errorf("runs: %w", err)
	}
	if s.Chaos != nil {
		if err := s.Chaos.Check(); err != nil {
			return choice{}, fmt.Errorf("runs: %w", err)
		}
	}
	return choice{scenario: withSeed(Scenario{Inline: true}, seed), rules: s.Rules, chaos: s.Chaos}, nil
}

// withSeed returns s with its random decisions pinned by seed if set, or
// else with a fresh seed.
func withSeed(s Scenario, seed *faults.Seed) Scenario {
	if seed == nil {
		s.Seed = faults.RandomSeed()
	} else {
		s.Seed, s.Pinned = *seed, true
	}
	return s
}

// begin starts the chosen run in the workspace, with its files restored
// from the seed snapshot and a home directory for each user. Its timers are
// not armed yet.
func (m *Manager) begin(chosen choice) (_ *activeRun, err error) {
	run, err := m.workspace.NewRun(chosen.scenario)
	if err != nil {
		return nil, err
	}
	root, err := os.OpenRoot(run.Files)
	if err != nil {
		return nil, fmt.Errorf("runs: open run files: %w", err)
	}
	defer func() {
		if err != nil {
			root.Close()
		}
	}()
	embedded, err := backend.New(root, backend.Options{Limits: m.opts.Limits, Logger: m.logger})
	if err != nil {
		return nil, err
	}
	if m.fixtures != nil {
		if err := m.fixtures.restore(embedded); err != nil {
			return nil, err
		}
	}
	for _, u := range m.opts.Server.Users {
		if err := embedded.MkdirAll(u.Home); err != nil {
			return nil, fmt.Errorf("runs: create home %s for %s: %w", u.Home, u.Name, err)
		}
	}

	// A run without a scenario has an engine too, for rules applied to it
	// later.
	rules, err := faults.New(chosen.rules, chosen.chaos, chosen.scenario.Seed, m.logger)
	if err != nil {
		return nil, err
	}
	return &activeRun{
		run:        run,
		root:       root,
		rules:      rules,
		handler:    Handler(run, embedded, rules, sftpproxy.Options{Logger: m.logger}),
		hooks:      Hooks(rules, m.logger),
		startRules: chosen.rules,
		startChaos: chosen.chaos,
	}, nil
}

func (m *Manager) active() *activeRun {
	m.mu.Lock()
	defer m.mu.Unlock()
	return m.current
}

// handle serves a session of the current run. Admission is closed while a
// reset replaces the run, so a connection is served by one run throughout.
func (m *Manager) handle(ctx context.Context, conn *sshfront.Conn, channel io.ReadWriteCloser) error {
	return m.active().handler(ctx, conn, channel)
}

// hooks returns the hooks of the current run.
func (m *Manager) hooks() sshfront.Hooks {
	return sshfront.Hooks{
		Connect: func(ctx context.Context, conn *sshfront.Conn) {
			m.active().hooks.Connect(ctx, conn)
		},
		Authenticate: func(ctx context.Context, conn *sshfront.Conn) {
			m.active().hooks.Authenticate(ctx, conn)
		},
	}
}

// scenarioAttrs are the log attributes of a run of scenario.
func scenarioAttrs(scenario Scenario) []any {
	switch {
	case scenario.Inline:
		return []any{"inline", true, "seed", scenario.Seed, "seed_pinned", scenario.Pinned}
	case scenario.Name == "":
		return nil
	}
	return []any{"scenario", scenario.Name, "seed", scenario.Seed, "seed_pinned", scenario.Pinned}
}
