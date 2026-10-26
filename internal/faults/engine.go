package faults

import (
	"cmp"
	"errors"
	"fmt"
	"log/slog"
	"maps"
	"reflect"
	"slices"
	"strings"
	"sync"
	"time"

	"github.com/nebarg/sftpit/internal/sftpproxy"
)

// ErrStaleRevision reports a change of rules that expects to replace a
// revision that is no longer current.
var ErrStaleRevision = errors.New("stale revision")

// Engine applies the rules of a scenario, and its chaos, to the requests of
// one run, which starts when the engine is made. Each rule counts the
// requests it matches from the start of the run, or from the change that
// applied it, and draws its random decisions from the run's seed. Its
// methods are safe for concurrent use.
type Engine struct {
	seed   Seed
	logger *slog.Logger

	mu sync.Mutex
	// revision numbers the rules: 1 for those the run starts with, and one
	// more for each change.
	revision uint64
	// rules are in the order they are tried: the scenario's own, then those
	// of chaos, if it is set.
	rules []*rule
	chaos *Chaos
	// sessions are the sessions that have not ended, which the rules a
	// change applies are timed for.
	sessions map[*Session]struct{}
	// stalls is closed to release the stalls and freezes in progress, and
	// then replaced.
	stalls chan struct{}

	// timers are the faults at moments of the run itself.
	timers []sftpproxy.Timer
}

// rule is a Rule with its counts and the state its decisions draw on, which
// the engine's mu guards; removed is only ever closed, once.
type rule struct {
	Rule
	ops    []Operation
	counts Counts

	// activation is the revision that applied the rule, or 0 for a rule the
	// run started with, and start is when it was applied, which a trigger
	// anchored to the run measures from.
	activation uint64
	start      time.Time

	// removed is closed once a change removes the rule, which ends the
	// waits it holds.
	removed chan struct{}

	// chaos is set for a rule of the engine's chaos, which matches nothing
	// while chaos is paused.
	chaos bool

	// attempts counts the opens of each user, path or both, for a rule with
	// an Attempt.
	attempts map[attemptKey]uint64

	// draws counts the requests of each user, path and operation, for a
	// rule that makes random decisions.
	draws map[drawKey]uint64

	// connections holds the moment of each connection, for a rule with a
	// moment measured from the connection, and users counts each user's
	// connections, which draw their moments in turn.
	connections map[uint64]*connectionMoment
	users       map[string]uint64

	// runAt is the moment of a rule with a moment measured from the run,
	// once drawn, and usedRunAt is set once a rule for requests has applied
	// at it.
	runAt     *time.Duration
	usedRunAt bool
}

// connectionMoment is a connection's moment for a rule. Every session on the
// connection shares it. Its used and fired are guarded by the engine's mu.
type connectionMoment struct {
	at time.Time

	// key is the key of the decisions about the moment.
	key Key

	// used is set once a rule for requests has applied at the moment, and
	// fired once a connection action has.
	used, fired bool
}

type attemptKey struct{ user, path string }

type drawKey struct {
	user, path string
	op         Operation
}

// Counts are what a rule has done in a run. A connection action at a moment
// of the run counts sessions rather than requests, and one at a moment of
// the connection counts connections: those whose client it matched, those
// it was then timed for, and those it fired in. A listener_down at a moment
// of the run is matched and selected once, for the run.
type Counts struct {
	// Matched counts the requests the rule matched.
	Matched uint64

	// Selected counts the requests the rule was chosen for. A transfer is
	// selected when its file is opened.
	Selected uint64

	// Fired counts the times the rule took effect. A transfer's fault takes
	// effect when it first changes a write or read, so a selected transfer
	// that never reaches its fault, or reaches it once MaxTriggers is used
	// up, does not count.
	Fired uint64
}

// New returns an engine for rules, and for chaos if it is set, for a run
// that starts now. It draws its random decisions from seed and logs each
// fault it injects to logger, or to slog.Default() if logger is nil. It logs
// each random decision at debug level.
func New(rules []Rule, chaos *Chaos, seed Seed, logger *slog.Logger) (*Engine, error) {
	if logger == nil {
		logger = slog.Default()
	}
	if err := check(rules, chaos); err != nil {
		return nil, err
	}
	e := &Engine{seed: seed, logger: logger, revision: 1, chaos: chaos, sessions: make(map[*Session]struct{}), stalls: make(chan struct{})}
	start := time.Now()
	for i, r := range tried(rules, chaos) {
		ru := newRule(r, 0, start)
		ru.chaos = i >= len(rules)
		e.rules = append(e.rules, ru)
	}
	e.timers = e.runTimers(e.rules)
	return e, nil
}

// check reports rules, or a chaos, that an engine cannot apply.
func check(rules []Rule, chaos *Chaos) error {
	if err := Check(rules); err != nil {
		return err
	}
	if chaos != nil {
		return chaos.Check()
	}
	return nil
}

// tried returns rules in the order they are tried: by priority, and as
// given among equal priorities, and then the rules of chaos, if it is set.
func tried(rules []Rule, chaos *Chaos) []Rule {
	all := slices.Clone(rules)
	slices.SortStableFunc(all, func(a, b Rule) int { return cmp.Compare(a.Priority, b.Priority) })
	if chaos != nil {
		all = append(all, chaos.Rules()...)
	}
	return all
}

func newRule(r Rule, activation uint64, start time.Time) *rule {
	ru := &rule{
		Rule:        r,
		ops:         r.selectedAt(),
		activation:  activation,
		start:       start,
		removed:     make(chan struct{}),
		attempts:    make(map[attemptKey]uint64),
		connections: make(map[uint64]*connectionMoment),
		users:       make(map[string]uint64),
	}
	if r.Probability != nil || r.Duration != nil || r.Cutoff != nil || r.Trigger != nil {
		ru.draws = make(map[drawKey]uint64)
	}
	return ru
}

// runTimers returns the timers of those of rules that take the listener
// down at a moment of the run. e.mu must be held, or e not yet shared.
func (e *Engine) runTimers(rules []*rule) []sftpproxy.Timer {
	var timers []sftpproxy.Timer
	for _, ru := range rules {
		if !ru.timedByRun() {
			continue
		}
		ru.counts.Matched++
		ru.counts.Selected++
		after := e.runMoment(ru)
		action, drawn := e.drawn(ru, Key{Rule: ru.ID, Activation: ru.activation, Ordinal: 1})
		attrs := append([]any{"rule", ru.ID, "anchor", Run, "at", after}, drawn...)
		timers = append(timers, sftpproxy.Timer{At: ru.start.Add(after), Action: action, Reserve: e.reserveMoment(ru, attrs, nil)})
	}
	return timers
}

// Timers returns the faults at moments of the run that act on the listener
// rather than on a session, ListenerDowns, for the run to take whatever its
// sessions are doing. Replace returns those of the rules it applies.
func (e *Engine) Timers() []sftpproxy.Timer {
	return e.timers
}

// Replace replaces the engine's rules with rules, and its chaos with chaos,
// all at once between two requests, as the next revision, if revision is
// still the current one.
//
// A rule with the ID and the definition of a current rule carries on as it
// was, with its counts, ordinals and moments, so a change that only pauses
// or resumes chaos keeps its rules as they were. Any other rule starts from
// now: its attempts and occurrences count from the change, and a trigger
// anchored to the run measures from it. A rule that is no longer there ends
// the delays, stalls and freezes it holds at once, and none of its moments
// come, but a transfer that it selected keeps its fault, so that a download
// is never corrupted only in part.
//
// Every session that has not ended is timed for the rules that start from
// now, as a session that starts now would be, through its MoreTimers.
// Replace returns the timers of those rules that take the listener down at
// a moment of the run, for the run to take as it takes Timers.
func (e *Engine) Replace(revision uint64, rules []Rule, chaos *Chaos) ([]sftpproxy.Timer, error) {
	if err := check(rules, chaos); err != nil {
		return nil, err
	}
	now := time.Now()
	e.mu.Lock()
	defer e.mu.Unlock()
	if revision != e.revision {
		return nil, fmt.Errorf("faults: %w: the current revision is %d, not %d", ErrStaleRevision, e.revision, revision)
	}
	e.revision++
	current := make(map[string]*rule, len(e.rules))
	for _, ru := range e.rules {
		current[ru.ID] = ru
	}
	// fresh are the rules that start from now: those added, and those
	// whose definition changed.
	var next, fresh []*rule
	var added, changed, kept []string
	for i, r := range tried(rules, chaos) {
		old := current[r.ID]
		delete(current, r.ID)
		if old != nil && reflect.DeepEqual(old.Rule, r) {
			next = append(next, old)
			kept = append(kept, r.ID)
			continue
		}
		if old != nil {
			close(old.removed)
			changed = append(changed, r.ID)
		} else {
			added = append(added, r.ID)
		}
		ru := newRule(r, e.revision, now)
		ru.chaos = i >= len(rules)
		next = append(next, ru)
		fresh = append(fresh, ru)
	}
	removed := slices.Sorted(maps.Keys(current))
	for _, ru := range current {
		close(ru.removed)
	}
	e.rules, e.chaos = next, chaos
	// A connection's moments are drawn in the order the connections came,
	// whatever order the map gives.
	live := slices.SortedFunc(maps.Keys(e.sessions), func(a, b *Session) int { return cmp.Compare(a.client.Connection, b.client.Connection) })
	for _, s := range live {
		s.timeAdded(fresh, now)
	}
	attrs := []any{"from", revision, "to", e.revision, "added", added, "changed", changed, "removed", removed, "kept", kept}
	if chaos != nil {
		attrs = append(attrs, "chaos", chaos.Preset, "chaos_paused", chaos.Paused)
	}
	e.logger.Info("rules changed", attrs...)
	return e.runTimers(fresh), nil
}

// paused reports whether ru is a rule of the engine's chaos, which is
// paused. e.mu must be held.
func (e *Engine) paused(ru *rule) bool {
	return ru.chaos && e.chaos.Paused
}

// ReleaseStalls releases every stall and freeze in progress, whichever rule
// chose it: a stalled request or reply goes on, and a frozen connection is
// closed. Those that begin later hold as usual.
func (e *Engine) ReleaseStalls() {
	e.mu.Lock()
	defer e.mu.Unlock()
	close(e.stalls)
	e.stalls = make(chan struct{})
	e.logger.Info("stalls released")
}

// Released returns the channel that the next ReleaseStalls closes, for
// sftpproxy.Options.Released, so that a stall or freeze that begins now
// waits on it.
func (e *Engine) Released() <-chan struct{} {
	e.mu.Lock()
	defer e.mu.Unlock()
	return e.stalls
}

// RuleSet is an engine's rules at one revision: the rules it was given, in
// the order they are tried, and its chaos, or nil, whose rules are tried
// after them. Counts holds what each rule has done so far, those of chaos
// included, by rule ID.
type RuleSet struct {
	Revision uint64
	Rules    []Rule
	Chaos    *Chaos
	Counts   map[string]Counts
}

// Rules returns the engine's current rules.
func (e *Engine) Rules() RuleSet {
	e.mu.Lock()
	defer e.mu.Unlock()
	set := RuleSet{Revision: e.revision, Chaos: e.chaos, Counts: make(map[string]Counts, len(e.rules))}
	for _, ru := range e.rules {
		if !ru.chaos {
			set.Rules = append(set.Rules, ru.Rule)
		}
		set.Counts[ru.ID] = ru.counts
	}
	return set
}

// Revision returns the revision of the engine's rules: 1 for those the run
// starts with, and one more for each change.
func (e *Engine) Revision() uint64 {
	e.mu.Lock()
	defer e.mu.Unlock()
	return e.revision
}

// Check reports the first of rules that an engine cannot apply as written.
// Their IDs may not start with chaos-, which only the rules of chaos have.
func Check(rules []Rule) error {
	ids := make(map[string]bool)
	for _, r := range rules {
		if r.ID == "" {
			return errors.New("faults: a rule has no ID")
		}
		if strings.HasPrefix(r.ID, chaosPrefix) {
			return fmt.Errorf("faults: rule ID %q starts with %s, which only the rules of a chaos preset have", r.ID, chaosPrefix)
		}
		if ids[r.ID] {
			return fmt.Errorf("faults: rule ID %q is used twice", r.ID)
		}
		ids[r.ID] = true
		if err := r.check(); err != nil {
			return fmt.Errorf("faults: rule %q: %w", r.ID, err)
		}
	}
	return nil
}

// fires reports whether r fires for the request of the decision k, which it
// selects: always, unless r has a Probability.
func (e *Engine) fires(r *rule, k Key) bool {
	if r.Probability == nil {
		return true
	}
	k.Choice = "probability"
	d := e.seed.Draw(k)
	fires := d.Fires(*r.Probability)
	e.logger.Debug("decision", "key", k, "draw", d, "probability", *r.Probability, "fires", fires)
	return fires
}

// action returns r's action for the request of the decision k, with any
// value r draws for it, which it also returns as log attributes.
func (e *Engine) action(r *rule, k Key) (sftpproxy.Action, []any) {
	a, drawn := e.drawn(r, k)
	if r.timedByTransfer() {
		at := e.moment(r, k)
		return sftpproxy.Timed{After: at, Action: a}, append(drawn, "at", at)
	}
	return a, drawn
}

// drawn returns r's action with the values r draws for the decision k, which
// it also returns as log attributes, and with its waits released when r is
// removed.
func (e *Engine) drawn(r *rule, k Key) (sftpproxy.Action, []any) {
	switch a := r.Action.(type) {
	case sftpproxy.Delay:
		if r.Duration != nil {
			a.Duration = drawFrom(e, k, "duration", *r.Duration)
			return r.released(a), []any{"duration", a.Duration}
		}
	case sftpproxy.ListenerDown:
		if r.Duration != nil {
			a.Duration = drawFrom(e, k, "duration", *r.Duration)
			return a, []any{"duration", a.Duration}
		}
	case sftpproxy.PartialUpload:
		if r.Cutoff != nil {
			a.Cutoff = drawFrom(e, k, "cutoff", *r.Cutoff)
			return r.released(a), []any{"cutoff", a.Cutoff}
		}
	}
	return r.released(r.Action), nil
}

// released returns a with the delay, stall or freeze it holds, if any,
// ended when the rule is removed.
func (r *rule) released(a sftpproxy.Action) sftpproxy.Action {
	switch a := a.(type) {
	case sftpproxy.Delay:
		a.Release = r.removed
		return a
	case sftpproxy.Stall:
		a.Release = r.removed
		return a
	case sftpproxy.Freeze:
		a.Release = r.removed
		return a
	case sftpproxy.PartialUpload:
		a.Result = r.released(a.Result)
		return a
	}
	return a
}

// isRemoved reports whether a change has removed the rule.
func (r *rule) isRemoved() bool {
	select {
	case <-r.removed:
		return true
	default:
		return false
	}
}

// moment returns the moment of r's trigger for the decision k: its at,
// drawn if its bounds differ.
func (e *Engine) moment(r *rule, k Key) time.Duration {
	at := r.Trigger.At
	if at.Min == at.Max {
		return at.Min
	}
	return drawFrom(e, k, "at", *at)
}

// connectionMoment returns c's connection's moment for r, drawn the first
// time one of its sessions asks.
func (e *Engine) connectionMoment(r *rule, c Client) *connectionMoment {
	m := r.connections[c.Connection]
	if m == nil {
		r.users[c.User]++
		k := Key{Rule: r.ID, Activation: r.activation, User: c.User, Ordinal: r.users[c.User]}
		m = &connectionMoment{at: c.Authenticated.Add(e.moment(r, k)), key: k}
		r.connections[c.Connection] = m
	}
	return m
}

// runMoment returns the moment of r's trigger from the run, or from the
// change that applied r, drawn once.
func (e *Engine) runMoment(r *rule) time.Duration {
	if r.runAt == nil {
		at := e.moment(r, Key{Rule: r.ID, Activation: r.activation, Ordinal: 1})
		r.runAt = &at
	}
	return *r.runAt
}

// drawFrom returns the value that the choice of the decision k draws from r.
func drawFrom[T ~int64 | ~uint64](e *Engine, k Key, choice string, r Range[T]) T {
	k.Choice = choice
	d := e.seed.Draw(k)
	v := Between(d, r.Min, r.Max)
	e.logger.Debug("decision", "key", k, "draw", d, "min", r.Min, "max", r.Max, "value", v)
	return v
}

// reserveTransfer returns the Reserve of a transfer that r selected, which
// lets the fault take effect if r has not used up its MaxTriggers by then,
// even once a change has removed r.
func (e *Engine) reserveTransfer(r *rule, attrs []any) func() bool {
	return func() bool {
		e.mu.Lock()
		defer e.mu.Unlock()
		return e.fire(r, attrs)
	}
}

// reserveMoment returns the Reserve of a moment that r timed, which lets the
// fault take effect if r is still a current rule, not paused, and has not
// used up its MaxTriggers by then. Given once, a moment of a connection, the
// fault takes effect only once, whichever of the connection's sessions it
// is timed for.
func (e *Engine) reserveMoment(r *rule, attrs []any, once *connectionMoment) func() bool {
	return func() bool {
		e.mu.Lock()
		defer e.mu.Unlock()
		if r.isRemoved() {
			e.logger.Info("rule suppressed", append(attrs, "reason", "removed")...)
			return false
		}
		if e.paused(r) {
			e.logger.Info("rule suppressed", append(attrs, "reason", "paused")...)
			return false
		}
		if once != nil {
			if once.fired {
				return false
			}
			once.fired = true
		}
		return e.fire(r, attrs)
	}
}

// fire counts a firing of r and reports true, unless r has used up its
// MaxTriggers. e.mu must be held.
func (e *Engine) fire(r *rule, attrs []any) bool {
	if r.spent() {
		e.logger.Info("rule suppressed", append(attrs, "reason", "max_triggers")...)
		return false
	}
	r.counts.Fired++
	e.logger.Info("rule fired", attrs...)
	return true
}

func (r *rule) matches(c Client, op Operation, req sftpproxy.Request) bool {
	return slices.Contains(r.ops, op) &&
		r.matchesClient(c) &&
		r.Match.Path.matches(req.Path) &&
		r.Match.Target.matches(req.Target)
}

func (r *rule) matchesClient(c Client) bool {
	m := r.Match
	return (m.User == "" || m.User == c.User) && (m.KeyFingerprint == "" || m.KeyFingerprint == c.KeyFingerprint)
}

// count counts a request the rule matched and returns its ordinal: its
// attempt, for a rule with an Attempt, and otherwise its occurrence.
func (r *rule) count(user, path string) uint64 {
	r.counts.Matched++
	a := r.Match.Attempt
	if a == nil {
		return r.counts.Matched
	}
	var k attemptKey
	if a.PerUser {
		k.user = user
	}
	if a.PerPath {
		k.path = path
	}
	r.attempts[k]++
	return r.attempts[k]
}

// decisionKey counts a request the rule matched among those with the same
// user, path and operation, and returns the key of the rule's random
// decisions about it, without a Choice.
func (r *rule) decisionKey(user, path string, op Operation) Key {
	k := Key{Rule: r.ID, Activation: r.activation, User: user, Path: path, Operation: string(op)}
	if r.draws != nil {
		dk := drawKey{user, path, op}
		r.draws[dk]++
		k.Ordinal = r.draws[dk]
	}
	return k
}

func (r *rule) selects(ordinal uint64) bool {
	switch m := r.Match; {
	case m.Attempt != nil:
		return slices.Contains(m.Attempt.Numbers, ordinal)
	case m.Occurrence != nil:
		return slices.Contains(m.Occurrence, ordinal)
	}
	return true
}

// spent reports whether the rule has taken effect as often as it may.
func (r *rule) spent() bool {
	return r.MaxTriggers > 0 && r.counts.Fired >= uint64(r.MaxTriggers)
}
