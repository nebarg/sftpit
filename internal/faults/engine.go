package faults

import (
	"cmp"
	"errors"
	"fmt"
	"log/slog"
	"slices"
	"sync"
	"time"

	"github.com/nebarg/sftpit/internal/sftpproxy"
)

// Engine applies the rules of a scenario to the requests of one run, which
// starts when the engine is made. Each rule counts the requests it matches
// from the start of the run, and draws its random decisions from the run's
// seed. Its methods are safe for concurrent use.
type Engine struct {
	seed   Seed
	start  time.Time
	logger *slog.Logger

	mu    sync.Mutex
	rules []*rule

	// timers are the faults at moments of the run itself.
	timers []sftpproxy.Timer
}

// rule is a Rule with its counts.
type rule struct {
	Rule
	ops    []Operation
	counts Counts

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
// connection shares it.
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
// of the run or the connection counts sessions rather than requests: those
// whose client it matched, those it was then timed for, and those it fired
// in. A listener_down at a moment of the run is matched and selected once,
// for the run.
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

// New returns an engine for rules, for a run that starts now. It draws its
// random decisions from seed and logs each fault it injects to logger, or to
// slog.Default() if logger is nil. It logs each random decision at debug
// level.
func New(rules []Rule, seed Seed, logger *slog.Logger) (*Engine, error) {
	if logger == nil {
		logger = slog.Default()
	}
	if err := Check(rules); err != nil {
		return nil, err
	}
	e := &Engine{seed: seed, start: time.Now(), logger: logger}
	for _, r := range rules {
		ru := &rule{
			Rule:        r,
			ops:         r.selectedAt(),
			attempts:    make(map[attemptKey]uint64),
			connections: make(map[uint64]*connectionMoment),
			users:       make(map[string]uint64),
		}
		if r.Probability != nil || r.Duration != nil || r.Cutoff != nil || r.Trigger != nil {
			ru.draws = make(map[drawKey]uint64)
		}
		e.rules = append(e.rules, ru)
	}
	slices.SortStableFunc(e.rules, func(a, b *rule) int { return cmp.Compare(a.Priority, b.Priority) })
	for _, ru := range e.rules {
		if !ru.timedByRun() {
			continue
		}
		ru.counts.Matched++
		ru.counts.Selected++
		after := e.runMoment(ru)
		action, drawn := e.drawn(ru, Key{Rule: ru.ID, Ordinal: 1})
		attrs := append([]any{"rule", ru.ID, "anchor", Run, "at", after}, drawn...)
		e.timers = append(e.timers, sftpproxy.Timer{At: e.start.Add(after), Action: action, Reserve: e.reserve(ru, attrs, nil)})
	}
	return e, nil
}

// Timers returns the faults at moments of the run that act on the listener
// rather than on a session, ListenerDowns, for the run to take whatever its
// sessions are doing.
func (e *Engine) Timers() []sftpproxy.Timer {
	return e.timers
}

// Check reports the first of rules that an engine cannot apply as written.
func Check(rules []Rule) error {
	ids := make(map[string]bool)
	for _, r := range rules {
		if r.ID == "" {
			return errors.New("faults: a rule has no ID")
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

// Counts returns what each rule has done so far, by rule ID.
func (e *Engine) Counts() map[string]Counts {
	e.mu.Lock()
	defer e.mu.Unlock()
	counts := make(map[string]Counts, len(e.rules))
	for _, r := range e.rules {
		counts[r.ID] = r.counts
	}
	return counts
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
// it also returns as log attributes.
func (e *Engine) drawn(r *rule, k Key) (sftpproxy.Action, []any) {
	switch a := r.Action.(type) {
	case sftpproxy.Delay:
		if r.Duration != nil {
			a.Duration = drawFrom(e, k, "duration", *r.Duration)
			return a, []any{"duration", a.Duration}
		}
	case sftpproxy.ListenerDown:
		if r.Duration != nil {
			a.Duration = drawFrom(e, k, "duration", *r.Duration)
			return a, []any{"duration", a.Duration}
		}
	case sftpproxy.PartialUpload:
		if r.Cutoff != nil {
			a.Cutoff = drawFrom(e, k, "cutoff", *r.Cutoff)
			return a, []any{"cutoff", a.Cutoff}
		}
	}
	return r.Action, nil
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
		k := Key{Rule: r.ID, User: c.User, Ordinal: r.users[c.User]}
		m = &connectionMoment{at: c.Authenticated.Add(e.moment(r, k)), key: k}
		r.connections[c.Connection] = m
	}
	return m
}

// runMoment returns the moment of r's trigger from the run, drawn once.
func (e *Engine) runMoment(r *rule) time.Duration {
	if r.runAt == nil {
		at := e.moment(r, Key{Rule: r.ID, Ordinal: 1})
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

// reserve returns the Reserve of a transfer that r selected, or of a moment
// it timed, which lets the fault take effect if r has not used up its
// MaxTriggers by then. A moment of a connection takes effect only once,
// whichever of the connection's sessions it is timed for.
func (e *Engine) reserve(r *rule, attrs []any, once *connectionMoment) func() bool {
	return func() bool {
		e.mu.Lock()
		defer e.mu.Unlock()
		if once != nil {
			if once.fired {
				return false
			}
			once.fired = true
		}
		if r.spent() {
			e.logger.Info("rule suppressed", append(attrs, "reason", "max_triggers")...)
			return false
		}
		r.counts.Fired++
		e.logger.Info("rule fired", attrs...)
		return true
	}
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
	k := Key{Rule: r.ID, User: user, Path: path, Operation: string(op)}
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
