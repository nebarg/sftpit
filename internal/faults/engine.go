package faults

import (
	"cmp"
	"errors"
	"fmt"
	"log/slog"
	"slices"
	"sync"

	"github.com/nebarg/sftpit/internal/sftpproxy"
)

// Engine applies the rules of a scenario to the requests of one run. Each
// rule counts the requests it matches from the start of the run, and draws
// its random decisions from the run's seed. Its methods are safe for
// concurrent use.
type Engine struct {
	seed   Seed
	logger *slog.Logger

	mu    sync.Mutex
	rules []*rule
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
}

type attemptKey struct{ user, path string }

type drawKey struct {
	user, path string
	op         Operation
}

// Counts are what a rule has done in a run.
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

// New returns an engine for rules, which draws its random decisions from
// seed and logs each fault it injects to logger, or to slog.Default() if
// logger is nil. It logs each random decision at debug level.
func New(rules []Rule, seed Seed, logger *slog.Logger) (*Engine, error) {
	if logger == nil {
		logger = slog.Default()
	}
	if err := Check(rules); err != nil {
		return nil, err
	}
	e := &Engine{seed: seed, logger: logger}
	for _, r := range rules {
		ru := &rule{Rule: r, ops: r.selectedAt(), attempts: make(map[attemptKey]uint64)}
		if r.Probability != nil || r.Duration != nil || r.Cutoff != nil {
			ru.draws = make(map[drawKey]uint64)
		}
		e.rules = append(e.rules, ru)
	}
	slices.SortStableFunc(e.rules, func(a, b *rule) int { return cmp.Compare(a.Priority, b.Priority) })
	return e, nil
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

// Session returns the faults for one SFTP session, whose client logged in as
// user with the key whose fingerprint is keyFingerprint, or with a password
// if keyFingerprint is empty. It is meant for sftpproxy.Options.Faults.
func (e *Engine) Session(user, keyFingerprint string) func(sftpproxy.Request) sftpproxy.Action {
	return func(r sftpproxy.Request) sftpproxy.Action {
		return e.decide(user, keyFingerprint, r)
	}
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

// decide returns the action of the first rule that selects r and fires for
// it, if any. Every rule that matches r counts it, whichever rule is chosen,
// so a rule's attempts, occurrences and draws do not depend on the rules
// before it.
func (e *Engine) decide(user, keyFingerprint string, r sftpproxy.Request) sftpproxy.Action {
	op := operationOf(r)
	e.mu.Lock()
	defer e.mu.Unlock()
	var chosen *rule
	var ordinal uint64
	var key Key
	for _, ru := range e.rules {
		if !ru.matches(user, keyFingerprint, op, r) {
			continue
		}
		n := ru.count(user, r.Path)
		k := ru.decisionKey(user, r.Path, op)
		if chosen == nil && ru.selects(n) && !ru.spent() && e.fires(ru, k) {
			chosen, ordinal, key = ru, n, k
		}
	}
	if chosen == nil {
		return nil
	}
	chosen.counts.Selected++
	action, drawn := e.action(chosen, key)
	fired := append([]any{"rule", chosen.ID, "request", op, "path", r.Path, "user", user, "ordinal", ordinal}, drawn...)
	switch a := action.(type) {
	case sftpproxy.PartialUpload:
		a.Reserve = e.reserve(chosen, fired)
		e.logger.Debug("rule selected", fired...)
		return a
	case sftpproxy.CorruptDownload:
		a.Reserve = e.reserve(chosen, fired)
		e.logger.Debug("rule selected", fired...)
		return a
	}
	chosen.counts.Fired++
	e.logger.Info("rule fired", fired...)
	return action
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
	switch a := r.Action.(type) {
	case sftpproxy.Delay:
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

// drawFrom returns the value that the choice of the decision k draws from r.
func drawFrom[T ~int64 | ~uint64](e *Engine, k Key, choice string, r Range[T]) T {
	k.Choice = choice
	d := e.seed.Draw(k)
	v := Between(d, r.Min, r.Max)
	e.logger.Debug("decision", "key", k, "draw", d, "min", r.Min, "max", r.Max, "value", v)
	return v
}

// reserve returns the Reserve of a transfer that r selected, which lets the
// fault take effect if r has not used up its MaxTriggers by then.
func (e *Engine) reserve(r *rule, attrs []any) func() bool {
	return func() bool {
		e.mu.Lock()
		defer e.mu.Unlock()
		if r.spent() {
			e.logger.Info("rule suppressed", append(attrs, "reason", "max_triggers")...)
			return false
		}
		r.counts.Fired++
		e.logger.Info("rule fired", attrs...)
		return true
	}
}

func (r *rule) matches(user, keyFingerprint string, op Operation, req sftpproxy.Request) bool {
	m := r.Match
	return slices.Contains(r.ops, op) &&
		(m.User == "" || m.User == user) &&
		(m.KeyFingerprint == "" || m.KeyFingerprint == keyFingerprint) &&
		m.Path.matches(req.Path) &&
		m.Target.matches(req.Target)
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
