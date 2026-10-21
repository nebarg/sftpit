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
// rule counts the requests it matches from the start of the run. Its methods
// are safe for concurrent use.
type Engine struct {
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
}

type attemptKey struct{ user, path string }

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

// New returns an engine for rules, which logs each fault it injects to
// logger, or to slog.Default() if logger is nil.
func New(rules []Rule, logger *slog.Logger) (*Engine, error) {
	if logger == nil {
		logger = slog.Default()
	}
	if err := Check(rules); err != nil {
		return nil, err
	}
	e := &Engine{logger: logger}
	for _, r := range rules {
		e.rules = append(e.rules, &rule{Rule: r, ops: r.selectedAt(), attempts: make(map[attemptKey]uint64)})
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

// decide returns the action of the first rule that selects r, if any. Every
// rule that matches r counts it, whichever rule is chosen, so a rule's
// attempts and occurrences do not depend on the rules before it.
func (e *Engine) decide(user, keyFingerprint string, r sftpproxy.Request) sftpproxy.Action {
	op := operationOf(r)
	e.mu.Lock()
	defer e.mu.Unlock()
	var chosen *rule
	var ordinal uint64
	for _, ru := range e.rules {
		if !ru.matches(user, keyFingerprint, op, r) {
			continue
		}
		n := ru.count(user, r.Path)
		if chosen == nil && ru.selects(n) && !ru.spent() {
			chosen, ordinal = ru, n
		}
	}
	if chosen == nil {
		return nil
	}
	chosen.counts.Selected++
	fired := []any{"rule", chosen.ID, "request", op, "path", r.Path, "user", user, "ordinal", ordinal}
	switch a := chosen.Action.(type) {
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
	return chosen.Action
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
