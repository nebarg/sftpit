package faults

import (
	"time"

	"github.com/nebarg/sftpit/internal/sftpproxy"
)

// Client is the client of one SFTP session.
type Client struct {
	User string

	// KeyFingerprint is the SHA-256 fingerprint of the key the client logged
	// in with, or "" for a password.
	KeyFingerprint string

	// Connection identifies the client's connection among the run's, and
	// Authenticated is when it authenticated, which triggers anchored to the
	// connection measure from. Every session on a connection shares its
	// moments.
	Connection    uint64
	Authenticated time.Time
}

// Session holds the faults of one SFTP session: the action for each of its
// requests, and the connection actions timed for it. Its methods are safe
// for concurrent use.
type Session struct {
	e      *Engine
	client Client
	timers []sftpproxy.Timer

	// moments holds the connection's moment for each rule for requests
	// whose trigger is anchored to the connection. They are guarded by the
	// engine's mu.
	moments map[*rule]*connectionMoment
}

// Session returns the faults of an SFTP session of client. A connection
// action at a moment of the run is timed for each session that starts
// before the moment; one at a moment of the connection fires in one session
// of the connection, the first in which the moment comes.
func (e *Engine) Session(c Client) *Session {
	s := &Session{e: e, client: c, moments: make(map[*rule]*connectionMoment)}
	now := time.Now()
	e.mu.Lock()
	defer e.mu.Unlock()
	for _, ru := range e.rules {
		t := ru.Trigger
		if t == nil || t.At == nil || t.Anchor == Transfer || !ru.matchesClient(c) {
			continue
		}
		if t.Anchor == Connection {
			_, seen := ru.connections[c.Connection]
			m := e.connectionMoment(ru, c)
			if !ru.timedBySession() {
				s.moments[ru] = m
				continue
			}
			if !seen {
				ru.counts.Matched++
				ru.counts.Selected++
			}
			attrs := []any{"rule", ru.ID, "user", c.User, "anchor", t.Anchor, "at", m.at.Sub(c.Authenticated)}
			s.timers = append(s.timers, sftpproxy.Timer{At: m.at, Action: ru.Action, Reserve: e.reserve(ru, attrs, m)})
			continue
		}
		if !ru.timedBySession() {
			continue
		}
		ru.counts.Matched++
		after := e.runMoment(ru)
		if at := e.start.Add(after); !at.Before(now) {
			ru.counts.Selected++
			attrs := []any{"rule", ru.ID, "user", c.User, "anchor", t.Anchor, "at", after}
			s.timers = append(s.timers, sftpproxy.Timer{At: at, Action: ru.Action, Reserve: e.reserve(ru, attrs, nil)})
		}
	}
	return s
}

// Timers returns the connection actions timed for the session, for
// sftpproxy.Options.Timers.
func (s *Session) Timers() []sftpproxy.Timer {
	return s.timers
}

// Decide returns the action of the first rule that selects r and fires for
// it, if any, for sftpproxy.Options.Faults. Every rule that matches r counts
// it, whichever rule is chosen, so a rule's attempts, occurrences and draws
// do not depend on the rules before it. A rule whose trigger is not active
// does not match.
func (s *Session) Decide(r sftpproxy.Request) sftpproxy.Action {
	e := s.e
	op := operationOf(r)
	now := time.Now()
	e.mu.Lock()
	defer e.mu.Unlock()
	var chosen *rule
	var ordinal uint64
	var key Key
	for _, ru := range e.rules {
		if !ru.matches(s.client, op, r) || !s.active(ru, now) {
			continue
		}
		n := ru.count(s.client.User, r.Path)
		k := ru.decisionKey(s.client.User, r.Path, op)
		if chosen == nil && ru.selects(n) && !ru.spent() {
			s.use(ru)
			if e.fires(ru, k) {
				chosen, ordinal, key = ru, n, k
			}
		}
	}
	if chosen == nil {
		return nil
	}
	chosen.counts.Selected++
	action, drawn := e.action(chosen, key)
	fired := append([]any{"rule", chosen.ID, "request", op, "path", r.Path, "user", s.client.User, "ordinal", ordinal}, drawn...)
	switch a := action.(type) {
	case sftpproxy.PartialUpload:
		a.Reserve = e.reserve(chosen, fired, nil)
		e.logger.Debug("rule selected", fired...)
		return a
	case sftpproxy.CorruptDownload:
		a.Reserve = e.reserve(chosen, fired, nil)
		e.logger.Debug("rule selected", fired...)
		return a
	case sftpproxy.Timed:
		a.Reserve = e.reserve(chosen, fired, nil)
		e.logger.Debug("rule selected", fired...)
		return a
	}
	chosen.counts.Fired++
	e.logger.Info("rule fired", fired...)
	return action
}

// active reports whether ru's trigger lets it apply to a request at now: in
// its window, or from its moment until it has applied once.
func (s *Session) active(ru *rule, now time.Time) bool {
	t := ru.Trigger
	if t == nil || ru.timedByTransfer() {
		return true
	}
	anchor := s.e.start
	if t.Anchor == Connection {
		anchor = s.client.Authenticated
	}
	if w := t.Window; w != nil {
		since := now.Sub(anchor)
		return since >= w.From && since < w.Until
	}
	if t.Anchor == Run {
		return !ru.usedRunAt && !now.Before(anchor.Add(s.e.runMoment(ru)))
	}
	m := s.moments[ru]
	return m != nil && !m.used && !now.Before(m.at)
}

// use records that ru has been tried for a request, which uses up its
// moment if it has one: a probability that misses then does not try again.
func (s *Session) use(ru *rule) {
	t := ru.Trigger
	switch {
	case t == nil || t.At == nil || ru.timedByTransfer():
	case t.Anchor == Run:
		ru.usedRunAt = true
	default:
		s.moments[ru].used = true
	}
}
