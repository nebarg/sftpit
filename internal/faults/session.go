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

	// more delivers the timers of the rules that a change applies once the
	// session has started, until ended is closed.
	more  chan sftpproxy.Timer
	ended chan struct{}
}

// Session returns the faults of an SFTP session of client, which End ends.
// A connection action at a moment of the run is timed for each session that
// starts before the moment; one at a moment of the connection fires in one
// session of the connection, the first in which the moment comes.
func (e *Engine) Session(c Client) *Session {
	s := &Session{
		e:       e,
		client:  c,
		moments: make(map[*rule]*connectionMoment),
		more:    make(chan sftpproxy.Timer),
		ended:   make(chan struct{}),
	}
	now := time.Now()
	e.mu.Lock()
	defer e.mu.Unlock()
	e.sessions[s] = struct{}{}
	for _, ru := range e.rules {
		if t, ok := s.time(ru, now); ok {
			s.timers = append(s.timers, t)
		}
	}
	return s
}

// time returns the session's timer for ru, if ru fires at a moment of the
// connection, or of the run that is still to come at now. If ru is instead
// a rule for requests whose trigger is anchored to the connection, time
// records the connection's moment for it. e.mu must be held.
func (s *Session) time(ru *rule, now time.Time) (sftpproxy.Timer, bool) {
	e, c, t := s.e, s.client, ru.Trigger
	if t == nil || t.At == nil || t.Anchor == Transfer || ru.timedByRun() || !ru.matchesClient(c) {
		return sftpproxy.Timer{}, false
	}
	if t.Anchor == Connection {
		_, seen := ru.connections[c.Connection]
		m := e.connectionMoment(ru, c)
		if !ru.timedBySession() {
			s.moments[ru] = m
			return sftpproxy.Timer{}, false
		}
		if !seen {
			ru.counts.Matched++
			ru.counts.Selected++
		}
		action, drawn := e.drawn(ru, m.key)
		attrs := append([]any{"rule", ru.ID, "user", c.User, "anchor", t.Anchor, "at", m.at.Sub(c.Authenticated)}, drawn...)
		return sftpproxy.Timer{At: m.at, Action: action, Reserve: e.reserveMoment(ru, attrs, m)}, true
	}
	if !ru.timedBySession() {
		return sftpproxy.Timer{}, false
	}
	ru.counts.Matched++
	after := e.runMoment(ru)
	at := ru.start.Add(after)
	if at.Before(now) {
		return sftpproxy.Timer{}, false
	}
	ru.counts.Selected++
	attrs := []any{"rule", ru.ID, "user", c.User, "anchor", t.Anchor, "at", after}
	return sftpproxy.Timer{At: at, Action: ru.released(ru.Action), Reserve: e.reserveMoment(ru, attrs, nil)}, true
}

// timeAdded times the session for rules, which a change has just applied, as
// Session would. It delivers each timer through MoreTimers without waiting
// for the session to take it. e.mu must be held.
func (s *Session) timeAdded(rules []*rule, now time.Time) {
	for _, ru := range rules {
		if t, ok := s.time(ru, now); ok {
			go func() {
				select {
				case s.more <- t:
				case <-s.ended:
				}
			}()
		}
	}
}

// Timers returns the connection actions timed for the session as it
// started, for sftpproxy.Options.Timers.
func (s *Session) Timers() []sftpproxy.Timer {
	return s.timers
}

// MoreTimers delivers the connection actions of the rules that a change
// applies during the session, for sftpproxy.Options.MoreTimers.
func (s *Session) MoreTimers() <-chan sftpproxy.Timer {
	return s.more
}

// End ends the session, so that no change of rules times it again. It is
// safe to call more than once.
func (s *Session) End() {
	s.e.mu.Lock()
	defer s.e.mu.Unlock()
	if _, live := s.e.sessions[s]; live {
		delete(s.e.sessions, s)
		close(s.ended)
	}
}

// Decide returns the action of the first rule that selects r and fires for
// it, if any, for sftpproxy.Options.Faults. Every rule that matches r counts
// it, whichever rule is chosen, so a rule's attempts, occurrences and draws
// do not depend on the rules before it. A rule whose trigger is not active,
// or a rule of chaos while it is paused, does not match.
func (s *Session) Decide(r sftpproxy.Request) sftpproxy.Action {
	return s.decide(operationOf(r), r)
}

// Connect returns the action of the first rule that selects a connection of
// c as it is accepted, before the SSH handshake, if any: a Delay, Drop,
// Freeze or ListenerDown. The client has not logged in yet, so c has only
// its Connection.
func (e *Engine) Connect(c Client) sftpproxy.Action {
	return e.event(Connect, c)
}

// Authenticate returns the action of the first rule that selects c's login
// as the server accepts it, before telling the client, if any: a Delay,
// Drop, Freeze or ListenerDown.
func (e *Engine) Authenticate(c Client) sftpproxy.Action {
	return e.event(Authenticate, c)
}

// event decides the connection event op of c, which no rule times from the
// connection, so it needs none of a session's moments.
func (e *Engine) event(op Operation, c Client) sftpproxy.Action {
	s := &Session{e: e, client: c}
	return s.decide(op, sftpproxy.Request{})
}

func (s *Session) decide(op Operation, r sftpproxy.Request) sftpproxy.Action {
	e := s.e
	now := time.Now()
	e.mu.Lock()
	defer e.mu.Unlock()
	var chosen *rule
	var ordinal uint64
	var key Key
	for _, ru := range e.rules {
		if e.paused(ru) || !ru.matches(s.client, op, r) || !s.active(ru, now) {
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
	fired := []any{"rule", chosen.ID, "operation", op}
	if !op.IsEvent() {
		fired = append(fired, "path", r.Path)
	}
	if s.client.User != "" {
		fired = append(fired, "user", s.client.User)
	}
	fired = append(append(fired, "ordinal", ordinal), drawn...)
	switch a := action.(type) {
	case sftpproxy.PartialUpload:
		a.Reserve = e.reserveTransfer(chosen, fired)
		e.logger.Debug("rule selected", fired...)
		return a
	case sftpproxy.CorruptDownload:
		a.Reserve = e.reserveTransfer(chosen, fired)
		e.logger.Debug("rule selected", fired...)
		return a
	case sftpproxy.Timed:
		a.Reserve = e.reserveMoment(chosen, fired, nil)
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
	anchor := ru.start
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
