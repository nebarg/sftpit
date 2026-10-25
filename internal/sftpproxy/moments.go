package sftpproxy

import (
	"fmt"
	"time"
)

// checkMoment reports an action that the session cannot take at a moment.
func (s *session) checkMoment(a Action) error {
	switch a.(type) {
	case Drop, Freeze, ListenerDown, EndSession:
		return s.checkTarget(a)
	}
	return fmt.Errorf("sftpproxy: a fault at a moment must be a Drop, Freeze, EndSession or ListenerDown, not %T", a)
}

// arm takes t's action, which checkMoment has accepted, at its moment,
// unless the session ends first.
func (s *session) arm(t Timer) {
	s.wg.Go(func() { s.at(time.Until(t.At), nil, &request{action: t.Action}, t.Reserve) })
}

// armEach arms each timer it receives from timers until the session ends or
// timers is closed.
func (s *session) armEach(timers <-chan Timer) {
	for {
		select {
		case t, ok := <-timers:
			if !ok {
				return
			}
			if err := s.checkMoment(t.Action); err != nil {
				s.stop(err)
				return
			}
			s.arm(t)
		case <-s.done:
			return
		}
	}
}

// at takes m's action, a fault for a moment, once after passes, unless
// closing is closed or the session ends first.
func (s *session) at(after time.Duration, closing <-chan struct{}, m *request, reserve func() bool) {
	timer := time.NewTimer(after)
	defer timer.Stop()
	select {
	case <-timer.C:
		s.fire(m, reserve)
	case <-closing:
	case <-s.done:
	}
}

// fire takes m's action, unless reserve declines it. A ListenerDown that
// leaves connections open is taken at once, and the session carries on.
// Otherwise nothing more reaches the backend, and once the backend has
// answered every request it was sent, the session ends as the action says,
// whatever replies are still to be written: a connection that fails at a
// moment loses them.
func (s *session) fire(m *request, reserve func() bool) {
	if reserve != nil && !reserve() {
		return
	}
	s.tracker.fault(m)
	s.logFault(m)
	if !endsSession(m.action) {
		s.listener.Down(m.action.(ListenerDown).Duration, false)
		return
	}
	s.mu.Lock()
	s.halted, s.fired = true, true
	drained := s.drained
	if s.unanswered > 0 && drained == nil {
		drained = make(chan struct{})
		s.drained = drained
	}
	s.mu.Unlock()
	if drained != nil {
		select {
		case <-drained:
		case <-s.done:
			return
		}
	}
	select {
	case s.moments <- m:
	case <-s.done:
	}
}

// armTimed starts the clock of req's Timed on the handle id that req opened.
// Closing the handle stops it, and a handle the client has already closed
// never starts it.
func (s *session) armTimed(req *request, id string) {
	h, closing := s.tracker.watchClose(id)
	if h == nil {
		return
	}
	m := &request{action: req.timed.Action, path: req.path, handle: h}
	s.wg.Go(func() { s.at(req.timed.After, closing, m, req.timed.Reserve) })
}

func (s *session) hasFired() bool {
	s.mu.Lock()
	defer s.mu.Unlock()
	return s.fired
}

// awaitMoment ends the session at the fault for a moment that has fired,
// once the backend has answered what it was sent.
func (s *session) awaitMoment() error {
	select {
	case m := <-s.moments:
		return s.drop(m)
	case <-s.done:
		return errStopped
	}
}
