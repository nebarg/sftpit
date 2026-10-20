package sftpproxy

// ReplyOrder is the order in which a session delivers replies.
type ReplyOrder int

const (
	// RequestOrder delivers replies in the order of the client's requests,
	// and forwards requests one at a time, as OpenSSH's sftp-server handles
	// them. A request held before the backend holds back every later one.
	RequestOrder ReplyOrder = iota

	// CompletionOrder delivers each reply as soon as it is ready, as a server
	// that handles requests concurrently may. Requests on the same file still
	// reach the backend in order, but a request held before the backend holds
	// back only later requests on its own files.
	CompletionOrder
)

func (o ReplyOrder) String() string {
	if o == CompletionOrder {
		return "completion"
	}
	return "request"
}

// completionState is the part of a session that only completion order uses.
// Every field but inFlight is guarded by the session's mu.
type completionState struct {
	// inFlight bounds the requests the session handles at once, as the reply
	// queue does in request order.
	inFlight chan struct{}

	// dropping is set once a drop has its place in the reply stream or is
	// waiting for one, so that a second drop that reaches its turn changes
	// nothing.
	dropping bool

	// pendingDrop waits for the backend to answer every request it has.
	pendingDrop *request

	// waiting maps each file to its latest request that has yet to have its
	// turn.
	waiting map[string]*request
}

// schedule processes req, in completion order, once every earlier request
// on its files has had its turn, so the backend sees the requests on each
// file in the order they were sent. A reply held after the backend has acted
// holds back nothing: the operation has already happened in order.
func (s *session) schedule(req *request) error {
	req.turn = make(chan struct{})
	var earlier []chan struct{}
	s.mu.Lock()
	for _, name := range req.files() {
		if prev := s.completion.waiting[name]; prev != nil {
			earlier = append(earlier, prev.turn)
		}
		s.completion.waiting[name] = req
	}
	s.mu.Unlock()

	if len(earlier) == 0 && !holdsBefore(req.action) {
		return s.takeTurn(req)
	}
	s.wg.Go(func() {
		for _, turn := range earlier {
			select {
			case <-turn:
			case <-s.done:
				return
			}
		}
		if err := s.takeTurn(req); err != nil {
			s.stop(err)
		}
	})
	return nil
}

// takeTurn processes req and then lets later requests on its files go.
func (s *session) takeTurn(req *request) error {
	err := s.process(req)
	s.mu.Lock()
	for _, name := range req.files() {
		if s.completion.waiting[name] == req {
			delete(s.completion.waiting, name)
		}
	}
	s.mu.Unlock()
	close(req.turn)
	return err
}

// files returns the canonical paths req acts on: its path and, for a
// rename, its target. A request on an unknown handle acts on none the proxy
// knows of.
func (r *request) files() []string {
	var names []string
	if r.path != "" {
		names = append(names, r.path)
	}
	if r.target != "" && r.target != r.path {
		names = append(names, r.target)
	}
	return names
}

func holdsBefore(a Action) bool {
	switch a := a.(type) {
	case Delay:
		return a.When == Before
	case Stall:
		return a.When == Before
	}
	return false
}
