package backend

import (
	"slices"
	"sync"
)

// holds keeps changes to a file out, from every session, while a snapshot
// reads it. Changes to the same file can run together, and reads never
// wait.
type holds struct {
	mu    sync.Mutex
	locks map[string]*pathLock
}

// pathLock is the lock on one virtual path, kept while anyone uses it.
type pathLock struct {
	sync.RWMutex
	users int
}

// change waits until no snapshot holds any of the virtual paths names, and
// then keeps snapshots of them waiting until the returned function is
// called.
func (h *holds) change(names ...string) (done func()) {
	// Locks taken in one order cannot deadlock against each other.
	names = slices.Compact(slices.Sorted(slices.Values(names)))
	locks := make([]*pathLock, len(names))
	for i, name := range names {
		locks[i] = h.use(name)
		locks[i].RLock()
	}
	return func() {
		for i, l := range locks {
			l.RUnlock()
			h.release(names[i], l)
		}
	}
}

// hold waits for changes to the virtual path name that are under way, and
// then keeps every new one waiting until the returned function is called.
func (h *holds) hold(name string) (release func()) {
	l := h.use(name)
	l.Lock()
	return func() {
		l.Unlock()
		h.release(name, l)
	}
}

func (h *holds) use(name string) *pathLock {
	h.mu.Lock()
	defer h.mu.Unlock()
	if h.locks == nil {
		h.locks = make(map[string]*pathLock)
	}
	l := h.locks[name]
	if l == nil {
		l = &pathLock{}
		h.locks[name] = l
	}
	l.users++
	return l
}

func (h *holds) release(name string, l *pathLock) {
	h.mu.Lock()
	defer h.mu.Unlock()
	l.users--
	if l.users == 0 {
		delete(h.locks, name)
	}
}
