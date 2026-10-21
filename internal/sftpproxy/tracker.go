package sftpproxy

import (
	"fmt"
	"path"
	"slices"
	"sync"

	"github.com/nebarg/sftpit/internal/sftpwire"
)

// slot holds the outcome of one client request until every earlier reply
// has been written.
type slot chan outcome

// outcome is what the client gets for a request: a reply packet, or a
// connection drop in its place.
type outcome struct {
	packet []byte
	drop   *request
}

// request is a client request on its way to the backend, or answered by the
// proxy itself.
type request struct {
	clientID uint32
	proxyID  uint32
	packet   sftpwire.Packet
	action   Action

	// path is the canonical path the request acts on. For a request on a
	// handle, it is the path the handle was opened with, or empty if the
	// handle is unknown.
	path string

	// target is a rename's canonical destination.
	target string

	// handle is the open handle a request on a handle uses, if the proxy
	// knows it.
	handle *handle

	// upload is the cutoff on the handle a request uses or, for an OPEN, the
	// cutoff the handle it opens will have.
	upload *upload

	// cut is set when the cutoff decided the request, rather than Faults.
	cut bool

	// download is the corruption on the handle a request uses or, for an
	// OPEN, the corruption the handle it opens will have.
	download *download

	// eof is set for a read that the corruption on its handle answers with
	// EOF itself.
	eof bool

	// split is set for a READ that crosses an omitted range, and for the
	// second backend read it becomes.
	split *split

	// snapshot is set for the CLOSE of a faulted file handle, and closed
	// once the session has snapshotted the file.
	snapshot chan struct{}

	reply slot

	// turn is closed, in completion order, once the request has reached the
	// backend or been answered, so later requests on its files can go.
	turn chan struct{}
}

// tracker maps the proxy's backend request IDs to client requests, records
// which path each open handle refers to and resolves client paths.
type tracker struct {
	dir        string
	extensions map[string]bool

	mu      sync.Mutex
	nextID  uint32
	pending map[uint32]*request
	handles map[string]*handle
}

// handle is an open handle as the tracker knows it. Its fields are guarded
// by the tracker's mu.
type handle struct {
	path     string
	upload   *upload
	download *download

	// file is set for a handle that OPEN returned, rather than OPENDIR.
	file bool

	// faulted is set once a fault has acted on the OPEN that returned the
	// handle or on a request through it.
	faulted bool

	// snapshotted is set once the session has snapshotted the handle's
	// file.
	snapshotted bool
}

// newTracker returns a tracker for a session whose backend default directory
// is dir and which offers the client exts.
func newTracker(dir string, exts []sftpwire.Extension) *tracker {
	t := &tracker{
		dir:        dir,
		extensions: make(map[string]bool, len(exts)),
		pending:    make(map[uint32]*request),
		handles:    make(map[string]*handle),
	}
	for _, ext := range exts {
		t.extensions[ext.Name] = true
	}
	return t
}

// describe resolves the paths in p in place and returns the request to
// register when it is forwarded. If the proxy must answer p itself instead,
// describe returns the status to send.
//
// Requests on unknown handles are forwarded: the backend knows no more
// handles than the proxy does, and its own error is the faithful answer.
func (t *tracker) describe(clientID uint32, p sftpwire.Packet) (*request, *sftpwire.StatusReply) {
	t.mu.Lock()
	defer t.mu.Unlock()

	req := &request{clientID: clientID, packet: p}
	ok := true
	switch p := p.(type) {
	case *sftpwire.Open:
		p.Path, ok = t.resolve(p.Path)
		req.path = p.Path
	case *sftpwire.OpenDir:
		p.Path, ok = t.resolve(p.Path)
		req.path = p.Path
	case *sftpwire.Stat:
		p.Path, ok = t.resolve(p.Path)
		req.path = p.Path
	case *sftpwire.LStat:
		p.Path, ok = t.resolve(p.Path)
		req.path = p.Path
	case *sftpwire.SetStat:
		p.Path, ok = t.resolve(p.Path)
		req.path = p.Path
	case *sftpwire.Remove:
		p.Path, ok = t.resolve(p.Path)
		req.path = p.Path
	case *sftpwire.Mkdir:
		p.Path, ok = t.resolve(p.Path)
		req.path = p.Path
	case *sftpwire.Rmdir:
		p.Path, ok = t.resolve(p.Path)
		req.path = p.Path
	case *sftpwire.RealPath:
		// OpenSSH and pkg/sftp both canonicalize an empty path as ".".
		if p.Path == "" {
			p.Path = "."
		}
		p.Path, _ = t.resolve(p.Path)
		req.path = p.Path
	case *sftpwire.Rename:
		p.OldPath, ok = t.resolve(p.OldPath)
		if ok {
			p.NewPath, ok = t.resolve(p.NewPath)
		}
		req.path, req.target = p.OldPath, p.NewPath
	case *sftpwire.PosixRename:
		if !t.extensions[sftpwire.ExtPosixRename] {
			return req, status(sftpwire.StatusOpUnsupported)
		}
		p.OldPath, ok = t.resolve(p.OldPath)
		if ok {
			p.NewPath, ok = t.resolve(p.NewPath)
		}
		req.path, req.target = p.OldPath, p.NewPath
	case *sftpwire.StatVFS:
		if !t.extensions[sftpwire.ExtStatVFS] {
			return req, status(sftpwire.StatusOpUnsupported)
		}
		p.Path, ok = t.resolve(p.Path)
		req.path = p.Path
	case *sftpwire.Close:
		t.use(req, p.Handle)
	case *sftpwire.Read:
		t.use(req, p.Handle)
	case *sftpwire.Write:
		t.use(req, p.Handle)
	case *sftpwire.FStat:
		t.use(req, p.Handle)
	case *sftpwire.FSetStat:
		t.use(req, p.Handle)
	case *sftpwire.ReadDir:
		t.use(req, p.Handle)
	default:
		panic(fmt.Sprintf("sftpproxy: no tracking for %T", p))
	}
	if !ok {
		return req, status(sftpwire.StatusNoSuchFile)
	}
	return req, nil
}

// use attributes req to the open handle id, if the proxy knows it.
func (t *tracker) use(req *request, id string) {
	if h := t.handles[id]; h != nil {
		req.handle, req.path, req.upload, req.download = h, h.path, h.upload, h.download
	}
}

// fault records that a fault acts on req, which marks the handle it uses as
// faulted.
func (t *tracker) fault(req *request) {
	if req.handle == nil {
		return
	}
	t.mu.Lock()
	defer t.mu.Unlock()
	req.handle.faulted = true
}

// faultedFile reports whether h is a file handle that a fault has acted on.
func (t *tracker) faultedFile(h *handle) bool {
	if h == nil {
		return false
	}
	t.mu.Lock()
	defer t.mu.Unlock()
	return h.file && h.faulted
}

// claimSnapshot reports whether the file of h, a faulted file handle, has
// yet to be snapshotted, and records that it now has been. A client can
// close a handle twice before the backend has seen either CLOSE.
func (t *tracker) claimSnapshot(h *handle) bool {
	t.mu.Lock()
	defer t.mu.Unlock()
	if h.snapshotted {
		return false
	}
	h.snapshotted = true
	return true
}

// claimSnapshots returns, in order, the paths of the faulted file handles
// whose files have yet to be snapshotted, both those still open and those
// whose CLOSE the backend has not answered, and records that they now have
// been.
func (t *tracker) claimSnapshots() []string {
	t.mu.Lock()
	defer t.mu.Unlock()
	var paths []string
	claim := func(h *handle) {
		if h != nil && h.file && h.faulted && !h.snapshotted {
			h.snapshotted = true
			paths = append(paths, h.path)
		}
	}
	for _, h := range t.handles {
		claim(h)
	}
	for _, req := range t.pending {
		if _, ok := req.packet.(*sftpwire.Close); ok {
			claim(req.handle)
		}
	}
	slices.Sort(paths)
	return paths
}

// register records req as pending under a new proxy request ID, and the
// second backend read of a split READ under another, just before they are
// forwarded. A request the proxy answers itself is never registered,
// so it leaves no trace: a CLOSE that fails before the backend sees it keeps
// its handle known, as the backend still has it open.
func (t *tracker) register(req *request) {
	t.mu.Lock()
	defer t.mu.Unlock()

	req.proxyID = t.newID()
	t.pending[req.proxyID] = req
	if req.split != nil {
		rest := req.split.rest
		rest.proxyID = t.newID()
		t.pending[rest.proxyID] = rest
	}
	if c, ok := req.packet.(*sftpwire.Close); ok {
		// The draft makes a handle invalid as soon as CLOSE is sent, even if
		// the close then fails.
		delete(t.handles, c.Handle)
	}
}

// resolve makes p absolute against the backend's default directory and
// cleans it lexically, so rules and the backend see the same path. An empty
// path names no file, as in OpenSSH.
func (t *tracker) resolve(p string) (string, bool) {
	if p == "" {
		return "", false
	}
	if !path.IsAbs(p) {
		return path.Join(t.dir, p), true
	}
	return path.Clean(p), true
}

func (t *tracker) newID() uint32 {
	for {
		id := t.nextID
		t.nextID++
		if _, inUse := t.pending[id]; !inUse {
			return id
		}
	}
}

// complete matches a backend reply to its pending request, checks that the
// reply answers that kind of request and records any handle it opens.
func (t *tracker) complete(proxyID uint32, reply sftpwire.Packet) (*request, error) {
	t.mu.Lock()
	defer t.mu.Unlock()

	req, ok := t.pending[proxyID]
	if !ok {
		return nil, fmt.Errorf("sftpproxy: backend replied to unknown request %d", proxyID)
	}
	delete(t.pending, proxyID)
	if !replyFits(req.packet, reply) {
		return nil, fmt.Errorf("sftpproxy: backend answered %v with %v", operation(req.packet), reply.Type())
	}
	if h, ok := reply.(*sftpwire.HandleReply); ok {
		if _, open := t.handles[h.Handle]; open {
			return nil, fmt.Errorf("sftpproxy: backend returned handle %q, which is already open", h.Handle)
		}
		_, file := req.packet.(*sftpwire.Open)
		t.handles[h.Handle] = &handle{path: req.path, upload: req.upload, download: req.download, file: file, faulted: req.action != nil}
	}
	return req, nil
}

// replyFits reports whether reply can answer req. Any request can fail with
// a status; requests that return data expect one particular reply type.
func replyFits(req, reply sftpwire.Packet) bool {
	if _, ok := reply.(*sftpwire.StatusReply); ok {
		return true
	}
	switch req := req.(type) {
	case *sftpwire.Open, *sftpwire.OpenDir:
		_, ok := reply.(*sftpwire.HandleReply)
		return ok
	case *sftpwire.Read:
		data, ok := reply.(*sftpwire.DataReply)
		return ok && uint64(len(data.Data)) <= uint64(req.Length)
	case *sftpwire.ReadDir:
		_, ok := reply.(*sftpwire.NameReply)
		return ok
	case *sftpwire.RealPath:
		name, ok := reply.(*sftpwire.NameReply)
		return ok && len(name.Entries) == 1
	case *sftpwire.Stat, *sftpwire.LStat, *sftpwire.FStat:
		_, ok := reply.(*sftpwire.AttrsReply)
		return ok
	case *sftpwire.StatVFS:
		_, ok := reply.(*sftpwire.ExtendedReply)
		return ok
	}
	return false
}

func status(code sftpwire.StatusCode) *sftpwire.StatusReply {
	return &sftpwire.StatusReply{Code: code, Message: code.Message()}
}

// operation names a request for logs and errors, telling the extended
// requests apart.
func operation(p sftpwire.Packet) string {
	switch p.(type) {
	case *sftpwire.PosixRename:
		return sftpwire.ExtPosixRename
	case *sftpwire.StatVFS:
		return sftpwire.ExtStatVFS
	}
	return p.Type().String()
}
