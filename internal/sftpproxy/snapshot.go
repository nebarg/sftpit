package sftpproxy

import (
	"crypto/sha256"
	"encoding/hex"

	"github.com/nebarg/sftpit/internal/sftpwire"
)

// Snapshot describes the file that a faulted handle left behind.
type Snapshot struct {
	Size   int64
	SHA256 [sha256.Size]byte

	// Copy names the copy of the file kept as evidence, or is empty if none
	// was.
	Copy string
}

// How a faulted handle came to be closed, as its snapshot records it.
const (
	closedByClient     = "client"
	closedByFault      = "fault"
	closedBySessionEnd = "session end"
)

// prepareSnapshot arranges for req, if it closes a faulted file handle, to
// wait for the file to be snapshotted once the backend has closed it.
func (s *session) prepareSnapshot(req *request) {
	if _, ok := req.packet.(*sftpwire.Close); ok && s.snapshot != nil && s.tracker.faultedFile(req.handle) {
		req.snapshot = make(chan struct{})
	}
}

// awaitSnapshot waits, if req closes a faulted file handle, until the file
// has been snapshotted or the session ends, so that no later request can
// change the file first. A drop that stopped req reaching the backend
// snapshots the file itself.
func (s *session) awaitSnapshot(req *request) error {
	if req.snapshot == nil {
		return nil
	}
	select {
	case <-req.snapshot:
		return nil
	case <-s.done:
		return errStopped
	}
}

// snapshotClosed snapshots the file of the faulted handle that req, a CLOSE
// the backend has answered, closed, unless an earlier CLOSE of the handle
// already has.
func (s *session) snapshotClosed(req *request) {
	if req.snapshot == nil {
		return
	}
	if s.tracker.claimSnapshot(req.handle) {
		s.takeSnapshot(req.path, closedByClient)
	}
	close(req.snapshot)
}

// snapshotRest snapshots the files of every faulted handle that the session
// has yet to snapshot, once a drop or the end of the session means nothing
// more will reach the backend.
func (s *session) snapshotRest(closedBy string) {
	if s.snapshot == nil {
		return
	}
	for _, path := range s.tracker.claimSnapshots() {
		s.takeSnapshot(path, closedBy)
	}
}

func (s *session) takeSnapshot(path, closedBy string) {
	snap, err := s.snapshot(path)
	if err != nil {
		s.logger.Error("snapshot failed", "path", path, "closed_by", closedBy, "err", err)
		return
	}
	attrs := []any{"path", path, "closed_by", closedBy, "size", snap.Size, "sha256", hex.EncodeToString(snap.SHA256[:])}
	if snap.Copy != "" {
		attrs = append(attrs, "copy", snap.Copy)
	}
	s.logger.Info("snapshot", attrs...)
}
