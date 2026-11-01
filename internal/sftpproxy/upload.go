package sftpproxy

import (
	"context"
	"fmt"
	"log/slog"
	"math"

	"github.com/nebarg/sftpit/internal/sftpwire"
)

// upload is a PartialUpload on an open handle.
type upload struct {
	PartialUpload

	// reached is set once a write on the handle has reached the cutoff, and
	// declined if Reserve then refused the cutoff.
	reached, declined bool
}

// cut applies the cutoff on req's handle if req is a write that reaches it,
// and reports whether it did. Only the first write to reach the cutoff is
// logged as a fault; the writes it cuts off after that are its effects.
func (s *session) cut(req *request) bool {
	w, ok := req.packet.(*sftpwire.Write)
	if !ok || req.upload == nil || req.upload.declined {
		return false
	}
	u := req.upload
	if w.Offset < u.Cutoff && uint64(len(w.Data)) <= u.Cutoff-w.Offset {
		return false
	}
	level := slog.LevelDebug
	if !u.reached {
		u.reached, level = true, slog.LevelInfo
		if u.Reserve != nil && !u.Reserve() {
			u.declined = true
			return false
		}
	}
	when := Before
	if w.Offset < u.Cutoff {
		w.Data = w.Data[:u.Cutoff-w.Offset]
		when = After
	}
	req.action, req.cut = withWhen(u.Result, when), true
	s.logger.Log(context.Background(), level, "injected fault", s.faultAttrs(req)...)
	return true
}

// withWhen returns a, the result of a PartialUpload, taking effect when.
func withWhen(a Action, when When) Action {
	switch a := a.(type) {
	case Fail:
		a.When = when
		return a
	case Drop:
		a.When = when
		return a
	case Freeze:
		a.When = when
		return a
	}
	panic(fmt.Sprintf("sftpproxy: %T cannot end an upload", a))
}

// stored is a CorruptUpload on an open handle.
type stored struct {
	CorruptUpload

	// corrupted is set once the corruption has changed a write on the
	// handle, and declined if Reserve refused the first change.
	corrupted, declined bool
}

// corruptStored applies the upload corruption on req's handle if req is a
// write that it changes, and reports whether it did. A write it changes
// faults the handle, so its file is snapshotted. Only the first write it
// changes is logged as a fault; the writes it changes after that are its
// effects.
func (s *session) corruptStored(req *request) bool {
	w, ok := req.packet.(*sftpwire.Write)
	if !ok || req.stored == nil || req.stored.declined {
		return false
	}
	st := req.stored
	start, end := w.Offset, w.Offset+uint64(len(w.Data))
	if end < start {
		// No file reaches this far, so the backend refuses the write.
		return false
	}
	from, to := st.Offset, st.Offset+st.Length
	if st.Corruption == Truncate {
		to = math.MaxUint64
	}
	changes := end > from && start < to
	if st.Corruption == OmitRange {
		changes = end > from
	}
	if !changes {
		return false
	}
	level := slog.LevelDebug
	if !st.corrupted {
		st.corrupted, level = true, slog.LevelInfo
		if st.Reserve != nil && !st.Reserve() {
			st.declined = true
			return false
		}
	}
	attrs := []any{"request", operation(w), "path", req.path, "fault", "corrupt_upload", "corruption", st.Corruption, "at", st.Offset}
	if st.Corruption != Truncate {
		attrs = append(attrs, "length", st.Length)
	}
	s.logger.Log(context.Background(), level, "injected fault", append(attrs, "offset", w.Offset)...)
	s.tracker.fault(req)

	switch st.Corruption {
	case FlipBytes:
		for i := max(from, start) - start; i < min(to, end)-start; i++ {
			w.Data[i] ^= 1
		}
	case Truncate, OmitRange:
		// The bytes kept are those below the range and, for OmitRange,
		// those after it, which move down to where the range began and so
		// follow on from the bytes below it.
		var kept []byte
		if start < from {
			kept = w.Data[:min(end, from)-start]
		}
		if st.Corruption == OmitRange && end > to {
			kept = append(kept, w.Data[max(start, to)-start:]...)
		}
		switch {
		case len(kept) == 0:
			req.own = status(sftpwire.StatusOK)
		case start >= from:
			// Only OmitRange keeps bytes of a write that starts in its range
			// or after it.
			w.Offset = max(start, to) - st.Length
		}
		w.Data = kept
	}
	return true
}
