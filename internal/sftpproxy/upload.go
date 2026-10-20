package sftpproxy

import (
	"context"
	"fmt"
	"log/slog"

	"github.com/nebarg/sftpit/internal/sftpwire"
)

// upload is a PartialUpload on an open handle.
type upload struct {
	PartialUpload

	// reached is set once a write on the handle has reached the cutoff.
	reached bool
}

// cut applies the cutoff on req's handle if req is a write that reaches it,
// and reports whether it did. Only the first write to reach the cutoff is
// logged as a fault; the writes it cuts off after that are its effects.
func (s *session) cut(req *request) bool {
	w, ok := req.packet.(*sftpwire.Write)
	if !ok || req.upload == nil {
		return false
	}
	u := req.upload
	when := Before
	switch {
	case w.Offset >= u.Cutoff:
	case uint64(len(w.Data)) > u.Cutoff-w.Offset:
		w.Data = w.Data[:u.Cutoff-w.Offset]
		when = After
	default:
		return false
	}
	req.action, req.cut = withWhen(u.Result, when), true

	level := slog.LevelDebug
	if !u.reached {
		u.reached, level = true, slog.LevelInfo
	}
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
