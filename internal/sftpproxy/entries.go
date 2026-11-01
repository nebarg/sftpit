package sftpproxy

import (
	"fmt"
	"path"

	"github.com/nebarg/sftpit/internal/sftpwire"
)

// rewriteEntries applies the fault chosen for each entry of p, if p is the
// backend's reply to req, a READDIR: a WrongSize misreports the entry's
// size and a Hide leaves the entry out. The entries . and .. name no file
// of their own, so they keep no fault. It reports whether the reply had
// entries and a Hide left out every one.
func (s *session) rewriteEntries(req *request, p sftpwire.Packet) (emptied bool, err error) {
	names, ok := p.(*sftpwire.NameReply)
	if _, readdir := req.packet.(*sftpwire.ReadDir); !ok || !readdir || s.faults == nil || req.path == "" {
		return false, nil
	}
	kept := names.Entries[:0]
	for _, e := range names.Entries {
		if e.Filename == "." || e.Filename == ".." {
			kept = append(kept, e)
			continue
		}
		name := path.Join(req.path, e.Filename)
		switch a := s.faults(Request{Packet: req.packet, Path: name, Entry: true}).(type) {
		case nil:
		case WrongSize:
			s.resize(req, name, a, &e.Attrs, &e.Longname)
		case Hide:
			s.logger.Info("injected fault", "request", operation(req.packet), "path", name, "fault", "hide")
			continue
		default:
			return false, fmt.Errorf("sftpproxy: a %T fault cannot apply to a READDIR entry", a)
		}
		kept = append(kept, e)
	}
	emptied = len(names.Entries) > 0 && len(kept) == 0
	names.Entries = kept
	return emptied, nil
}

// readOn sends req, a READDIR whose every entry a Hide left out, to the
// backend again for the directory's next entries. A reply with no entries
// would end the client's listing early, as OpenSSH's client stops at one,
// so the client gets the next reply with entries, or the EOF. If a drop has
// stopped forwarding by then, the client gets EOF at once.
//
// It runs on the goroutine relaying replies, which must not block writing
// to the backend, so the request is written from a goroutine of its own. It
// counts as unanswered from the start, so a drain cannot finish before it.
func (s *session) readOn(req *request) {
	s.mu.Lock()
	s.unanswered++
	s.mu.Unlock()
	s.wg.Go(func() {
		s.sendMu.Lock()
		defer s.sendMu.Unlock()
		if s.isHalted() {
			s.answer(req.reply, outcome{packet: sftpwire.AppendPacket(nil, req.clientID, status(sftpwire.StatusEOF))})
			s.answered()
			return
		}
		s.tracker.register(req)
		if _, err := s.backend.Write(sftpwire.AppendPacket(nil, req.proxyID, req.packet)); err != nil {
			s.stop(fmt.Errorf("sftpproxy: write backend request: %w", err))
		}
	})
}
