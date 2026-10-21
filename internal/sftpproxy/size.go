package sftpproxy

import (
	"fmt"
	"path"
	"strconv"
	"strings"

	"github.com/nebarg/sftpit/internal/sftpwire"
)

// misreport rewrites the sizes in p, the backend's reply to req, that a
// WrongSize chosen for req, or for an entry of a READDIR reply, misreports.
func (s *session) misreport(req *request, p sftpwire.Packet) error {
	switch p := p.(type) {
	case *sftpwire.AttrsReply:
		if req.wrongSize != nil {
			s.resize(req, req.path, *req.wrongSize, &p.Attrs, nil)
		}
	case *sftpwire.NameReply:
		if _, ok := req.packet.(*sftpwire.ReadDir); !ok || s.faults == nil || req.path == "" {
			return nil
		}
		for i := range p.Entries {
			e := &p.Entries[i]
			name := path.Join(req.path, e.Filename)
			switch a := s.faults(Request{Packet: req.packet, Path: name, Entry: true}).(type) {
			case nil:
			case WrongSize:
				s.resize(req, name, a, &e.Attrs, &e.Longname)
			default:
				return fmt.Errorf("sftpproxy: a %T fault cannot apply to a READDIR entry", a)
			}
		}
	}
	return nil
}

// resize misreports the size in attrs, and in longname if there is one, as
// w says, and logs the fault, if attrs has a size.
func (s *session) resize(req *request, name string, w WrongSize, attrs *sftpwire.Attrs, longname *string) {
	if attrs.Flags&sftpwire.AttrSize == 0 {
		return
	}
	actual := attrs.Size
	attrs.Size = w.reported(actual)
	if longname != nil {
		*longname = withSize(*longname, actual, attrs.Size)
	}
	s.logger.Info("injected fault", "request", operation(req.packet), "path", name, "fault", "wrong_size", "actual", actual, "reported", attrs.Size)
}

// withSize returns longname with its size field changed from actual to
// reported. The size is the fifth field of a longname in the style of
// ls -l, which OpenSSH and pkg/sftp both use. A longname that does not show
// actual there is returned unchanged.
func withSize(longname string, actual, reported uint64) string {
	var start, end int
	for range 5 {
		start = end + len(longname[end:]) - len(strings.TrimLeft(longname[end:], " "))
		end = start + strings.IndexByte(longname[start:]+" ", ' ')
	}
	if longname[start:end] != strconv.FormatUint(actual, 10) {
		return longname
	}
	// Keep the field's right edge, which ls -l aligns, unless the new size
	// is too wide to fit with a space before it.
	gap := start - len(strings.TrimRight(longname[:start], " "))
	size := strconv.FormatUint(reported, 10)
	spaces := max(1, gap+end-start-len(size))
	return strings.TrimRight(longname[:start], " ") + strings.Repeat(" ", spaces) + size + longname[end:]
}
