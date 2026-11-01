package sftpproxy

import (
	"strconv"
	"strings"

	"github.com/nebarg/sftpit/internal/sftpwire"
)

// misreport rewrites the size in p, the backend's reply to req, if a
// WrongSize was chosen for req.
func (s *session) misreport(req *request, p sftpwire.Packet) {
	if a, ok := p.(*sftpwire.AttrsReply); ok && req.wrongSize != nil {
		s.resize(req, req.path, *req.wrongSize, &a.Attrs, nil)
	}
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
