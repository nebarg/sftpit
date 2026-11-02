package sftpproxy

import (
	"strings"

	"github.com/nebarg/sftpit/internal/sftpwire"
)

// changes are the OPEN flags with which a client can change a file.
const changes = sftpwire.OpenWrite | sftpwire.OpenAppend | sftpwire.OpenCreate | sftpwire.OpenTruncate | sftpwire.OpenExclusive

// enforce returns the refusal of req if it would change a read-only path,
// and logs it, or nil.
func (s *session) enforce(req *request) *sftpwire.StatusReply {
	var rename bool
	switch p := req.packet.(type) {
	case *sftpwire.Open:
		if p.Flags&changes == 0 {
			return nil
		}
	case *sftpwire.SetStat, *sftpwire.FSetStat, *sftpwire.Remove, *sftpwire.Mkdir, *sftpwire.Rmdir:
	case *sftpwire.Rename, *sftpwire.PosixRename:
		rename = true
	default:
		return nil
	}
	for _, dir := range s.readOnly {
		if within(req.path, dir) || rename && (within(req.target, dir) || within(dir, req.path) || within(dir, req.target)) {
			attrs := []any{"request", operation(req.packet), "path", req.path}
			if rename {
				attrs = append(attrs, "target", req.target)
			}
			s.logger.Info("policy denied", append(attrs, "read_only", dir)...)
			req.readOnly = dir
			return status(sftpwire.StatusPermissionDenied)
		}
	}
	return nil
}

// within reports whether the path p is dir or beneath it. A request on a
// handle the proxy does not know has no path, which is within nothing and
// holds nothing.
func within(p, dir string) bool {
	return p != "" && dir != "" && (p == dir || strings.HasPrefix(p, strings.TrimSuffix(dir, "/")+"/"))
}
