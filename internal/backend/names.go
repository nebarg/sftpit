package backend

import "strings"

// rootName converts a clean absolute virtual path into the name relative to
// the root under which the host stores it, which is the path without its
// leading slash. A file is stored under the name the client gave it, so the
// host's own rules for names apply, such as whether it ignores case.
func rootName(virtual string) string {
	if virtual == "/" {
		return "."
	}
	return strings.TrimPrefix(virtual, "/")
}
