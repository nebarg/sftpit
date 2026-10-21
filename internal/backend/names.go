package backend

import (
	"fmt"
	"slices"
	"strconv"
	"strings"
)

// rootName converts a clean absolute virtual path into a name relative to
// the root, encoding each segment.
func rootName(virtual string) string {
	if virtual == "/" {
		return "."
	}
	segments := strings.Split(strings.TrimPrefix(virtual, "/"), "/")
	for i, s := range segments {
		segments[i] = encodeName(s)
	}
	return strings.Join(segments, "/")
}

// deviceNames are the names Windows takes for devices, with or without an
// extension, whatever their case.
var deviceNames = []string{
	"con", "prn", "aux", "nul",
	"com0", "com1", "com2", "com3", "com4", "com5", "com6", "com7", "com8", "com9",
	"lpt0", "lpt1", "lpt2", "lpt3", "lpt4", "lpt5", "lpt6", "lpt7", "lpt8", "lpt9",
}

// encodeName encodes one segment of a virtual path as the name it has on
// the host, so that storage behaves like a case-sensitive POSIX volume
// whatever the host's volume ignores or refuses. Lowercase ASCII letters,
// digits, '-', '_' and '.' stay as they are. A capital becomes '^' and its
// lowercase letter, and any other byte '%' and two lowercase hex digits. A
// trailing '.', which Windows strips, is escaped, and so is the first letter
// of a device name. NUL stays as it is, so the host refuses the name.
func encodeName(name string) string {
	var b strings.Builder
	for i := range len(name) {
		switch c := name[i]; {
		case 'a' <= c && c <= 'z', '0' <= c && c <= '9', c == '-', c == '_', c == '.', c == 0:
			b.WriteByte(c)
		case 'A' <= c && c <= 'Z':
			b.WriteByte('^')
			b.WriteByte(c - 'A' + 'a')
		default:
			fmt.Fprintf(&b, "%%%02x", c)
		}
	}
	encoded := b.String()
	if strings.HasSuffix(encoded, ".") {
		encoded = encoded[:len(encoded)-1] + "%2e"
	}
	if stem, _, _ := strings.Cut(encoded, "."); slices.Contains(deviceNames, stem) {
		encoded = fmt.Sprintf("%%%02x", encoded[0]) + encoded[1:]
	}
	return encoded
}

// decodeName returns the virtual name that encodeName encodes as name on
// the host, and false if encodeName gives no name that.
func decodeName(name string) (string, bool) {
	b := make([]byte, 0, len(name))
	for i := 0; i < len(name); i++ {
		switch c := name[i]; {
		case c == '^' && i+1 < len(name):
			b = append(b, name[i+1]-'a'+'A')
			i++
		case c == '%' && i+2 < len(name):
			v, err := strconv.ParseUint(name[i+1:i+3], 16, 8)
			if err != nil {
				return "", false
			}
			b = append(b, byte(v))
			i += 2
		default:
			b = append(b, c)
		}
	}
	// Only the one encoding of each name decodes, so no two names on the
	// host refer to the same virtual name.
	decoded := string(b)
	return decoded, encodeName(decoded) == name
}
