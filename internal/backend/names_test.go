package backend

import (
	"path"
	"path/filepath"
	"testing"
)

func TestRootName(t *testing.T) {
	tests := []struct{ virtual, want string }{
		{"/", "."},
		{"/orders.csv", "orders.csv"},
		{"/Incoming/Orders 2026.CSV", "Incoming/Orders 2026.CSV"},
		{"/café/a:b.csv", "café/a:b.csv"},
		{`/back\slash/..\x`, `back\slash/..\x`},
		{"/trailing.", "trailing."},
	}
	for _, tt := range tests {
		if got := rootName(tt.virtual); got != tt.want {
			t.Errorf("rootName(%q) = %q, want %q", tt.virtual, got, tt.want)
		}
	}
}

// FuzzRootNameIsLocal checks that a path cleaned as pkg/sftp cleans it gives
// a name that stays inside the root, whatever the client sent.
func FuzzRootNameIsLocal(f *testing.F) {
	for _, p := range []string{"/", "/..", "/../../etc/passwd", "/a/../../b", `/..\..\x`, "//a//b/", "/etc/passwd", "/a/./b"} {
		f.Add(p)
	}
	f.Fuzz(func(t *testing.T, p string) {
		clean := path.Join("/", filepath.ToSlash(filepath.Clean(p)))
		if name := rootName(clean); !filepath.IsLocal(name) {
			t.Errorf("rootName(%q) = %q, which is not local to the root", clean, name)
		}
	})
}
