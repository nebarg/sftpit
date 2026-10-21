package integration

import (
	"fmt"
	"os"
	"path/filepath"
	"slices"
	"strings"
	"testing"

	"github.com/nebarg/sftpit/internal/sftpproxy"
)

// TestOpenSSHKeepsEveryName uploads files whose names differ only in case,
// or that a host volume might refuse or change, and checks that OpenSSH
// lists and downloads each one as its own file, as from a case-sensitive
// Linux server, whatever the host's volume is.
func TestOpenSSHKeepsEveryName(t *testing.T) {
	sftpPath := openSSHOrSkip(t)
	// sftp shows names as the locale says, so the test fixes the locale.
	t.Setenv("LC_ALL", "C")
	names := []string{"Orders.csv", "orders.csv", "ORDERS.CSV", "café.csv", "con.txt", "a:b.csv", "trailing."}

	srv := startServer(t, proxied, sftpproxy.Options{})
	work := t.TempDir()
	var batch strings.Builder
	batch.WriteString("mkdir in\n")
	for i, name := range names {
		local := filepath.Join(work, "up", strings.Repeat("x", i+1))
		if err := os.MkdirAll(filepath.Dir(local), 0o700); err != nil {
			t.Fatal(err)
		}
		writeFile(t, local, []byte(name))
		// Quoting keeps the names' characters from the batch parser.
		batch.WriteString(`put "` + local + `" "in/` + name + "\"\n")
	}
	batch.WriteString("ls -1 in\n")
	for i, name := range names {
		batch.WriteString(`get "in/` + name + `" "` + filepath.Join(work, "down", strings.Repeat("x", i+1)) + "\"\n")
	}
	if err := os.Mkdir(filepath.Join(work, "down"), 0o700); err != nil {
		t.Fatal(err)
	}

	out, err := openSSH(t, sftpPath, srv, work, batch.String())
	if err != nil {
		t.Fatalf("sftp failed: %v\n%s", err, out)
	}
	var listed []string
	inListing := false
	for _, l := range splitLines(out) {
		switch {
		case strings.HasPrefix(string(l), "sftp> ls"):
			inListing = true
		case strings.HasPrefix(string(l), "sftp> "):
			inListing = false
		case inListing:
			listed = append(listed, strings.TrimPrefix(string(l), "in/"))
		}
	}
	var shown []string
	for _, name := range names {
		shown = append(shown, openSSHShows(name))
	}
	if want := slices.Sorted(slices.Values(shown)); !slices.Equal(slices.Sorted(slices.Values(listed)), want) {
		t.Errorf("sftp listed %q, want %q:\n%s", listed, want, out)
	}
	for i, name := range names {
		got, err := os.ReadFile(filepath.Join(work, "down", strings.Repeat("x", i+1)))
		if err != nil || string(got) != name {
			t.Errorf("downloading %s gave %q (%v), want its own content", name, got, err)
		}
	}
}

// openSSHShows returns name as OpenSSH's sftp prints it in the C locale,
// with each non-ASCII byte as a backslash and three octal digits.
func openSSHShows(name string) string {
	var b strings.Builder
	for i := range len(name) {
		if c := name[i]; c >= 0x80 {
			fmt.Fprintf(&b, `\%03o`, c)
		} else {
			b.WriteByte(c)
		}
	}
	return b.String()
}
