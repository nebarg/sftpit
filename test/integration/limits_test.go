package integration

import (
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/nebarg/sftpit/internal/backend"
	"github.com/nebarg/sftpit/internal/sftpproxy"
)

// limitsBatch fills the files up to each of their limits. A leading "-" lets
// the batch continue after a command that the limits refuse.
const limitsBatch = `df
-put big.bin
-put part.bin
-mkdir dir
df
rm big.bin
put part.bin whole.bin
df
`

// TestOpenSSHStopsAtStorageLimits checks that OpenSSH sees refusals at the
// limits as failed requests, the same through the proxy as without it, that
// they leave the bytes below each limit in place, and that df reports the
// limits.
func TestOpenSSHStopsAtStorageLimits(t *testing.T) {
	sftpPath := openSSHOrSkip(t)
	limits := backend.Limits{MaxFileBytes: 1 << 20, MaxTotalBytes: 3 << 19, MaxFiles: 2, MaxOpenFiles: 256}
	big := randomBytes(1<<20 + 1)
	part := randomBytes(3 << 18)
	since := time.Now().Add(-time.Hour)

	transcripts := make(map[route][]line)
	trees := make(map[route][]treeEntry)
	for _, via := range routes {
		srv := startLimitedServer(t, via, sftpproxy.Options{}, limits)
		work := t.TempDir()
		writeFile(t, filepath.Join(work, "big.bin"), big)
		writeFile(t, filepath.Join(work, "part.bin"), part)

		out, err := openSSH(t, sftpPath, srv, work, limitsBatch)
		if err != nil {
			t.Fatalf("%s: sftp failed: %v\n%s", via, err, out)
		}
		transcripts[via] = splitLines(out)
		trees[via] = readTree(t, srv.files, since)
	}

	assertSameLines(t, "sftp output", transcripts[direct], transcripts[proxied])
	assertSameLines(t, "stored files", trees[direct], trees[proxied])
	// OpenSSH writes 32 KiB at a time, so a limit that is a multiple of that
	// keeps every write below it.
	assertFiles(t, trees[proxied], map[string][]byte{
		"part.bin":  part[:1<<19],
		"whole.bin": part,
	})
	out := lines(transcripts[proxied])
	for _, want := range []string{
		`write remote "/big.bin": Failure`,
		`write remote "/part.bin": Failure`,
		`remote mkdir "/dir": Failure`,
	} {
		if !strings.Contains(out, want) {
			t.Errorf("sftp output does not have %q:\n%s", want, out)
		}
	}
	// df reports sizes in KiB: 1536 in all, used up after the refusals and
	// with 256 left once big.bin is gone.
	var used []string
	for l := range strings.Lines(out) {
		if fields := strings.Fields(l); len(fields) == 5 && fields[0] == "1536" {
			used = append(used, fields[1])
		}
	}
	if want := []string{"0", "1536", "1280"}; strings.Join(used, " ") != strings.Join(want, " ") {
		t.Errorf("df shows %v KiB used, want %v:\n%s", used, want, out)
	}
}
