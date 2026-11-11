package integration

import (
	"fmt"
	"path/filepath"
	"testing"
	"time"

	"github.com/nebarg/sftpit/internal/sftpproxy"
)

func TestPhpseclibTransparency(t *testing.T) {
	t.Parallel()
	for _, p := range phpseclibs {
		t.Run(p.name, func(t *testing.T) {
			t.Parallel()
			p.orSkip(t)
			assertPhpseclibTransparency(t, p)
		})
	}
}

// assertPhpseclibTransparency runs p's workload directly and through the
// proxy, and checks that both runs give the same transcript and files.
func assertPhpseclibTransparency(t *testing.T, p *phpseclib) {
	t.Helper()
	upload := randomBytes(4<<20 + 321)
	since := time.Now().Add(-time.Hour)
	transcripts := make(map[route][]line)
	trees := make(map[route][]treeEntry)
	for _, via := range routes {
		srv := startServer(t, via, sftpproxy.Options{})
		work := t.TempDir()
		writeFile(t, filepath.Join(work, "orders.csv"), upload)
		transcripts[via] = p.run(t, srv, "workload.php", work)
		trees[via] = readTree(t, srv.files, since)
	}

	assertSameLines(t, p.name+" transcript", transcripts[direct], transcripts[proxied])
	assertSameLines(t, "stored files", trees[direct], trees[proxied])
	assertFiles(t, trees[proxied], map[string][]byte{
		"incoming/orders.csv":   []byte("replXY"),
		"incoming/relative.txt": []byte("relative"),
	})
	results := phpseclibResults(t, transcripts[proxied])
	wantResults := map[string]any{
		"download orders.csv":  downloadResult(len(upload), upload),
		"download a range":     downloadResult(70000, upload[1000:71000]),
		"rename onto existing": false,
		"rename after delete":  true,
		"get after replacing":  "replacement",
		"get after offset put": "replXYZment",
		"chown":                false,
		"symlink":              false,
	}
	// phpseclib 2 has no posix_rename, so its workload deletes and renames.
	if p == phpseclib2 {
		wantResults["rename onto deleted"] = true
	} else {
		wantResults["posix_rename onto existing"] = true
	}
	for op, want := range wantResults {
		if got := results[op]; got != want {
			t.Errorf("%s = %v, want %v", op, got, want)
		}
	}
}

// downloadResult is how the workload reports a download: its length and
// SHA-256.
func downloadResult(n int, data []byte) string {
	return fmt.Sprintf("%d %s", n, digest(data))
}
