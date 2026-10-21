package integration

import (
	"bytes"
	"errors"
	"io/fs"
	"maps"
	"os"
	"path/filepath"
	"slices"
	"strings"
	"sync"
	"sync/atomic"
	"testing"

	"github.com/nebarg/sftpit/internal/backend"
	"github.com/nebarg/sftpit/internal/sftpproxy"
	"github.com/nebarg/sftpit/internal/sftpwire"
)

// The paths publish.php uploads to and then publishes at.
const (
	temporaryPath = "/incoming/orders.csv.part"
	publishedPath = "/incoming/orders.csv"
)

// TestLaravelUploadRecovery has a Laravel application publish orders.csv
// through a .part file, with its first upload cut off and each result, and
// checks what each of its uploaders leaves behind. The uploader that
// recovers must publish exactly the uploaded file, and only once an upload
// has succeeded. The other two have defects, which the stored files and the
// requests must show.
func TestLaravelUploadRecovery(t *testing.T) {
	php := phpseclibOrSkip(t)

	data := randomBytes(4<<20 + 321)
	partial := data[:uploadCutoff]
	openTemporary := "OPEN " + temporaryPath
	closeTemporary := "CLOSE " + temporaryPath
	publish := "RENAME " + temporaryPath + " -> " + publishedPath
	cutOffWith := map[string]sftpproxy.Action{
		"fail":  sftpproxy.Fail{Status: sftpwire.StatusFailure},
		"drop":  sftpproxy.Drop{},
		"reset": sftpproxy.Drop{Reset: true},
	}
	tests := []struct {
		uploader string
		result   string
		// outcomes are publish.php's results, by operation.
		outcomes map[string]any
		// requests holds the sequences in which the requests on the
		// temporary and published paths, apart from writes, may arrive.
		// phpseclib sends a CLOSE after a failed upload without waiting
		// for its reply, so where the uploader disconnects at once, the
		// CLOSE races the disconnect, as it would on OpenSSH.
		requests [][]string
		// published and temporary are what the two paths hold at the end,
		// nil for nothing.
		published, temporary []byte
	}{
		{
			uploader: "recover", result: "fail",
			outcomes: map[string]any{"upload 1": false, "upload 2": true, "move": true},
			requests: [][]string{
				{openTemporary, closeTemporary, openTemporary, closeTemporary, publish},
				{openTemporary, openTemporary, closeTemporary, publish},
			},
			published: data,
		},
		{
			uploader: "recover", result: "drop",
			outcomes:  map[string]any{"upload 1": false, "upload 2": true, "move": true},
			requests:  [][]string{{openTemporary, openTemporary, closeTemporary, publish}},
			published: data,
		},
		{
			uploader: "recover", result: "reset",
			outcomes:  map[string]any{"upload 1": false, "upload 2": true, "move": true},
			requests:  [][]string{{openTemporary, openTemporary, closeTemporary, publish}},
			published: data,
		},
		// Ignoring the result publishes the partial file after a drop, once
		// Flysystem reconnects for the move. After a status failure the move
		// fails before it renames anything, because the connection answers
		// it with earlier requests' replies.
		{
			uploader: "ignore-result", result: "fail",
			outcomes:  map[string]any{"upload 1": false, "move": false},
			requests:  [][]string{{openTemporary, closeTemporary}, {openTemporary}},
			temporary: partial,
		},
		{
			uploader: "ignore-result", result: "drop",
			outcomes:  map[string]any{"upload 1": false, "move": true},
			requests:  [][]string{{openTemporary, publish}},
			published: partial,
		},
		{
			uploader: "ignore-result", result: "reset",
			outcomes:  map[string]any{"upload 1": false, "move": true},
			requests:  [][]string{{openTemporary, publish}},
			published: partial,
		},
		// After a status failure, retries on the same connection never even
		// open the file. A drop forces a new connection, so they recover.
		{
			uploader: "same-connection", result: "fail",
			outcomes:  map[string]any{"upload 1": false, "upload 2": false, "upload 3": false},
			requests:  [][]string{{openTemporary, closeTemporary}},
			temporary: partial,
		},
		{
			uploader: "same-connection", result: "drop",
			outcomes:  map[string]any{"upload 1": false, "upload 2": true, "move": true},
			requests:  [][]string{{openTemporary, openTemporary, closeTemporary, publish}},
			published: data,
		},
		{
			uploader: "same-connection", result: "reset",
			outcomes:  map[string]any{"upload 1": false, "upload 2": true, "move": true},
			requests:  [][]string{{openTemporary, openTemporary, closeTemporary, publish}},
			published: data,
		},
	}
	for _, tt := range tests {
		t.Run(tt.uploader+"/"+tt.result, func(t *testing.T) {
			result := cutOffWith[tt.result]
			var logs snapshotLog
			var requests requestLog
			var cutOff atomic.Bool
			srv := startServer(t, proxied, sftpproxy.Options{
				Faults: func(r sftpproxy.Request) sftpproxy.Action {
					requests.add(r)
					if _, ok := r.Packet.(*sftpwire.Open); ok && r.Path == temporaryPath && cutOff.CompareAndSwap(false, true) {
						return sftpproxy.PartialUpload{Cutoff: uploadCutoff, Result: result}
					}
					return nil
				},
				Logger: logs.logger(),
			})
			work := t.TempDir()
			writeFile(t, filepath.Join(work, "orders.csv"), data)

			outcomes := results(t, runPhpseclib(t, php, srv, "publish.php", work, tt.uploader))
			srv.waitForSessions()

			if !maps.Equal(outcomes, tt.outcomes) {
				t.Errorf("publish.php gave %v, want %v", outcomes, tt.outcomes)
			}
			if got := requests.get(); !slices.ContainsFunc(tt.requests, func(want []string) bool { return slices.Equal(got, want) }) {
				t.Errorf("requests:\n%s\nwant one of %q", strings.Join(got, "\n"), tt.requests)
			}
			assertHolds(t, srv, publishedPath, tt.published)
			assertHolds(t, srv, temporaryPath, tt.temporary)
			if fired := strings.Count(logs.text(), `msg="injected fault"`); fired != 1 {
				t.Errorf("the fault fired %d times, want once", fired)
			}
			logs.assertSnapshot(t, srv, temporaryPath, partial, snapshotClosedBy(phpseclibClosedBy, result)...)
		})
	}
}

// requestLog records the requests on the temporary and published paths,
// apart from writes, which a faults function sees in the order they arrive.
type requestLog struct {
	mu       sync.Mutex
	requests []string
}

func (l *requestLog) add(r sftpproxy.Request) {
	if _, ok := r.Packet.(*sftpwire.Write); ok || r.Entry {
		return
	}
	paths := []string{temporaryPath, publishedPath}
	if !slices.Contains(paths, r.Path) && !slices.Contains(paths, r.Target) {
		return
	}
	request := strings.TrimPrefix(r.Packet.Type().String(), "SSH_FXP_") + " " + r.Path
	if r.Target != "" {
		request += " -> " + r.Target
	}
	l.mu.Lock()
	defer l.mu.Unlock()
	l.requests = append(l.requests, request)
}

func (l *requestLog) get() []string {
	l.mu.Lock()
	defer l.mu.Unlock()
	return slices.Clone(l.requests)
}

// assertHolds checks that the file at the virtual path name holds want, or
// that there is no file there if want is nil.
func assertHolds(t *testing.T, srv *server, name string, want []byte) {
	t.Helper()
	got, err := os.ReadFile(filepath.Join(srv.files, filepath.FromSlash(backend.StoredName(name))))
	switch {
	case want == nil && !errors.Is(err, fs.ErrNotExist):
		t.Errorf("%s holds %d bytes (%v), want no file", name, len(got), err)
	case want != nil && (err != nil || !bytes.Equal(got, want)):
		t.Errorf("%s holds %d bytes with SHA-256 %s (%v), want %d with %s", name, len(got), digest(got), err, len(want), digest(want))
	}
}
