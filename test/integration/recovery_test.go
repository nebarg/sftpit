package integration

import (
	"log/slog"
	"maps"
	"os"
	"path/filepath"
	"slices"
	"strconv"
	"strings"
	"sync"
	"sync/atomic"
	"testing"

	"github.com/nebarg/sftpit/internal/faults"
	"github.com/nebarg/sftpit/internal/sftpproxy"
	"github.com/nebarg/sftpit/internal/sftpwire"
)

// TestLaravelUploadRecovery has a Laravel application publish orders.csv
// through a .part file, with its first upload cut off and each result, and
// checks what each of its uploaders leaves behind. The uploader that
// recovers must publish exactly the uploaded file, and only once an upload
// has succeeded. The other two have defects, which the stored files and the
// requests must show.
func TestLaravelUploadRecovery(t *testing.T) {
	// Not parallel: a snapshot is not ordered against other sessions, so
	// under the load of parallel tests publish.php's retry on a new
	// connection can change the cut-off file before the first session,
	// slowed down, snapshots it.
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
			var logs capturedLog
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

			outcomes := phpseclibResults(t, runPhpseclib(t, php, srv, "publish.php", work, tt.uploader))
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

// TestLaravelUploadRecoveryFromAScenario injects the first upload's cutoff
// from a scenario in the configuration, as sftpit serve --scenario does, and
// checks that the recovering uploader publishes the whole file and that the
// rule took effect once.
func TestLaravelUploadRecoveryFromAScenario(t *testing.T) {
	// Not parallel: a snapshot is not ordered against other sessions, so
	// under the load of parallel tests publish.php's retry on a new
	// connection can change the cut-off file before the first session,
	// slowed down, snapshots it.
	php := phpseclibOrSkip(t)

	opts := scenarioOptions(t, `  upload-recovery:
    faults:
      - id: first-upload-cutoff
        match:
          user: `+testUser+`
          operation: write
          path: `+temporaryPath+`
          attempt:
            per: [user, path]
            numbers: [1]
        action:
          type: partial_upload
          cutoff_offset: `+strconv.Itoa(uploadCutoff)+`
          result: status
          status: failure
`, "upload-recovery")
	var logs capturedLog
	opts.Logger = logs.logger()
	_, srv := startRuns(t, opts)
	work := t.TempDir()
	data := randomBytes(4<<20 + 321)
	writeFile(t, filepath.Join(work, "orders.csv"), data)

	outcomes := phpseclibResults(t, runPhpseclib(t, php, srv, "publish.php", work, "recover"))
	srv.waitForSessions()

	if want := map[string]any{"upload 1": false, "upload 2": true, "move": true}; !maps.Equal(outcomes, want) {
		t.Errorf("publish.php gave %v, want %v", outcomes, want)
	}
	assertHolds(t, srv, publishedPath, data)
	assertHolds(t, srv, temporaryPath, nil)
	logs.assertSnapshot(t, srv, temporaryPath, data[:uploadCutoff], phpseclibClosedBy...)
	if got, want := srv.counts(t, "first-upload-cutoff"), (faults.Counts{Matched: 2, Selected: 1, Fired: 1}); got != want {
		t.Errorf("counts = %+v, want both opens matched and the first cut off", got)
	}
	if fired := `msg="rule fired" rule=first-upload-cutoff operation=open_write path=` + temporaryPath + ` user=` + testUser + ` ordinal=1`; !strings.Contains(logs.text(), fired) {
		t.Errorf("logs lack %s:\n%s", fired, logs.text())
	}
}

// TestLaravelRepublishLosesThePublishedFile has a Laravel application
// publish orders.csv over an earlier version, with the rename that follows
// Flysystem's delete failing. A standard rename never replaces its target,
// so Flysystem's move() deletes the published file and renames again, and
// when that rename fails the published file is gone. The debug log records
// the order of the requests on the published file and their results.
func TestLaravelRepublishLosesThePublishedFile(t *testing.T) {
	t.Parallel()
	php := phpseclibOrSkip(t)

	seed := t.TempDir()
	previous := randomBytes(64<<10 + 123)
	if err := os.Mkdir(filepath.Join(seed, "incoming"), 0o700); err != nil {
		t.Fatal(err)
	}
	writeFile(t, filepath.Join(seed, filepath.FromSlash(publishedPath)), previous)
	opts := scenarioOptions(t, `  republish:
    faults:
      - id: fail-rename-after-delete
        match:
          operation: rename
          source: `+temporaryPath+`
          target: `+publishedPath+`
          occurrence: [2]
        action: {type: fail, when: before, status: failure}
`, "republish")
	var logs capturedLog
	opts.Logger = slog.New(slog.NewTextHandler(&logs, &slog.HandlerOptions{Level: slog.LevelDebug}))
	opts.SeedDir = seed
	_, srv := startRuns(t, opts)
	work := t.TempDir()
	data := randomBytes(1<<20 + 321)
	writeFile(t, filepath.Join(work, "orders.csv"), data)

	outcomes := phpseclibResults(t, runPhpseclib(t, php, srv, "publish.php", work, "recover"))
	srv.waitForSessions()

	if want := map[string]any{"upload 1": true, "move": false}; !maps.Equal(outcomes, want) {
		t.Errorf("publish.php gave %v, want %v", outcomes, want)
	}
	var got []string
	for l := range strings.Lines(connID.ReplaceAllString(logs.text(), "conn=N ")) {
		if strings.Contains(l, " path="+publishedPath+" ") || strings.Contains(l, " target="+publishedPath+" ") {
			_, l, _ = strings.Cut(l, " msg=")
			got = append(got, strings.TrimSpace(l))
		}
	}
	user := "conn=N user=" + testUser
	want := []string{
		`"sftp request" ` + user + ` request=SSH_FXP_RENAME path=` + temporaryPath + ` target=` + publishedPath + ` result=SSH_FX_FAILURE`,
		`"sftp request" ` + user + ` request=SSH_FXP_STAT path=` + publishedPath + ` result=SSH_FXP_ATTRS`,
		`"sftp request" ` + user + ` request=SSH_FXP_REMOVE path=` + publishedPath + ` result=SSH_FX_OK`,
		`"injected fault" ` + user + ` request=SSH_FXP_RENAME path=` + temporaryPath + ` target=` + publishedPath + ` fault=fail when=before status=SSH_FX_FAILURE`,
	}
	if !slices.Equal(got, want) {
		t.Errorf("requests on %s:\n%s\nwant\n%s", publishedPath, strings.Join(got, "\n"), strings.Join(want, "\n"))
	}
	assertHolds(t, srv, publishedPath, nil)
	assertHolds(t, srv, temporaryPath, data)
	if got, want := srv.counts(t, "fail-rename-after-delete"), (faults.Counts{Matched: 2, Selected: 1, Fired: 1}); got != want {
		t.Errorf("counts = %+v, want both renames matched and the second failed", got)
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

// TestLaravelUploadRecoveryFromAResetMidUpload resets the connection half a
// second into the first upload, whatever phpseclib is sending then, and
// checks that the recovering uploader publishes the whole file. Writes in the
// first two seconds of the run wait, so that the upload is still under way.
func TestLaravelUploadRecoveryFromAResetMidUpload(t *testing.T) {
	t.Parallel()
	php := phpseclibOrSkip(t)

	opts := scenarioOptions(t, `  reset-mid-upload:
    faults:
      - id: slow-start
        match: {operation: write, path: `+temporaryPath+`}
        trigger: {window: {from: 0s, until: 2s}, anchor: run}
        action: {type: delay, when: before, duration: 20ms}
      - id: reset-into-first-upload
        match: {operation: write, path: `+temporaryPath+`, attempt: {numbers: [1]}}
        trigger: {at: 500ms, anchor: transfer}
        action: {type: close_connection, mode: rst}
`, "reset-mid-upload")
	var logs capturedLog
	opts.Logger = logs.logger()
	_, srv := startRuns(t, opts)
	work := t.TempDir()
	data := randomBytes(4<<20 + 321)
	writeFile(t, filepath.Join(work, "orders.csv"), data)

	outcomes := phpseclibResults(t, runPhpseclib(t, php, srv, "publish.php", work, "recover"))
	srv.waitForSessions()

	if want := map[string]any{"upload 1": false, "upload 2": true, "move": true}; !maps.Equal(outcomes, want) {
		t.Errorf("publish.php gave %v, want %v", outcomes, want)
	}
	assertHolds(t, srv, publishedPath, data)
	assertHolds(t, srv, temporaryPath, nil)
	if got, want := srv.counts(t, "reset-into-first-upload"), (faults.Counts{Matched: 2, Selected: 1, Fired: 1}); got != want {
		t.Errorf("counts = %+v, want both opens matched and the first reset", got)
	}
	text := connID.ReplaceAllString(logs.text(), "conn=N ")
	for _, want := range []string{
		`msg="rule fired" rule=reset-into-first-upload operation=open_write path=` + temporaryPath + ` user=` + testUser + ` ordinal=1 at=500ms`,
		`msg="injected fault" conn=N user=` + testUser + ` path=` + temporaryPath + ` fault=close_connection when=timer mode=rst`,
		`msg=snapshot conn=N user=` + testUser + ` path=` + temporaryPath + ` closed_by=fault`,
	} {
		if !strings.Contains(text, want) {
			t.Errorf("logs lack %s:\n%s", want, text)
		}
	}
}

// TestLaravelReconnectsWhenItsFirstLoginsAreCutOff closes the connection as
// the server accepts each of the first four logins, before phpseclib hears
// of it, and checks that Flysystem's own retries, four of them, reconnect
// and publish the file.
func TestLaravelReconnectsWhenItsFirstLoginsAreCutOff(t *testing.T) {
	t.Parallel()
	php := phpseclibOrSkip(t)

	opts := scenarioOptions(t, `  cut-off-logins:
    faults:
      - id: first-logins
        match: {operation: authenticate, user: `+testUser+`, occurrence: [1, 2, 3, 4]}
        action: {type: close_connection}
`, "cut-off-logins")
	var logs capturedLog
	opts.Logger = logs.logger()
	_, srv := startRuns(t, opts)
	work := t.TempDir()
	data := randomBytes(1<<20 + 321)
	writeFile(t, filepath.Join(work, "orders.csv"), data)

	outcomes := phpseclibResults(t, runPhpseclib(t, php, srv, "publish.php", work, "recover"))
	srv.waitForSessions()

	if want := map[string]any{"upload 1": true, "move": true}; !maps.Equal(outcomes, want) {
		t.Errorf("publish.php gave %v, want %v", outcomes, want)
	}
	assertHolds(t, srv, publishedPath, data)
	if got, want := srv.counts(t, "first-logins"), (faults.Counts{Matched: 5, Selected: 4, Fired: 4}); got != want {
		t.Errorf("counts = %+v, want five logins matched and the first four cut off", got)
	}
	for conn := range 4 {
		want := `msg="injected fault" conn=` + strconv.Itoa(conn+1) + ` operation=authenticate user=` + testUser + ` fault=close_connection mode=fin`
		if !strings.Contains(logs.text(), want) {
			t.Errorf("logs lack %s:\n%s", want, logs.text())
		}
	}
}
