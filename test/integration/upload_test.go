package integration

import (
	"bytes"
	"fmt"
	"log/slog"
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

// uploadCutoff is where partial uploads are cut off. It falls inside a write
// for both clients, so the write that crosses it is trimmed.
const uploadCutoff = 1<<20 + 1000

// uploadClients upload work/orders.csv to /orders.csv.
var uploadClients = []struct {
	name string
	// failedUpload returns what the client reports about an upload, which
	// must fail.
	failedUpload func(t *testing.T, srv *server, work string) string
	// transfer is an upload, or a download, that must succeed.
	transfer func(t *testing.T, srv *server, work string, upload bool)
	// closedBy holds how a snapshot may say a handle was closed when the
	// client sees its upload fail and closes it.
	closedBy []string
}{
	{name: "OpenSSH", failedUpload: failedOpenSSHUpload, transfer: transferWithOpenSSH, closedBy: []string{"client"}},
	{
		name:         "phpseclib",
		failedUpload: failedPhpseclibUpload,
		transfer:     transferWithPhpseclib,
		closedBy:     phpseclibClosedBy,
	},
}

// phpseclibClosedBy holds how a snapshot may say phpseclib closed a handle
// whose upload failed. phpseclib takes the reply to its first WRITE for its
// CLOSE's, so it disconnects without waiting for its CLOSE to be answered.
// The session can end before then, and the end closes the handle.
var phpseclibClosedBy = []string{"client", `"session end"`}

// TestPartialUploadsKeepTheBytesBelowTheCutoff cuts off each client's
// pipelined upload, in both reply orders, and checks that exactly the bytes
// below the cutoff are stored and snapshotted, and what the client reports.
func TestPartialUploadsKeepTheBytesBelowTheCutoff(t *testing.T) {
	// A client that is reset mid-upload reports whichever of its reads and
	// writes fails first, which varies from run to run.
	const (
		reset       = "Connection reset by"
		brokenPipe  = "Broken pipe"
		normalClose = "Connection to 127.0.0.1 closed by remote host."

		phpseclibWrite = "RuntimeException: Unable to write"
		// phpseclib says the connection closed "by server" or
		// "prematurely", depending on where it was reading.
		phpseclibClosed = `phpseclib3\Exception\ConnectionClosedException: Connection closed`
	)
	results := []struct {
		name   string
		result sftpproxy.Action
		// reports holds what each client may report.
		reports map[string][]string
	}{
		{
			name:   "fail",
			result: sftpproxy.Fail{Status: sftpwire.StatusFailure},
			reports: map[string][]string{
				"OpenSSH":   {`write remote "/orders.csv": Failure`},
				"phpseclib": {"NET_SFTP_STATUS_FAILURE: Failure"},
			},
		},
		{
			name:   "drop",
			result: sftpproxy.Drop{},
			reports: map[string][]string{
				"OpenSSH":   {normalClose},
				"phpseclib": {phpseclibClosed},
			},
		},
		{
			name:   "reset",
			result: sftpproxy.Drop{Reset: true},
			reports: map[string][]string{
				"OpenSSH":   {reset, brokenPipe},
				"phpseclib": {phpseclibWrite, phpseclibClosed},
			},
		},
	}

	data := randomBytes(4<<20 + 321)
	for _, c := range uploadClients {
		for _, order := range []sftpproxy.ReplyOrder{sftpproxy.RequestOrder, sftpproxy.CompletionOrder} {
			for _, r := range results {
				t.Run(c.name+"/"+order.String()+"/"+r.name, func(t *testing.T) {
					var logs snapshotLog
					srv := startServer(t, proxied, sftpproxy.Options{
						Faults:     onFirstUpload(sftpproxy.PartialUpload{Cutoff: uploadCutoff, Result: r.result}),
						ReplyOrder: order,
						Logger:     logs.logger(),
					})
					work := t.TempDir()
					writeFile(t, filepath.Join(work, "orders.csv"), data)

					report := c.failedUpload(t, srv, work)
					// A handle that the session's end closes is snapshotted
					// once the client has gone.
					srv.waitForSessions()
					want := r.reports[c.name]
					if !slices.ContainsFunc(want, func(w string) bool { return strings.Contains(report, w) }) {
						t.Errorf("%s reported %q, want one of %q", c.name, report, want)
					}
					got, err := os.ReadFile(filepath.Join(srv.files, "orders.csv"))
					if err != nil || !bytes.Equal(got, data[:uploadCutoff]) {
						t.Errorf("stored %d bytes (%v), want the first %d bytes of the upload", len(got), err, uploadCutoff)
					}
					logs.assertSnapshot(t, srv, "/orders.csv", data[:uploadCutoff], snapshotClosedBy(c.closedBy, r.result)...)
				})
			}
		}
	}
}

// TestRetryLeavesThePartialUploadsSnapshot cuts off each client's first
// upload and then uploads again, as an application recovering from the
// failure would. The retry truncates the partial file, but the snapshot
// still records exactly the bytes below the cutoff.
func TestRetryLeavesThePartialUploadsSnapshot(t *testing.T) {
	results := []struct {
		name   string
		result sftpproxy.Action
	}{
		{name: "fail", result: sftpproxy.Fail{Status: sftpwire.StatusFailure}},
		{name: "drop", result: sftpproxy.Drop{}},
	}

	data := randomBytes(4<<20 + 321)
	for _, c := range uploadClients {
		for _, r := range results {
			t.Run(c.name+"/"+r.name, func(t *testing.T) {
				var logs snapshotLog
				srv := startServer(t, proxied, sftpproxy.Options{
					Faults: onFirstUpload(sftpproxy.PartialUpload{Cutoff: uploadCutoff, Result: r.result}),
					Logger: logs.logger(),
				})
				work := t.TempDir()
				writeFile(t, filepath.Join(work, "orders.csv"), data)

				c.failedUpload(t, srv, work)
				// phpseclib does not wait for its CLOSE to be answered, so its
				// handle can be snapshotted only as its session ends. A retry
				// on a new connection must not reach the file before then.
				srv.waitForSessions()
				c.transfer(t, srv, work, true)

				got, err := os.ReadFile(filepath.Join(srv.files, "orders.csv"))
				if err != nil || !bytes.Equal(got, data) {
					t.Errorf("stored %d bytes (%v) after the retry, want the whole upload", len(got), err)
				}
				logs.assertSnapshot(t, srv, "/orders.csv", data[:uploadCutoff], snapshotClosedBy(c.closedBy, r.result)...)
			})
		}
	}
}

func failedOpenSSHUpload(t *testing.T, srv *server, work string) string {
	t.Helper()
	out, err := openSSH(t, openSSHOrSkip(t), srv, work, "put orders.csv /orders.csv\n")
	if err == nil {
		t.Errorf("sftp succeeded, want the upload to fail:\n%s", out)
	}
	return string(out)
}

func failedPhpseclibUpload(t *testing.T, srv *server, work string) string {
	t.Helper()
	transcript := runPhpseclib(t, phpseclibOrSkip(t), srv, "transfer.php", work, "put")
	report, failed := failures(t, transcript)["put"]
	if !failed {
		t.Errorf("phpseclib put succeeded, want it to fail: %v", transcript)
	}
	return report
}

// onFirstUpload returns faults that apply action to the first OPEN of
// /orders.csv, so that a retry succeeds.
func onFirstUpload(action sftpproxy.Action) func(sftpproxy.Request) sftpproxy.Action {
	var applied atomic.Bool
	return func(r sftpproxy.Request) sftpproxy.Action {
		if _, ok := r.Packet.(*sftpwire.Open); ok && r.Path == "/orders.csv" && applied.CompareAndSwap(false, true) {
			return action
		}
		return nil
	}
}

// snapshotClosedBy returns how a snapshot may say a handle was closed when
// its upload gets result: by the fault, if result drops the connection, or
// else as the client closes it, which byClient holds.
func snapshotClosedBy(byClient []string, result sftpproxy.Action) []string {
	if _, ok := result.(sftpproxy.Drop); ok {
		return []string{"fault"}
	}
	return byClient
}

// snapshotLog collects what a proxied server logs, to check its snapshots.
type snapshotLog struct {
	mu  sync.Mutex
	buf bytes.Buffer
}

func (l *snapshotLog) Write(p []byte) (int, error) {
	l.mu.Lock()
	defer l.mu.Unlock()
	return l.buf.Write(p)
}

func (l *snapshotLog) logger() *slog.Logger {
	return slog.New(slog.NewTextHandler(l, nil))
}

func (l *snapshotLog) text() string {
	l.mu.Lock()
	defer l.mu.Unlock()
	return l.buf.String()
}

// assertSnapshot checks that srv has logged one snapshot: of the file at the
// virtual path name holding data, closed as one of closedBy says, with a copy
// of data in the run's snapshots directory.
func (l *snapshotLog) assertSnapshot(t *testing.T, srv *server, name string, data []byte, closedBy ...string) {
	t.Helper()
	var got []string
	for line := range strings.Lines(l.text()) {
		if strings.Contains(line, "msg=snapshot") {
			// Leave out the time.
			_, rest, _ := strings.Cut(strings.TrimSpace(line), " ")
			got = append(got, rest)
		}
	}
	stored := backend.StoredName(name)
	var want []string
	for _, by := range closedBy {
		want = append(want, fmt.Sprintf("level=INFO msg=snapshot path=%s closed_by=%s size=%d sha256=%s copy=snapshots/1/%s", name, by, len(data), digest(data), stored))
	}
	if len(got) != 1 || !slices.Contains(want, got[0]) {
		t.Errorf("snapshots logged:\n%s\nwant one of:\n%s", strings.Join(got, "\n"), strings.Join(want, "\n"))
	}
	copied, err := os.ReadFile(filepath.Join(srv.run.Dir, "snapshots", "1", filepath.FromSlash(stored)))
	if err != nil || !bytes.Equal(copied, data) {
		t.Errorf("the snapshot's copy has %d bytes (%v), want the %d snapshotted", len(copied), err, len(data))
	}
}
