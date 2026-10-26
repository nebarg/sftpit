package integration

import (
	"path/filepath"
	"slices"
	"strings"
	"sync/atomic"
	"testing"

	"github.com/nebarg/sftpit/internal/sftpproxy"
	"github.com/nebarg/sftpit/internal/sftpwire"
)

// uploadClients upload work/orders.csv to /orders.csv.
var uploadClients = []struct {
	name string
	// failedUpload returns what the client reports about an upload, which
	// must fail.
	failedUpload func(t *testing.T, srv *server, work string) string
	// transfer is an upload, or a download, that must succeed.
	transfer func(t testing.TB, srv *server, work string, upload bool)
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

// TestPartialUploadsKeepTheBytesBelowTheCutoff cuts off each client's
// pipelined upload, in both reply orders, and checks that exactly the bytes
// below the cutoff are stored and snapshotted, and what the client reports.
func TestPartialUploadsKeepTheBytesBelowTheCutoff(t *testing.T) {
	t.Parallel()
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
					var logs capturedLog
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
					assertHolds(t, srv, "/orders.csv", data[:uploadCutoff])
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
	t.Parallel()
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
				var logs capturedLog
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

				assertHolds(t, srv, "/orders.csv", data)
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
	report, failed := phpseclibFailures(t, transcript)["put"]
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
