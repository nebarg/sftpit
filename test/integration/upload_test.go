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
}{
	{name: "OpenSSH", failedUpload: failedOpenSSHUpload, transfer: transferWithOpenSSH},
	{name: "phpseclib", failedUpload: phpseclib3.failedUpload, transfer: phpseclib3.transfer},
	{name: "phpseclib2", failedUpload: phpseclib2.failedUpload, transfer: phpseclib2.transfer},
}

// TestPartialUploadsKeepTheBytesBelowTheCutoff cuts off each client's
// pipelined upload, in both reply orders, and checks that exactly the bytes
// below the cutoff are stored, and what the client reports.
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
		// phpseclib 2 returns false and raises notices instead, which say
		// the same as phpseclib's exceptions. A write that meets a reset
		// fails with no notice, so the report then gives no reason at all.
		phpseclib2ClosedByServer = "Connection closed (by server) prematurely"
		phpseclib2Closed         = "Connection closed prematurely"
		noReason                 = ""
	)
	results := []struct {
		name   string
		result sftpproxy.Action
		// logged is how the server's log names the result, which tells a
		// reset from a normal close when a client's report does not.
		logged string
		// reports holds what each client may report.
		reports map[string][]string
	}{
		{
			name:   "fail",
			result: sftpproxy.Fail{Status: sftpwire.StatusFailure},
			logged: "fault=fail",
			reports: map[string][]string{
				"OpenSSH":    {`write remote "/orders.csv": Failure`},
				"phpseclib":  {"NET_SFTP_STATUS_FAILURE: Failure"},
				"phpseclib2": {"NET_SFTP_STATUS_FAILURE: Failure"},
			},
		},
		{
			name:   "drop",
			result: sftpproxy.Drop{},
			logged: "mode=fin",
			reports: map[string][]string{
				"OpenSSH":    {normalClose},
				"phpseclib":  {phpseclibClosed},
				"phpseclib2": {phpseclib2ClosedByServer, phpseclib2Closed},
			},
		},
		{
			name:   "reset",
			result: sftpproxy.Drop{Reset: true},
			logged: "mode=rst",
			reports: map[string][]string{
				"OpenSSH":    {reset, brokenPipe},
				"phpseclib":  {phpseclibWrite, phpseclibClosed},
				"phpseclib2": {noReason, phpseclib2ClosedByServer, phpseclib2Closed},
			},
		},
	}

	data := randomBytes(4<<20 + 321)
	for _, c := range uploadClients {
		for _, order := range []sftpproxy.ReplyOrder{sftpproxy.RequestOrder, sftpproxy.CompletionOrder} {
			for _, r := range results {
				t.Run(c.name+"/"+order.String()+"/"+r.name, func(t *testing.T) {
					t.Parallel()
					var logs capturedLog
					srv := startServer(t, proxied, sftpproxy.Options{
						Faults:     onFirstUpload(sftpproxy.PartialUpload{Cutoff: uploadCutoff, Result: r.result}),
						ReplyOrder: order,
						Logger:     logs.logger(),
					})
					work := t.TempDir()
					writeFile(t, filepath.Join(work, "orders.csv"), data)

					report := c.failedUpload(t, srv, work)
					srv.waitForSessions()
					want := r.reports[c.name]
					if !slices.ContainsFunc(want, func(w string) bool { return reports(report, w) }) {
						t.Errorf("%s reported %q, want one of %q", c.name, report, want)
					}
					if !strings.Contains(logs.text(), r.logged) {
						t.Errorf("logs lack %q:\n%s", r.logged, logs.text())
					}
					assertHolds(t, srv, "/orders.csv", data[:uploadCutoff])
				})
			}
		}
	}
}

// reports reports whether a client's report says want, or says nothing if
// want is empty.
func reports(report, want string) bool {
	if want == "" {
		return report == ""
	}
	return strings.Contains(report, want)
}

// TestARetryStoresTheWholeFile cuts off each client's first upload and then
// uploads again, as an application recovering from the failure would, and
// checks that the retry stores the whole file.
func TestARetryStoresTheWholeFile(t *testing.T) {
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
				t.Parallel()
				var logs capturedLog
				srv := startServer(t, proxied, sftpproxy.Options{
					Faults: onFirstUpload(sftpproxy.PartialUpload{Cutoff: uploadCutoff, Result: r.result}),
					Logger: logs.logger(),
				})
				work := t.TempDir()
				writeFile(t, filepath.Join(work, "orders.csv"), data)

				c.failedUpload(t, srv, work)
				srv.waitForSessions()
				c.transfer(t, srv, work, true)

				assertHolds(t, srv, "/orders.csv", data)
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

// onFirstUpload returns faults that apply action to the first OPEN of
// /orders.csv, so that a retry succeeds.
func onFirstUpload(action sftpproxy.Action) func(sftpproxy.Request) sftpproxy.Fault {
	var applied atomic.Bool
	return faultsOf(func(r sftpproxy.Request) sftpproxy.Action {
		if _, ok := r.Packet.(*sftpwire.Open); ok && r.Path == "/orders.csv" && applied.CompareAndSwap(false, true) {
			return action
		}
		return nil
	})
}

// TestCorruptedUploadsAreTheSameForEveryClient uploads a file through each
// corruption with each client, in both reply orders, and checks that the
// client reports success while the server stores exactly the corrupted file.
func TestCorruptedUploadsAreTheSameForEveryClient(t *testing.T) {
	t.Parallel()
	data := randomBytes(4<<20 + 321)
	flipped := slices.Clone(data)
	for i := range 64 {
		flipped[corruptAt+i] ^= 1
	}
	corruptions := []struct {
		corruption sftpproxy.CorruptUpload
		want       []byte
	}{
		{
			corruption: sftpproxy.CorruptUpload{Corruption: sftpproxy.Truncate, Offset: corruptAt},
			want:       data[:corruptAt],
		},
		{
			corruption: sftpproxy.CorruptUpload{Corruption: sftpproxy.OmitRange, Offset: corruptAt, Length: 40_000},
			want:       slices.Concat(data[:corruptAt], data[corruptAt+40_000:]),
		},
		{
			corruption: sftpproxy.CorruptUpload{Corruption: sftpproxy.FlipBytes, Offset: corruptAt, Length: 64},
			want:       flipped,
		},
	}
	for _, c := range uploadClients {
		for _, order := range []sftpproxy.ReplyOrder{sftpproxy.RequestOrder, sftpproxy.CompletionOrder} {
			for _, tt := range corruptions {
				t.Run(c.name+"/"+order.String()+"/"+tt.corruption.Corruption.String(), func(t *testing.T) {
					t.Parallel()
					var logs capturedLog
					srv := startServer(t, proxied, sftpproxy.Options{
						Faults: faultsOf(func(r sftpproxy.Request) sftpproxy.Action {
							if open, ok := r.Packet.(*sftpwire.Open); ok && r.Path == "/orders.csv" && open.Flags&sftpwire.OpenWrite != 0 {
								return tt.corruption
							}
							return nil
						}),
						ReplyOrder: order,
						Logger:     logs.logger(),
					})
					work := t.TempDir()
					writeFile(t, filepath.Join(work, "orders.csv"), data)

					c.transfer(t, srv, work, true)
					srv.waitForSessions()

					assertHolds(t, srv, "/orders.csv", tt.want)
				})
			}
		}
	}
}
