package integration

import (
	"bytes"
	"os"
	"path/filepath"
	"slices"
	"strings"
	"testing"

	"github.com/nebarg/sftpit/internal/sftpproxy"
	"github.com/nebarg/sftpit/internal/sftpwire"
)

// uploadCutoff is where partial uploads are cut off. It falls inside a write
// for both clients, so the write that crosses it is trimmed.
const uploadCutoff = 1<<20 + 1000

// TestPartialUploadsKeepTheBytesBelowTheCutoff cuts off each client's
// pipelined upload, in both reply orders, and checks that exactly the bytes
// below the cutoff are stored, and what the client reports.
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
	clients := []struct {
		name string
		// upload uploads work/orders.csv to /orders.csv and returns what the
		// client reports about it, which must be a failure.
		upload func(t *testing.T, srv *server, work string) string
	}{
		{name: "OpenSSH", upload: failedOpenSSHUpload},
		{name: "phpseclib", upload: failedPhpseclibUpload},
	}

	data := randomBytes(4<<20 + 321)
	for _, c := range clients {
		for _, order := range []sftpproxy.ReplyOrder{sftpproxy.RequestOrder, sftpproxy.CompletionOrder} {
			for _, r := range results {
				t.Run(c.name+"/"+order.String()+"/"+r.name, func(t *testing.T) {
					cut := sftpproxy.PartialUpload{Cutoff: uploadCutoff, Result: r.result}
					srv := startServer(t, proxied, sftpproxy.Options{
						Faults: func(req sftpproxy.Request) sftpproxy.Action {
							if _, ok := req.Packet.(*sftpwire.Open); ok && req.Path == "/orders.csv" {
								return cut
							}
							return nil
						},
						ReplyOrder: order,
					})
					work := t.TempDir()
					writeFile(t, filepath.Join(work, "orders.csv"), data)

					report := c.upload(t, srv, work)
					want := r.reports[c.name]
					if !slices.ContainsFunc(want, func(w string) bool { return strings.Contains(report, w) }) {
						t.Errorf("%s reported %q, want one of %q", c.name, report, want)
					}
					got, err := os.ReadFile(filepath.Join(srv.files, "orders.csv"))
					if err != nil || !bytes.Equal(got, data[:uploadCutoff]) {
						t.Errorf("stored %d bytes (%v), want the first %d bytes of the upload", len(got), err, uploadCutoff)
					}
				})
			}
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
