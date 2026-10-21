package integration

import (
	"path/filepath"
	"slices"
	"strings"
	"testing"
	"time"

	"github.com/nebarg/sftpit/internal/sftpproxy"
	"github.com/nebarg/sftpit/internal/sftpwire"
)

// renameBatch uploads a file under a temporary name and publishes it with a
// rename, which is where each test injects its fault. A leading "-" lets the
// batch list the directory even if the rename fails.
const renameBatch = `mkdir in
put orders.csv in/orders.part
-rename in/orders.part in/orders.csv
ls -1 in
`

// TestOpenSSHRenameFaults injects each response fault into OpenSSH's rename
// and checks what the client reports and which name the file ends up under.
func TestOpenSSHRenameFaults(t *testing.T) {
	sftpPath := openSSHOrSkip(t)

	const (
		closed  = "Connection to 127.0.0.1 closed by remote host."
		timeout = "Timeout, server 127.0.0.1 not responding."
		delay   = 200 * time.Millisecond
	)
	// OpenSSH 10 reports a reset as a read that failed. 9.6 reports only
	// that sending its disconnect message failed.
	reset := []string{"Read from remote host 127.0.0.1: Connection reset by peer", "client_loop: send disconnect: Broken pipe"}
	tests := []struct {
		name   string
		action sftpproxy.Action
		// output holds the forms in which the tested versions of sftp
		// report the rename, if they report it at all.
		output []string
		// lost reports that the connection ends at the rename.
		lost bool
		// renamed reports that the file ends up under its final name.
		renamed bool
	}{
		{name: "delay before", action: sftpproxy.Delay{When: sftpproxy.Before, Duration: delay}, renamed: true},
		{name: "delay after", action: sftpproxy.Delay{When: sftpproxy.After, Duration: delay}, renamed: true},
		{name: "fail before", action: sftpproxy.Fail{When: sftpproxy.Before, Status: sftpwire.StatusPermissionDenied}, output: []string{"Permission denied"}},
		{name: "fail after", action: sftpproxy.Fail{When: sftpproxy.After, Status: sftpwire.StatusFailure}, output: []string{"Failure"}, renamed: true},
		{name: "drop before", action: sftpproxy.Drop{When: sftpproxy.Before}, output: []string{closed}, lost: true},
		{name: "drop after", action: sftpproxy.Drop{When: sftpproxy.After}, output: []string{closed}, lost: true, renamed: true},
		{name: "reset before", action: sftpproxy.Drop{When: sftpproxy.Before, Reset: true}, output: reset, lost: true},
		{name: "reset after", action: sftpproxy.Drop{When: sftpproxy.After, Reset: true}, output: reset, lost: true, renamed: true},
		{name: "freeze after", action: sftpproxy.Freeze{When: sftpproxy.After, Limit: time.Minute}, output: []string{timeout}, lost: true, renamed: true},
	}

	data := []byte("id,total\n1,9.99\n")
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			srv := startServer(t, proxied, sftpproxy.Options{Faults: func(r sftpproxy.Request) sftpproxy.Action {
				if r.Target == "/in/orders.csv" {
					return tt.action
				}
				return nil
			}})
			work := t.TempDir()
			writeFile(t, filepath.Join(work, "orders.csv"), data)

			start := time.Now()
			// The keepalives let the client notice a frozen connection.
			out, err := openSSH(t, sftpPath, srv, work, renameBatch, "ServerAliveInterval=1", "ServerAliveCountMax=2")
			elapsed := time.Since(start)
			if lost := err != nil; lost != tt.lost {
				t.Errorf("sftp error = %v, want the connection lost: %v\n%s", err, tt.lost, out)
			}
			if tt.output != nil && !slices.ContainsFunc(tt.output, func(o string) bool { return strings.Contains(string(out), o) }) {
				t.Errorf("sftp output contains none of %q:\n%s", tt.output, out)
			}
			if _, ok := tt.action.(sftpproxy.Delay); ok && elapsed < delay {
				t.Errorf("sftp finished after %v, want at least %v", elapsed, delay)
			}

			name := "in/orders.part"
			if tt.renamed {
				name = "in/orders.csv"
			}
			assertFiles(t, readTree(t, srv.files, start), map[string][]byte{name: data})
		})
	}
}

// TestPhpseclibRenameFaults injects each response fault into phpseclib's
// rename, as Flysystem's move() makes it, and checks what phpseclib reports
// and which name the file ends up under.
func TestPhpseclibRenameFaults(t *testing.T) {
	php := phpseclibOrSkip(t)

	const (
		closed = `phpseclib3\Exception\ConnectionClosedException: Connection closed by server`
		delay  = 200 * time.Millisecond
		freeze = time.Second
	)
	tests := []struct {
		name   string
		action sftpproxy.Action
		// report is phpseclib's error for the rename, if it fails.
		report string
		// renamed reports that the file ends up under its final name.
		renamed bool
	}{
		{name: "delay before", action: sftpproxy.Delay{When: sftpproxy.Before, Duration: delay}, renamed: true},
		{name: "delay after", action: sftpproxy.Delay{When: sftpproxy.After, Duration: delay}, renamed: true},
		{name: "fail before", action: sftpproxy.Fail{When: sftpproxy.Before, Status: sftpwire.StatusPermissionDenied}, report: "NET_SFTP_STATUS_PERMISSION_DENIED: Permission denied"},
		{name: "fail after", action: sftpproxy.Fail{When: sftpproxy.After, Status: sftpwire.StatusFailure}, report: "NET_SFTP_STATUS_FAILURE: Failure", renamed: true},
		{name: "drop before", action: sftpproxy.Drop{When: sftpproxy.Before}, report: closed},
		{name: "drop after", action: sftpproxy.Drop{When: sftpproxy.After}, report: closed, renamed: true},
		{name: "reset before", action: sftpproxy.Drop{When: sftpproxy.Before, Reset: true}, report: closed},
		{name: "reset after", action: sftpproxy.Drop{When: sftpproxy.After, Reset: true}, report: closed, renamed: true},
		// phpseclib sends no keepalives, so it waits until the connection
		// closes.
		{name: "freeze after", action: sftpproxy.Freeze{When: sftpproxy.After, Limit: freeze}, report: closed, renamed: true},
	}

	data := []byte("id,total\n1,9.99\n")
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			srv := startServer(t, proxied, sftpproxy.Options{Faults: func(r sftpproxy.Request) sftpproxy.Action {
				if r.Target == "/in/orders.csv" {
					return tt.action
				}
				return nil
			}})
			work := t.TempDir()
			writeFile(t, filepath.Join(work, "orders.csv"), data)

			start := time.Now()
			transcript := runPhpseclib(t, php, srv, "rename.php", work)
			elapsed := time.Since(start)
			if results(t, transcript)["put"] != true {
				t.Fatalf("phpseclib put failed: %v", transcript)
			}
			if got := failures(t, transcript)["rename"]; got != tt.report {
				t.Errorf("rename error = %q, want %q", got, tt.report)
			}
			switch a := tt.action.(type) {
			case sftpproxy.Delay:
				if elapsed < a.Duration {
					t.Errorf("phpseclib finished after %v, want at least %v", elapsed, a.Duration)
				}
			case sftpproxy.Freeze:
				if elapsed < a.Limit {
					t.Errorf("phpseclib finished after %v, want at least %v", elapsed, a.Limit)
				}
			}

			name := "in/orders.part"
			if tt.renamed {
				name = "in/orders.csv"
			}
			assertFiles(t, readTree(t, srv.files, start), map[string][]byte{name: data})
		})
	}
}
