package integration

import (
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/nebarg/sftpit/internal/config"
)

// TestOpenSSHOutages takes the server down, closing OpenSSH's connection,
// at a login and after a request. A reconnect during the outage is refused,
// and one after it succeeds.
func TestOpenSSHOutages(t *testing.T) {
	t.Parallel()
	sftpPath := openSSHOrSkip(t)

	const outage = 1500 * time.Millisecond
	tests := []struct {
		name   string
		fault  config.Fault
		batch  string
		output string
		// stored is the file the first connection leaves, if any.
		stored string
	}{
		{
			name:   "at the first login",
			fault:  config.Fault{Name: "Outage", Steps: []string{"authenticate"}, Do: "down", Seconds: new(outage.Seconds()), First: new(uint64(1))},
			batch:  "ls\n",
			output: "Connection closed by 127.0.0.1 port",
		},
		{
			name:   "after a rename",
			fault:  config.Fault{Name: "Outage", Steps: []string{"rename"}, Do: "down", Seconds: new(outage.Seconds()), After: true},
			batch:  "put orders.csv orders.csv.part\nrename orders.csv.part orders.csv\n",
			output: "Connection to 127.0.0.1 closed by remote host.",
			stored: "/orders.csv",
		},
	}
	data := randomBytes(2 << 20)
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()
			var logs capturedLog
			srv := startFaults(t, logs.logger(), tt.fault)
			work := t.TempDir()
			writeFile(t, filepath.Join(work, "orders.csv"), data)

			out, err := openSSH(t, sftpPath, srv, work, tt.batch)
			downAt := time.Now()
			if err == nil || !strings.Contains(string(out), tt.output) {
				t.Errorf("the first sftp = %v, want %q:\n%s", err, tt.output, out)
			}
			if out, err := openSSH(t, sftpPath, srv, work, "ls\n"); err == nil || !strings.Contains(string(out), "Connection refused") {
				t.Errorf("sftp during the outage = %v, want the connection refused:\n%s", err, out)
			}
			time.Sleep(time.Until(downAt.Add(outage + 500*time.Millisecond)))
			if out, err := openSSH(t, sftpPath, srv, work, "ls\n"); err != nil {
				t.Errorf("sftp after the outage failed: %v\n%s", err, out)
			}
			srv.waitForSessions()

			if tt.stored != "" {
				assertHolds(t, srv, tt.stored, data)
			}
			if got := srv.counts("outage-1").Fired; got != 1 {
				t.Errorf("the outage fired %d times, want once", got)
			}
			if !strings.Contains(logs.text(), "fault=listener_down") || !strings.Contains(logs.text(), "duration=1.5s close_existing=true") {
				t.Errorf("logs lack the outage:\n%s", logs.text())
			}
		})
	}
}
