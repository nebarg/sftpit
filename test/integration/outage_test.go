package integration

import (
	"maps"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/nebarg/sftpit/internal/faults"
	"github.com/nebarg/sftpit/internal/sftpproxy"
)

// TestOpenSSHOutages takes the server down, closing OpenSSH's connection,
// at a login, after a request and at a moment of the run. A reconnect during
// the outage is refused, and one after it succeeds.
func TestOpenSSHOutages(t *testing.T) {
	t.Parallel()
	sftpPath := openSSHOrSkip(t)

	const outage = 1500 * time.Millisecond
	down := sftpproxy.ListenerDown{Duration: outage, CloseExisting: true}
	slow := faults.Rule{ID: "slow", Priority: 1, Match: faults.Match{Operations: []faults.Operation{faults.Write}}, Action: sftpproxy.Delay{When: sftpproxy.Before, Duration: 20 * time.Millisecond}}
	afterRename := down
	afterRename.When = sftpproxy.After
	tests := []struct {
		name   string
		rule   faults.Rule
		batch  string
		output string
		// stored is the file the first connection leaves, if any.
		stored string
		// slow slows each write, so that the upload outlasts the moment.
		slow bool
	}{
		{
			name:   "at the first login",
			rule:   faults.Rule{ID: "outage", MaxTriggers: 1, Match: faults.Match{Operations: []faults.Operation{faults.Authenticate}}, Action: down},
			batch:  "ls\n",
			output: "Connection closed by 127.0.0.1 port",
		},
		{
			name:   "after a rename",
			rule:   faults.Rule{ID: "outage", Match: faults.Match{Operations: []faults.Operation{faults.Rename}}, Action: afterRename},
			batch:  "put orders.csv orders.csv.part\nrename orders.csv.part orders.csv\n",
			output: "Connection to 127.0.0.1 closed by remote host.",
			stored: "/orders.csv",
		},
		{
			name:   "at a moment of the run",
			rule:   faults.Rule{ID: "outage", Trigger: &faults.Trigger{Anchor: faults.Run, At: &faults.Range[time.Duration]{Min: 500 * time.Millisecond, Max: 500 * time.Millisecond}}, Action: down},
			batch:  "put orders.csv\n",
			output: "Connection to 127.0.0.1 closed by remote host.",
			slow:   true,
		},
	}
	data := randomBytes(2 << 20)
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			var logs capturedLog
			rules := []faults.Rule{tt.rule}
			if tt.slow {
				rules = append(rules, slow)
			}
			srv := startScenario(t, rules, 0, logs.logger())
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
			if got := srv.counts(t, "outage").Fired; got != 1 {
				t.Errorf("the outage fired %d times, want once", got)
			}
			if !strings.Contains(logs.text(), "fault=listener_down") || !strings.Contains(logs.text(), "duration=1.5s close_existing=true") {
				t.Errorf("logs lack the outage:\n%s", logs.text())
			}
		})
	}
}

// TestLaravelGivesUpDuringAnOutage takes the server down for two seconds at
// the first login. Flysystem retries the connection at once, and the
// recovering uploader after 100 ms each time, so every attempt falls in the
// outage and nothing is published: an uploader needs to back off for longer
// than the outages it should ride out.
func TestLaravelGivesUpDuringAnOutage(t *testing.T) {
	t.Parallel()
	php := phpseclibOrSkip(t)

	var logs capturedLog
	srv := startScenario(t, []faults.Rule{{
		ID:          "outage",
		MaxTriggers: 1,
		Match:       faults.Match{Operations: []faults.Operation{faults.Authenticate}},
		Action:      sftpproxy.ListenerDown{Duration: 2 * time.Second, CloseExisting: true},
	}}, 0, logs.logger())
	work := t.TempDir()
	writeFile(t, filepath.Join(work, "orders.csv"), randomBytes(1<<20))

	outcomes := phpseclibResults(t, runPhpseclib(t, php, srv, "publish.php", work, "recover"))
	srv.waitForSessions()

	if want := map[string]any{"upload 1": false, "upload 2": false, "upload 3": false}; !maps.Equal(outcomes, want) {
		t.Errorf("publish.php gave %v, want every upload to fail during the outage", outcomes)
	}
	assertHolds(t, srv, publishedPath, nil)
	if got, want := srv.counts(t, "outage"), (faults.Counts{Matched: 1, Selected: 1, Fired: 1}); got != want {
		t.Errorf("counts = %+v, want only the first login to reach the server", got)
	}
}
