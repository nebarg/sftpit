package integration

import (
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/nebarg/sftpit/internal/config"
	"github.com/nebarg/sftpit/internal/faults"
	"github.com/nebarg/sftpit/internal/runs"
	"github.com/nebarg/sftpit/internal/sftpproxy"
)

// TestOpenSSHAcrossAReset resets the run while OpenSSH uploads through slow
// writes. The reset closes OpenSSH's connection, nothing changes the
// upload's file once the reset has returned, and the next connection finds
// only the seed's files.
func TestOpenSSHAcrossAReset(t *testing.T) {
	t.Parallel()
	sftpPath := openSSHOrSkip(t)

	seed := t.TempDir()
	writeFile(t, filepath.Join(seed, "orders.csv"), []byte("id,total\n"))
	slow := faults.Rule{ID: "slow", Match: faults.Match{Operations: []faults.Operation{faults.Write}}, Action: sftpproxy.Delay{Duration: 10 * time.Millisecond}}
	m, srv := startRuns(t, runs.Options{
		SeedDir:   seed,
		Scenarios: map[string]config.Scenario{"slow": {Rules: []faults.Rule{slow}}},
		Scenario:  "slow",
	})
	work := t.TempDir()
	writeFile(t, filepath.Join(work, "big.bin"), randomBytes(8<<20))

	type result struct {
		out []byte
		err error
	}
	uploaded := make(chan result, 1)
	cmd := openSSHCommand(t, sftpPath, srv, work, "put big.bin\n")
	go func() {
		out, err := cmd.CombinedOutput()
		uploaded <- result{out, err}
	}()
	upload := srv.path("/big.bin")
	deadline := time.Now().Add(clientTimeout)
	for info, err := os.Stat(upload); err != nil || info.Size() == 0; info, err = os.Stat(upload) {
		if time.Now().After(deadline) {
			t.Fatalf("the upload did not begin: %v", err)
		}
		time.Sleep(10 * time.Millisecond)
	}

	if _, err := m.Reset(t.Context(), runs.ResetRequest{}); err != nil {
		t.Fatalf("Reset: %v", err)
	}
	before, err := os.Stat(upload)
	if err != nil {
		t.Fatal(err)
	}
	r := <-uploaded
	if r.err == nil || !strings.Contains(string(r.out), "Connection to 127.0.0.1 closed by remote host.") {
		t.Errorf("sftp across the reset = %v, want the connection closed:\n%s", r.err, r.out)
	}
	time.Sleep(200 * time.Millisecond)
	switch after, err := os.Stat(upload); {
	case err != nil:
		t.Errorf("the upload's file after the reset: %v", err)
	case after.Size() != before.Size() || before.Size() >= 8<<20:
		t.Errorf("the upload's file had %d bytes at the reset and %d later, want it cut short and unchanged", before.Size(), after.Size())
	}

	out, err := openSSH(t, sftpPath, srv, work, "ls -1\n")
	if err != nil || !strings.Contains(string(out), "orders.csv") || strings.Contains(string(out), "big.bin") {
		t.Errorf("sftp in the next run = %v, want only the seed's file:\n%s", err, out)
	}
}
