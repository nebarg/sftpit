package integration

import (
	"crypto/sha256"
	"errors"
	"io/fs"
	"os"
	"path/filepath"
	"testing"

	"github.com/nebarg/sftpit/internal/config"
	"github.com/nebarg/sftpit/internal/runs"
)

// TestOpenSSHPublishesThroughAPartFile has OpenSSH's sftp stand in for an
// application that uploads under a temporary name and then renames the file
// into place, with a fault that refuses its first upload's first write. An
// uploader that tries again publishes the whole file; one that ignores the
// failure publishes only part of it.
func TestOpenSSHPublishesThroughAPartFile(t *testing.T) {
	t.Parallel()
	sftpPath := openSSHOrSkip(t)
	data := randomBytes(4<<20 + 321)
	sum := sha256.Sum256(data)
	upload := "put orders.csv " + temporaryPath + "\n"
	publish := "rename " + temporaryPath + " " + publishedPath + "\n"

	tests := []struct {
		name string
		// batches are the sftp sessions the uploader runs, in turn.
		batches []string
		passed  bool
	}{
		{"tries again", []string{"mkdir /incoming\n" + upload, upload + publish}, true},
		{"ignores the failure", []string{"mkdir /incoming\n-" + upload + publish}, false},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()
			m, srv := startRuns(t, runs.Options{})
			// The first write to the temporary file is refused.
			cutoff := config.Fault{Name: "First upload cutoff", Steps: []string{"write"}, Do: "refuse", File: temporaryPath, Only: new(uint64(1))}
			if _, err := m.AddFault(cutoff); err != nil {
				t.Fatalf("AddFault: %v", err)
			}
			work := t.TempDir()
			writeFile(t, filepath.Join(work, "orders.csv"), data)

			for i, batch := range tt.batches {
				out, err := openSSH(t, sftpPath, srv, work, batch)
				// Only the first session's upload is cut off, and only an
				// uploader that minds the failure stops there.
				if wantErr := i == 0 && tt.passed; (err != nil) != wantErr {
					t.Errorf("sftp session %d = %v, want an error %v:\n%s", i+1, err, wantErr, out)
				}
			}

			srv.waitForSessions()
			if got := m.Rules().Counts["first-upload-cutoff-1"]; got.Fired != 1 {
				t.Errorf("the cutoff fired %+v, want once", got)
			}
			published, err := os.ReadFile(srv.path(publishedPath))
			if err != nil {
				t.Fatalf("the published file: %v", err)
			}
			if got := sha256.Sum256(published); (got == sum) != tt.passed {
				t.Errorf("the published file holds %d bytes with sha256 %x; want the whole upload: %v", len(published), got, tt.passed)
			}
			if _, err := os.Stat(srv.path(temporaryPath)); !errors.Is(err, fs.ErrNotExist) {
				t.Errorf("the temporary file is still there (%v)", err)
			}
		})
	}
}
