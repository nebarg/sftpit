package integration

import (
	"crypto/sha256"
	"encoding/hex"
	"path/filepath"
	"strconv"
	"strings"
	"testing"
	"time"
)

// TestOpenSSHPublishesThroughAPartFile has OpenSSH's sftp stand in for an
// application that uploads under a temporary name and then renames the file
// into place, with a scenario that cuts off its first upload, and checks the
// run's verdict. An uploader that tries again publishes the whole file and
// passes; one that ignores the failure publishes what was stored and fails,
// on the published file's hash.
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
			opts := scenarioOptions(t, `  publish:
    faults:
      - id: first-upload-cutoff
        fail_upload:
          path: `+temporaryPath+`
          attempts: [1]
          after_bytes: `+strconv.Itoa(uploadCutoff)+`
    assertions:
      - {type: rule_fired, rule_id: first-upload-cutoff, exactly: 1}
      - {type: file_hash, path: `+publishedPath+`, sha256: `+hex.EncodeToString(sum[:])+`}
      - {type: path_absent, path: `+temporaryPath+`}
`, "publish")
			m, srv := startRuns(t, opts)
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

			r, err := m.Assert(t.Context(), srv.run.ID, 5*time.Second)
			if err != nil {
				t.Fatalf("Assert: %v", err)
			}
			if r.Passed != tt.passed {
				t.Errorf("the run passed %v, want %v: %+v", r.Passed, tt.passed, r)
			}
			if got := r.Rules["first-upload-cutoff"].Fired; got != 1 {
				t.Errorf("the cutoff fired %d times, want once", got)
			}
			for _, a := range r.Assertions {
				if wantPass := tt.passed || !strings.HasPrefix(a.Description, "file_hash "); a.Passed != wantPass {
					t.Errorf("%s passed %v, want %v: %s", a.Description, a.Passed, wantPass, a.Detail)
				}
			}
		})
	}
}
