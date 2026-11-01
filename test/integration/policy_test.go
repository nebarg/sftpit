package integration

import (
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/nebarg/sftpit/internal/config"
	"github.com/nebarg/sftpit/internal/runs"
)

// TestOpenSSHCannotChangeAReadOnlyPath makes /reference read-only and
// checks that OpenSSH's sftp can download from it but that every change to
// it is refused, while uploads elsewhere work.
func TestOpenSSHCannotChangeAReadOnlyPath(t *testing.T) {
	t.Parallel()
	sftpPath := openSSHOrSkip(t)

	seed := t.TempDir()
	rates := randomBytes(64<<10 + 321)
	for _, dir := range []string{"reference", "incoming"} {
		if err := os.Mkdir(filepath.Join(seed, dir), 0o700); err != nil {
			t.Fatal(err)
		}
	}
	writeFile(t, filepath.Join(seed, "reference", "rates.csv"), rates)
	var logs capturedLog
	_, srv := startRuns(t, runs.Options{
		SeedDir: seed,
		Policy:  config.Policy{ReadOnly: []config.ReadOnly{{PathPrefix: "/reference"}}},
		Logger:  logs.logger(),
	})
	work := t.TempDir()
	upload := randomBytes(1000)
	writeFile(t, filepath.Join(work, "upload.csv"), upload)

	out, err := openSSH(t, sftpPath, srv, work, `get /reference/rates.csv
put upload.csv /incoming/upload.csv
-put upload.csv /reference/upload.csv
-rm /reference/rates.csv
-chmod 600 /reference/rates.csv
-mkdir /reference/archive
-rmdir /reference
-rename /reference/rates.csv /incoming/rates.csv
-rename /incoming/upload.csv /reference/upload.csv
-rename / /moved
`)
	if err != nil {
		t.Fatalf("sftp failed: %v\n%s", err, out)
	}
	srv.waitForSessions()

	assertDownloaded(t, filepath.Join(work, "rates.csv"), rates)
	assertHolds(t, srv, "/reference/rates.csv", rates)
	assertHolds(t, srv, "/reference/upload.csv", nil)
	assertHolds(t, srv, "/incoming/upload.csv", upload)
	assertHolds(t, srv, "/incoming/rates.csv", nil)
	for _, want := range []string{
		`dest open "/reference/upload.csv": Permission denied`,
		`remote delete /reference/rates.csv: Permission denied`,
		`remote setstat "/reference/rates.csv": Permission denied`,
		`remote mkdir "/reference/archive": Permission denied`,
		`remote rmdir "/reference": Permission denied`,
		`remote rename "/reference/rates.csv" to "/incoming/rates.csv": Permission denied`,
		`remote rename "/incoming/upload.csv" to "/reference/upload.csv": Permission denied`,
		// Moving the root would move /reference with it.
		`remote rename "/" to "/moved": Permission denied`,
	} {
		if !strings.Contains(string(out), want) {
			t.Errorf("sftp did not say %s:\n%s", want, out)
		}
	}
	text := connID.ReplaceAllString(logs.text(), "conn=N ")
	denied := `msg="policy denied" conn=N user=` + testUser + ` request=`
	for _, want := range []string{
		denied + `SSH_FXP_OPEN path=/reference/upload.csv read_only=/reference`,
		denied + `SSH_FXP_SETSTAT path=/reference/rates.csv read_only=/reference`,
		denied + `posix-rename@openssh.com path=/ target=/moved read_only=/reference`,
	} {
		if !strings.Contains(text, want) {
			t.Errorf("logs lack %s:\n%s", want, text)
		}
	}
	if n := strings.Count(text, `msg="policy denied"`); n != 8 {
		t.Errorf("logged %d denials, want 8:\n%s", n, text)
	}
}
