package integration

import (
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

// TestOpenSSHMissesHiddenFiles hides 250 files with the missing_file recipe
// and checks that OpenSSH's sftp lists only the file that is not hidden,
// and finds no hidden file to download or remove, while the files stay on
// the server. The hidden files come first in a listing, so the backend's
// second batch of 100 entries holds only hidden files, which the proxy must
// read past rather than end the listing.
func TestOpenSSHMissesHiddenFiles(t *testing.T) {
	t.Parallel()
	sftpPath := openSSHOrSkip(t)

	seed := t.TempDir()
	if err := os.Mkdir(filepath.Join(seed, "outgoing"), 0o700); err != nil {
		t.Fatal(err)
	}
	for i := range 250 {
		writeFile(t, filepath.Join(seed, "outgoing", fmt.Sprintf("hidden-%03d.csv", i)), []byte("id\n"))
	}
	data := randomBytes(64<<10 + 321)
	writeFile(t, filepath.Join(seed, "outgoing", "orders.csv"), data)
	opts := scenarioOptions(t, `  missing:
    faults:
      - id: missing
        missing_file: {path_glob: /outgoing/hidden-*.csv}
`, "missing")
	var logs capturedLog
	opts.Logger = logs.logger()
	opts.SeedDir = seed
	_, srv := startRuns(t, opts)
	work := t.TempDir()

	out, err := openSSH(t, sftpPath, srv, work, `ls -1a /outgoing
get /outgoing/orders.csv
-get /outgoing/hidden-007.csv
-rm /outgoing/hidden-007.csv
-rename /outgoing/hidden-007.csv /outgoing/renamed.csv
`)
	if err != nil {
		t.Fatalf("sftp failed: %v\n%s", err, out)
	}
	srv.waitForSessions()

	var listed []string
	for l := range strings.Lines(string(out)) {
		if l = strings.TrimSpace(l); strings.HasPrefix(l, "/outgoing/") {
			listed = append(listed, l)
		}
	}
	if want := "/outgoing/. /outgoing/.. /outgoing/orders.csv"; strings.Join(listed, " ") != want {
		t.Errorf("sftp listed %q, want %s:\n%s", listed, want, out)
	}
	assertDownloaded(t, filepath.Join(work, "orders.csv"), data)
	for _, want := range []string{
		`File "/outgoing/hidden-007.csv" not found.`,
		`remote delete /outgoing/hidden-007.csv: No such file or directory`,
		`remote rename "/outgoing/hidden-007.csv" to "/outgoing/renamed.csv": No such file or directory`,
	} {
		if !strings.Contains(string(out), want) {
			t.Errorf("sftp did not say %s:\n%s", want, out)
		}
	}
	if _, err := os.Stat(filepath.Join(work, "hidden-007.csv")); !os.IsNotExist(err) {
		t.Errorf("sftp downloaded a hidden file: %v", err)
	}
	for i := range 250 {
		assertHolds(t, srv, fmt.Sprintf("/outgoing/hidden-%03d.csv", i), []byte("id\n"))
	}
	text := connID.ReplaceAllString(logs.text(), "conn=N ")
	if entries := strings.Count(text, "request=SSH_FXP_READDIR path=/outgoing/hidden-"); entries != 250 {
		t.Errorf("logged %d hidden entries, want 250", entries)
	}
	// get and rm look the file up before they act.
	hidden := `msg="injected fault" conn=N user=` + testUser + ` request=`
	for _, want := range []string{
		hidden + `SSH_FXP_LSTAT path=/outgoing/hidden-007.csv fault=hide when=before`,
		hidden + `SSH_FXP_REMOVE path=/outgoing/hidden-007.csv fault=hide when=before`,
		hidden + `posix-rename@openssh.com path=/outgoing/hidden-007.csv target=/outgoing/renamed.csv fault=hide when=before`,
	} {
		if !strings.Contains(text, want) {
			t.Errorf("logs lack %s:\n%s", want, text)
		}
	}
}
