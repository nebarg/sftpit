package integration

import (
	"bytes"
	"context"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"golang.org/x/crypto/ssh/knownhosts"
)

// openSSHBatch is run with sftp -b. A leading "-" lets the batch continue
// after a command that is expected to fail.
const openSSHBatch = `pwd
-mkdir in
-mkdir in
put upload.bin in/orders.part
ls -1 in
rename in/orders.part in/orders.csv
get in/orders.csv download.bin
put small.txt in/other.csv
-rename -l in/other.csv in/orders.csv
put small.txt in/replacement.csv
rename in/replacement.csv in/other.csv
put upload.bin in/orders.csv
reget in/orders.csv partial.bin
put small.txt in/resumed.bin
reput upload.bin in/resumed.bin
put -p stamped.txt in/stamped.txt
chmod 640 in/stamped.txt
-chown 0 in/stamped.txt
-ln -s in/stamped.txt in/link
-ln in/stamped.txt in/hard
-df
-get in/missing.csv missing.bin
-rm in/missing.csv
-rmdir in
mkdir in/nested
rmdir in/nested
cd in
put small.txt relative.txt
pwd
ls -1
cd ..
rm in/other.csv
ls -1 in
`

func TestOpenSSHTransparency(t *testing.T) {
	if testing.Short() {
		t.Skip("runs the OpenSSH sftp client")
	}
	sftpPath, err := exec.LookPath("sftp")
	if err != nil {
		t.Skip("OpenSSH sftp client not installed")
	}

	upload := randomBytes(4<<20 + 321)
	small := []byte("small file\n")
	stamped := []byte("preserved times\n")
	stamp := time.Date(2026, 3, 4, 5, 6, 7, 0, time.UTC)
	since := time.Now().Add(-time.Hour)

	transcripts := make(map[route][]line)
	trees := make(map[route][]treeEntry)
	for _, via := range routes {
		srv := startServer(t, via)
		work := t.TempDir()
		writeFile(t, filepath.Join(work, "upload.bin"), upload)
		writeFile(t, filepath.Join(work, "small.txt"), small)
		writeFile(t, filepath.Join(work, "stamped.txt"), stamped)
		writeFile(t, filepath.Join(work, "partial.bin"), upload[:1000])
		if err := os.Chtimes(filepath.Join(work, "stamped.txt"), stamp, stamp); err != nil {
			t.Fatal(err)
		}

		transcripts[via] = runOpenSSH(t, sftpPath, srv, work)
		trees[via] = readTree(t, srv.files, since)

		for _, name := range []string{"download.bin", "partial.bin"} {
			got, err := os.ReadFile(filepath.Join(work, name))
			if err != nil || !bytes.Equal(got, upload) {
				t.Errorf("%s: local %s does not match the upload (%v)", via, name, err)
			}
		}
	}

	assertSameLines(t, "sftp output", transcripts[direct], transcripts[proxied])
	assertSameLines(t, "stored files", trees[direct], trees[proxied])
	assertFiles(t, trees[proxied], map[string][]byte{
		"in/orders.csv":   upload,
		"in/resumed.bin":  append(append([]byte(nil), small...), upload[len(small):]...),
		"in/stamped.txt":  stamped,
		"in/relative.txt": small,
	})
	for _, e := range trees[proxied] {
		if e.path == "in/stamped.txt" && (e.mode != 0o640 || e.mtime != stamp.Format(time.RFC3339)) {
			t.Errorf("in/stamped.txt: mode %v mtime %s, want -rw-r----- and %s", e.mode, e.mtime, stamp.Format(time.RFC3339))
		}
	}
}

func runOpenSSH(t *testing.T, sftpPath string, srv *server, work string) []line {
	t.Helper()
	dir := t.TempDir()
	keyFile := writeClientKey(t, dir)
	var known []string
	for _, key := range hostKeys {
		known = append(known, knownhosts.Line([]string{srv.addr}, key.PublicKey()))
	}
	knownHosts := filepath.Join(dir, "known_hosts")
	writeFile(t, knownHosts, []byte(strings.Join(known, "\n")+"\n"))
	batch := filepath.Join(dir, "batch")
	writeFile(t, batch, []byte(openSSHBatch))

	ctx, cancel := context.WithTimeout(context.Background(), clientTimeout)
	defer cancel()
	cmd := exec.CommandContext(ctx, sftpPath,
		"-b", batch,
		"-P", srv.port,
		"-F", os.DevNull,
		"-i", keyFile,
		"-o", "IdentitiesOnly=yes",
		"-o", "IdentityAgent=none",
		"-o", "BatchMode=yes",
		"-o", "StrictHostKeyChecking=yes",
		"-o", "UserKnownHostsFile="+knownHosts,
		"-o", "GlobalKnownHostsFile="+os.DevNull,
		testUser+"@127.0.0.1",
	)
	cmd.Dir = work
	out, err := cmd.CombinedOutput()
	if err != nil {
		t.Fatalf("sftp failed: %v\n%s", err, out)
	}
	return splitLines(out)
}
