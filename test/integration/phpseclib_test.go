package integration

import (
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
	"testing"
	"time"

	"golang.org/x/crypto/ssh"
)

const phpseclibDir = "phpseclib"

func TestPhpseclibTransparency(t *testing.T) {
	if testing.Short() {
		t.Skip("runs phpseclib")
	}
	php, err := exec.LookPath("php")
	if err != nil {
		t.Skip("php not installed")
	}
	if _, err := os.Stat(filepath.Join(phpseclibDir, "vendor", "autoload.php")); err != nil {
		t.Skipf("phpseclib not installed; run composer install in test/integration/%s", phpseclibDir)
	}

	upload := randomBytes(4<<20 + 321)
	since := time.Now().Add(-time.Hour)
	transcripts := make(map[route][]line)
	trees := make(map[route][]treeEntry)
	for _, via := range routes {
		srv := startServer(t, via)
		work := t.TempDir()
		writeFile(t, filepath.Join(work, "orders.csv"), upload)
		transcripts[via] = runPhpseclib(t, php, srv, work)
		trees[via] = readTree(t, srv.files, since)
	}

	assertSameLines(t, "phpseclib transcript", transcripts[direct], transcripts[proxied])
	assertSameLines(t, "stored files", trees[direct], trees[proxied])
	assertFiles(t, trees[proxied], map[string][]byte{
		"incoming/orders.csv":   []byte("replXY"),
		"incoming/relative.txt": []byte("relative"),
	})
	results := results(t, transcripts[proxied])
	wantResults := map[string]any{
		"download orders.csv":        result(len(upload), upload),
		"download a range":           result(70000, upload[1000:71000]),
		"rename onto existing":       false,
		"rename after delete":        true,
		"posix_rename onto existing": true,
		"get after offset put":       "replXYZment",
		"chown":                      false,
		"symlink":                    false,
	}
	for op, want := range wantResults {
		if got := results[op]; got != want {
			t.Errorf("%s = %v, want %v", op, got, want)
		}
	}
}

func runPhpseclib(t *testing.T, php string, srv *server, work string) []line {
	t.Helper()
	var keys bytes.Buffer
	for _, key := range hostKeys {
		keys.Write(ssh.MarshalAuthorizedKey(key.PublicKey()))
	}
	hostKeysFile := filepath.Join(t.TempDir(), "host_keys")
	writeFile(t, hostKeysFile, keys.Bytes())

	ctx, cancel := context.WithTimeout(context.Background(), clientTimeout)
	defer cancel()
	cmd := exec.CommandContext(ctx, php, filepath.Join(phpseclibDir, "workload.php"),
		"127.0.0.1", srv.port, testUser, testPassword, hostKeysFile, work)
	var stderr bytes.Buffer
	cmd.Stderr = &stderr
	out, err := cmd.Output()
	if err != nil || stderr.Len() > 0 {
		t.Fatalf("phpseclib workload: %v\nstdout:\n%s\nstderr:\n%s", err, out, stderr.Bytes())
	}
	return splitLines(out)
}

// results maps each operation in a transcript to its JSON result.
func results(t *testing.T, transcript []line) map[string]any {
	t.Helper()
	byOp := make(map[string]any)
	for _, l := range transcript {
		var entry struct {
			Op     string `json:"op"`
			Result any    `json:"result"`
		}
		if err := json.Unmarshal([]byte(l), &entry); err != nil {
			t.Fatalf("transcript line %q: %v", l, err)
		}
		byOp[entry.Op] = entry.Result
	}
	return byOp
}

// result is how the workload reports a download: its length and SHA-256.
func result(n int, data []byte) string {
	return fmt.Sprintf("%d %s", n, digest(data))
}
