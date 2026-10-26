package integration

import (
	"bytes"
	"os"
	"path/filepath"
	"strconv"
	"strings"
	"testing"

	"github.com/nebarg/sftpit/internal/sftpproxy"
	"github.com/nebarg/sftpit/internal/sftpwire"
)

// sizeBatch shows the size of /orders.csv from a listing's longnames, from
// its attributes and from LSTAT, downloads the file and resumes a download.
// A leading "-" lets the batch continue if the resume is refused.
const sizeBatch = `ls -l /
ls -ln /
ls -l /orders.csv
get /orders.csv got.csv
-reget /orders.csv partial.csv
`

// partialSize is how much of the file the resumed download starts with.
const partialSize = 1000

// TestClientsReportTheWrongSize misreports the size of a file in every
// reply that gives it, and checks what each client reports and that each
// still downloads the whole file, which is unchanged on the server.
func TestClientsReportTheWrongSize(t *testing.T) {
	t.Parallel()
	data := randomBytes(4<<20 + 321)
	sizes := []struct {
		name      string
		wrongSize sftpproxy.WrongSize
		reported  int
	}{
		{name: "smaller", wrongSize: sftpproxy.WrongSize{Delta: -1024}, reported: len(data) - 1024},
		{name: "larger", wrongSize: sftpproxy.WrongSize{Delta: 1024}, reported: len(data) + 1024},
		{name: "zero", wrongSize: sftpproxy.WrongSize{}, reported: 0},
	}

	for _, tt := range sizes {
		t.Run("OpenSSH/"+tt.name, func(t *testing.T) {
			sftpPath := openSSHOrSkip(t)
			srv := startServer(t, proxied, sftpproxy.Options{Faults: misreportSizeOf("/orders.csv", tt.wrongSize)})
			writeFile(t, srv.path("/orders.csv"), data)
			work := t.TempDir()
			writeFile(t, filepath.Join(work, "partial.csv"), data[:partialSize])

			out, err := openSSH(t, sftpPath, srv, work, sizeBatch)
			if err != nil {
				t.Fatalf("sftp failed: %v\n%s", err, out)
			}
			var shown []string
			for l := range strings.Lines(string(out)) {
				if fields := strings.Fields(l); len(fields) > 4 && strings.HasSuffix(l, "orders.csv\n") {
					shown = append(shown, fields[4])
				}
			}
			want := strconv.Itoa(tt.reported)
			if len(shown) != 3 || shown[0] != want || shown[1] != want || shown[2] != want {
				t.Errorf("sftp listed sizes %v, want %s from each ls:\n%s", shown, want, out)
			}
			assertDownloaded(t, filepath.Join(work, "got.csv"), data)

			// A resume trusts the size: it refuses to resume from beyond it.
			refused := strings.Contains(string(out), `Unable to resume download of "partial.csv": local file is larger than remote`)
			if wantRefused := tt.reported < partialSize; refused != wantRefused {
				t.Errorf("sftp refused to resume: %v, want %v:\n%s", refused, wantRefused, out)
			}
			wantPartial := data
			if refused {
				wantPartial = data[:partialSize]
			}
			assertDownloaded(t, filepath.Join(work, "partial.csv"), wantPartial)
			assertHolds(t, srv, "/orders.csv", data)
		})

		t.Run("phpseclib/"+tt.name, func(t *testing.T) {
			php := phpseclibOrSkip(t)
			srv := startServer(t, proxied, sftpproxy.Options{Faults: misreportSizeOf("/orders.csv", tt.wrongSize)})
			writeFile(t, srv.path("/orders.csv"), data)
			work := t.TempDir()

			results := phpseclibResults(t, runPhpseclib(t, php, srv, "sizes.php", work))
			for _, op := range []string{"stat", "lstat", "rawlist"} {
				if got := results[op]; got != float64(tt.reported) {
					t.Errorf("phpseclib %s gave size %v, want %d", op, got, tt.reported)
				}
			}
			if results["get"] != true {
				t.Errorf("phpseclib get = %v, want true", results["get"])
			}
			assertDownloaded(t, filepath.Join(work, "orders.csv"), data)
			assertHolds(t, srv, "/orders.csv", data)
		})
	}
}

// misreportSizeOf returns faults that misreport the size of name as
// wrongSize in every reply that gives it.
func misreportSizeOf(name string, wrongSize sftpproxy.WrongSize) func(sftpproxy.Request) sftpproxy.Action {
	return func(r sftpproxy.Request) sftpproxy.Action {
		if r.Path != name {
			return nil
		}
		switch r.Packet.(type) {
		case *sftpwire.Stat, *sftpwire.LStat, *sftpwire.FStat:
			return wrongSize
		}
		if r.Entry {
			return wrongSize
		}
		return nil
	}
}

func assertDownloaded(t *testing.T, name string, want []byte) {
	t.Helper()
	got, err := os.ReadFile(name)
	if err != nil || !bytes.Equal(got, want) {
		t.Errorf("%s has %d bytes (%v), want %d", name, len(got), err, len(want))
	}
}
