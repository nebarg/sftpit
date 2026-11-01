package integration

import (
	"bytes"
	"errors"
	"io"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"golang.org/x/crypto/ssh"

	"github.com/nebarg/sftpit/internal/sftpproxy"
	"github.com/nebarg/sftpit/internal/sftpwire"
)

// TestClientsOnACutOffDownload cuts off a 4 MiB download at uploadCutoff
// with each result, in both reply orders, and checks what the server
// delivers and what each client reports and leaves behind. Every client
// keeps what it saved, and phpseclib reports a status failure as success.
func TestClientsOnACutOffDownload(t *testing.T) {
	t.Parallel()
	data := randomBytes(4<<20 + 321)
	partial := data[:uploadCutoff]
	results := []struct {
		name   string
		result sftpproxy.Action
		// exact is set where a client stores every byte below the cutoff,
		// and unset where it may store fewer, which are still a prefix.
		exact map[string]bool
		// openSSH is what OpenSSH's sftp prints, and phpseclib what its
		// get() returns, or the exception it throws.
		openSSH   string
		phpseclib string
	}{
		{
			name:      "fail",
			result:    sftpproxy.Fail{Status: sftpwire.StatusFailure},
			exact:     map[string]bool{"OpenSSH": true, "phpseclib": true},
			openSSH:   `read remote "/orders.csv" : Failure`,
			phpseclib: "true",
		},
		// OpenSSH's ssh exits when the server closes the connection, losing
		// data it had received but not yet passed to sftp.
		{
			name:      "drop",
			result:    sftpproxy.Drop{},
			exact:     map[string]bool{"phpseclib": true},
			openSSH:   "closed by remote host",
			phpseclib: "phpseclib3\\Exception\\ConnectionClosedException",
		},
		// A reset can discard data the client's host had received, so
		// neither client reliably stores it all, and what each reports
		// varies.
		{
			name:   "reset",
			result: sftpproxy.Drop{Reset: true},
		},
	}

	for _, order := range []sftpproxy.ReplyOrder{sftpproxy.RequestOrder, sftpproxy.CompletionOrder} {
		for _, tt := range results {
			start := func(t *testing.T) *server {
				srv := startServer(t, proxied, sftpproxy.Options{
					Faults: func(r sftpproxy.Request) sftpproxy.Action {
						if open, ok := r.Packet.(*sftpwire.Open); ok && open.Flags&sftpwire.OpenWrite == 0 {
							return sftpproxy.PartialDownload{Cutoff: uploadCutoff, Result: tt.result}
						}
						return nil
					},
					ReplyOrder: order,
				})
				writeFile(t, srv.path("/orders.csv"), data)
				return srv
			}
			name := order.String() + "/" + tt.name

			// What the server delivers, read in order one read at a time.
			if tt.name != "reset" {
				t.Run("delivered/"+name, func(t *testing.T) {
					srv := start(t)
					c := pkgSFTPClient(t, srv, ssh.Password(testPassword))
					defer c.Close()
					f, err := c.Open("/orders.csv")
					if err != nil {
						t.Fatalf("Open: %v", err)
					}
					var got []byte
					buf := make([]byte, 32<<10)
					for {
						n, err := f.Read(buf)
						got = append(got, buf[:n]...)
						if err != nil {
							if errors.Is(err, io.EOF) {
								t.Errorf("the download ended with EOF, want %v", tt.result)
							}
							break
						}
					}
					if !bytes.Equal(got, partial) {
						t.Errorf("the server delivered %d bytes, want the %d below the cutoff", len(got), len(partial))
					}
				})
			}

			t.Run("OpenSSH/"+name, func(t *testing.T) {
				sftpPath := openSSHOrSkip(t)
				srv := start(t)
				work := t.TempDir()
				out, err := openSSH(t, sftpPath, srv, work, "get /orders.csv orders.csv\n")
				if err == nil {
					t.Errorf("sftp succeeded:\n%s", out)
				}
				if !strings.Contains(string(out), tt.openSSH) {
					t.Errorf("sftp did not say %s:\n%s", tt.openSSH, out)
				}
				assertSavedPrefix(t, filepath.Join(work, "orders.csv"), partial, tt.exact["OpenSSH"])
				assertHolds(t, srv, "/orders.csv", data)
			})

			t.Run("phpseclib/"+name, func(t *testing.T) {
				php := phpseclibOrSkip(t)
				srv := start(t)
				work := t.TempDir()
				entries := decodeTranscript(t, runPhpseclib(t, php, srv, "transfer.php", work, "get"))
				got := "true"
				if thrown, ok := entries[0].Result.(map[string]any); ok {
					got, _ = thrown["exception"].(string)
				} else if entries[0].Result != true {
					got = "false"
				}
				if tt.phpseclib != "" && got != tt.phpseclib {
					t.Errorf("phpseclib get gave %s, want %s", got, tt.phpseclib)
				}
				assertSavedPrefix(t, filepath.Join(work, "orders.csv"), partial, tt.exact["phpseclib"])
				assertHolds(t, srv, "/orders.csv", data)
			})
		}
	}
}

// assertSavedPrefix checks that the client saved the file name, holding
// exactly partial or, unless exact, a prefix of it.
func assertSavedPrefix(t *testing.T, name string, partial []byte, exact bool) {
	t.Helper()
	got, err := os.ReadFile(name)
	switch {
	case err != nil:
		t.Errorf("the client left no file: %v", err)
	case exact && !bytes.Equal(got, partial):
		t.Errorf("the client saved %d bytes, want the %d below the cutoff", len(got), len(partial))
	case !bytes.HasPrefix(partial, got):
		t.Errorf("the client saved %d bytes, which are not a prefix of the %d below the cutoff", len(got), len(partial))
	}
}
