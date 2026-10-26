package integration

import (
	"bytes"
	"os"
	"path/filepath"
	"slices"
	"testing"

	"github.com/nebarg/sftpit/internal/sftpproxy"
	"github.com/nebarg/sftpit/internal/sftpwire"
)

// corruptAt is where downloads are corrupted. It falls inside a read for
// both clients, so the corruption splits or shortens that read.
const corruptAt = 1<<20 + 1000

// TestCorruptedDownloadsAreTheSameForEveryClient downloads a file through
// each corruption with each client, in both reply orders, and checks that
// the client reports success and stores exactly the corrupted file, and that
// the file on the server is unchanged.
func TestCorruptedDownloadsAreTheSameForEveryClient(t *testing.T) {
	t.Parallel()
	data := randomBytes(4<<20 + 321)
	flipped := slices.Clone(data)
	for i := range 64 {
		flipped[corruptAt+i] ^= 1
	}
	corruptions := []struct {
		corruption sftpproxy.CorruptDownload
		want       []byte
	}{
		{
			corruption: sftpproxy.CorruptDownload{Corruption: sftpproxy.Truncate, Offset: corruptAt},
			want:       data[:corruptAt],
		},
		{
			corruption: sftpproxy.CorruptDownload{Corruption: sftpproxy.OmitRange, Offset: corruptAt, Length: 40_000},
			want:       slices.Concat(data[:corruptAt], data[corruptAt+40_000:]),
		},
		{
			corruption: sftpproxy.CorruptDownload{Corruption: sftpproxy.FlipBytes, Offset: corruptAt, Length: 64},
			want:       flipped,
		},
	}
	clients := []struct {
		name     string
		transfer func(t testing.TB, srv *server, work string, upload bool)
	}{
		{name: "OpenSSH", transfer: transferWithOpenSSH},
		{name: "phpseclib", transfer: transferWithPhpseclib},
	}

	for _, c := range clients {
		for _, order := range []sftpproxy.ReplyOrder{sftpproxy.RequestOrder, sftpproxy.CompletionOrder} {
			for _, tt := range corruptions {
				t.Run(c.name+"/"+order.String()+"/"+tt.corruption.Corruption.String(), func(t *testing.T) {
					srv := startServer(t, proxied, sftpproxy.Options{
						Faults: func(r sftpproxy.Request) sftpproxy.Action {
							if open, ok := r.Packet.(*sftpwire.Open); ok && r.Path == "/orders.csv" && open.Flags&sftpwire.OpenWrite == 0 {
								return tt.corruption
							}
							return nil
						},
						ReplyOrder: order,
					})
					writeFile(t, srv.path("/orders.csv"), data)
					work := t.TempDir()

					c.transfer(t, srv, work, false)
					got, err := os.ReadFile(filepath.Join(work, "orders.csv"))
					if err != nil || !bytes.Equal(got, tt.want) {
						t.Errorf("downloaded %d bytes (%v), want the %d bytes of the corrupted file", len(got), err, len(tt.want))
					}
					assertHolds(t, srv, "/orders.csv", data)
				})
			}
		}
	}
}
