package integration

import (
	"io"
	"os"
	"path/filepath"
	"testing"

	"golang.org/x/crypto/ssh"

	"github.com/nebarg/sftpit/internal/sftpproxy"
)

// BenchmarkTransfer uploads and downloads a file over SSH, directly against
// the embedded backend and through the proxy in each reply order, so that
// the difference is the proxy's cost as a client sees it.
func BenchmarkTransfer(b *testing.B) {
	data := randomBytes(64 << 20)
	servers := []struct {
		name  string
		via   route
		order sftpproxy.ReplyOrder
	}{
		{name: "direct", via: direct},
		{name: "proxied", via: proxied, order: sftpproxy.RequestOrder},
		{name: "proxied-completion", via: proxied, order: sftpproxy.CompletionOrder},
	}
	clients := []struct {
		name     string
		transfer func(t testing.TB, srv *server, work string, upload bool)
	}{
		{name: "pkg-sftp", transfer: transferWithPkgSFTP},
		{name: "OpenSSH", transfer: transferWithOpenSSH},
	}

	for _, c := range clients {
		for _, direction := range []string{"upload", "download"} {
			for _, r := range servers {
				b.Run(c.name+"/"+direction+"/"+r.name, func(b *testing.B) {
					srv := startServer(b, r.via, sftpproxy.Options{ReplyOrder: r.order})
					work := b.TempDir()
					writeFile(b, filepath.Join(work, "orders.csv"), data)
					upload := direction == "upload"
					if !upload {
						writeFile(b, srv.path("/orders.csv"), data)
					}
					b.SetBytes(int64(len(data)))
					for b.Loop() {
						c.transfer(b, srv, work, upload)
					}
				})
			}
		}
	}
}

// transferWithPkgSFTP uploads work/orders.csv to /orders.csv, or downloads
// it back, with pkg/sftp's client and its concurrent requests.
func transferWithPkgSFTP(tb testing.TB, srv *server, work string, upload bool) {
	tb.Helper()
	c := pkgSFTPClient(tb, srv, ssh.Password(testPassword))
	defer c.Close()
	if upload {
		local, err := os.Open(filepath.Join(work, "orders.csv"))
		if err != nil {
			tb.Fatal(err)
		}
		defer local.Close()
		f, err := c.Create("/orders.csv")
		if err != nil {
			tb.Fatalf("Create: %v", err)
		}
		_, err = f.ReadFrom(local)
		if closeErr := f.Close(); err == nil {
			err = closeErr
		}
		if err != nil {
			tb.Fatalf("upload: %v", err)
		}
		return
	}
	f, err := c.Open("/orders.csv")
	if err != nil {
		tb.Fatalf("Open: %v", err)
	}
	defer f.Close()
	if _, err := f.WriteTo(io.Discard); err != nil {
		tb.Fatalf("download: %v", err)
	}
}
