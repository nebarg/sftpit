package integration

import (
	"bytes"
	"errors"
	"fmt"
	"io"
	"net"
	"os"
	"path/filepath"
	"testing"

	"github.com/pkg/sftp"
	"golang.org/x/crypto/ssh"

	"github.com/nebarg/sftpit/internal/sftpproxy"
)

// BenchmarkTransfer uploads and downloads a file over SSH, directly against
// the embedded backend and through the proxy in each reply order, so that
// the difference is the proxy's cost as a client sees it.
func BenchmarkTransfer(b *testing.B) {
	data := randomBytes(64 << 20)
	routes := []struct {
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
		transfer func(b *testing.B, srv *server, work string, upload bool)
	}{
		{name: "pkg-sftp", transfer: transferWithPkgSFTP},
		{name: "OpenSSH", transfer: benchOpenSSH},
	}

	for _, c := range clients {
		for _, direction := range []string{"upload", "download"} {
			for _, r := range routes {
				b.Run(c.name+"/"+direction+"/"+r.name, func(b *testing.B) {
					srv := startServer(b, r.via, sftpproxy.Options{ReplyOrder: r.order})
					work := b.TempDir()
					writeFile(b, filepath.Join(work, "bench.bin"), data)
					upload := direction == "upload"
					if !upload {
						writeFile(b, filepath.Join(srv.files, "bench.bin"), data)
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

// transferWithPkgSFTP uploads work/bench.bin to /bench.bin, or downloads it
// back, with pkg/sftp's client and its concurrent requests.
func transferWithPkgSFTP(b *testing.B, srv *server, work string, upload bool) {
	c := pkgSFTPClient(b, srv, ssh.Password(testPassword))
	defer c.Close()
	if upload {
		local, err := os.Open(filepath.Join(work, "bench.bin"))
		if err != nil {
			b.Fatal(err)
		}
		defer local.Close()
		f, err := c.Create("/bench.bin")
		if err != nil {
			b.Fatalf("Create: %v", err)
		}
		_, err = f.ReadFrom(local)
		if closeErr := f.Close(); err == nil {
			err = closeErr
		}
		if err != nil {
			b.Fatalf("upload: %v", err)
		}
		return
	}
	f, err := c.Open("/bench.bin")
	if err != nil {
		b.Fatalf("Open: %v", err)
	}
	defer f.Close()
	if _, err := f.WriteTo(io.Discard); err != nil {
		b.Fatalf("download: %v", err)
	}
}

// pkgSFTPClient logs in to srv over SSH with pkg/sftp's client, using auth.
// Closing the client closes the connection too.
func pkgSFTPClient(tb testing.TB, srv *server, auth ssh.AuthMethod) *sshSFTPClient {
	tb.Helper()
	conn, err := ssh.Dial("tcp", srv.addr, &ssh.ClientConfig{
		User: testUser,
		Auth: []ssh.AuthMethod{auth},
		HostKeyCallback: func(_ string, _ net.Addr, key ssh.PublicKey) error {
			for _, k := range hostKeys {
				if bytes.Equal(k.PublicKey().Marshal(), key.Marshal()) {
					return nil
				}
			}
			return fmt.Errorf("unknown host key %s", key.Type())
		},
	})
	if err != nil {
		tb.Fatalf("ssh.Dial: %v", err)
	}
	c, err := sftp.NewClient(conn, sftp.UseConcurrentWrites(true))
	if err != nil {
		conn.Close()
		tb.Fatalf("sftp.NewClient: %v", err)
	}
	return &sshSFTPClient{Client: c, conn: conn}
}

type sshSFTPClient struct {
	*sftp.Client
	conn *ssh.Client
}

func (c *sshSFTPClient) Close() error {
	return errors.Join(c.Client.Close(), c.conn.Close())
}

func benchOpenSSH(b *testing.B, srv *server, work string, upload bool) {
	batch := "get /bench.bin bench.out\n"
	if upload {
		batch = "put bench.bin /bench.bin\n"
	}
	if out, err := openSSH(b, openSSHOrSkip(b), srv, work, batch); err != nil {
		b.Fatalf("sftp failed: %v\n%s", err, out)
	}
}
