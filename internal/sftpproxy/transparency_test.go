package sftpproxy_test

import (
	"bytes"
	"context"
	"crypto/sha256"
	"errors"
	"fmt"
	"io"
	"log/slog"
	"math/rand/v2"
	"net"
	"os"
	"slices"
	"strings"
	"testing"

	"github.com/pkg/sftp"

	"sftpit/internal/sftpproxy"
)

// TestProxyIsTransparent runs one workload directly against a pkg/sftp
// server and again through the proxy in each reply order, and requires
// identical outcomes.
func TestProxyIsTransparent(t *testing.T) {
	upload := make([]byte, 1<<20+123)
	rand.NewChaCha8([32]byte{}).Read(upload)

	direct := runWorkload(t, newSFTPClient(t, inMemoryBackend(t)), upload)

	for _, order := range []sftpproxy.ReplyOrder{sftpproxy.RequestOrder, sftpproxy.CompletionOrder} {
		t.Run(order.String(), func(t *testing.T) {
			client, _ := startProxyWith(t, context.Background(), inMemoryBackend(t), sftpproxy.Options{
				ReplyOrder: order,
				Logger:     slog.New(slog.DiscardHandler),
			})
			proxied := runWorkload(t, newSFTPClient(t, client.conn), upload)
			if !slices.Equal(proxied, direct) {
				t.Errorf("outcomes differ through the proxy\ndirect:\n%s\nproxied:\n%s",
					strings.Join(direct, "\n"), strings.Join(proxied, "\n"))
			}
		})
	}
}

// runWorkload exercises every supported operation, including failures, and
// returns a transcript of the outcomes.
func runWorkload(t *testing.T, c *sftp.Client, upload []byte) []string {
	t.Helper()
	var transcript []string
	record := func(op string, err error, results ...any) {
		line := op + ": " + fmt.Sprint(results...)
		if err != nil {
			line = op + ": error " + err.Error()
		}
		transcript = append(transcript, line)
	}
	stat := func(op string, statFunc func(string) (os.FileInfo, error), name string) {
		fi, err := statFunc(name)
		if err != nil {
			record(op+" "+name, err)
			return
		}
		record(op+" "+name, nil, fi.Name(), " ", fi.Size(), " ", fi.Mode())
	}
	write := func(name string, data []byte) {
		f, err := c.Create(name)
		if err != nil {
			record("create "+name, err)
			return
		}
		_, err = f.ReadFrom(bytes.NewReader(data))
		record("upload "+name, err)
		record("close "+name, f.Close())
	}
	read := func(name string) {
		f, err := c.Open(name)
		if err != nil {
			record("open "+name, err)
			return
		}
		h := sha256.New()
		n, err := f.WriteTo(h)
		record("download "+name, err, n, " ", fmt.Sprintf("%x", h.Sum(nil)))
		record("close "+name, f.Close())
	}
	list := func(dir string) {
		entries, err := c.ReadDir(dir)
		var names []string
		for _, e := range entries {
			names = append(names, fmt.Sprint(e.Name(), " ", e.Size(), " ", e.Mode()))
		}
		record("list "+dir, err, names)
	}

	wd, err := c.Getwd()
	record("getwd", err, wd)
	record("mkdir /in", c.Mkdir("/in"))
	record("mkdir /in again", c.Mkdir("/in"))
	write("/in/orders.part", upload)
	stat("stat", c.Stat, "/in/orders.part")
	record("rename to /in/orders.csv", c.Rename("/in/orders.part", "/in/orders.csv"))
	read("/in/orders.csv")
	write("in/other.csv", []byte("relative path"))
	record("rename onto an existing file", c.Rename("/in/other.csv", "/in/orders.csv"))
	record("posix-rename onto an existing file", c.PosixRename("/in/other.csv", "/in/orders.csv"))
	list("/in")
	read("/in/orders.csv")
	read("in/../in/other.csv")
	stat("lstat", c.Lstat, "/in/orders.csv")
	record("truncate /in/orders.csv", c.Truncate("/in/orders.csv", 10))
	stat("stat after truncate", c.Stat, "/in/orders.csv")
	resolved, err := c.RealPath("in/./orders.csv")
	record("realpath", err, resolved)
	_, err = c.StatVFS("/")
	record("statvfs", err)
	stat("stat", c.Stat, "/in/missing.csv")
	read("/in/missing.csv")
	record("remove a missing file", c.Remove("/in/missing.csv"))
	record("rmdir a non-empty directory", c.RemoveDirectory("/in"))
	record("remove /in/orders.csv", c.Remove("/in/orders.csv"))
	record("remove /in/other.csv", c.Remove("/in/other.csv"))
	record("rmdir /in", c.RemoveDirectory("/in"))
	list("/")
	return transcript
}

// inMemoryBackend serves pkg/sftp's in-memory filesystem over a pipe and
// returns the client's end.
func inMemoryBackend(t *testing.T) net.Conn {
	t.Helper()
	clientEnd, serverEnd := net.Pipe()
	srv := sftp.NewRequestServer(serverEnd, sftp.InMemHandler())
	done := make(chan error, 1)
	go func() { done <- srv.Serve() }()
	t.Cleanup(func() {
		srv.Close()
		if err := <-done; err != nil && !errors.Is(err, io.EOF) && !errors.Is(err, io.ErrClosedPipe) {
			t.Errorf("backend Serve: %v", err)
		}
	})
	return clientEnd
}

func newSFTPClient(t *testing.T, conn net.Conn) *sftp.Client {
	t.Helper()
	c, err := sftp.NewClientPipe(conn, conn, sftp.UseConcurrentWrites(true))
	if err != nil {
		t.Fatalf("sftp.NewClientPipe: %v", err)
	}
	t.Cleanup(func() { c.Close() })
	return c
}
