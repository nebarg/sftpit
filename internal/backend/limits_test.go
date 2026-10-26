package backend_test

import (
	"bytes"
	"errors"
	"fmt"
	"io/fs"
	"log/slog"
	"maps"
	"math"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"testing"

	"github.com/pkg/sftp"

	"github.com/nebarg/sftpit/internal/backend"
	"github.com/nebarg/sftpit/internal/sftpwire"
)

func TestLimitsRefuseRequestsThatWouldPassThem(t *testing.T) {
	full := map[string]string{"a": "0123456789", "b": "0123456789", "c": ""}
	tests := []struct {
		name string
		// files are there when the backend starts; a name ending in a slash
		// is a directory.
		files   map[string]string
		request func(c *sftp.Client) error
		path    string
		limit   string
		max     int64
	}{
		{
			name:    "a write past max_file_bytes",
			files:   map[string]string{"a": "01234567"},
			request: func(c *sftp.Client) error { return writeAt(c, "/a", "89!", 8, 0) },
			path:    "/a", limit: "max_file_bytes", max: 10,
		},
		{
			name:    "a sparse write past max_file_bytes",
			files:   map[string]string{"a": ""},
			request: func(c *sftp.Client) error { return writeAt(c, "/a", "!", 10, 0) },
			path:    "/a", limit: "max_file_bytes", max: 10,
		},
		{
			name:    "an append past max_file_bytes",
			files:   map[string]string{"a": "0123456789"},
			request: func(c *sftp.Client) error { return writeAt(c, "/a", "!", 0, os.O_APPEND) },
			path:    "/a", limit: "max_file_bytes", max: 10,
		},
		{
			name:    "a truncate past max_file_bytes",
			files:   map[string]string{"a": ""},
			request: func(c *sftp.Client) error { return c.Truncate("/a", 11) },
			path:    "/a", limit: "max_file_bytes", max: 10,
		},
		{
			name:    "a write past max_total_bytes",
			files:   full,
			request: func(c *sftp.Client) error { return writeAt(c, "/c", "012345", 0, 0) },
			path:    "/c", limit: "max_total_bytes", max: 25,
		},
		{
			name:    "a truncate past max_total_bytes",
			files:   full,
			request: func(c *sftp.Client) error { return c.Truncate("/c", 6) },
			path:    "/c", limit: "max_total_bytes", max: 25,
		},
		{
			name:    "a write whose end overflows",
			files:   map[string]string{"a": ""},
			request: func(c *sftp.Client) error { return writeAt(c, "/a", "01", math.MaxInt64-1, 0) },
			path:    "/a", limit: "max_file_bytes", max: 10,
		},
		{
			name:  "a create past max_files",
			files: map[string]string{"a": "", "b": "", "d/": "", "d/c": ""},
			request: func(c *sftp.Client) error {
				_, err := c.Create("/d/new")
				return err
			},
			path: "/d/new", limit: "max_files", max: 4,
		},
		{
			name:  "a read-only create past max_files",
			files: map[string]string{"a": "", "b": "", "c": "", "d/": ""},
			request: func(c *sftp.Client) error {
				_, err := c.OpenFile("/new", os.O_RDONLY|os.O_CREATE)
				return err
			},
			path: "/new", limit: "max_files", max: 4,
		},
		{
			name:    "a mkdir past max_files",
			files:   map[string]string{"a": "", "b": "", "c": "", "d/": ""},
			request: func(c *sftp.Client) error { return c.Mkdir("/new") },
			path:    "/new", limit: "max_files", max: 4,
		},
		{
			name:  "an open past max_open_files",
			files: map[string]string{"a": "", "b": ""},
			request: func(c *sftp.Client) error {
				for range 2 {
					if _, err := c.Open("/a"); err != nil {
						return fmt.Errorf("an open below the limit: %w", err)
					}
				}
				_, err := c.OpenFile("/b", os.O_WRONLY)
				return err
			},
			path: "/b", limit: "max_open_files", max: 2,
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			dir := t.TempDir()
			writeTree(t, dir, tt.files)
			var logs bytes.Buffer
			e := newBackendIn(t, dir, backend.Options{Limits: tight, Logger: slog.New(slog.NewTextHandler(&logs, nil))})
			c := newClient(t, e, "/")
			before := readHostTree(t, dir)

			assertStatus(t, tt.request(c), sftpwire.StatusFailure)
			if after := readHostTree(t, dir); !maps.Equal(after, before) {
				t.Errorf("files changed from %v to %v", before, after)
			}
			want := fmt.Sprintf(`level=WARN msg="storage limit reached" path=%s limit=%s max=%d`, tt.path, tt.limit, tt.max)
			if !strings.Contains(logs.String(), want) {
				t.Errorf("log does not have %q:\n%s", want, logs.String())
			}
		})
	}
}

func TestLimitsAllowRequestsUpToThem(t *testing.T) {
	dir := t.TempDir()
	var logs bytes.Buffer
	e := newBackendIn(t, dir, backend.Options{Limits: tight, Logger: slog.New(slog.NewTextHandler(&logs, nil))})
	c := newClient(t, e, "/")
	steps := []struct {
		name    string
		request func() error
	}{
		{"a file of max_file_bytes", func() error { return writeAt(c, "/a", "0123456789", 0, os.O_CREATE) }},
		{"files of max_total_bytes", func() error {
			return errors.Join(writeAt(c, "/b", "0123456789", 0, os.O_CREATE), writeAt(c, "/c", "012", 0, os.O_CREATE),
				writeAt(c, "/c", "34", 3, 0))
		}},
		{"a write within a file while the files are full", func() error { return writeAt(c, "/a", "ab", 0, 0) }},
		{"a directory that makes max_files", func() error { return c.Mkdir("/d") }},
		{"an open with create of a file there already", func() error { return writeAt(c, "/a", "cd", 0, os.O_CREATE) }},
		{"a truncate that frees bytes, and growth into them", func() error {
			return errors.Join(c.Truncate("/c", 0), c.Truncate("/c", 5))
		}},
		{"a remove that frees a file, and a new file in its place", func() error {
			return errors.Join(c.Remove("/b"), writeAt(c, "/e", "0123456789", 0, os.O_CREATE))
		}},
		{"a posix-rename that frees its target, and a new file in its place", func() error {
			return errors.Join(c.PosixRename("/e", "/a"), writeAt(c, "/f", "0123456789", 0, os.O_CREATE))
		}},
		{"an rmdir that frees a directory, and a new one in its place", func() error {
			return errors.Join(c.RemoveDirectory("/d"), c.Mkdir("/g"))
		}},
	}
	for _, step := range steps {
		if err := step.request(); err != nil {
			t.Fatalf("%s: %v", step.name, err)
		}
	}
	want := map[string]string{"a": "0123456789", "c": "\x00\x00\x00\x00\x00", "f": "0123456789", "g/": ""}
	if got := readHostTree(t, dir); !maps.Equal(got, want) {
		t.Errorf("files = %q, want %q", got, want)
	}
	if logs.Len() > 0 {
		t.Errorf("requests within the limits were logged:\n%s", logs.String())
	}
	// The files are back at every limit.
	assertStatus(t, writeAt(c, "/c", "!", 5, 0), sftpwire.StatusFailure)
	assertStatus(t, c.Mkdir("/h"), sftpwire.StatusFailure)
}

func TestLimitsCountOpenFileHandlesAcrossSessions(t *testing.T) {
	dir := t.TempDir()
	writeTree(t, dir, map[string]string{"a": "data"})
	e := newBackendIn(t, dir, backend.Options{Limits: tight, Logger: slog.New(slog.DiscardHandler)})
	conn := e.Open("/")
	first, err := sftp.NewClientPipe(conn, conn)
	if err != nil {
		t.Fatalf("NewClientPipe: %v", err)
	}
	// An open that fails leaves no handle open.
	for range 3 {
		_, err := first.Open("/missing")
		assertStatus(t, err, sftpwire.StatusNoSuchFile)
	}
	for range 2 {
		if _, err := first.Open("/a"); err != nil {
			t.Fatalf("Open below the limit: %v", err)
		}
	}
	second := newClient(t, e, "/")
	_, err = second.Open("/a")
	assertStatus(t, err, sftpwire.StatusFailure)
	// Directory handles hold no descriptor, so they do not count.
	if _, err := second.ReadDir("/"); err != nil {
		t.Errorf("ReadDir at the limit: %v", err)
	}

	// Ending a session closes the handles it left open.
	first.Close()
	if err := conn.Close(); err != nil {
		t.Fatalf("backend session: %v", err)
	}
	for range 2 {
		f, err := second.Open("/a")
		if err != nil {
			t.Fatalf("Open once the other session ended: %v", err)
		}
		defer f.Close()
	}
}

func TestStatVFSReportsTheLimits(t *testing.T) {
	dir := t.TempDir()
	writeTree(t, dir, map[string]string{"a": strings.Repeat("a", 4096), "d/": "", "d/b": "b"})
	limits := backend.Limits{MaxFileBytes: 1 << 20, MaxTotalBytes: 10 * 4096, MaxFiles: 10, MaxOpenFiles: 4}
	e := newBackendIn(t, dir, backend.Options{Limits: limits})
	c := newClient(t, e, "/")

	want := sftp.StatVFS{
		Bsize: 4096, Frsize: 4096, Blocks: 10,
		// 4097 bytes are used, which leaves 8 whole blocks.
		Bfree: 8, Bavail: 8,
		Files: 10, Ffree: 7, Favail: 7,
		Namemax: 255,
	}
	for _, name := range []string{"/", "/d", "/d/b"} {
		if got, err := statVFS(c, name); err != nil || got != want {
			t.Errorf("StatVFS(%s) = %+v, %v; want %+v", name, got, err, want)
		}
	}
	// A file extended by a truncate counts at its full size.
	if err := c.Truncate("/a", 2*4096); err != nil {
		t.Fatalf("Truncate: %v", err)
	}
	want.Bfree, want.Bavail = 7, 7
	if got, err := statVFS(c, "/"); err != nil || got != want {
		t.Errorf("StatVFS after a truncate = %+v, %v; want %+v", got, err, want)
	}
	_, err := c.StatVFS("/missing")
	assertStatus(t, err, sftpwire.StatusNoSuchFile)
}

// TestLimitsStayExactAcrossSessions has several sessions upload, rename and
// remove files at once, mostly past the limits, and then checks that exactly
// what is left of each limit can still be used.
func TestLimitsStayExactAcrossSessions(t *testing.T) {
	limits := backend.Limits{MaxFileBytes: 1 << 20, MaxTotalBytes: 200_000, MaxFiles: 20, MaxOpenFiles: 64}
	dir := t.TempDir()
	writeTree(t, dir, map[string]string{"probe": ""})
	e := newBackendIn(t, dir, backend.Options{Limits: limits, Logger: slog.New(slog.DiscardHandler)})
	data := make([]byte, 64<<10)
	var clients []*sftp.Client
	for range 8 {
		clients = append(clients, newClient(t, e, "/"))
	}

	var wg sync.WaitGroup
	for i, c := range clients {
		wg.Go(func() {
			for j := range 20 {
				// Refusals at the limits are expected, and leave partial files.
				name := fmt.Sprintf("/s%d-%d", i, j%5)
				if f, err := c.Create(name); err == nil {
					f.ReadFrom(bytes.NewReader(data))
					f.Close()
				}
				if j%3 == 0 {
					c.PosixRename(name, fmt.Sprintf("/s%d-renamed", i))
				}
				if j%4 == 0 {
					c.Remove(fmt.Sprintf("/s%d-%d", i, (j+1)%5))
				}
			}
		})
	}
	wg.Wait()

	var bytesUsed, filesUsed int64
	err := filepath.WalkDir(dir, func(name string, d fs.DirEntry, err error) error {
		if err != nil || name == dir {
			return err
		}
		info, err := d.Info()
		if err != nil {
			return err
		}
		filesUsed++
		bytesUsed += info.Size()
		return nil
	})
	if err != nil {
		t.Fatal(err)
	}
	if bytesUsed > limits.MaxTotalBytes || filesUsed > limits.MaxFiles {
		t.Fatalf("the sessions left %d bytes in %d files and directories, past the limits", bytesUsed, filesUsed)
	}
	c := clients[0]
	free := limits.MaxTotalBytes - bytesUsed
	if err := c.Truncate("/probe", free); err != nil {
		t.Errorf("growing a file into the last %d bytes: %v", free, err)
	}
	assertStatus(t, c.Truncate("/probe", free+1), sftpwire.StatusFailure)
	for i := range limits.MaxFiles - filesUsed {
		if err := c.Mkdir(fmt.Sprintf("/probe-%d", i)); err != nil {
			t.Fatalf("making one of the last %d directories: %v", limits.MaxFiles-filesUsed, err)
		}
	}
	assertStatus(t, c.Mkdir("/probe-past"), sftpwire.StatusFailure)
}

func TestMkdirAllCountsEveryDirectory(t *testing.T) {
	dir := t.TempDir()
	e := newBackendIn(t, dir, backend.Options{Limits: backend.Limits{MaxFileBytes: 1, MaxTotalBytes: 1, MaxFiles: 2, MaxOpenFiles: 1}})
	for range 2 {
		if err := e.MkdirAll("/partners/b"); err != nil {
			t.Fatalf("MkdirAll: %v", err)
		}
	}
	if err := e.MkdirAll("/partners/c"); !errors.Is(err, backend.ErrLimit) || !strings.Contains(err.Error(), "max_files is 2") {
		t.Errorf("MkdirAll past the limit = %v, want ErrLimit naming max_files", err)
	}
	assertMissing(t, filepath.Join(dir, "partners", "c"))
}

// statVFS returns pkg/sftp's StatVFS without the request ID it carries.
func statVFS(c *sftp.Client, name string) (sftp.StatVFS, error) {
	s, err := c.StatVFS(name)
	if err != nil {
		return sftp.StatVFS{}, err
	}
	s.ID = 0
	return *s, nil
}

// readHostTree reads everything under dir as writeTree would write it.
func readHostTree(t *testing.T, dir string) map[string]string {
	t.Helper()
	files := make(map[string]string)
	err := filepath.WalkDir(dir, func(name string, d fs.DirEntry, err error) error {
		if err != nil || name == dir {
			return err
		}
		rel, err := filepath.Rel(dir, name)
		if err != nil {
			return err
		}
		rel = filepath.ToSlash(rel)
		if d.IsDir() {
			files[rel+"/"] = ""
			return nil
		}
		content, err := os.ReadFile(name)
		files[rel] = string(content)
		return err
	})
	if err != nil {
		t.Fatal(err)
	}
	return files
}

// TestWritesToARemovedFileDoNotCount checks that writes through a handle
// whose file another session has removed take nothing from the limits: the
// file is no longer in the tree, and goes once the handle closes.
func TestWritesToARemovedFileDoNotCount(t *testing.T) {
	limits := backend.Limits{MaxFileBytes: 10, MaxTotalBytes: 10, MaxFiles: 4, MaxOpenFiles: 4}
	e := newBackendIn(t, t.TempDir(), backend.Options{Limits: limits, Logger: slog.New(slog.DiscardHandler)})
	writer, remover := newClient(t, e, "/"), newClient(t, e, "/")

	f, err := writer.Create("/a")
	if err != nil {
		t.Fatalf("Create: %v", err)
	}
	if err := remover.Remove("/a"); err != nil {
		t.Fatalf("Remove: %v", err)
	}
	if _, err := f.Write([]byte("01234567")); err != nil {
		t.Fatalf("Write through the removed file's handle: %v", err)
	}
	if err := f.Close(); err != nil {
		t.Fatalf("Close: %v", err)
	}
	if err := writeAt(writer, "/b", "0123456789", 0, os.O_CREATE); err != nil {
		t.Errorf("a write of max_total_bytes once the removed file closed: %v", err)
	}
}
