package backend_test

import (
	"errors"
	"io"
	"io/fs"
	"os"
	"path/filepath"
	"slices"
	"testing"
	"time"

	"github.com/nebarg/sftpit/internal/backend"
)

func TestListDescribesWhatClientsSee(t *testing.T) {
	dir, e := newBackend(t)
	c := newClient(t, e, "/")
	for _, d := range []string{"/Incoming", "/Incoming/2026 Q1"} {
		if err := c.Mkdir(d); err != nil {
			t.Fatalf("Mkdir %s: %v", d, err)
		}
	}
	for name, content := range map[string]string{"/Incoming/Orders.CSV": "id,total\n", "/Incoming/2026 Q1/a.txt": "a", "/readme": ""} {
		f, err := c.Create(name)
		if err != nil {
			t.Fatalf("Create %s: %v", name, err)
		}
		if _, err := f.Write([]byte(content)); err != nil {
			t.Fatalf("Write %s: %v", name, err)
		}
		f.Close()
	}
	if err := c.Chmod("/Incoming/Orders.CSV", 0o640); err != nil {
		t.Fatal(err)
	}
	mtime := time.Date(2026, 10, 1, 12, 0, 0, 0, time.UTC)
	if err := c.Chtimes("/readme", mtime, mtime); err != nil {
		t.Fatal(err)
	}
	// Names that sftpit cannot have given are left out, as clients never
	// see them.
	for _, name := range []string{"Copied.txt", "%2e%2e"} {
		if err := os.WriteFile(filepath.Join(dir, name), nil, 0o600); err != nil {
			t.Fatal(err)
		}
	}
	root := openRoot(t, dir)

	files, err := backend.List(root, "/")
	if err != nil {
		t.Fatalf("List: %v", err)
	}
	var got []string
	for _, f := range files {
		kind := "file"
		if f.Dir {
			kind = "dir"
		}
		got = append(got, f.Path+" "+kind)
	}
	want := []string{"/ dir", "/Incoming dir", "/Incoming/2026 Q1 dir", "/Incoming/2026 Q1/a.txt file", "/Incoming/Orders.CSV file", "/readme file"}
	if !slices.Equal(got, want) {
		t.Errorf("List = %q, want %q", got, want)
	}
	for _, f := range files {
		switch f.Path {
		case "/Incoming/Orders.CSV":
			if f.Size != 9 || f.Mode != 0o640 {
				t.Errorf("%s: size %d, mode %v; want 9 and 0640", f.Path, f.Size, f.Mode)
			}
		case "/readme":
			if !f.ModTime.Equal(mtime) {
				t.Errorf("%s: modified %v, want %v", f.Path, f.ModTime, mtime)
			}
		}
	}

	if files, err := backend.List(root, "/Incoming/2026 Q1"); err != nil || len(files) != 2 || files[1].Path != "/Incoming/2026 Q1/a.txt" {
		t.Errorf("List of a directory = %+v, %v; want it and its file", files, err)
	}
	if files, err := backend.List(root, "/readme"); err != nil || len(files) != 1 || files[0].Dir {
		t.Errorf("List of a file = %+v, %v; want the file", files, err)
	}
	if _, err := backend.List(root, "/incoming"); !errors.Is(err, fs.ErrNotExist) {
		t.Errorf("List of a name in the wrong case = %v, want fs.ErrNotExist", err)
	}
}

func TestOpenReadsAStoredFile(t *testing.T) {
	dir, e := newBackend(t)
	c := newClient(t, e, "/")
	f, err := c.Create("/Orders.csv")
	if err != nil {
		t.Fatal(err)
	}
	if _, err := f.Write([]byte("id,total\n")); err != nil {
		t.Fatal(err)
	}
	f.Close()
	if err := c.Mkdir("/dir"); err != nil {
		t.Fatal(err)
	}
	root := openRoot(t, dir)

	opened, err := backend.Open(root, "/Orders.csv")
	if err != nil {
		t.Fatalf("Open: %v", err)
	}
	defer opened.Close()
	if b, err := io.ReadAll(opened); err != nil || string(b) != "id,total\n" {
		t.Errorf("read %q, %v", b, err)
	}
	if _, err := backend.Open(root, "/dir"); !errors.Is(err, backend.ErrNotFile) {
		t.Errorf("Open of a directory = %v, want ErrNotFile", err)
	}
	if _, err := backend.Open(root, "/orders.csv"); !errors.Is(err, fs.ErrNotExist) {
		t.Errorf("Open of a missing file = %v, want fs.ErrNotExist", err)
	}
}

func openRoot(t *testing.T, dir string) *os.Root {
	t.Helper()
	root, err := os.OpenRoot(dir)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { root.Close() })
	return root
}
