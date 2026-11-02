package control_test

import (
	"crypto/sha256"
	"encoding/hex"
	"io"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/nebarg/sftpit/internal/runs"
)

func TestFilesListARunsFiles(t *testing.T) {
	seed := t.TempDir()
	if err := os.Mkdir(filepath.Join(seed, "Incoming"), 0o750); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(seed, "Incoming", "Orders.csv"), []byte("id,total\n"), 0o640); err != nil {
		t.Fatal(err)
	}
	m, api := start(t, runs.Options{SeedDir: seed})
	path := "/api/v1/runs/" + m.Status().Run.ID + "/files"

	code, body := call(t, api, "GET", path, "")
	if code != http.StatusOK || body["live"] != true {
		t.Fatalf("GET %s = %d %v, want the live run's files", path, code, body)
	}
	files := body["files"].([]any)
	var paths []string
	for _, f := range files {
		paths = append(paths, f.(map[string]any)["path"].(string))
	}
	if strings.Join(paths, " ") != "/ /Incoming /Incoming/Orders.csv" {
		t.Fatalf("paths = %v", paths)
	}
	orders := files[2].(map[string]any)
	if orders["type"] != "file" || orders["size"] != 9.0 || orders["mode"] != "0640" || orders["seed"] != "unchanged" || orders["mtime"] == nil || orders["sha256"] != nil {
		t.Errorf("file = %v, want the seed's 9-byte file, unchanged, without a hash", orders)
	}
	if dir := files[1].(map[string]any); dir["type"] != "dir" || dir["mode"] != "0750" {
		t.Errorf("directory = %v", dir)
	}

	code, body = call(t, api, "GET", path+"?path=/Incoming/Orders.csv&hash=true", "")
	want := sha256.Sum256([]byte("id,total\n"))
	if got := body["files"].([]any); code != http.StatusOK || len(got) != 1 || got[0].(map[string]any)["sha256"] != hex.EncodeToString(want[:]) {
		t.Errorf("one file with its hash = %d %v, want %x", code, body, want)
	}

	for query, want := range map[string]int{
		"?path=/missing":        http.StatusNotFound,
		"?path=Incoming":        http.StatusBadRequest,
		"?hash=maybe":           http.StatusBadRequest,
		"?path=/Incoming/../..": http.StatusOK,
	} {
		if code, body := call(t, api, "GET", path+query, ""); code != want {
			t.Errorf("GET %s = %d %v, want %d", query, code, body, want)
		}
	}
	if code, _ := call(t, api, "GET", "/api/v1/runs/20261024-101500.123-3f9a/files", ""); code != http.StatusNotFound {
		t.Errorf("files of an unknown run = %d, want 404", code)
	}
}

func TestFileContentIsADownloadThatAnswersRanges(t *testing.T) {
	seed := t.TempDir()
	if err := os.WriteFile(filepath.Join(seed, "page.html"), []byte("<script>alert(1)</script>"), 0o600); err != nil {
		t.Fatal(err)
	}
	m, api := start(t, runs.Options{SeedDir: seed})
	path := "/api/v1/runs/" + m.Status().Run.ID + "/files/content?path=/page.html"

	resp := get(t, api, path, nil)
	if b, _ := io.ReadAll(resp.Body); resp.StatusCode != http.StatusOK || string(b) != "<script>alert(1)</script>" {
		t.Errorf("GET %s = %d %q", path, resp.StatusCode, b)
	}
	for header, want := range map[string]string{
		"Content-Type":            "application/octet-stream",
		"Content-Disposition":     `attachment; filename=page.html`,
		"X-Content-Type-Options":  "nosniff",
		"Content-Security-Policy": "default-src 'none'; sandbox",
		"Cache-Control":           "no-store",
	} {
		if got := resp.Header.Get(header); got != want {
			t.Errorf("%s: %q, want %q", header, got, want)
		}
	}

	// A preview asks for the start of the file.
	resp = get(t, api, path, map[string]string{"Range": "bytes=0-7"})
	if b, _ := io.ReadAll(resp.Body); resp.StatusCode != http.StatusPartialContent || string(b) != "<script>" {
		t.Errorf("a range = %d %q, want 206 with the first 8 bytes", resp.StatusCode, b)
	}

	for query, want := range map[string]int{
		"":                   http.StatusBadRequest,
		"?path=/":            http.StatusBadRequest,
		"?path=/missing":     http.StatusNotFound,
		"?path=relative.txt": http.StatusBadRequest,
	} {
		if code, body := call(t, api, "GET", "/api/v1/runs/"+m.Status().Run.ID+"/files/content"+query, ""); code != want {
			t.Errorf("content %q = %d %v, want %d", query, code, body, want)
		}
	}
}

func TestSnapshotsOfARunWithoutAny(t *testing.T) {
	m, api := start(t, runs.Options{})
	run := "/api/v1/runs/" + m.Status().Run.ID
	if code, body := call(t, api, "GET", run+"/snapshots", ""); code != http.StatusOK || len(body["snapshots"].([]any)) != 0 {
		t.Errorf("snapshots = %d %v, want none", code, body)
	}
	for _, n := range []string{"1", "0", "x"} {
		if code, body := call(t, api, "GET", run+"/snapshots/"+n+"/content", ""); code != http.StatusNotFound {
			t.Errorf("snapshot %s = %d %v, want 404", n, code, body)
		}
	}
}

// get makes a GET request to api with headers, as the command line would.
func get(t *testing.T, api http.Handler, path string, headers map[string]string) *http.Response {
	t.Helper()
	req := httptest.NewRequest("GET", path, nil)
	req.Host = host
	for k, v := range headers {
		req.Header.Set(k, v)
	}
	rec := httptest.NewRecorder()
	api.ServeHTTP(rec, req)
	return rec.Result()
}
