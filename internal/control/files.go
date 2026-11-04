package control

import (
	"errors"
	"fmt"
	"io"
	"io/fs"
	"mime"
	"net/http"
	"os"
	"path"
	"strconv"
	"time"

	"github.com/nebarg/sftpit/internal/runs"
)

// File describes a file or directory of a run in a reply.
type File struct {
	Path    string    `json:"path"`
	Type    string    `json:"type"`
	Size    int64     `json:"size"`
	Mode    string    `json:"mode"`
	ModTime time.Time `json:"mtime"`
	SHA256  string    `json:"sha256,omitempty"`
	Seed    string    `json:"seed,omitempty"`
}

// Snapshot describes a copy that a run kept of a file a faulted handle left
// behind, in a reply.
type Snapshot struct {
	Number  int       `json:"number"`
	Path    string    `json:"path"`
	Copy    string    `json:"copy"`
	Size    int64     `json:"size"`
	ModTime time.Time `json:"mtime"`
	SHA256  string    `json:"sha256,omitempty"`
}

// files answers with the files of a run under the path the query gives, or
// beneath the root, with their hashes if the query asks for them.
func (a *api) files(w http.ResponseWriter, r *http.Request) {
	name, err := queryPath(r, "/")
	if err != nil {
		writeError(w, http.StatusBadRequest, err)
		return
	}
	hash, err := queryHash(r)
	if err != nil {
		writeError(w, http.StatusBadRequest, err)
		return
	}
	files, live, err := a.runs.Files(r.PathValue("id"), name, hash)
	if err != nil {
		writeError(w, fileStatus(err), err)
		return
	}
	body := struct {
		Live  bool   `json:"live"`
		Files []File `json:"files"`
	}{Live: live, Files: make([]File, 0, len(files))}
	for _, f := range files {
		kind := "file"
		if f.Dir {
			kind = "dir"
		}
		body.Files = append(body.Files, File{Path: f.Path, Type: kind, Size: f.Size, Mode: fmt.Sprintf("%04o", f.Mode), ModTime: f.ModTime.UTC(), SHA256: f.SHA256, Seed: f.Seed})
	}
	writeJSON(w, http.StatusOK, body)
}

// fileContent answers with the content of a run's file.
func (a *api) fileContent(w http.ResponseWriter, r *http.Request) {
	name, err := queryPath(r, "")
	if err != nil {
		writeError(w, http.StatusBadRequest, err)
		return
	}
	f, _, err := a.runs.OpenFile(r.PathValue("id"), name)
	if err != nil {
		writeError(w, fileStatus(err), err)
		return
	}
	defer f.Close()
	serveFile(w, r, f, name)
}

// snapshots answers with the copies a run kept, with their hashes if the
// query asks for them.
func (a *api) snapshots(w http.ResponseWriter, r *http.Request) {
	hash, err := queryHash(r)
	if err != nil {
		writeError(w, http.StatusBadRequest, err)
		return
	}
	copies, err := a.runs.Snapshots(r.PathValue("id"), hash)
	if err != nil {
		writeError(w, fileStatus(err), err)
		return
	}
	body := struct {
		Snapshots []Snapshot `json:"snapshots"`
	}{Snapshots: make([]Snapshot, 0, len(copies))}
	for _, c := range copies {
		body.Snapshots = append(body.Snapshots, Snapshot{Number: c.Number, Path: c.Path, Copy: c.Copy, Size: c.Size, ModTime: c.ModTime.UTC(), SHA256: c.SHA256})
	}
	writeJSON(w, http.StatusOK, body)
}

// snapshotContent answers with the content of a copy a run kept.
func (a *api) snapshotContent(w http.ResponseWriter, r *http.Request) {
	n, err := strconv.Atoi(r.PathValue("n"))
	if err != nil || n < 1 {
		writeError(w, http.StatusNotFound, fmt.Errorf("snapshot %q: %w", r.PathValue("n"), fs.ErrNotExist))
		return
	}
	f, c, err := a.runs.OpenSnapshot(r.PathValue("id"), n)
	if err != nil {
		writeError(w, fileStatus(err), err)
		return
	}
	defer f.Close()
	serveFile(w, r, f, c.Path)
}

// fileStatus returns the HTTP status that answers err from reading a run's
// files.
func fileStatus(err error) int {
	switch {
	case errors.Is(err, fs.ErrNotExist):
		return http.StatusNotFound
	case errors.Is(err, runs.ErrNotFile):
		return http.StatusBadRequest
	}
	return statusFor(err)
}

// trace answers with a run's trace, as JSON Lines: the whole lines written
// so far, for a run still writing it.
func (a *api) trace(w http.ResponseWriter, r *http.Request) {
	run := r.PathValue("id")
	f, size, err := a.runs.OpenTrace(run)
	if err != nil {
		writeError(w, fileStatus(err), err)
		return
	}
	defer f.Close()
	info, err := f.Stat()
	if err != nil {
		writeError(w, http.StatusInternalServerError, err)
		return
	}
	serveDownload(w, r, "events-"+run+".jsonl", "application/jsonl", info.ModTime(), io.NewSectionReader(f, 0, size))
}

// serveFile sends the content of f, the file name, as a download that a
// browser neither displays nor runs, and answers range requests, so a
// preview can ask for the start of a file.
func serveFile(w http.ResponseWriter, r *http.Request, f *os.File, name string) {
	info, err := f.Stat()
	if err != nil {
		writeError(w, http.StatusInternalServerError, err)
		return
	}
	serveDownload(w, r, path.Base(name), "application/octet-stream", info.ModTime(), f)
}

// serveDownload sends content as the download filename, of type
// contentType, which a browser neither displays nor runs, answering range
// requests.
func serveDownload(w http.ResponseWriter, r *http.Request, filename, contentType string, modTime time.Time, content io.ReadSeeker) {
	h := w.Header()
	h.Set("Content-Type", contentType)
	h.Set("Content-Disposition", mime.FormatMediaType("attachment", map[string]string{"filename": filename}))
	h.Set("Content-Security-Policy", "default-src 'none'; sandbox")
	h.Set("Cache-Control", "no-store")
	http.ServeContent(w, r, "", modTime, content)
}

// queryPath returns the clean absolute path that the query's path gives,
// or def if it gives none and def is not "".
func queryPath(r *http.Request, def string) (string, error) {
	name := r.URL.Query().Get("path")
	switch {
	case name == "" && def != "":
		return def, nil
	case name == "":
		return "", fmt.Errorf("path is required: the file's absolute path")
	case !path.IsAbs(name):
		return "", fmt.Errorf("path %q is not absolute", name)
	}
	return path.Clean(name), nil
}

// queryHash reports whether the query asks for hashes.
func queryHash(r *http.Request) (bool, error) {
	value := r.URL.Query().Get("hash")
	if value == "" {
		return false, nil
	}
	hash, err := strconv.ParseBool(value)
	if err != nil {
		return false, fmt.Errorf("hash %q is not true or false", value)
	}
	return hash, nil
}
