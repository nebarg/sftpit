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

// fileStatus returns the HTTP status that answers err from reading a file.
func fileStatus(err error) int {
	switch {
	case errors.Is(err, fs.ErrNotExist):
		return http.StatusNotFound
	case errors.Is(err, runs.ErrNotFile):
		return http.StatusBadRequest
	}
	return statusFor(err)
}

// serveFile sends f, the file at name, as a download.
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
		return "", errors.New("path is required: the file's absolute path")
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
