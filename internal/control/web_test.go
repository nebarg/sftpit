package control_test

import (
	"io"
	"net/http"
	"net/http/httptest"
	"regexp"
	"strings"
	"testing"

	"github.com/nebarg/sftpit/internal/control"
	"github.com/nebarg/sftpit/internal/runs"
)

func TestTheDashboardIsServedUnderItsPolicy(t *testing.T) {
	_, api := start(t, runs.Options{})
	for path, contentType := range map[string]string{
		"/":           "text/html; charset=utf-8",
		"/ui/app.js":  "text/javascript; charset=utf-8",
		"/ui/app.css": "text/css; charset=utf-8",
	} {
		resp := get(t, api, path, nil)
		h := resp.Header
		if resp.StatusCode != http.StatusOK || h.Get("Content-Type") != contentType {
			t.Errorf("GET %s = %s with %q, want 200 with %q", path, resp.Status, h.Get("Content-Type"), contentType)
		}
		if csp := h.Get("Content-Security-Policy"); !strings.Contains(csp, "default-src 'self'") || !strings.Contains(csp, "frame-ancestors 'none'") {
			t.Errorf("GET %s has the policy %q, want only its own sources and no framing", path, csp)
		}
		if h.Get("X-Content-Type-Options") != "nosniff" || h.Get("Cache-Control") != "no-cache" || h.Get("Referrer-Policy") != "no-referrer" {
			t.Errorf("GET %s has the headers %v", path, h)
		}
	}
	for _, path := range []string{"/ui/test/format.test.js", "/ui/missing.js", "/index.html.bak", "/api/v1/missing"} {
		if resp := get(t, api, path, nil); resp.StatusCode != http.StatusNotFound {
			t.Errorf("GET %s = %s, want 404", path, resp.Status)
		}
	}
	req := httptest.NewRequest(http.MethodGet, "/", nil)
	req.Host = "attacker.example"
	rec := httptest.NewRecorder()
	api.ServeHTTP(rec, req)
	if rec.Code != http.StatusForbidden {
		t.Errorf("GET / from another host = %d, want 403", rec.Code)
	}
}

// The policy refuses inline scripts, styles and handlers, so the page must
// not need them.
func TestTheDashboardPageNeedsNothingInline(t *testing.T) {
	_, api := start(t, runs.Options{})
	page := body(t, get(t, api, "/", nil))
	for _, inline := range []*regexp.Regexp{
		regexp.MustCompile(`<script(?:\s[^>]*)?>\s*[^<\s]`),
		regexp.MustCompile(`<style`),
		regexp.MustCompile(`\sstyle=`),
		regexp.MustCompile(`\son[a-z]+=`),
		regexp.MustCompile(`(?:src|href)="(?:https?:)?//`),
	} {
		if loc := inline.FindStringIndex(page); loc != nil {
			t.Errorf("the page has %q, which its policy would block", page[loc[0]:min(loc[1]+20, len(page))])
		}
	}
}

// Every file that the page and its modules load is embedded.
func TestEveryFileTheDashboardLoadsIsServed(t *testing.T) {
	_, api := start(t, runs.Options{})
	refs := regexp.MustCompile(`(?:src|href)="(/ui/[^"]+)"|from "\./([^"]+)"`)
	queue := []string{"/"}
	seen := map[string]bool{"/": true}
	for len(queue) > 0 {
		path := queue[0]
		queue = queue[1:]
		resp := get(t, api, path, nil)
		if resp.StatusCode != http.StatusOK {
			t.Errorf("GET %s = %s, want 200", path, resp.Status)
			continue
		}
		for _, m := range refs.FindAllStringSubmatch(body(t, resp), -1) {
			next := m[1]
			if next == "" {
				next = "/ui/" + m[2]
			}
			if !seen[next] {
				seen[next] = true
				queue = append(queue, next)
			}
		}
	}
	for _, module := range []string{"/ui/app.js", "/ui/api.js", "/ui/format.js", "/ui/timeline.js", "/ui/preview.js", "/ui/tree.js", "/ui/rules.js", "/ui/connection.js", "/ui/dom.js", "/ui/edit.js", "/ui/builder.js", "/ui/chaos.js"} {
		if !seen[module] {
			t.Errorf("the page does not load %s", module)
		}
	}
}

func TestServerReportsHowToConnect(t *testing.T) {
	m, _ := start(t, runs.Options{})
	server := control.Server{
		SFTPAddress:  "127.0.0.1:2122",
		Profile:      "loopback",
		ControlHosts: []string{},
		HostKeys:     []control.HostKey{{Type: "ssh-ed25519", Fingerprint: "SHA256:x"}},
		Users:        []control.User{{Name: "test", Home: "/", Password: true}},
		DefaultLogin: &control.Login{User: "test", Password: "test"},
		ReadOnly:     []control.ReadOnly{{PathPrefix: "/reference"}},
		Workspace:    "/tmp/w",
	}
	api := control.Handler(m, control.Options{Server: server})
	code, body := call(t, api, "GET", "/api/v1/server", "")
	want := map[string]any{
		"sftp_address":  "127.0.0.1:2122",
		"profile":       "loopback",
		"control_hosts": []any{},
		"host_keys":     []any{map[string]any{"type": "ssh-ed25519", "fingerprint": "SHA256:x"}},
		"users":         []any{map[string]any{"name": "test", "home": "/", "password": true, "keys": 0}},
		"default_login": map[string]any{"user": "test", "password": "test"},
		"read_only":     []any{map[string]any{"path_prefix": "/reference"}},
		"workspace":     "/tmp/w",
	}
	if code != http.StatusOK || !equalJSON(body, want) {
		t.Errorf("GET /api/v1/server = %d %v, want %v", code, body, want)
	}
}

func body(t *testing.T, resp *http.Response) string {
	t.Helper()
	b, err := io.ReadAll(resp.Body)
	if err != nil {
		t.Fatal(err)
	}
	return string(b)
}
