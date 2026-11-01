package sftpproxy_test

import (
	"strings"
	"sync/atomic"
	"testing"
	"testing/synctest"

	"github.com/nebarg/sftpit/internal/sftpproxy"
	"github.com/nebarg/sftpit/internal/sftpwire"
)

func TestReadOnlyRefusesChangesBeforeFaults(t *testing.T) {
	open := func(path string, flags uint32) *sftpwire.Open { return &sftpwire.Open{Path: path, Flags: flags} }
	rename := func(from, to string) *sftpwire.Rename { return &sftpwire.Rename{OldPath: from, NewPath: to} }
	tests := []struct {
		name     string
		readOnly []string
		request  sftpwire.Packet
		denied   bool
	}{
		{"an open for reading", []string{"/ref"}, open("/ref/a", sftpwire.OpenRead), false},
		{"an open for writing", []string{"/ref"}, open("/ref/a", sftpwire.OpenWrite), true},
		{"an open for appending", []string{"/ref"}, open("/ref/a", sftpwire.OpenRead|sftpwire.OpenAppend), true},
		{"an open that creates", []string{"/ref"}, open("/ref/a", sftpwire.OpenRead|sftpwire.OpenCreate), true},
		{"an open that truncates", []string{"/ref"}, open("/ref/a", sftpwire.OpenRead|sftpwire.OpenTruncate), true},
		{"an exclusive open", []string{"/ref"}, open("/ref/a", sftpwire.OpenRead|sftpwire.OpenExclusive), true},
		{"a write beside the prefix", []string{"/ref"}, open("/ref-old/a", sftpwire.OpenWrite), false},
		{"a write anywhere under /", []string{"/"}, open("/out/a", sftpwire.OpenWrite), true},
		{"a stat", []string{"/ref"}, &sftpwire.Stat{Path: "/ref/a"}, false},
		{"a listing", []string{"/ref"}, &sftpwire.OpenDir{Path: "/ref"}, false},
		{"a setstat", []string{"/ref"}, &sftpwire.SetStat{Path: "/ref/a"}, true},
		{"a remove", []string{"/ref"}, &sftpwire.Remove{Path: "/ref/a"}, true},
		{"a remove elsewhere", []string{"/ref"}, &sftpwire.Remove{Path: "/out/a"}, false},
		{"a mkdir of the prefix", []string{"/ref"}, &sftpwire.Mkdir{Path: "/ref"}, true},
		{"a mkdir beneath it", []string{"/ref"}, &sftpwire.Mkdir{Path: "/ref/new"}, true},
		{"an rmdir of the prefix", []string{"/ref"}, &sftpwire.Rmdir{Path: "/ref"}, true},
		{"a mkdir above it", []string{"/data/ref"}, &sftpwire.Mkdir{Path: "/data"}, false},
		{"a rename out", []string{"/ref"}, rename("/ref/a", "/out/a"), true},
		{"a rename in", []string{"/ref"}, rename("/out/a", "/ref/a"), true},
		{"a posix rename in", []string{"/ref"}, &sftpwire.PosixRename{OldPath: "/out/a", NewPath: "/ref/a"}, true},
		{"a rename of a directory above it", []string{"/data/ref"}, rename("/data", "/old"), true},
		{"a rename onto a directory above it", []string{"/data/ref"}, rename("/new", "/data"), true},
		{"a rename beside it", []string{"/data/ref"}, rename("/data/a", "/data/b"), false},
		{"a relative path", []string{"/ref"}, &sftpwire.Remove{Path: "ref/a"}, true},
		{"a path with ..", []string{"/ref"}, &sftpwire.Remove{Path: "/out/../ref/a"}, true},
		{"the second prefix", []string{"/ref", "/archive"}, &sftpwire.Remove{Path: "/archive/a"}, true},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			synctest.Test(t, func(t *testing.T) {
				var logs syncBuffer
				var asked atomic.Int32
				p, fb := startProxyOnFake(t, sftpproxy.Options{
					ReadOnly: tt.readOnly,
					Faults: func(sftpproxy.Request) sftpproxy.Action {
						asked.Add(1)
						return nil
					},
					Logger: logs.logger(),
				})

				p.client.send(t, 1, tt.request)
				if tt.denied {
					p.client.assertStatus(t, 1, sftpwire.StatusPermissionDenied, "Permission denied")
					fb.assertNoRequest(t)
					if asked.Load() != 0 {
						t.Error("Faults was asked about a request the policy refused")
					}
					logs.assertLogged(t, `msg="policy denied" request=`)
					return
				}
				req := fb.next(t)
				if req.packet.Type() != tt.request.Type() {
					t.Fatalf("backend received %v, want %v", req.packet.Type(), tt.request.Type())
				}
				fb.reply(t, req.id, status(sftpwire.StatusOK))
				p.client.assertStatus(t, 1, sftpwire.StatusOK, "Success")
				if strings.Contains(logs.String(), "policy denied") {
					t.Errorf("logged a denial:\n%s", logs.String())
				}
			})
		})
	}
}

func TestReadOnlyRefusesAnFSetStatOnAHandleOpenedForReading(t *testing.T) {
	synctest.Test(t, func(t *testing.T) {
		var logs syncBuffer
		p, fb := startProxyOnFake(t, sftpproxy.Options{ReadOnly: []string{"/f"}, Logger: logs.logger()})
		openForDownload(t, p, fb)

		p.client.send(t, 2, &sftpwire.FSetStat{Handle: "h"})
		p.client.assertStatus(t, 2, sftpwire.StatusPermissionDenied, "Permission denied")
		fb.assertNoRequest(t)
		logs.assertLogged(t, `msg="policy denied" request=SSH_FXP_FSETSTAT path=/f read_only=/f`)
	})
}

func TestReadOnlyLogsARenameWithBothPaths(t *testing.T) {
	synctest.Test(t, func(t *testing.T) {
		var logs syncBuffer
		p, _ := startProxyOnFake(t, sftpproxy.Options{ReadOnly: []string{"/ref"}, Logger: logs.logger()})

		p.client.send(t, 1, &sftpwire.Rename{OldPath: "/out/a", NewPath: "/ref/a"})
		p.client.assertStatus(t, 1, sftpwire.StatusPermissionDenied, "Permission denied")
		logs.assertLogged(t, `msg="policy denied" request=SSH_FXP_RENAME path=/out/a target=/ref/a read_only=/ref`)
	})
}
