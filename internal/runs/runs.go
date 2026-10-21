// Package runs connects the SFTP sessions of a run to the workspace it
// serves: each session passes through the proxy, which can inject faults,
// on its way to the embedded backend, and the files that faulted handles
// leave behind are snapshotted from the workspace. It also keeps the
// workspace itself: a directory that one process at a time locks, holding
// the host keys and the files of each run.
package runs

import (
	"context"
	"io"
	"log/slog"

	"github.com/nebarg/sftpit/internal/backend"
	"github.com/nebarg/sftpit/internal/sftpproxy"
	"github.com/nebarg/sftpit/internal/sshfront"
)

// Handler returns an sshfront.Handler that relays each SFTP session of run
// through sftpproxy to a new session on embedded, which serves the run's
// files, starting in the user's home directory. Each session runs with opts
// and its own connection as opts.Conn, so a Drop or Freeze acts on the
// client that caused it. Snapshots hold back every session's changes to
// their file, and keep copies in the run's snapshots directory.
func Handler(run *Run, embedded *backend.Embedded, opts sftpproxy.Options) sshfront.Handler {
	logger := opts.Logger
	if logger == nil {
		logger = slog.Default()
	}
	snaps := &snapshots{run: run, embedded: embedded, logger: logger, budget: maxCopyBytes}
	opts.Snapshot = snaps.take
	return func(ctx context.Context, conn *sshfront.Conn, channel io.ReadWriteCloser) error {
		opts := opts
		opts.Conn = conn
		return sftpproxy.Serve(ctx, channel, embedded.Open(conn.Home()), opts)
	}
}
