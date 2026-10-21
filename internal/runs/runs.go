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

	"github.com/nebarg/sftpit/internal/backend"
	"github.com/nebarg/sftpit/internal/sftpproxy"
	"github.com/nebarg/sftpit/internal/sshfront"
)

// Handler returns an sshfront.Handler that relays each SFTP session through
// sftpproxy to a new session on embedded, starting in the user's home
// directory. Each session runs with opts and its own connection as
// opts.Conn, so a Drop or Freeze acts on the client that caused it, and
// takes its snapshots from embedded's files.
func Handler(embedded *backend.Embedded, opts sftpproxy.Options) sshfront.Handler {
	opts.Snapshot = func(path string) (sftpproxy.Snapshot, error) {
		size, sum, err := embedded.Digest(path)
		return sftpproxy.Snapshot{Size: size, SHA256: sum}, err
	}
	return func(ctx context.Context, conn *sshfront.Conn, channel io.ReadWriteCloser) error {
		opts := opts
		opts.Conn = conn
		return sftpproxy.Serve(ctx, channel, embedded.Open(conn.Home()), opts)
	}
}
