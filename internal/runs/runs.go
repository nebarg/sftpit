// Package runs serves the runs of a workspace. A Manager serves them one at
// a time through its own SSH server, each run starting from a snapshot of
// the seed, and resets to the next run, changes a run's rules and releases
// its stalls. Each session passes through the proxy, which can inject
// faults, on its way to the embedded backend, the connection hooks inject
// faults as clients connect and log in, and the files that faulted handles
// leave behind are snapshotted from the workspace. The workspace is a
// directory that one process at a time locks, holding the host keys and the
// files of each run.
package runs

import (
	"context"
	"io"
	"log/slog"

	"github.com/nebarg/sftpit/internal/backend"
	"github.com/nebarg/sftpit/internal/faults"
	"github.com/nebarg/sftpit/internal/sftpproxy"
	"github.com/nebarg/sftpit/internal/sshfront"
)

// Handler returns an sshfront.Handler that relays each SFTP session of run
// through sftpproxy to a new session on embedded, which serves the run's
// files, starting in the user's home directory. Each session runs with opts,
// its own connection as opts.Conn, so a Drop or Freeze acts on the client
// that caused it, and the server that accepted the connection as
// opts.Listener. Its faults and timers come from rules, for the user and key
// it logged in with and the time it did, including the timers of rules that
// a change applies during the session, and its stalls and freezes end when
// rules releases them; or they come from opts if rules is nil. Each session
// logs with the connection's ID and user, as the SSH server does.
// Snapshots hold back every session's changes to their file, and keep copies
// in the run's snapshots directory.
func Handler(run *Run, embedded *backend.Embedded, rules *faults.Engine, opts sftpproxy.Options) sshfront.Handler {
	logger := opts.Logger
	if logger == nil {
		logger = slog.Default()
	}
	snaps := &snapshots{run: run, embedded: embedded, logger: logger, budget: maxCopyBytes}
	opts.Snapshot = snaps.take
	return func(ctx context.Context, conn *sshfront.Conn, channel io.ReadWriteCloser) error {
		opts := opts
		opts.Conn, opts.Listener = conn, conn.Server()
		opts.Logger = logger.With("conn", conn.ID(), "user", conn.User())
		if rules != nil {
			s := rules.Session(faults.Client{User: conn.User(), KeyFingerprint: conn.KeyFingerprint(), Connection: conn.ID(), Authenticated: conn.Authenticated()})
			defer s.End()
			opts.Faults, opts.Timers, opts.MoreTimers, opts.Released = s.Decide, s.Timers(), s.MoreTimers(), rules.Released
		}
		return sftpproxy.Serve(ctx, channel, embedded.Open(conn.Home()), opts)
	}
}
