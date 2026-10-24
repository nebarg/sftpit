package main

import (
	"cmp"
	"context"
	"errors"
	"flag"
	"fmt"
	"io"
	"log/slog"
	"net"
	"net/http"
	"os"
	"path/filepath"
	"strconv"
	"strings"
	"time"

	"golang.org/x/crypto/ssh"

	"github.com/nebarg/sftpit/internal/backend"
	"github.com/nebarg/sftpit/internal/config"
	"github.com/nebarg/sftpit/internal/control"
	"github.com/nebarg/sftpit/internal/faults"
	"github.com/nebarg/sftpit/internal/runs"
	"github.com/nebarg/sftpit/internal/sshfront"
)

const serveUsage = `Usage: sftpit serve [flags]

Runs an SFTP server on a loopback address until interrupted, with a control
API over HTTP that reports on the current run and resets it. Files live in a
temporary workspace that is deleted when sftpit stops, unless --data-dir
names one to keep.

Flags:
  --config FILE        read settings, users and scenarios from FILE
  --scenario NAME      inject the faults of the scenario NAME in the
                       config; without it, no faults are injected
  --seed N             pin the scenario's random decisions to seed N, in
                       place of its own seed or a fresh one every run
  --sftp-listen ADDR   listen on ADDR instead of the configured address
                       (default 127.0.0.1:2122; port 0 picks a free port)
  --http-listen ADDR   serve the control API on ADDR instead of the
                       configured address (default 127.0.0.1:8122)
  --seed-dir DIR       start every run with a copy of the files under DIR,
                       as they are at startup
  --data-dir DIR       keep the workspace in DIR, with its host keys and its
                       last five runs; DIR must be empty or a workspace
  --env-file FILE      also read secrets from FILE; may be repeated, and
                       later files override earlier ones
  --ready-file FILE    once listening, write the addresses, workspace and
                       host-key fingerprints to FILE as JSON, for a test
                       harness or sftpit reset; FILE is removed at exit
`

func serve(ctx context.Context, args []string, stdout, stderr io.Writer) int {
	flags := flag.NewFlagSet("serve", flag.ContinueOnError)
	flags.SetOutput(io.Discard)
	opts := config.Options{}
	flags.StringVar(&opts.ConfigFile, "config", "", "")
	flags.StringVar(&opts.SFTPListen, "sftp-listen", "", "")
	flags.StringVar(&opts.HTTPListen, "http-listen", "", "")
	flags.StringVar(&opts.SeedDir, "seed-dir", "", "")
	flags.StringVar(&opts.DataDir, "data-dir", "", "")
	flags.StringVar(&opts.Scenario, "scenario", "", "")
	flags.Func("seed", "", func(s string) error {
		seed, err := parseSeed(s)
		if err != nil {
			return err
		}
		opts.Seed = &seed
		return nil
	})
	var readyPath string
	flags.StringVar(&readyPath, "ready-file", "", "")
	flags.Func("env-file", "", func(name string) error {
		opts.EnvFiles = append(opts.EnvFiles, name)
		return nil
	})
	if err := flags.Parse(args); err != nil {
		if errors.Is(err, flag.ErrHelp) {
			fmt.Fprint(stdout, serveUsage)
			return exitOK
		}
		fmt.Fprintf(stderr, "sftpit serve: %v\n\n%s", err, serveUsage)
		return exitUsage
	}
	if flags.NArg() > 0 {
		fmt.Fprintf(stderr, "sftpit serve: unexpected arguments %q\n", flags.Args())
		return exitUsage
	}
	if opts.Seed != nil && opts.Scenario == "" {
		fmt.Fprintln(stderr, "sftpit serve: --seed needs --scenario, whose random decisions it pins")
		return exitUsage
	}
	if readyPath != "" {
		if err := prepareReadyFile(readyPath); err != nil {
			fmt.Fprintf(stderr, "sftpit serve: --ready-file: %v\n", err)
			return exitUsage
		}
	}

	cfg, err := config.Load(opts)
	if err != nil {
		fmt.Fprintf(stderr, "sftpit serve: %v\n", err)
		return exitUsage
	}
	for _, warning := range cfg.Warnings {
		fmt.Fprintf(stderr, "sftpit serve: warning: %s\n", warning)
	}
	if err := runServer(ctx, cfg, readyPath, stdout, stderr); err != nil {
		fmt.Fprintf(stderr, "sftpit serve: %v\n", err)
		if errors.Is(err, backend.ErrUnsupportedFile) || errors.Is(err, backend.ErrLimit) ||
			errors.Is(err, errSeedHoldsWorkspace) || errors.Is(err, runs.ErrNotWorkspace) {
			return exitUsage
		}
		return exitFailure
	}
	return exitOK
}

var errSeedHoldsWorkspace = errors.New("the seed directory contains the workspace, so it would be copied into itself")

// runServer serves SFTP from runs in the configured workspace, or in a
// temporary one, and the control API, until ctx is cancelled, then shuts
// down and deletes a temporary workspace. If readyPath is set, it writes
// the ready file there once it listens, and removes it as it shuts down.
func runServer(ctx context.Context, cfg *config.Config, readyPath string, stdout, stderr io.Writer) (err error) {
	logger := slog.New(slog.NewTextHandler(stderr, nil))

	workspace, err := openWorkspace(cfg.DataDir)
	if err != nil {
		return err
	}
	defer func() {
		if closeErr := workspace.Close(); closeErr != nil && err == nil {
			err = closeErr
		}
	}()
	if cfg.SeedDir != "" && within(workspace.Dir(), cfg.SeedDir) {
		return errSeedHoldsWorkspace
	}
	hostKeys, err := sshfront.LoadOrCreateHostKeys(cmp.Or(cfg.HostKeyDir, workspace.IdentityDir()))
	if err != nil {
		return err
	}

	manager, err := runs.Start(workspace, runs.Options{
		Server:    sshfront.Config{HostKeys: hostKeys, Users: cfg.Users, Logger: logger},
		SeedDir:   cfg.SeedDir,
		Limits:    cfg.Limits,
		Scenarios: cfg.Scenarios,
		Scenario:  cfg.Scenario,
		Seed:      cfg.Seed,
		Logger:    logger,
	})
	if err != nil {
		return err
	}
	defer func() {
		if closeErr := manager.Close(); closeErr != nil && err == nil {
			err = closeErr
		}
	}()
	sftpLn, err := listenLoopback("sftp_listen", cfg.SFTPListen)
	if err != nil {
		return err
	}
	httpLn, err := listenLoopback("http_listen", cfg.HTTPListen)
	if err != nil {
		sftpLn.Close()
		return err
	}
	// Clients that connect once the file exists wait in the listeners'
	// backlogs until the servers accept them.
	if readyPath != "" {
		ready := newReadyFile(sftpLn.Addr().String(), httpLn.Addr().String(), workspace.Dir(), hostKeys)
		if err := writeReadyFile(readyPath, ready); err != nil {
			sftpLn.Close()
			httpLn.Close()
			return err
		}
	}

	srv := manager.Server()
	sftpServed := make(chan error, 1)
	go func() { sftpServed <- srv.Serve(sftpLn) }()
	api := &http.Server{
		Handler:           control.Handler(manager),
		ReadHeaderTimeout: 10 * time.Second,
		ErrorLog:          slog.NewLogLogger(logger.Handler(), slog.LevelWarn),
	}
	apiServed := make(chan error, 1)
	go func() { apiServed <- api.Serve(httpLn) }()

	printBanner(stdout, sftpLn.Addr().String(), httpLn.Addr().String(), workspace, manager.Status().Run, hostKeys, cfg)

	select {
	case <-ctx.Done():
		fmt.Fprintln(stdout, "Stopping.")
	case err = <-sftpServed:
		sftpServed = nil
	case err = <-apiServed:
		apiServed = nil
	}
	if readyPath != "" {
		if removeErr := os.Remove(readyPath); removeErr != nil {
			err = errors.Join(err, fmt.Errorf("remove ready file: %w", removeErr))
		}
	}
	err = errors.Join(err, api.Close(), srv.Close())
	if sftpServed != nil {
		<-sftpServed
	}
	if apiServed != nil {
		<-apiServed
	}
	return err
}

// parseSeed parses a seed given on the command line.
func parseSeed(s string) (faults.Seed, error) {
	n, err := strconv.ParseUint(s, 10, 64)
	if err != nil {
		return 0, errors.New("a seed is a whole number from 0 to 18446744073709551615")
	}
	return faults.Seed(n), nil
}

func openWorkspace(dataDir string) (*runs.Workspace, error) {
	if dataDir == "" {
		return runs.TempWorkspace()
	}
	return runs.OpenWorkspace(dataDir)
}

// within reports whether name is dir or lies under it, once symlinks in
// both are resolved.
func within(name, dir string) bool {
	name, err := filepath.EvalSymlinks(name)
	if err != nil {
		return false
	}
	dir, err = filepath.EvalSymlinks(dir)
	if err != nil {
		return false
	}
	rel, err := filepath.Rel(dir, name)
	return err == nil && filepath.IsLocal(rel)
}

// listenLoopback listens on addr, the value of setting, and refuses an
// address that turns out not to be loopback, as a host name could.
func listenLoopback(setting, addr string) (net.Listener, error) {
	ln, err := net.Listen("tcp", addr)
	if err != nil {
		return nil, err
	}
	if tcp, ok := ln.Addr().(*net.TCPAddr); !ok || !tcp.IP.IsLoopback() {
		ln.Close()
		return nil, fmt.Errorf("%s %q resolved to %v, which is not a loopback address", setting, addr, ln.Addr())
	}
	return ln, nil
}

func printBanner(w io.Writer, addr, apiAddr string, workspace *runs.Workspace, run runs.Run, hostKeys []ssh.Signer, cfg *config.Config) {
	fmt.Fprintf(w, "sftpit is serving SFTP on %s\n", addr)
	fmt.Fprintf(w, "  control API: http://%s/api/v1/\n", apiAddr)
	if workspace.Temporary() {
		fmt.Fprintf(w, "  workspace: %s (deleted when sftpit stops)\n", workspace.Dir())
	} else {
		fmt.Fprintf(w, "  workspace: %s (kept, with its last five runs)\n", workspace.Dir())
	}
	fmt.Fprintf(w, "  run: %s\n", run.ID)
	if s := run.Scenario; s.Name != "" {
		rules := "rules"
		if len(cfg.Rules()) == 1 {
			rules = "rule"
		}
		fmt.Fprintf(w, "  scenario: %s (%d fault %s)\n", s.Name, len(cfg.Rules()), rules)
		if s.Pinned {
			fmt.Fprintf(w, "  seed: %d (pinned)\n", s.Seed)
		} else {
			fmt.Fprintf(w, "  seed: %d (fresh; --seed %[1]d repeats its decisions)\n", s.Seed)
		}
	}
	if cfg.SeedDir != "" {
		fmt.Fprintf(w, "  seeded from: %s\n", cfg.SeedDir)
	}
	fmt.Fprintln(w, "  host keys:")
	for _, key := range hostKeys {
		fmt.Fprintf(w, "    %s %s\n", key.PublicKey().Type(), ssh.FingerprintSHA256(key.PublicKey()))
	}
	if cfg.DefaultCredentials {
		fmt.Fprintf(w, "  login: user %q, password %q\n", config.DefaultUser, config.DefaultPassword)
	} else {
		var users []string
		for _, u := range cfg.Users {
			users = append(users, u.Name+" ("+loginMethods(u)+")")
		}
		fmt.Fprintf(w, "  users: %s\n", strings.Join(users, ", "))
	}
	fmt.Fprintln(w, "Press Ctrl+C to stop.")
}

func loginMethods(u sshfront.User) string {
	switch {
	case u.Password != "" && len(u.AuthorizedKeys) > 0:
		return "password or key"
	case u.Password != "":
		return "password"
	}
	return "key"
}
