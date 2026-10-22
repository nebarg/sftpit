package main

import (
	"context"
	"errors"
	"flag"
	"fmt"
	"io"
	"log/slog"
	"net"
	"os"
	"path/filepath"
	"strconv"
	"strings"

	"golang.org/x/crypto/ssh"

	"github.com/nebarg/sftpit/internal/backend"
	"github.com/nebarg/sftpit/internal/config"
	"github.com/nebarg/sftpit/internal/faults"
	"github.com/nebarg/sftpit/internal/runs"
	"github.com/nebarg/sftpit/internal/sftpproxy"
	"github.com/nebarg/sftpit/internal/sshfront"
)

const serveUsage = `Usage: sftpit serve [flags]

Runs an SFTP server on a loopback address until interrupted. Files live in a
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
  --seed-dir DIR       copy the files under DIR into the workspace at startup
  --data-dir DIR       keep the workspace in DIR, with its host keys and its
                       last five runs; DIR must be empty or a workspace
  --env-file FILE      also read secrets from FILE; may be repeated, and
                       later files override earlier ones
`

func serve(ctx context.Context, args []string, stdout, stderr io.Writer) int {
	flags := flag.NewFlagSet("serve", flag.ContinueOnError)
	flags.SetOutput(io.Discard)
	opts := config.Options{}
	flags.StringVar(&opts.ConfigFile, "config", "", "")
	flags.StringVar(&opts.SFTPListen, "sftp-listen", "", "")
	flags.StringVar(&opts.SeedDir, "seed-dir", "", "")
	flags.StringVar(&opts.DataDir, "data-dir", "", "")
	flags.StringVar(&opts.Scenario, "scenario", "", "")
	flags.Func("seed", "", func(s string) error {
		n, err := strconv.ParseUint(s, 10, 64)
		if err != nil {
			return errors.New("a seed is a whole number from 0 to 18446744073709551615")
		}
		seed := faults.Seed(n)
		opts.Seed = &seed
		return nil
	})
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

	cfg, err := config.Load(opts)
	if err != nil {
		fmt.Fprintf(stderr, "sftpit serve: %v\n", err)
		return exitUsage
	}
	for _, warning := range cfg.Warnings {
		fmt.Fprintf(stderr, "sftpit serve: warning: %s\n", warning)
	}
	if err := runServer(ctx, cfg, stdout, stderr); err != nil {
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

// runServer serves SFTP from a new run in the configured workspace, or in a
// temporary one, until ctx is cancelled, then shuts down and deletes a
// temporary workspace.
func runServer(ctx context.Context, cfg *config.Config, stdout, stderr io.Writer) (err error) {
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
	scenario := runs.Scenario{Name: cfg.Scenario}
	switch {
	case cfg.Scenario == "":
	case cfg.Seed != nil:
		scenario.Seed, scenario.Pinned = *cfg.Seed, true
	default:
		scenario.Seed = faults.RandomSeed()
	}
	run, err := workspace.NewRun(scenario)
	if err != nil {
		return err
	}

	hostKeyDir := cfg.HostKeyDir
	if hostKeyDir == "" {
		hostKeyDir = workspace.IdentityDir()
	}
	hostKeys, err := sshfront.LoadOrCreateHostKeys(hostKeyDir)
	if err != nil {
		return err
	}

	root, err := os.OpenRoot(run.Files)
	if err != nil {
		return fmt.Errorf("open run files: %w", err)
	}
	defer root.Close()
	embedded, err := backend.New(root, backend.Options{Limits: cfg.Limits, Logger: logger})
	if err != nil {
		return err
	}
	if cfg.SeedDir != "" {
		if err := embedded.Seed(cfg.SeedDir); err != nil {
			return err
		}
	}
	for _, u := range cfg.Users {
		if err := embedded.MkdirAll(u.Home); err != nil {
			return fmt.Errorf("create home %s for %s: %w", u.Home, u.Name, err)
		}
	}

	var rules *faults.Engine
	if cfg.Scenario != "" {
		if rules, err = faults.New(cfg.Rules, scenario.Seed, logger); err != nil {
			return err
		}
	}
	srv, err := sshfront.New(sshfront.Config{
		HostKeys: hostKeys,
		Users:    cfg.Users,
		Handler:  runs.Handler(run, embedded, rules, sftpproxy.Options{Logger: logger}),
		Logger:   logger,
	})
	if err != nil {
		return err
	}
	ln, err := listenLoopback(cfg.SFTPListen)
	if err != nil {
		return err
	}
	served := make(chan error, 1)
	go func() { served <- srv.Serve(ln) }()

	printBanner(stdout, ln.Addr().String(), workspace, run, hostKeys, cfg)

	select {
	case <-ctx.Done():
		fmt.Fprintln(stdout, "Stopping.")
		closeErr := srv.Close()
		<-served
		return closeErr
	case err := <-served:
		srv.Close()
		return err
	}
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

// listenLoopback listens on addr and refuses an address that turns out not
// to be loopback, as a host name could.
func listenLoopback(addr string) (net.Listener, error) {
	ln, err := net.Listen("tcp", addr)
	if err != nil {
		return nil, err
	}
	if tcp, ok := ln.Addr().(*net.TCPAddr); !ok || !tcp.IP.IsLoopback() {
		ln.Close()
		return nil, fmt.Errorf("sftp_listen %q resolved to %v, which is not a loopback address", addr, ln.Addr())
	}
	return ln, nil
}

func printBanner(w io.Writer, addr string, workspace *runs.Workspace, run *runs.Run, hostKeys []ssh.Signer, cfg *config.Config) {
	fmt.Fprintf(w, "sftpit is serving SFTP on %s\n", addr)
	if workspace.Temporary() {
		fmt.Fprintf(w, "  workspace: %s (deleted when sftpit stops)\n", workspace.Dir())
	} else {
		fmt.Fprintf(w, "  workspace: %s (kept, with its last five runs)\n", workspace.Dir())
	}
	fmt.Fprintf(w, "  run: %s\n", run.ID)
	if s := run.Scenario; s.Name != "" {
		rules := "rules"
		if len(cfg.Rules) == 1 {
			rules = "rule"
		}
		fmt.Fprintf(w, "  scenario: %s (%d fault %s)\n", s.Name, len(cfg.Rules), rules)
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
