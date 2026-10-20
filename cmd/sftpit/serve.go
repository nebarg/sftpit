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
	"strings"

	"golang.org/x/crypto/ssh"

	"sftpit/internal/backend"
	"sftpit/internal/config"
	"sftpit/internal/sftpproxy"
	"sftpit/internal/sshfront"
)

const serveUsage = `Usage: sftpit serve [flags]

Runs an SFTP server on a loopback address until interrupted. Files live in a
temporary workspace that is deleted when sftpit stops.

Flags:
  --config FILE        read settings and users from FILE
  --sftp-listen ADDR   listen on ADDR instead of the configured address
                       (default 127.0.0.1:2122; port 0 picks a free port)
  --seed-dir DIR       copy the files under DIR into the workspace at startup
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
		if errors.Is(err, backend.ErrUnsupportedFile) || errors.Is(err, errSeedHoldsWorkspace) {
			return exitUsage
		}
		return exitFailure
	}
	return exitOK
}

var errSeedHoldsWorkspace = errors.New("the seed directory contains the workspace, so it would be copied into itself")

// runServer serves SFTP from a new temporary workspace until ctx is
// cancelled, then shuts down and deletes the workspace.
func runServer(ctx context.Context, cfg *config.Config, stdout, stderr io.Writer) (err error) {
	logger := slog.New(slog.NewTextHandler(stderr, nil))

	workspace, err := os.MkdirTemp("", "sftpit-")
	if err != nil {
		return fmt.Errorf("create workspace: %w", err)
	}
	defer func() {
		if removeErr := os.RemoveAll(workspace); removeErr != nil && err == nil {
			err = fmt.Errorf("delete workspace: %w", removeErr)
		}
	}()

	hostKeyDir := cfg.HostKeyDir
	if hostKeyDir == "" {
		hostKeyDir = filepath.Join(workspace, "identity")
	}
	hostKeys, err := sshfront.LoadOrCreateHostKeys(hostKeyDir)
	if err != nil {
		return err
	}

	filesDir := filepath.Join(workspace, "fs")
	if err := os.Mkdir(filesDir, 0o700); err != nil {
		return fmt.Errorf("create workspace: %w", err)
	}
	root, err := os.OpenRoot(filesDir)
	if err != nil {
		return fmt.Errorf("open workspace: %w", err)
	}
	defer root.Close()
	embedded := backend.New(root)
	if cfg.SeedDir != "" {
		if within(workspace, cfg.SeedDir) {
			return errSeedHoldsWorkspace
		}
		if err := embedded.Seed(cfg.SeedDir); err != nil {
			return err
		}
	}
	for _, u := range cfg.Users {
		if err := embedded.MkdirAll(u.Home); err != nil {
			return fmt.Errorf("create home %s for %s: %w", u.Home, u.Name, err)
		}
	}

	srv, err := sshfront.New(sshfront.Config{
		HostKeys: hostKeys,
		Users:    cfg.Users,
		Handler: func(ctx context.Context, conn *sshfront.Conn, channel io.ReadWriteCloser) error {
			return sftpproxy.Serve(ctx, channel, embedded.Open(conn.Home()), sftpproxy.Options{Logger: logger})
		},
		Logger: logger,
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

	printBanner(stdout, ln.Addr().String(), workspace, hostKeys, cfg)

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

func printBanner(w io.Writer, addr, workspace string, hostKeys []ssh.Signer, cfg *config.Config) {
	fmt.Fprintf(w, "sftpit is serving SFTP on %s\n", addr)
	fmt.Fprintf(w, "  workspace: %s (deleted when sftpit stops)\n", workspace)
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
