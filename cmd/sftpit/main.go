// Sftpit runs a local SFTP server for developing and testing file
// integrations, with faults that can be injected on demand.
package main

import (
	"context"
	"fmt"
	"io"
	"os"
	"os/signal"
	"runtime/debug"
	"syscall"
)

const (
	exitOK = 0
	// exitUsage reports an invalid command line or configuration.
	exitUsage = 2
	// exitFailure reports that sftpit could not start or keep running.
	exitFailure = 3
)

const usage = `Usage: sftpit <command>

Commands:
  serve     Run the SFTP server
  version   Print the build version
  help      Show this help

Run "sftpit serve --help" for the server's flags.
`

func main() {
	ctx, stop := signal.NotifyContext(context.Background(), os.Interrupt, syscall.SIGTERM)
	// After the first signal, restore the default handling, so a second one
	// stops sftpit even if shutting down hangs.
	go func() {
		<-ctx.Done()
		stop()
	}()
	os.Exit(run(ctx, os.Args[1:], os.Stdout, os.Stderr))
}

func run(ctx context.Context, args []string, stdout, stderr io.Writer) int {
	if len(args) == 0 {
		fmt.Fprint(stderr, usage)
		return exitUsage
	}
	if args[0] == "serve" {
		return serve(ctx, args[1:], stdout, stderr)
	}
	if len(args) > 1 {
		fmt.Fprintf(stderr, "sftpit %s: unexpected arguments %q\n", args[0], args[1:])
		return exitUsage
	}

	switch args[0] {
	case "version":
		fmt.Fprintln(stdout, "sftpit", buildVersion())
		return exitOK
	case "help", "-h", "--help":
		fmt.Fprint(stdout, usage)
		return exitOK
	default:
		fmt.Fprintf(stderr, "sftpit: unknown command %q\n\n%s", args[0], usage)
		return exitUsage
	}
}

func buildVersion() string {
	info, ok := debug.ReadBuildInfo()
	if !ok {
		return "unknown"
	}

	var revision string
	var modified bool
	for _, setting := range info.Settings {
		switch setting.Key {
		case "vcs.revision":
			revision = setting.Value
		case "vcs.modified":
			modified = setting.Value == "true"
		}
	}

	if revision == "" {
		return info.Main.Version
	}
	if len(revision) > 12 {
		revision = revision[:12]
	}
	if modified {
		revision += "-dirty"
	}
	return fmt.Sprintf("%s (%s)", info.Main.Version, revision)
}
