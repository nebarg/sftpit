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
  reset     Start the next run of a running server
  config    Check or explain a configuration file
  version   Print the build version
  help      Show this help

Run "sftpit serve --help" for the server's flags, "sftpit reset --help" for
a reset's, and "sftpit config --help" for the configuration commands.
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
	switch args[0] {
	case "serve":
		return serve(ctx, args[1:], stdout, stderr)
	case "reset":
		return resetCommand(ctx, args[1:], stdout, stderr)
	case "config":
		return configCommand(args[1:], stdout, stderr)
	case "version", "help", "-h", "--help":
		if len(args) > 1 {
			fmt.Fprintf(stderr, "sftpit %s: unexpected arguments %q\n", args[0], args[1:])
			return exitUsage
		}
		if args[0] == "version" {
			fmt.Fprintln(stdout, "sftpit", buildVersion())
		} else {
			fmt.Fprint(stdout, usage)
		}
		return exitOK
	}
	fmt.Fprintf(stderr, "sftpit: unknown command %q\n\n%s", args[0], usage)
	return exitUsage
}

// buildVersion returns the version go build records: a module version, a
// pseudo-version with the revision, marked +dirty for uncommitted changes,
// or (devel) for go run.
func buildVersion() string {
	info, ok := debug.ReadBuildInfo()
	if !ok {
		return "unknown"
	}
	return info.Main.Version
}
