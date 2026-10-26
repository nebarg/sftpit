package main

import (
	"context"
	"errors"
	"flag"
	"fmt"
	"io"
	"net/http"

	"github.com/nebarg/sftpit/internal/control"
	"github.com/nebarg/sftpit/internal/faults"
)

const resetUsage = `Usage: sftpit reset --ready-file FILE [flags]

Ends the current run of a running sftpit serve and starts the next: its
clients are disconnected, and the next run starts with the seed's files,
its counters from zero and its timers from its start.

Flags:
  --ready-file FILE   find the server through FILE, which serve
                      --ready-file wrote
  --scenario NAME     start a run of the scenario NAME, or of none if NAME
                      is ""; without it, the current scenario runs again,
                      with its seed if that was pinned
  --seed N            pin the next run's random decisions to seed N, in
                      place of the scenario's own seed or a fresh one
`

func resetCommand(ctx context.Context, args []string, stdout, stderr io.Writer) int {
	flags := flag.NewFlagSet("reset", flag.ContinueOnError)
	flags.SetOutput(io.Discard)
	var readyPath string
	var req control.ResetRequest
	flags.StringVar(&readyPath, "ready-file", "", "")
	flags.Func("scenario", "", func(name string) error {
		req.Scenario = &name
		return nil
	})
	flags.Func("seed", "", func(s string) error {
		seed, err := faults.ParseSeed(s)
		if err != nil {
			return err
		}
		req.Seed = (*control.Seed)(&seed)
		return nil
	})
	if err := flags.Parse(args); err != nil {
		if errors.Is(err, flag.ErrHelp) {
			fmt.Fprint(stdout, resetUsage)
			return exitOK
		}
		fmt.Fprintf(stderr, "sftpit reset: %v\n\n%s", err, resetUsage)
		return exitUsage
	}
	if flags.NArg() > 0 {
		fmt.Fprintf(stderr, "sftpit reset: unexpected arguments %q\n", flags.Args())
		return exitUsage
	}
	if readyPath == "" {
		fmt.Fprintln(stderr, "sftpit reset: --ready-file is required")
		return exitUsage
	}

	rf, err := readReadyFile(readyPath)
	if err != nil {
		fmt.Fprintf(stderr, "sftpit reset: %v\n", err)
		return exitFailure
	}
	status, err := (&control.Client{Addr: rf.HTTPAddress}).Reset(ctx, req)
	if err != nil {
		fmt.Fprintf(stderr, "sftpit reset: %v\n", err)
		if refused, ok := errors.AsType[*control.Error](err); ok && refused.StatusCode == http.StatusBadRequest {
			return exitUsage
		}
		return exitFailure
	}
	fmt.Fprintln(stdout, describeRun(status.Run))
	return exitOK
}

// describeRun describes a run in one line, as in
// "run 20261024-101500.123-3f9a: scenario flaky-partner, seed 7 (pinned)".
func describeRun(r control.RunStatus) string {
	scenario := "scenario " + r.Scenario
	switch {
	case r.Inline:
		scenario = "an inline scenario"
	case r.Scenario == "":
		return fmt.Sprintf("run %s: no faults", r.ID)
	}
	seed := "fresh"
	if r.SeedPinned {
		seed = "pinned"
	}
	return fmt.Sprintf("run %s: %s, seed %d (%s)", r.ID, scenario, uint64(r.Seed), seed)
}
