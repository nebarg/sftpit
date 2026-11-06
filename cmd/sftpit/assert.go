package main

import (
	"context"
	"encoding/json"
	"errors"
	"flag"
	"fmt"
	"io"
	"os"
	"strings"
	"time"

	"github.com/nebarg/sftpit/internal/control"
	"github.com/nebarg/sftpit/internal/runs"
)

const assertUsage = `Usage: sftpit assert --ready-file FILE [flags]

Ends the current run of a running sftpit serve and gives the verdict on it:
admission closes, its clients have until the timeout to close their files,
every connection ends, and the scenario's assertions are checked. The run
admits no clients until a reset starts the next. A file still open by the
timeout, or a run that states no assertions, is a failure.

It exits with 0 if the run passed, 1 if it failed, 2 for bad flags, and 3 if
there is no verdict.

Flags:
  --ready-file FILE   find the server through FILE, which serve
                      --ready-file wrote
  --timeout D         how long clients have to close their files (default 10s)
  --format F          write the verdict as text or json (default text)
  --output FILE       write the verdict to FILE, not to standard output
`

func assertCommand(ctx context.Context, args []string, stdout, stderr io.Writer) int {
	flags := flag.NewFlagSet("assert", flag.ContinueOnError)
	flags.SetOutput(io.Discard)
	var readyPath, format, output string
	var timeout time.Duration
	flags.StringVar(&readyPath, "ready-file", "", "")
	flags.DurationVar(&timeout, "timeout", 10*time.Second, "")
	flags.StringVar(&format, "format", "text", "")
	flags.StringVar(&output, "output", "", "")
	if err := flags.Parse(args); err != nil {
		if errors.Is(err, flag.ErrHelp) {
			fmt.Fprint(stdout, assertUsage)
			return exitOK
		}
		fmt.Fprintf(stderr, "sftpit assert: %v\n\n%s", err, assertUsage)
		return exitUsage
	}
	switch {
	case flags.NArg() > 0:
		fmt.Fprintf(stderr, "sftpit assert: unexpected arguments %q\n", flags.Args())
		return exitUsage
	case readyPath == "":
		fmt.Fprintln(stderr, "sftpit assert: --ready-file is required")
		return exitUsage
	case format != "text" && format != "json":
		fmt.Fprintf(stderr, "sftpit assert: --format %q is not text or json\n", format)
		return exitUsage
	case timeout < 0:
		fmt.Fprintf(stderr, "sftpit assert: --timeout %s is negative\n", timeout)
		return exitUsage
	}

	rf, err := readReadyFile(readyPath)
	if err != nil {
		fmt.Fprintf(stderr, "sftpit assert: %v\n", err)
		return exitFailure
	}
	client := &control.Client{Addr: rf.HTTPAddress}
	status, err := client.Status(ctx)
	if err != nil {
		fmt.Fprintf(stderr, "sftpit assert: %v\n", err)
		return exitFailure
	}
	report, err := client.Assert(ctx, status.Run.ID, timeout)
	if err != nil {
		fmt.Fprintf(stderr, "sftpit assert: %v\n", err)
		return exitFailure
	}
	verdict, err := renderVerdict(format, status.Run, report)
	if err != nil {
		fmt.Fprintf(stderr, "sftpit assert: %v\n", err)
		return exitFailure
	}
	if output == "" {
		fmt.Fprint(stdout, verdict)
	} else if err := os.WriteFile(output, []byte(verdict), 0o644); err != nil {
		fmt.Fprintf(stderr, "sftpit assert: %v\n", err)
		return exitFailure
	}
	if !report.Passed {
		return exitAssertionsFailed
	}
	return exitOK
}

// renderVerdict writes report in format, json or text, for the run r.
func renderVerdict(format string, r control.RunStatus, report runs.Report) (string, error) {
	if format == "json" {
		b, err := json.MarshalIndent(report, "", "  ")
		if err != nil {
			return "", fmt.Errorf("write the verdict: %w", err)
		}
		return string(b) + "\n", nil
	}
	var b strings.Builder
	fmt.Fprintln(&b, describeRun(r))
	for _, a := range report.Assertions {
		result := "pass"
		if !a.Passed {
			result = "FAIL"
		}
		fmt.Fprintf(&b, "  %s  %s: %s\n", result, a.Description, a.Detail)
	}
	for _, problem := range report.Problems {
		fmt.Fprintf(&b, "  FAIL  %s\n", problem)
	}
	if !report.Trace.Complete {
		fmt.Fprintln(&b, "  note  the trace is incomplete")
	}
	if report.Interactive {
		fmt.Fprintln(&b, "  note  the rules changed during the run, so another run may not repeat it")
	}
	if report.Passed {
		fmt.Fprintln(&b, "passed")
	} else {
		fmt.Fprintln(&b, "failed")
	}
	return b.String(), nil
}
