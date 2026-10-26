package main

import (
	"errors"
	"flag"
	"fmt"
	"io"

	"github.com/nebarg/sftpit/internal/config"
)

const configUsage = `Usage: sftpit config <command> --config FILE [flags]

Commands:
  validate   check the file, its users, secrets and every scenario,
             without starting anything; serve checks the seed's contents,
             the data directory and the host keys when it starts
  explain    print the configuration as sftpit reads it: every default
             filled in, recipes in the long form and each secret's
             source, but never its value

Flags:
  --config FILE     the configuration file to read
  --env-file FILE   also read secrets from FILE; may be repeated, and later
                    files override earlier ones
`

func configCommand(args []string, stdout, stderr io.Writer) int {
	if len(args) > 0 && (args[0] == "help" || args[0] == "-h" || args[0] == "--help") {
		fmt.Fprint(stdout, configUsage)
		return exitOK
	}
	if len(args) == 0 || (args[0] != "validate" && args[0] != "explain") {
		fmt.Fprintf(stderr, "sftpit config: expected validate or explain\n\n%s", configUsage)
		return exitUsage
	}
	command := args[0]
	flags := flag.NewFlagSet("config "+command, flag.ContinueOnError)
	flags.SetOutput(io.Discard)
	opts := config.Options{}
	flags.StringVar(&opts.ConfigFile, "config", "", "")
	flags.Func("env-file", "", func(name string) error {
		opts.EnvFiles = append(opts.EnvFiles, name)
		return nil
	})
	if err := flags.Parse(args[1:]); err != nil {
		if errors.Is(err, flag.ErrHelp) {
			fmt.Fprint(stdout, configUsage)
			return exitOK
		}
		fmt.Fprintf(stderr, "sftpit config %s: %v\n\n%s", command, err, configUsage)
		return exitUsage
	}
	if flags.NArg() > 0 {
		fmt.Fprintf(stderr, "sftpit config %s: unexpected arguments %q\n", command, flags.Args())
		return exitUsage
	}
	if opts.ConfigFile == "" {
		fmt.Fprintf(stderr, "sftpit config %s: --config is required\n", command)
		return exitUsage
	}

	if command == "explain" {
		explained, err := config.Explain(opts)
		if err != nil {
			fmt.Fprintf(stderr, "sftpit config explain: %v\n", err)
			return exitUsage
		}
		// The output is the configuration file, so a short write must fail.
		if _, err := stdout.Write(explained); err != nil {
			fmt.Fprintf(stderr, "sftpit config explain: %v\n", err)
			return exitFailure
		}
		return exitOK
	}
	cfg, err := config.Load(opts)
	if err != nil {
		fmt.Fprintf(stderr, "sftpit config validate: %v\n", err)
		return exitUsage
	}
	for _, warning := range cfg.Warnings {
		fmt.Fprintf(stderr, "sftpit config validate: warning: %s\n", warning)
	}
	fmt.Fprintf(stdout, "%s is valid: %s and %s\n", opts.ConfigFile, count(len(cfg.Users), "user"), count(len(cfg.Scenarios), "scenario"))
	return exitOK
}

// count returns n things, as in "1 user" or "2 users".
func count(n int, thing string) string {
	if n == 1 {
		return "1 " + thing
	}
	return fmt.Sprintf("%d %ss", n, thing)
}
