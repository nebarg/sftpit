package config

import (
	"bytes"
	"cmp"
	"fmt"
	"io"
	"maps"
	"slices"

	"go.yaml.in/yaml/v3"
)

// Explain returns the configuration that Load reads for opts, written as a
// configuration file: every default filled in, every path absolute, and
// each scenario's faults with their presets and defaults filled in. Comments
// say where each secret comes from, without its value. Loading the result
// gives the same configuration. Unlike Load, Explain reports a missing or
// empty secret in a comment rather than as an error.
func Explain(opts Options) ([]byte, error) {
	r, err := read(opts)
	if err != nil {
		return nil, err
	}
	cfg := r.cfg
	f := fileConfig{
		SchemaVersion: schemaVersion,
		EnvFile:       r.envFiles,
		ScenariosDir:  cfg.Scenarios.Dir(),
		Server:        serverConfig{SFTPListen: cfg.SFTPListen, HTTPListen: cfg.HTTPListen, HostKey: cmp.Or(cfg.HostKeyDir, hostKeyWorkspace), ReplyOrder: cfg.ReplyOrder.String()},
		Storage: storageConfig{
			DataDir:       cfg.DataDir,
			SeedDir:       cfg.SeedDir,
			MaxFileBytes:  &cfg.Limits.MaxFileBytes,
			MaxTotalBytes: &cfg.Limits.MaxTotalBytes,
			MaxFiles:      &cfg.Limits.MaxFiles,
			MaxOpenFiles:  &cfg.Limits.MaxOpenFiles,
		},
	}
	for i, u := range r.file.Users {
		f.Users = append(f.Users, userConfig{Name: u.Name, PasswordEnv: u.PasswordEnv, Home: cfg.Users[i].Home})
		if u.AuthorizedKeys != "" {
			f.Users[i].AuthorizedKeys = resolvePath(r.dir, u.AuthorizedKeys)
		}
	}
	for _, r := range cfg.Policy.ReadOnly {
		f.Policy.ReadOnly = append(f.Policy.ReadOnly, readOnlyConfig{PathPrefix: r.PathPrefix, Users: r.Users})
	}
	for name, sc := range cfg.Scenarios.configured {
		resolved, err := sc.Resolved()
		if err != nil {
			return nil, fmt.Errorf("config: scenarios.%s: %w", name, err)
		}
		if f.Scenarios == nil {
			f.Scenarios = make(map[string]Scenario)
		}
		f.Scenarios[name] = resolved
	}

	var doc yaml.Node
	if err := doc.Encode(f); err != nil {
		return nil, fmt.Errorf("config: write the configuration: %w", err)
	}
	b := bytes.NewBufferString(r.header(opts.ConfigFile))
	if err := encodeYAML(b, &doc); err != nil {
		return nil, fmt.Errorf("config: write the configuration: %w", err)
	}
	return b.Bytes(), nil
}

// encodeYAML writes v to w as YAML, indented by two spaces.
func encodeYAML(w io.Writer, v any) error {
	enc := yaml.NewEncoder(w)
	enc.SetIndent(2)
	if err := enc.Encode(v); err != nil {
		return err
	}
	return enc.Close()
}

// header returns the comments that open an explained configuration.
func (r *reading) header(configFile string) string {
	var b bytes.Buffer
	if configFile == "" {
		b.WriteString("# The configuration sftpit uses without a config file.\n")
	} else {
		fmt.Fprintf(&b, "# The configuration sftpit reads from %s.\n", configFile)
	}
	b.WriteString("# Every default is filled in, every path is absolute, and each scenario's\n# faults have their presets and defaults filled in.\n")
	if r.cfg.DefaultCredentials {
		fmt.Fprintf(&b, "#\n# No users are configured, so sftpit accepts the user %s with the password %s.\n", DefaultUser, DefaultPassword)
	}
	names := slices.Sorted(maps.Keys(referencedSecrets(r.file.Users)))
	if len(names) > 0 {
		b.WriteString("#\n# Secrets, whose values are never shown:\n")
	}
	for _, name := range names {
		value, found := r.secrets.values[name]
		switch {
		case !found:
			fmt.Fprintf(&b, "#   %s: missing; it is not in %s\n", name, r.secrets.searched)
		case value == "":
			fmt.Fprintf(&b, "#   %s: empty, in %s\n", name, r.secrets.sources[name])
		default:
			fmt.Fprintf(&b, "#   %s: from %s\n", name, r.secrets.sources[name])
		}
	}
	return b.String()
}
