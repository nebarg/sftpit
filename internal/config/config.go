// Package config loads sftpit's configuration file, applies command-line
// overrides and resolves the secrets the configuration references.
//
// Secrets come only from the fields that name an environment variable, such
// as password_env. Each variable is looked up in the process environment
// first and then in the env files the configuration or the command line
// declares. Values from env files are never copied into the process
// environment, and values the configuration does not reference are never
// kept.
package config

import (
	"bytes"
	"errors"
	"fmt"
	"io"
	"io/fs"
	"maps"
	"net"
	"net/netip"
	"os"
	"path"
	"path/filepath"
	"slices"
	"strconv"
	"strings"

	"go.yaml.in/yaml/v3"
	"golang.org/x/crypto/ssh"

	"github.com/nebarg/sftpit/internal/backend"
	"github.com/nebarg/sftpit/internal/sshfront"
)

// SchemaVersion is the configuration file format this package reads.
const SchemaVersion = 1

// Defaults used when neither the configuration nor the command line sets a
// value.
const (
	DefaultSFTPListen = "127.0.0.1:2122"
	DefaultUser       = "test"
	DefaultPassword   = "test"

	DefaultMaxFileBytes  = 1 << 30
	DefaultMaxTotalBytes = 4 << 30
	DefaultMaxFiles      = 10000
	DefaultMaxOpenFiles  = 256
)

// hostKeyWorkspace selects the host keys kept in the workspace.
const hostKeyWorkspace = "workspace"

// Config is a validated configuration with its secrets resolved.
type Config struct {
	// SFTPListen is the loopback address the SFTP server listens on.
	SFTPListen string

	// HostKeyDir is the directory holding the host keys, or "" for the
	// workspace's own.
	HostKeyDir string

	// SeedDir is the absolute path of the directory copied into the
	// workspace at startup, or "" for an empty workspace.
	SeedDir string

	// DataDir is the absolute path of the workspace to keep, or "" for a
	// temporary one.
	DataDir string

	// Limits bound each run's files and the handles open on them.
	Limits backend.Limits

	Users []sshfront.User

	// DefaultCredentials reports whether Users is the built-in test user,
	// because no users were configured.
	DefaultCredentials bool

	// Warnings describe problems that do not prevent sftpit from starting.
	Warnings []string
}

// Options are the command-line settings. They take precedence over the
// configuration file.
type Options struct {
	// ConfigFile is the configuration file to read, or "" for none.
	ConfigFile string

	// SFTPListen overrides the configured listen address when non-empty.
	SFTPListen string

	// SeedDir overrides the configured seed directory when non-empty.
	SeedDir string

	// DataDir overrides the configured workspace directory when non-empty.
	DataDir string

	// EnvFiles are read after the configuration's env files, so their
	// values override those.
	EnvFiles []string

	// LookupEnv reads the process environment. Nil means os.LookupEnv.
	LookupEnv func(string) (string, bool)
}

type fileConfig struct {
	SchemaVersion int           `yaml:"schema_version"`
	EnvFile       stringList    `yaml:"env_file"`
	Server        serverConfig  `yaml:"server"`
	Storage       storageConfig `yaml:"storage"`
	Users         []userConfig  `yaml:"users"`
}

type storageConfig struct {
	DataDir       string `yaml:"data_dir"`
	SeedDir       string `yaml:"seed_dir"`
	MaxFileBytes  *int64 `yaml:"max_file_bytes"`
	MaxTotalBytes *int64 `yaml:"max_total_bytes"`
	MaxFiles      *int64 `yaml:"max_files"`
	MaxOpenFiles  *int64 `yaml:"max_open_files"`
}

type serverConfig struct {
	SFTPListen string `yaml:"sftp_listen"`
	HostKey    string `yaml:"host_key"`
}

type userConfig struct {
	Name           string `yaml:"name"`
	PasswordEnv    string `yaml:"password_env"`
	AuthorizedKeys string `yaml:"authorized_keys"`
	Home           string `yaml:"home"`
}

// stringList accepts either a single string or a list of strings.
type stringList []string

func (l *stringList) UnmarshalYAML(n *yaml.Node) error {
	switch n.Kind {
	case yaml.ScalarNode:
		var s string
		if err := n.Decode(&s); err != nil {
			return err
		}
		*l = stringList{s}
		return nil
	case yaml.SequenceNode:
		var ss []string
		if err := n.Decode(&ss); err != nil {
			return err
		}
		*l = ss
		return nil
	}
	return fmt.Errorf("line %d: expected a path or a list of paths", n.Line)
}

// Load reads the configuration file named in opts, if any, applies the
// command-line overrides and resolves every referenced secret. It starts no
// listeners and writes nothing.
func Load(opts Options) (*Config, error) {
	lookupEnv := opts.LookupEnv
	if lookupEnv == nil {
		lookupEnv = os.LookupEnv
	}

	var f fileConfig
	dir := "."
	if opts.ConfigFile != "" {
		decoded, err := decodeFile(opts.ConfigFile)
		if err != nil {
			return nil, err
		}
		f = *decoded
		dir = filepath.Dir(opts.ConfigFile)
	}

	cfg := &Config{SFTPListen: DefaultSFTPListen}
	if f.Server.SFTPListen != "" {
		cfg.SFTPListen = f.Server.SFTPListen
	}
	if opts.SFTPListen != "" {
		cfg.SFTPListen = opts.SFTPListen
	}
	if err := checkLoopback(cfg.SFTPListen); err != nil {
		return nil, err
	}
	if hostKey := f.Server.HostKey; hostKey != "" && hostKey != hostKeyWorkspace {
		cfg.HostKeyDir = resolvePath(dir, hostKey)
	}
	seedDir := opts.SeedDir
	if seedDir == "" && f.Storage.SeedDir != "" {
		seedDir = resolvePath(dir, f.Storage.SeedDir)
	}
	if seedDir != "" {
		resolved, err := checkSeedDir(seedDir)
		if err != nil {
			return nil, err
		}
		cfg.SeedDir = resolved
	}
	dataDir := opts.DataDir
	if dataDir == "" && f.Storage.DataDir != "" {
		dataDir = resolvePath(dir, f.Storage.DataDir)
	}
	if dataDir != "" {
		resolved, err := checkDataDir(dataDir, cfg.SeedDir)
		if err != nil {
			return nil, err
		}
		cfg.DataDir = resolved
	}
	limits, err := f.Storage.limits()
	if err != nil {
		return nil, err
	}
	cfg.Limits = limits

	if err := validateUsers(f.Users); err != nil {
		return nil, err
	}
	envFiles := make([]string, 0, len(f.EnvFile)+len(opts.EnvFiles))
	for _, name := range f.EnvFile {
		envFiles = append(envFiles, resolvePath(dir, name))
	}
	envFiles = append(envFiles, opts.EnvFiles...)
	secrets, warnings, err := resolveSecrets(referencedSecrets(f.Users), envFiles, lookupEnv)
	if err != nil {
		return nil, err
	}
	cfg.Warnings = warnings

	if len(f.Users) == 0 {
		cfg.Users = []sshfront.User{{Name: DefaultUser, Password: DefaultPassword, Home: "/"}}
		cfg.DefaultCredentials = true
		return cfg, nil
	}
	for i, u := range f.Users {
		user, err := u.resolve(dir, secrets)
		if err != nil {
			return nil, fmt.Errorf("users[%d] (%s): %w", i, u.Name, err)
		}
		cfg.Users = append(cfg.Users, user)
	}
	return cfg, nil
}

func decodeFile(name string) (*fileConfig, error) {
	data, err := os.ReadFile(name)
	if err != nil {
		return nil, fmt.Errorf("config: %w", err)
	}
	dec := yaml.NewDecoder(bytes.NewReader(data))
	dec.KnownFields(true)
	var f fileConfig
	if err := dec.Decode(&f); err != nil {
		if errors.Is(err, io.EOF) {
			return nil, fmt.Errorf("%s: the file is empty; it needs at least schema_version: %d", name, SchemaVersion)
		}
		return nil, fmt.Errorf("%s: %w", name, err)
	}
	if err := dec.Decode(new(yaml.Node)); !errors.Is(err, io.EOF) {
		return nil, fmt.Errorf("%s: expected a single YAML document", name)
	}
	switch f.SchemaVersion {
	case SchemaVersion:
	case 0:
		return nil, fmt.Errorf("%s: schema_version is required; use schema_version: %d", name, SchemaVersion)
	default:
		return nil, fmt.Errorf("%s: schema_version %d is not supported; this sftpit reads version %d", name, f.SchemaVersion, SchemaVersion)
	}
	return &f, nil
}

// resolvePath resolves a path from the configuration file against the
// file's directory rather than the working directory.
func resolvePath(dir, name string) string {
	if filepath.IsAbs(name) {
		return name
	}
	return filepath.Join(dir, name)
}

// checkLoopback requires addr to be a loopback IP address or localhost and
// a numeric port.
func checkLoopback(addr string) error {
	host, port, err := net.SplitHostPort(addr)
	if err != nil {
		return fmt.Errorf("sftp_listen %q: %w", addr, err)
	}
	if _, err := strconv.ParseUint(port, 10, 16); err != nil {
		return fmt.Errorf("sftp_listen %q: the port must be a number from 0 to 65535", addr)
	}
	if host == "localhost" {
		return nil
	}
	if ip, err := netip.ParseAddr(host); err == nil && ip.IsLoopback() {
		return nil
	}
	return fmt.Errorf("sftp_listen %q is not a loopback address; sftpit listens only on loopback, such as 127.0.0.1:2122 or [::1]:2122", addr)
}

// checkSeedDir requires the seed directory to exist and refuses the
// filesystem root and the home directory, whose whole trees would be copied.
func checkSeedDir(name string) (string, error) {
	abs, err := filepath.Abs(name)
	if err != nil {
		return "", fmt.Errorf("seed_dir: %w", err)
	}
	info, err := os.Stat(abs)
	if err != nil {
		return "", fmt.Errorf("seed_dir: %w", err)
	}
	if !info.IsDir() {
		return "", fmt.Errorf("seed_dir %s is not a directory", abs)
	}
	home, err := os.UserHomeDir()
	if filepath.Dir(abs) == abs || (err == nil && sameFile(abs, home)) {
		return "", fmt.Errorf("seed_dir %s would copy the whole tree under it; use a directory of test fixtures", abs)
	}
	return abs, nil
}

// checkDataDir refuses the filesystem root, the home directory and a
// directory inside the seed directory, which would be copied into itself.
// The directory need not exist yet.
func checkDataDir(name, seedDir string) (string, error) {
	abs, err := filepath.Abs(name)
	if err != nil {
		return "", fmt.Errorf("data_dir: %w", err)
	}
	home, err := os.UserHomeDir()
	if filepath.Dir(abs) == abs || (err == nil && sameFile(abs, home)) {
		return "", fmt.Errorf("data_dir %s is the filesystem root or the home directory; use a directory of its own", abs)
	}
	if seedDir != "" {
		if rel, err := filepath.Rel(seedDir, abs); err == nil && filepath.IsLocal(rel) {
			return "", fmt.Errorf("data_dir %s is inside seed_dir %s, which would be copied into itself", abs, seedDir)
		}
	}
	return abs, nil
}

// limits returns the configured storage limits, with the default for each
// one left unset. A limit cannot be turned off, only raised.
func (s storageConfig) limits() (backend.Limits, error) {
	limits := backend.Limits{
		MaxFileBytes:  DefaultMaxFileBytes,
		MaxTotalBytes: DefaultMaxTotalBytes,
		MaxFiles:      DefaultMaxFiles,
		MaxOpenFiles:  DefaultMaxOpenFiles,
	}
	settings := []struct {
		name  string
		value *int64
		limit *int64
	}{
		{"max_file_bytes", s.MaxFileBytes, &limits.MaxFileBytes},
		{"max_total_bytes", s.MaxTotalBytes, &limits.MaxTotalBytes},
		{"max_files", s.MaxFiles, &limits.MaxFiles},
		{"max_open_files", s.MaxOpenFiles, &limits.MaxOpenFiles},
	}
	for _, setting := range settings {
		if setting.value == nil {
			continue
		}
		if *setting.value < 1 {
			return backend.Limits{}, fmt.Errorf("%s is %d; storage limits must be at least 1 and cannot be turned off", setting.name, *setting.value)
		}
		*setting.limit = *setting.value
	}
	return limits, nil
}

func sameFile(a, b string) bool {
	ai, errA := os.Stat(a)
	bi, errB := os.Stat(b)
	return errA == nil && errB == nil && os.SameFile(ai, bi)
}

func validateUsers(users []userConfig) error {
	seen := make(map[string]int, len(users))
	for i, u := range users {
		field := fmt.Sprintf("users[%d]", i)
		if u.Name == "" {
			return fmt.Errorf("%s: name is required", field)
		}
		field += " (" + u.Name + ")"
		if j, ok := seen[u.Name]; ok {
			return fmt.Errorf("%s: users[%d] has the same name", field, j)
		}
		seen[u.Name] = i
		if u.PasswordEnv == "" && u.AuthorizedKeys == "" {
			return fmt.Errorf("%s: set password_env, authorized_keys or both", field)
		}
		if u.PasswordEnv != "" && !envNamePattern.MatchString(u.PasswordEnv) {
			return fmt.Errorf("%s: password_env %q is not a valid environment variable name", field, u.PasswordEnv)
		}
		if u.Home != "" && (!path.IsAbs(u.Home) || strings.ContainsRune(u.Home, 0)) {
			return fmt.Errorf("%s: home %q must be an absolute SFTP path, such as /%s", field, u.Home, u.Name)
		}
	}
	return nil
}

func referencedSecrets(users []userConfig) map[string]bool {
	names := make(map[string]bool)
	for _, u := range users {
		if u.PasswordEnv != "" {
			names[u.PasswordEnv] = true
		}
	}
	return names
}

func (u userConfig) resolve(dir string, secrets map[string]string) (sshfront.User, error) {
	user := sshfront.User{Name: u.Name, Home: path.Clean(u.Home)}
	if u.Home == "" {
		user.Home = "/"
	}
	if u.PasswordEnv != "" {
		user.Password = secrets[u.PasswordEnv]
	}
	if u.AuthorizedKeys != "" {
		keys, err := readAuthorizedKeys(resolvePath(dir, u.AuthorizedKeys))
		if err != nil {
			return sshfront.User{}, err
		}
		user.AuthorizedKeys = keys
	}
	return user, nil
}

// readAuthorizedKeys reads a file in OpenSSH's authorized_keys format.
// Options such as from= or command= are rejected rather than ignored,
// because sftpit cannot enforce them.
func readAuthorizedKeys(name string) ([]ssh.PublicKey, error) {
	data, err := os.ReadFile(name)
	if err != nil {
		return nil, fmt.Errorf("authorized_keys: %w", err)
	}
	var keys []ssh.PublicKey
	for i, line := range bytes.Split(data, []byte("\n")) {
		line = bytes.TrimSpace(line)
		if len(line) == 0 || line[0] == '#' {
			continue
		}
		key, _, options, _, err := ssh.ParseAuthorizedKey(line)
		if err != nil {
			return nil, fmt.Errorf("%s:%d: %w", name, i+1, err)
		}
		if len(options) > 0 {
			return nil, fmt.Errorf("%s:%d: key options such as %q are not supported", name, i+1, options[0])
		}
		keys = append(keys, key)
	}
	if len(keys) == 0 {
		return nil, fmt.Errorf("%s: no keys found", name)
	}
	return keys, nil
}

// resolveSecrets looks up each variable in names, first in the process
// environment and then in envFiles, where a later file overrides an earlier
// one. An env file that does not exist is skipped, so a configuration can
// declare a git-ignored file that CI replaces with real environment
// variables.
func resolveSecrets(names map[string]bool, envFiles []string, lookupEnv func(string) (string, bool)) (map[string]string, []string, error) {
	secrets := make(map[string]string, len(names))
	missing := make(map[string]bool)
	for name := range names {
		if value, ok := lookupEnv(name); ok {
			secrets[name] = value
		} else {
			missing[name] = true
		}
	}

	var warnings, searched []string
	fromFiles := make(map[string]string)
	for _, file := range envFiles {
		values, warning, err := readEnvFile(file, missing)
		if errors.Is(err, fs.ErrNotExist) {
			searched = append(searched, file+" (not found)")
			continue
		}
		if err != nil {
			return nil, nil, fmt.Errorf("env file: %w", err)
		}
		searched = append(searched, file)
		if warning != "" {
			warnings = append(warnings, warning)
		}
		for name, v := range values {
			fromFiles[name] = v.value
		}
	}

	for _, name := range slices.Sorted(maps.Keys(missing)) {
		value, ok := fromFiles[name]
		if !ok {
			where := "the environment"
			if len(searched) > 0 {
				where += " or " + strings.Join(searched, ", ")
			}
			return nil, nil, fmt.Errorf("%s is not set in %s", name, where)
		}
		secrets[name] = value
	}
	for _, name := range slices.Sorted(maps.Keys(secrets)) {
		if secrets[name] == "" {
			return nil, nil, fmt.Errorf("%s is set but empty", name)
		}
	}
	return secrets, warnings, nil
}
