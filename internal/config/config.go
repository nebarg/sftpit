// Package config loads sftpit's configuration file, applies command-line
// overrides and resolves the secrets the configuration references. It
// validates every scenario, explains a configuration as the file sftpit
// reads it as, and reads and writes rules and chaos in the JSON form that the
// control API uses.
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
	"cmp"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"io/fs"
	"maps"
	"os"
	"path"
	"path/filepath"
	"slices"
	"strings"

	"go.yaml.in/yaml/v3"
	"golang.org/x/crypto/ssh"

	"github.com/nebarg/sftpit/internal/backend"
	"github.com/nebarg/sftpit/internal/faults"
	"github.com/nebarg/sftpit/internal/sftpproxy"
	"github.com/nebarg/sftpit/internal/sshfront"
)

// schemaVersion is the configuration file format this package reads.
const schemaVersion = 1

// Defaults used when neither the configuration nor the command line sets a
// value.
const (
	DefaultSFTPListen = "127.0.0.1:2122"
	DefaultHTTPListen = "127.0.0.1:8122"
	DefaultUser       = "test"
	DefaultPassword   = "test"
)

// The listen addresses in the container profile, when neither the
// configuration nor the command line sets them: every interface.
const (
	ContainerSFTPListen = ":2122"
	ContainerHTTPListen = ":8122"
)

// DefaultLimits returns the storage limits sftpit serve has when the
// configuration sets none.
func DefaultLimits() backend.Limits {
	return backend.Limits{MaxFileBytes: 1 << 30, MaxTotalBytes: 4 << 30, MaxFiles: 10000, MaxOpenFiles: 256}
}

// DefaultMaxTraceBytes bounds each run's trace, the file of its events, when
// the configuration sets no bound.
const DefaultMaxTraceBytes = 64 << 20

// hostKeyWorkspace selects the host keys kept in the workspace.
const hostKeyWorkspace = "workspace"

// Config is a validated configuration with its secrets resolved.
type Config struct {
	// Profile says which addresses SFTPListen and HTTPListen may be.
	Profile Profile

	// SFTPListen is the address the SFTP server listens on, and HTTPListen
	// the one the control API listens on.
	SFTPListen string
	HTTPListen string

	// ControlHosts are the host names, besides localhost and loopback
	// addresses, that the control API answers to.
	ControlHosts []string

	// HostKeyDir is the absolute path of the directory holding the host
	// keys, or "" for the workspace's own.
	HostKeyDir string

	// ReplyOrder is the order in which each session's replies reach its
	// client.
	ReplyOrder sftpproxy.ReplyOrder

	// SeedDir is the absolute path of the directory copied into the
	// workspace at startup, or "" for an empty workspace.
	SeedDir string

	// DataDir is the absolute path of the workspace to keep, or "" for a
	// temporary one.
	DataDir string

	// Limits bound each run's files and the handles open on them.
	Limits backend.Limits

	// MaxTraceBytes bounds each run's trace, the file of its events.
	MaxTraceBytes int64

	// Users are the configured users, with their passwords resolved and
	// their homes cleaned, or the built-in test user if none are configured.
	Users []sshfront.User

	// DefaultCredentials reports whether Users is the built-in test user,
	// because no users were configured.
	DefaultCredentials bool

	// Policy is what clients may do, whatever faults a run injects.
	Policy Policy

	// Scenarios are the configuration's scenarios, by name.
	Scenarios map[string]Scenario

	// ScenarioFiles are the scenarios saved as files, one for each, which
	// are read again each time one is used.
	ScenarioFiles *ScenarioFiles

	// Scenario names the scenario whose rules inject faults, or is "" for
	// none.
	Scenario string

	// Seed is the seed given in place of the chosen scenario's own, or nil.
	Seed *faults.Seed

	// Warnings describe problems that do not prevent sftpit from starting.
	Warnings []string

	// chosen is the scenario that Scenario names, as it was read.
	chosen Scenario
}

// Chosen returns the scenario that Scenario names, from the configuration
// file or from its scenario file as it was read, or no scenario if Scenario
// is "".
func (c *Config) Chosen() Scenario {
	return c.chosen
}

// Scenario is a validated scenario.
type Scenario struct {
	// Description says what the scenario is for.
	Description string

	// Seed is the seed the scenario pins, or nil.
	Seed *faults.Seed

	// Rules are the scenario's fault rules, in the order they were given.
	Rules []faults.Rule

	// Chaos is the scenario's chaos, whose rules are tried after its own, or
	// nil.
	Chaos *faults.Chaos
}

// Options are the command-line settings. They take precedence over the
// configuration file.
type Options struct {
	// ConfigFile is the configuration file to read, or "" for none.
	ConfigFile string

	// Profile says which addresses sftpit may listen on, and which it
	// listens on by default.
	Profile Profile

	// SFTPListen and HTTPListen override the configured listen addresses
	// when non-empty.
	SFTPListen string
	HTTPListen string

	// ControlHosts are host names the control API answers to besides
	// localhost and loopback addresses.
	ControlHosts []string

	// SeedDir overrides the configured seed directory when non-empty.
	SeedDir string

	// DataDir overrides the configured workspace directory when non-empty.
	DataDir string

	// Scenario names the scenario whose faults to inject, or is "" for no
	// faults.
	Scenario string

	// Seed, if set, overrides the seed the scenario pins.
	Seed *faults.Seed

	// EnvFiles are read after the configuration's env files, so their
	// values override those.
	EnvFiles []string

	// LookupEnv reads the process environment. Nil means os.LookupEnv.
	LookupEnv func(string) (string, bool)
}

type fileConfig struct {
	SchemaVersion int           `yaml:"schema_version"`
	EnvFile       stringList    `yaml:"env_file,flow,omitempty"`
	ScenariosDir  string        `yaml:"scenarios_dir,omitempty"`
	Server        serverConfig  `yaml:"server"`
	Storage       storageConfig `yaml:"storage"`
	Users         []userConfig  `yaml:"users,omitempty"`
	Policy        policyConfig  `yaml:"policy,omitempty"`
	Events        eventsConfig  `yaml:"events,omitempty"`

	Scenarios map[string]scenarioConfig `yaml:"scenarios,omitempty"`
}

type storageConfig struct {
	DataDir       string `yaml:"data_dir,omitempty"`
	SeedDir       string `yaml:"seed_dir,omitempty"`
	MaxFileBytes  *int64 `yaml:"max_file_bytes,omitempty"`
	MaxTotalBytes *int64 `yaml:"max_total_bytes,omitempty"`
	MaxFiles      *int64 `yaml:"max_files,omitempty"`
	MaxOpenFiles  *int64 `yaml:"max_open_files,omitempty"`
}

type eventsConfig struct {
	MaxDiskBytes *int64 `yaml:"max_disk_bytes,omitempty"`
}

type serverConfig struct {
	SFTPListen string `yaml:"sftp_listen"`
	HTTPListen string `yaml:"http_listen"`
	HostKey    string `yaml:"host_key"`
	ReplyOrder string `yaml:"reply_order"`
}

// replyOrders are the reply orders a configuration names.
var replyOrders = map[string]sftpproxy.ReplyOrder{
	"request":    sftpproxy.RequestOrder,
	"completion": sftpproxy.CompletionOrder,
}

type userConfig struct {
	Name           string `yaml:"name"`
	PasswordEnv    string `yaml:"password_env,omitempty"`
	AuthorizedKeys string `yaml:"authorized_keys,omitempty"`
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
	return fmt.Errorf("line %d: expected a string or a list of strings", n.Line)
}

func (l *stringList) UnmarshalJSON(b []byte) error {
	if string(b) == "null" {
		return nil
	}
	var s string
	if err := json.Unmarshal(b, &s); err == nil {
		*l = stringList{s}
		return nil
	}
	var ss []string
	if err := json.Unmarshal(b, &ss); err != nil {
		return errors.New("expected a string or a list of strings")
	}
	*l = ss
	return nil
}

// MarshalYAML writes a list of one as a single string.
func (l stringList) MarshalYAML() (any, error) {
	if len(l) == 1 {
		return l[0], nil
	}
	return flowNode([]string(l))
}

// flowNode returns v as a YAML node in the flow style, such as [a, b].
func flowNode(v any) (*yaml.Node, error) {
	n := new(yaml.Node)
	if err := n.Encode(v); err != nil {
		return nil, err
	}
	n.Style = yaml.FlowStyle
	return n, nil
}

// Load reads the configuration file named in opts, if any, applies the
// command-line overrides and resolves every referenced secret. It starts no
// listeners and writes nothing.
func Load(opts Options) (*Config, error) {
	r, err := read(opts)
	if err != nil {
		return nil, err
	}
	if err := r.secrets.check(); err != nil {
		return nil, err
	}
	return r.cfg, nil
}

// reading is a configuration as read from its file.
type reading struct {
	cfg *Config

	// file is the configuration file as decoded, and dir the directory its
	// relative paths are resolved against. envFiles are the env files read,
	// in order, and secrets is what they and the environment held.
	file     fileConfig
	dir      string
	envFiles []string
	secrets  secretLookup
}

// read reads the configuration as Load does, but does not check that every
// secret is set, which Explain reports instead. Every path it gives is
// absolute.
func read(opts Options) (*reading, error) {
	lookupEnv := opts.LookupEnv
	if lookupEnv == nil {
		lookupEnv = os.LookupEnv
	}

	var f fileConfig
	dir, err := filepath.Abs(filepath.Dir(cmp.Or(opts.ConfigFile, ".")))
	if err != nil {
		return nil, fmt.Errorf("config: %w", err)
	}
	if opts.ConfigFile != "" {
		decoded, err := decodeFile(opts.ConfigFile)
		if err != nil {
			return nil, err
		}
		f = *decoded
	}

	sftpListen, httpListen := opts.Profile.defaultListen()
	cfg := &Config{
		Profile:    opts.Profile,
		SFTPListen: cmp.Or(opts.SFTPListen, f.Server.SFTPListen, sftpListen),
		HTTPListen: cmp.Or(opts.HTTPListen, f.Server.HTTPListen, httpListen),
	}
	var warnings []string
	for _, listen := range []struct{ setting, addr string }{{"sftp_listen", cfg.SFTPListen}, {"http_listen", cfg.HTTPListen}} {
		warning, err := opts.Profile.checkListen(listen.setting, listen.addr)
		if err != nil {
			return nil, err
		}
		if warning != "" {
			warnings = append(warnings, warning)
		}
	}
	for _, name := range opts.ControlHosts {
		if err := checkControlHost(name); err != nil {
			return nil, err
		}
	}
	cfg.ControlHosts = opts.ControlHosts
	if f.Server.ReplyOrder != "" {
		order, ok := replyOrders[f.Server.ReplyOrder]
		if !ok {
			return nil, fmt.Errorf("reply_order %q is not request or completion", f.Server.ReplyOrder)
		}
		cfg.ReplyOrder = order
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
	if cfg.MaxTraceBytes, err = f.Events.maxTraceBytes(); err != nil {
		return nil, err
	}

	if err := validateUsers(f.Users); err != nil {
		return nil, err
	}
	envFiles := make([]string, 0, len(f.EnvFile)+len(opts.EnvFiles))
	for _, name := range f.EnvFile {
		envFiles = append(envFiles, resolvePath(dir, name))
	}
	for _, name := range opts.EnvFiles {
		abs, err := filepath.Abs(name)
		if err != nil {
			return nil, fmt.Errorf("config: %w", err)
		}
		envFiles = append(envFiles, abs)
	}
	secrets, err := lookupSecrets(referencedSecrets(f.Users), envFiles, lookupEnv)
	if err != nil {
		return nil, err
	}
	cfg.Warnings = append(warnings, secrets.warnings...)

	if len(f.Users) == 0 {
		cfg.Users = []sshfront.User{{Name: DefaultUser, Password: DefaultPassword, Home: "/"}}
		cfg.DefaultCredentials = true
	}
	for i, u := range f.Users {
		user, err := u.resolve(dir, secrets.values)
		if err != nil {
			return nil, fmt.Errorf("users[%d] (%s): %w", i, u.Name, err)
		}
		cfg.Users = append(cfg.Users, user)
	}

	if cfg.Policy, err = f.Policy.policy(cfg.Users); err != nil {
		return nil, err
	}
	if cfg.Scenarios, err = scenarios(f.Scenarios, cfg.Users); err != nil {
		return nil, err
	}
	defaultDir := defaultScenariosDir
	if opts.ConfigFile == "" {
		defaultDir = defaultScenariosDirWithoutConfig
	}
	cfg.ScenarioFiles = NewScenarioFiles(resolvePath(dir, cmp.Or(f.ScenariosDir, defaultDir)), cfg.Users, cfg.Scenarios)
	files, err := cfg.ScenarioFiles.List()
	if err != nil {
		return nil, err
	}
	for _, file := range files {
		if file.Err != nil {
			return nil, file.Err
		}
	}
	if cfg.chosen, err = choose(opts.Scenario, cfg.Scenarios, files); err != nil {
		return nil, err
	}
	cfg.Scenario, cfg.Seed = opts.Scenario, opts.Seed
	return &reading{cfg: cfg, file: f, dir: dir, envFiles: envFiles, secrets: secrets}, nil
}

func decodeFile(name string) (*fileConfig, error) {
	data, err := os.ReadFile(name)
	if err != nil {
		return nil, fmt.Errorf("config: %w", err)
	}
	var f fileConfig
	if err := decodeStrict(data, &f, &f.SchemaVersion); err != nil {
		return nil, fmt.Errorf("%s: %w", name, err)
	}
	return &f, nil
}

// decodeStrict decodes data, a single YAML document, into v, refusing
// fields that v does not have, and checks the schema version it sets in
// version.
func decodeStrict(data []byte, v any, version *int) error {
	dec := yaml.NewDecoder(bytes.NewReader(data))
	dec.KnownFields(true)
	if err := dec.Decode(v); err != nil {
		if errors.Is(err, io.EOF) {
			return fmt.Errorf("the file is empty; it needs at least schema_version: %d", schemaVersion)
		}
		return err
	}
	if err := dec.Decode(new(yaml.Node)); !errors.Is(err, io.EOF) {
		return errors.New("expected a single YAML document")
	}
	switch *version {
	case schemaVersion:
	case 0:
		return fmt.Errorf("schema_version is required; use schema_version: %d", schemaVersion)
	default:
		return fmt.Errorf("schema_version %d is not supported; this sftpit reads version %d", *version, schemaVersion)
	}
	return nil
}

// resolvePath resolves a path from the configuration file against the
// file's directory rather than the working directory.
func resolvePath(dir, name string) string {
	if filepath.IsAbs(name) {
		return name
	}
	return filepath.Join(dir, name)
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
	if isRootOrHome(abs) {
		return "", fmt.Errorf("seed_dir %s would copy the whole tree under it; use a directory of test fixtures", abs)
	}
	return abs, nil
}

// isRootOrHome reports whether the absolute path abs is the filesystem root
// or the home directory.
func isRootOrHome(abs string) bool {
	if filepath.Dir(abs) == abs {
		return true
	}
	home, err := os.UserHomeDir()
	return err == nil && sameFile(abs, home)
}

// checkDataDir refuses the filesystem root, the home directory and a
// directory inside the seed directory, which would be copied into itself.
// The directory need not exist yet.
func checkDataDir(name, seedDir string) (string, error) {
	abs, err := filepath.Abs(name)
	if err != nil {
		return "", fmt.Errorf("data_dir: %w", err)
	}
	if isRootOrHome(abs) {
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
// one left unset. A limit can be set to any value of at least 1, but not
// turned off.
func (s storageConfig) limits() (backend.Limits, error) {
	limits := DefaultLimits()
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

// maxTraceBytes returns the configured bound on each run's trace, or the
// default if none is set. Like a storage limit, it cannot be turned off.
func (e eventsConfig) maxTraceBytes() (int64, error) {
	if e.MaxDiskBytes == nil {
		return DefaultMaxTraceBytes, nil
	}
	if *e.MaxDiskBytes < 1 {
		return 0, fmt.Errorf("events.max_disk_bytes is %d; it must be at least 1 and cannot be turned off", *e.MaxDiskBytes)
	}
	return *e.MaxDiskBytes, nil
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

// secretLookup is what looking up the referenced variables found.
type secretLookup struct {
	// values holds each variable found, and sources where it was found:
	// "the environment" or the env file's path.
	values, sources map[string]string

	// missing are the variables found nowhere, and searched says where
	// they were looked for.
	missing  []string
	searched string

	warnings []string
}

// lookupSecrets looks up each variable in names, first in the process
// environment and then in envFiles, where a later file overrides an earlier
// one. An env file that does not exist is skipped, so a configuration can
// declare a git-ignored file that CI replaces with real environment
// variables.
func lookupSecrets(names map[string]bool, envFiles []string, lookupEnv func(string) (string, bool)) (secretLookup, error) {
	l := secretLookup{values: make(map[string]string, len(names)), sources: make(map[string]string, len(names))}
	missing := make(map[string]bool)
	for name := range names {
		if value, ok := lookupEnv(name); ok {
			l.values[name], l.sources[name] = value, "the environment"
		} else {
			missing[name] = true
		}
	}

	var searched []string
	for _, file := range envFiles {
		values, warning, err := readEnvFile(file, missing)
		if errors.Is(err, fs.ErrNotExist) {
			searched = append(searched, file+" (not found)")
			continue
		}
		if err != nil {
			return secretLookup{}, fmt.Errorf("env file: %w", err)
		}
		searched = append(searched, file)
		if warning != "" {
			l.warnings = append(l.warnings, warning)
		}
		for name, v := range values {
			l.values[name], l.sources[name] = v.value, file
		}
	}

	for _, name := range slices.Sorted(maps.Keys(missing)) {
		if _, ok := l.values[name]; !ok {
			l.missing = append(l.missing, name)
		}
	}
	l.searched = "the environment"
	if len(searched) > 0 {
		l.searched += " or " + strings.Join(searched, ", ")
	}
	return l, nil
}

// check reports the first variable that is missing or empty.
func (l secretLookup) check() error {
	if len(l.missing) > 0 {
		return fmt.Errorf("%s is not set in %s", l.missing[0], l.searched)
	}
	for _, name := range slices.Sorted(maps.Keys(l.values)) {
		if l.values[name] == "" {
			return fmt.Errorf("%s is set but empty", name)
		}
	}
	return nil
}
