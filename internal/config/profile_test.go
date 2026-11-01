package config

import (
	"path/filepath"
	"slices"
	"strings"
	"testing"

	"github.com/nebarg/sftpit/internal/testutil"
)

func TestParseProfile(t *testing.T) {
	for name, want := range map[string]Profile{"loopback": Loopback, "container": Container} {
		if got, err := ParseProfile(name); err != nil || got != want || got.String() != name {
			t.Errorf("ParseProfile(%q) = %v, %v, want %v", name, got, err, want)
		}
	}
	for _, name := range []string{"", "remote", "Container"} {
		if _, err := ParseProfile(name); err == nil || !strings.Contains(err.Error(), "is not loopback or container") {
			t.Errorf("ParseProfile(%q) error = %v, want it refused", name, err)
		}
	}
}

func TestLoadListensOnEveryInterfaceInTheContainerProfile(t *testing.T) {
	cfg, err := Load(Options{Profile: Container, LookupEnv: noEnv})
	if err != nil {
		t.Fatalf("Load: %v", err)
	}
	if cfg.Profile != Container || cfg.SFTPListen != ":2122" || cfg.HTTPListen != ":8122" || len(cfg.Warnings) != 0 {
		t.Errorf("Load = %+v, want the container profile's defaults and no warnings", cfg)
	}
	config := testutil.WriteFile(t, filepath.Join(t.TempDir(), "sftpit.yaml"), "schema_version: 1\nserver:\n  sftp_listen: \"0.0.0.0:2200\"\n")
	cfg, err = Load(Options{Profile: Container, ConfigFile: config, HTTPListen: "192.0.2.1:0", LookupEnv: noEnv})
	if err != nil {
		t.Fatalf("Load: %v", err)
	}
	if cfg.SFTPListen != "0.0.0.0:2200" || cfg.HTTPListen != "192.0.2.1:0" {
		t.Errorf("SFTPListen = %q, HTTPListen = %q, want the configured addresses", cfg.SFTPListen, cfg.HTTPListen)
	}
	if _, err := Load(Options{Profile: Container, SFTPListen: "[::]:ssh", LookupEnv: noEnv}); err == nil || !strings.Contains(err.Error(), "the port must be a number") {
		t.Errorf("a named port: error = %v, want it refused", err)
	}
}

func TestLoadWarnsOfLoopbackAddressesInTheContainerProfile(t *testing.T) {
	cfg, err := Load(Options{Profile: Container, SFTPListen: "127.0.0.1:2122", HTTPListen: "localhost:8122", LookupEnv: noEnv})
	if err != nil {
		t.Fatalf("Load: %v", err)
	}
	want := []string{
		`sftp_listen "127.0.0.1:2122" is a loopback address, which other containers cannot reach`,
		`http_listen "localhost:8122" is a loopback address, which other containers cannot reach`,
	}
	if !slices.Equal(cfg.Warnings, want) {
		t.Errorf("Warnings = %q, want %q", cfg.Warnings, want)
	}
}

func TestLoadChecksTheControlHosts(t *testing.T) {
	hosts := []string{"sftpit", "files.test", "my_app", "Sftpit-2", "172.18.0.5", "fd00::1"}
	cfg, err := Load(Options{ControlHosts: hosts, LookupEnv: noEnv})
	if err != nil {
		t.Fatalf("Load: %v", err)
	}
	if !slices.Equal(cfg.ControlHosts, hosts) {
		t.Errorf("ControlHosts = %q, want %q", cfg.ControlHosts, hosts)
	}
	for _, host := range []string{"", "sftpit:8122", "[fd00::1]", "http://sftpit", ".sftpit", "sftpit.", "files..test", "my app"} {
		_, err := Load(Options{ControlHosts: []string{"sftpit", host}, LookupEnv: noEnv})
		if want := `control host "` + host + `" is not a host name or IP address without a port`; err == nil || !strings.Contains(err.Error(), want) {
			t.Errorf("%q: error = %v, want %q", host, err, want)
		}
	}
}
