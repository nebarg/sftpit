package config

import (
	"fmt"
	"net"
	"net/netip"
	"strconv"
	"strings"
)

// Profile says which addresses sftpit may listen on.
type Profile int

const (
	// Loopback listens only on loopback addresses.
	Loopback Profile = iota

	// Container listens on every interface by default, for a container
	// whose network is its own, so that other containers on its network
	// can reach it.
	Container
)

// profiles are the profiles the command line names.
var profiles = map[string]Profile{
	"loopback":  Loopback,
	"container": Container,
}

// ParseProfile returns the profile named s.
func ParseProfile(s string) (Profile, error) {
	p, ok := profiles[s]
	if !ok {
		return 0, fmt.Errorf("profile %q is not loopback or container", s)
	}
	return p, nil
}

func (p Profile) String() string {
	if p == Container {
		return "container"
	}
	return "loopback"
}

// defaultListen returns the addresses the profile listens on when neither
// the configuration nor the command line sets them.
func (p Profile) defaultListen() (sftp, http string) {
	if p == Container {
		return ContainerSFTPListen, ContainerHTTPListen
	}
	return DefaultSFTPListen, DefaultHTTPListen
}

// checkListen requires addr, the value of setting, to be a host and a
// numeric port, and the host to be localhost or a loopback IP address
// unless the profile is Container. It returns a warning for a loopback
// address in a container, which other containers cannot reach.
func (p Profile) checkListen(setting, addr string) (warning string, err error) {
	host, port, err := net.SplitHostPort(addr)
	if err != nil {
		return "", fmt.Errorf("%s %q: %w", setting, addr, err)
	}
	if _, err := strconv.ParseUint(port, 10, 16); err != nil {
		return "", fmt.Errorf("%s %q: the port must be a number from 0 to 65535", setting, addr)
	}
	loopback := host == "localhost"
	if ip, err := netip.ParseAddr(host); err == nil && ip.IsLoopback() {
		loopback = true
	}
	switch {
	case p == Container && loopback:
		return fmt.Sprintf("%s %q is a loopback address, which other containers cannot reach", setting, addr), nil
	case p == Loopback && !loopback:
		return "", fmt.Errorf("%s %q is not a loopback address; sftpit listens only on loopback, such as 127.0.0.1:%s or [::1]:%[3]s, unless --profile container is given", setting, addr, port)
	}
	return "", nil
}

// checkControlHost requires name to be a host name, such as a compose
// service's, or an IP address, without a port.
func checkControlHost(name string) error {
	if _, err := netip.ParseAddr(name); err == nil {
		return nil
	}
	valid := name != "" && !strings.ContainsFunc(name, func(r rune) bool { return !isHostNameRune(r) })
	if !valid || strings.HasPrefix(name, ".") || strings.HasSuffix(name, ".") || strings.Contains(name, "..") {
		return fmt.Errorf("control host %q is not a host name or IP address without a port, such as sftpit", name)
	}
	return nil
}

func isHostNameRune(r rune) bool {
	return 'a' <= r && r <= 'z' || 'A' <= r && r <= 'Z' || '0' <= r && r <= '9' || r == '-' || r == '.' || r == '_'
}
