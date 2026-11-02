package control

import "net/http"

// Options configure the control API.
type Options struct {
	// Hosts are the host names, besides localhost and loopback addresses,
	// that the API answers to.
	Hosts []string

	// Server describes the SFTP server, as the API reports it.
	Server Server
}

// Server describes the SFTP server: what a client needs to connect to it,
// and nothing secret.
type Server struct {
	// SFTPAddress is the address the server listens on, and Profile the
	// profile that chose it, "loopback" or "container".
	SFTPAddress string `json:"sftp_address"`
	Profile     string `json:"profile"`

	// ControlHosts are the host names the API answers to besides loopback
	// ones, such as a compose service's, by which clients in the same
	// network reach the server too.
	ControlHosts []string `json:"control_hosts"`

	HostKeys []HostKey `json:"host_keys"`
	Users    []User    `json:"users"`

	// DefaultLogin is the built-in test user's login, which sftpit accepts
	// only when the configuration has no users, and which is no secret.
	DefaultLogin *Login `json:"default_login,omitempty"`

	ReadOnly []ReadOnly `json:"read_only"`

	// Workspace is the directory that holds the runs.
	Workspace string `json:"workspace"`
}

// HostKey is one of the server's host keys.
type HostKey struct {
	Type        string `json:"type"`
	Fingerprint string `json:"fingerprint"`
}

// User describes a user: how it logs in, but not with what.
type User struct {
	Name     string `json:"name"`
	Home     string `json:"home"`
	Password bool   `json:"password"`
	Keys     int    `json:"keys"`
}

// Login is a user name with its password.
type Login struct {
	User     string `json:"user"`
	Password string `json:"password"`
}

// ReadOnly is a path that the policy makes read-only, for every user, or
// for Users if set.
type ReadOnly struct {
	PathPrefix string   `json:"path_prefix"`
	Users      []string `json:"users,omitempty"`
}

func (a *api) server(w http.ResponseWriter, _ *http.Request) {
	writeJSON(w, http.StatusOK, a.opts.Server)
}
