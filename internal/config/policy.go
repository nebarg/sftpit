package config

import (
	"errors"
	"fmt"
	"path"
	"slices"

	"github.com/nebarg/sftpit/internal/sshfront"
)

// Policy is what clients may do, whatever faults a run injects.
type Policy struct {
	// ReadOnly are the paths that clients cannot change.
	ReadOnly []ReadOnly
}

// ReadOnly is a path that clients cannot change, with everything beneath
// it.
type ReadOnly struct {
	// PathPrefix is a clean absolute SFTP path.
	PathPrefix string

	// Users are the users it applies to, or nil for every user.
	Users []string
}

// ReadOnlyFor returns the paths that user cannot change.
func (p Policy) ReadOnlyFor(user string) []string {
	var paths []string
	for _, r := range p.ReadOnly {
		if r.Users == nil || slices.Contains(r.Users, user) {
			paths = append(paths, r.PathPrefix)
		}
	}
	return paths
}

type policyConfig struct {
	ReadOnly []readOnlyConfig `yaml:"read_only,omitempty"`
}

type readOnlyConfig struct {
	PathPrefix string     `yaml:"path_prefix"`
	Users      stringList `yaml:"users,flow,omitempty"`
}

// policy validates pc against the configured users.
func (pc policyConfig) policy(users []sshfront.User) (Policy, error) {
	var p Policy
	for i, rc := range pc.ReadOnly {
		r, err := rc.readOnly(users)
		if err != nil {
			return Policy{}, fmt.Errorf("policy.read_only[%d]: %w", i, err)
		}
		p.ReadOnly = append(p.ReadOnly, r)
	}
	return p, nil
}

func (rc readOnlyConfig) readOnly(users []sshfront.User) (ReadOnly, error) {
	switch {
	case rc.PathPrefix == "":
		return ReadOnly{}, errors.New("path_prefix is required")
	case !path.IsAbs(rc.PathPrefix) || path.Clean(rc.PathPrefix) != rc.PathPrefix:
		return ReadOnly{}, fmt.Errorf("path_prefix %q is not a clean absolute path", rc.PathPrefix)
	case rc.Users != nil && len(rc.Users) == 0:
		return ReadOnly{}, errors.New("users needs at least one user; leave it out for every user")
	}
	for _, user := range rc.Users {
		if err := checkCredentials(user, "", users); err != nil {
			return ReadOnly{}, err
		}
	}
	return ReadOnly{PathPrefix: rc.PathPrefix, Users: rc.Users}, nil
}
