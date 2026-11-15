package config

import (
	"errors"
	"fmt"
	"io/fs"
	"os"
	"path"
	"path/filepath"
	"slices"
	"strings"

	"golang.org/x/crypto/ssh"

	"github.com/nebarg/sftpit/internal/sshfront"
)

// usersEnv is the environment variable that lists users, separated by
// spaces, as the atmoz/sftp image reads it.
const usersEnv = "SFTP_USERS"

// listedUser is a user given in the form the atmoz/sftp image takes,
// name:password[:e][:uid[:gid[:folder[,folder]...]]], so that a setup
// written for that image declares its users to sftpit unchanged.
type listedUser struct {
	name, password string

	// folders are the folders to make for the user, as absolute SFTP
	// paths.
	folders []string
}

// parseListedUser parses one user. Its errors name the user but never
// repeat the entry, which holds a password.
func parseListedUser(entry string) (listedUser, error) {
	fields := strings.Split(entry, ":")
	if len(fields) < 2 || fields[0] == "" {
		return listedUser{}, errors.New("a user is given as name:password, optionally followed by :uid:gid:folders")
	}
	u := listedUser{name: fields[0], password: fields[1]}
	if strings.ContainsAny(u.name, "/\x00") || u.name == "." || u.name == ".." {
		return listedUser{}, fmt.Errorf("user %q: the name must be usable as a directory name under /home", u.name)
	}
	rest := fields[2:]
	if len(rest) > 0 && rest[0] == "e" {
		return listedUser{}, fmt.Errorf("user %s: an encrypted password can't be checked; give the password itself", u.name)
	}
	if len(rest) > 3 {
		return listedUser{}, fmt.Errorf("user %s: there is nothing to give after the folders", u.name)
	}
	// sftpit has no owners, so the IDs are checked and then unused.
	for i, id := range rest[:min(len(rest), 2)] {
		if strings.Trim(id, "0123456789") != "" {
			return listedUser{}, fmt.Errorf("user %s: %s %q is not a number", u.name, []string{"uid", "gid"}[i], id)
		}
	}
	if len(rest) == 3 {
		for folder := range strings.SplitSeq(rest[2], ",") {
			if strings.ContainsRune(folder, 0) {
				return listedUser{}, fmt.Errorf("user %s: folder %q is not a path", u.name, folder)
			}
			if folder != "" {
				u.folders = append(u.folders, path.Join("/", folder))
			}
		}
	}
	return u, nil
}

// listedUsers returns the users listed in file, one to a line, if it
// exists, then entries, then those of the SFTP_USERS variable, which is the
// order the atmoz/sftp image reads them in.
func listedUsers(file string, entries []string, lookupEnv func(string) (string, bool)) ([]listedUser, error) {
	var users []listedUser
	if file != "" {
		fromFile, err := readUsersFile(file)
		if err != nil {
			return nil, err
		}
		users = fromFile
	}
	for _, entry := range entries {
		u, err := parseListedUser(entry)
		if err != nil {
			return nil, err
		}
		users = append(users, u)
	}
	listed, _ := lookupEnv(usersEnv)
	for entry := range strings.FieldsSeq(listed) {
		u, err := parseListedUser(entry)
		if err != nil {
			return nil, fmt.Errorf("%s: %w", usersEnv, err)
		}
		users = append(users, u)
	}
	return users, nil
}

// readUsersFile reads the users in the file name, one to a line, skipping
// blank lines and those that begin with #. A file that does not exist lists
// none.
func readUsersFile(name string) ([]listedUser, error) {
	data, err := os.ReadFile(name)
	if errors.Is(err, fs.ErrNotExist) {
		return nil, nil
	}
	if err != nil {
		return nil, fmt.Errorf("config: %w", err)
	}
	var users []listedUser
	line := 0
	for entry := range strings.Lines(string(data)) {
		line++
		entry = strings.TrimSpace(entry)
		if entry == "" || strings.HasPrefix(entry, "#") {
			continue
		}
		u, err := parseListedUser(entry)
		if err != nil {
			return nil, fmt.Errorf("%s:%d: %w", name, line, err)
		}
		users = append(users, u)
	}
	return users, nil
}

// listedHome returns the directory of the user called name in the run's
// files, as the atmoz/sftp image lays it out. The user sees it as /.
func listedHome(name string) string { return path.Join("/home", name) }

// withListed returns users with each of listed added, confined to a home of
// its own and starting at its /, and the folders to make for them, inside
// those homes. Each user's keys are the *.pub files in
// keysDir/<name>/.ssh/keys, unless keysDir is "". It refuses a name given
// more than once and a user who has neither a password nor a key.
func withListed(users []sshfront.User, listed []listedUser, keysDir string) ([]sshfront.User, []string, error) {
	var folders []string
	for _, l := range listed {
		if slices.ContainsFunc(users, func(u sshfront.User) bool { return u.Name == l.name }) {
			return nil, nil, fmt.Errorf("user %s is given more than once", l.name)
		}
		var keys []ssh.PublicKey
		if keysDir != "" {
			var err error
			if keys, err = readMountedKeys(keysDir, l.name); err != nil {
				return nil, nil, fmt.Errorf("user %s: %w", l.name, err)
			}
		}
		if l.password == "" && len(keys) == 0 {
			if keysDir == "" {
				return nil, nil, fmt.Errorf("user %s: a password is required", l.name)
			}
			return nil, nil, fmt.Errorf("user %s: give a password, or mount a public key file ending in .pub in %s", l.name, mountedKeysDir(keysDir, l.name))
		}
		root := listedHome(l.name)
		users = append(users, sshfront.User{Name: l.name, Password: l.password, AuthorizedKeys: keys, Home: "/", Root: root})
		for _, folder := range l.folders {
			folders = append(folders, path.Join(root, folder))
		}
	}
	return users, folders, nil
}

// mountedKeysDir returns the directory in which the atmoz/sftp image looks
// for the keys of the user called name, under the home directory dir.
func mountedKeysDir(dir, name string) string {
	return filepath.Join(dir, name, ".ssh", "keys")
}

// readMountedKeys returns the keys in the *.pub files of the user's keys
// directory, in the order of their names. A directory that does not exist
// holds none.
func readMountedKeys(dir, name string) ([]ssh.PublicKey, error) {
	keysDir := mountedKeysDir(dir, name)
	entries, err := os.ReadDir(keysDir)
	if errors.Is(err, fs.ErrNotExist) {
		return nil, nil
	}
	if err != nil {
		return nil, fmt.Errorf("config: %w", err)
	}
	var keys []ssh.PublicKey
	for _, e := range entries {
		if e.IsDir() || filepath.Ext(e.Name()) != ".pub" {
			continue
		}
		fileKeys, err := readAuthorizedKeys(filepath.Join(keysDir, e.Name()))
		if err != nil {
			return nil, err
		}
		keys = append(keys, fileKeys...)
	}
	return keys, nil
}
