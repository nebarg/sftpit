package config

import (
	"path/filepath"
	"reflect"
	"strings"
	"testing"

	"github.com/nebarg/sftpit/internal/sshfront"
	"github.com/nebarg/sftpit/internal/testutil"
)

func TestParseListedUserReadsEachForm(t *testing.T) {
	tests := []struct {
		entry string
		want  listedUser
	}{
		{"foo:pass", listedUser{name: "foo", password: "pass"}},
		{"foo:pass:1001", listedUser{name: "foo", password: "pass"}},
		{"foo:pass:1001:100", listedUser{name: "foo", password: "pass"}},
		{"foo:pass:1001:100:upload", listedUser{name: "foo", password: "pass", folders: []string{"/upload"}}},
		{"foo:pass:::upload,in/orders,", listedUser{name: "foo", password: "pass", folders: []string{"/upload", "/in/orders"}}},
		{"foo:pass:1001:100:../outside", listedUser{name: "foo", password: "pass", folders: []string{"/outside"}}},
	}
	for _, tt := range tests {
		t.Run(tt.entry, func(t *testing.T) {
			got, err := parseListedUser(tt.entry)
			if err != nil || !reflect.DeepEqual(got, tt.want) {
				t.Errorf("parseListedUser = %+v, %v; want %+v", got, err, tt.want)
			}
		})
	}
}

func TestParseListedUserSaysWhatIsWrongWithoutThePassword(t *testing.T) {
	const form = "a user is given as name:password, optionally followed by :uid:gid:folders"
	tests := []struct {
		name, entry, want string
	}{
		{"no password field", "foo", form},
		{"no name", ":s3cret", form},
		{"a name with a slash", "a/b:s3cret", `user "a/b": the name must be usable as a directory name under /home`},
		{"a name with a NUL", "a\x00b:s3cret", `user "a\x00b": the name must be usable as a directory name under /home`},
		{"a name of a dot", ".:s3cret", `user ".": the name must be usable as a directory name under /home`},
		{"a name of two dots", "..:s3cret", `user "..": the name must be usable as a directory name under /home`},
		{"an empty password", "foo:", "user foo: a password is required"},
		{"an encrypted password", "foo:s3cret:e", "user foo: an encrypted password can't be checked; give the password itself"},
		{"an encrypted password with a uid", "foo:s3cret:e:1001", "user foo: an encrypted password can't be checked; give the password itself"},
		{"a uid that is not a number", "foo:s3cret:upload", `user foo: uid "upload" is not a number`},
		{"a gid that is not a number", "foo:s3cret:1001:staff", `user foo: gid "staff" is not a number`},
		{"a field after the folders", "foo:s3cret:1001:100:upload:more", "user foo: there is nothing to give after the folders"},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			_, err := parseListedUser(tt.entry)
			if err == nil || err.Error() != tt.want {
				t.Errorf("parseListedUser(%q) error = %v, want %q", tt.entry, err, tt.want)
			}
			if err != nil && strings.Contains(err.Error(), "s3cret") {
				t.Errorf("the error %q repeats the password", err)
			}
		})
	}
}

func TestLoadAddsListedUsersInTheOrderTheyAreRead(t *testing.T) {
	dir := t.TempDir()
	config := testutil.WriteFile(t, filepath.Join(dir, "sftpit.yaml"), "schema_version: 1\nusers:\n  - {name: configured, password_env: P, home: /configured}\n")
	file := testutil.WriteFile(t, filepath.Join(dir, "users.conf"), "# partners\n\nfiled:one:1001:100:filed-in\n")
	env := fakeEnv{"P": "password", "SFTP_USERS": "first:two second:three:::second-in,shared"}

	cfg, err := Load(Options{ConfigFile: config, UsersFile: file, Users: []string{"argued:four:1002"}, LookupEnv: env.lookup})
	if err != nil {
		t.Fatalf("Load: %v", err)
	}
	want := []sshfront.User{
		{Name: "configured", Password: "password", Home: "/configured"},
		{Name: "filed", Password: "one", Home: "/", Root: "/home/filed"},
		{Name: "argued", Password: "four", Home: "/", Root: "/home/argued"},
		{Name: "first", Password: "two", Home: "/", Root: "/home/first"},
		{Name: "second", Password: "three", Home: "/", Root: "/home/second"},
	}
	if !reflect.DeepEqual(cfg.Users, want) {
		t.Errorf("Users = %+v, want %+v", cfg.Users, want)
	}
	if want := []string{"/home/filed/filed-in", "/home/second/second-in", "/home/second/shared"}; !reflect.DeepEqual(cfg.Folders, want) {
		t.Errorf("Folders = %v, want %v", cfg.Folders, want)
	}
	if cfg.DefaultCredentials {
		t.Error("DefaultCredentials is set though users were given")
	}
}

func TestLoadWithOnlyListedUsersHasNoTestUser(t *testing.T) {
	cfg, err := Load(Options{Users: []string{"foo:pass"}, UsersFile: filepath.Join(t.TempDir(), "missing.conf"), LookupEnv: noEnv})
	if err != nil {
		t.Fatalf("Load: %v", err)
	}
	if want := []sshfront.User{{Name: "foo", Password: "pass", Home: "/", Root: "/home/foo"}}; !reflect.DeepEqual(cfg.Users, want) || cfg.DefaultCredentials {
		t.Errorf("Users = %+v, DefaultCredentials = %t; want only %+v", cfg.Users, cfg.DefaultCredentials, want)
	}
}

func TestLoadRejectsListedUsersItCannotUse(t *testing.T) {
	dir := t.TempDir()
	config := testutil.WriteFile(t, filepath.Join(dir, "sftpit.yaml"), "schema_version: 1\nusers:\n  - {name: configured, password_env: P}\n")
	file := testutil.WriteFile(t, filepath.Join(dir, "users.conf"), "ok:pass\nbroken\n")
	tests := []struct {
		name string
		opts Options
		env  fakeEnv
		want string
	}{
		{"a name given twice", Options{Users: []string{"foo:one", "foo:two"}}, nil, "user foo is given more than once"},
		{"a name the configuration has", Options{ConfigFile: config, Users: []string{"configured:pass"}}, fakeEnv{"P": "password"}, "user configured is given more than once"},
		{"a bad entry in the variable", Options{}, fakeEnv{"SFTP_USERS": "foo:pass bar"}, "SFTP_USERS: a user is given as name:password, optionally followed by :uid:gid:folders"},
		{"a bad line in the file", Options{UsersFile: file}, nil, file + ":2: a user is given as name:password, optionally followed by :uid:gid:folders"},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			tt.opts.LookupEnv = tt.env.lookup
			if _, err := Load(tt.opts); err == nil || err.Error() != tt.want {
				t.Errorf("Load error = %v, want %q", err, tt.want)
			}
		})
	}
}

func TestWithListedGivesEachUserAHomeOfItsOwn(t *testing.T) {
	listed := []listedUser{
		{name: "foo", password: "one", folders: []string{"/upload", "/in/orders"}},
		{name: "bar", password: "two", folders: []string{"/upload", "/outside"}},
	}
	users, folders, err := withListed([]sshfront.User{{Name: "configured", Password: "p", Home: "/c"}}, listed)
	if err != nil {
		t.Fatalf("withListed: %v", err)
	}
	wantUsers := []sshfront.User{
		{Name: "configured", Password: "p", Home: "/c"},
		{Name: "foo", Password: "one", Home: "/", Root: "/home/foo"},
		{Name: "bar", Password: "two", Home: "/", Root: "/home/bar"},
	}
	if !reflect.DeepEqual(users, wantUsers) {
		t.Errorf("users = %+v, want %+v", users, wantUsers)
	}
	wantFolders := []string{"/home/foo/upload", "/home/foo/in/orders", "/home/bar/upload", "/home/bar/outside"}
	if !reflect.DeepEqual(folders, wantFolders) {
		t.Errorf("folders = %v, want %v", folders, wantFolders)
	}
}
