package config

import (
	"path/filepath"
	"reflect"
	"strings"
	"testing"

	"golang.org/x/crypto/ssh"

	"github.com/nebarg/sftpit/internal/sshfront"
	"github.com/nebarg/sftpit/internal/testutil"
)

func TestParseListedUserReadsEachForm(t *testing.T) {
	tests := []struct {
		entry string
		want  listedUser
	}{
		{"foo:pass", listedUser{name: "foo", password: "pass"}},
		{"foo:", listedUser{name: "foo"}},
		{"foo::1001", listedUser{name: "foo"}},
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
	users, folders, err := withListed([]sshfront.User{{Name: "configured", Password: "p", Home: "/c"}}, listed, "")
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

func TestLoadGivesListedUsersTheKeysMountedForThem(t *testing.T) {
	homes := t.TempDir()
	first := writeMountedKeys(t, homes, "foo", "a.pub")
	second := writeMountedKeys(t, homes, "foo", "b.pub")
	third := writeMountedKeys(t, homes, "foo", "c.pub")
	opts := Options{Users: []string{"foo::1001"}, MountedHomeDir: homes, LookupEnv: noEnv}

	cfg, err := Load(opts)
	if err != nil {
		t.Fatalf("Load: %v", err)
	}
	want := []sshfront.User{{Name: "foo", AuthorizedKeys: []ssh.PublicKey{first[0], second[0], third[0]}, Home: "/", Root: "/home/foo"}}
	if !reflect.DeepEqual(cfg.Users, want) {
		t.Errorf("Users = %+v, want %+v", cfg.Users, want)
	}
}

func TestLoadReadsEveryKeyOfAMountedFile(t *testing.T) {
	homes := t.TempDir()
	file := filepath.Join(homes, "foo", ".ssh", "keys", "both.pub")
	one := writeAuthorizedKeys(t, file, "")
	other := writeAuthorizedKeys(t, filepath.Join(t.TempDir(), "other.pub"), "")
	testutil.WriteFile(t, file, string(ssh.MarshalAuthorizedKey(one))+string(ssh.MarshalAuthorizedKey(other)))

	cfg, err := Load(Options{Users: []string{"foo:"}, MountedHomeDir: homes, LookupEnv: noEnv})
	if err != nil {
		t.Fatalf("Load: %v", err)
	}
	if want := []ssh.PublicKey{one, other}; !reflect.DeepEqual(cfg.Users[0].AuthorizedKeys, want) {
		t.Errorf("AuthorizedKeys = %v, want %v", cfg.Users[0].AuthorizedKeys, want)
	}
}

func TestLoadIgnoresMountedFilesThatAreNotKeys(t *testing.T) {
	homes := t.TempDir()
	keys := writeMountedKeys(t, homes, "foo", "id.pub")
	keysDir := filepath.Join(homes, "foo", ".ssh", "keys")
	testutil.WriteFile(t, filepath.Join(keysDir, "notes.txt"), "not a key")
	testutil.WriteFile(t, filepath.Join(keysDir, "id_ed25519"), "not a key")
	testutil.WriteFile(t, filepath.Join(keysDir, "nested.pub", "inner.pub"), "not a key")

	cfg, err := Load(Options{Users: []string{"foo::1001"}, MountedHomeDir: homes, LookupEnv: noEnv})
	if err != nil {
		t.Fatalf("Load: %v", err)
	}
	if !reflect.DeepEqual(cfg.Users[0].AuthorizedKeys, keys) {
		t.Errorf("AuthorizedKeys = %v, want %v", cfg.Users[0].AuthorizedKeys, keys)
	}
}

func TestLoadTakesAMissingKeysDirectoryAsNoKeys(t *testing.T) {
	cfg, err := Load(Options{Users: []string{"foo:pass"}, MountedHomeDir: t.TempDir(), LookupEnv: noEnv})
	if err != nil {
		t.Fatalf("Load: %v", err)
	}
	if want := []sshfront.User{{Name: "foo", Password: "pass", Home: "/", Root: "/home/foo"}}; !reflect.DeepEqual(cfg.Users, want) {
		t.Errorf("Users = %+v, want %+v", cfg.Users, want)
	}
}

func TestLoadRefusesAMountedKeyFileItCannotUse(t *testing.T) {
	tests := []struct {
		name, content, want string
	}{
		{"not a key", "AAAAC3NzaC1lZDI1NTE5AAAAIsecret-material\n", ":1: ssh: no key found"},
		{"an empty file", "", ": no keys found"},
		{"a key with options", "no-pty ssh-ed25519 AAAAC3NzaC1lZDI1NTE5AAAAIOxbLxUlPSDoUjFAHrnh+h4GuV/Xyr3pgQ7LyY2IHrtN\n", `:1: key options such as "no-pty" are not supported`},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			homes := t.TempDir()
			file := testutil.WriteFile(t, filepath.Join(homes, "foo", ".ssh", "keys", "bad.pub"), tt.content)
			_, err := Load(Options{Users: []string{"foo::1001"}, MountedHomeDir: homes, LookupEnv: noEnv})
			if want := "user foo: " + file + tt.want; err == nil || err.Error() != want {
				t.Errorf("Load error = %v, want %q", err, want)
			}
			if err != nil && strings.Contains(err.Error(), "secret-material") {
				t.Errorf("the error %q repeats key material", err)
			}
		})
	}
}

func TestLoadRefusesAListedUserWithNeitherPasswordNorKey(t *testing.T) {
	homes := t.TempDir()
	tests := []struct {
		name, home, want string
	}{
		{"no keys directory in use", "", "user foo: a password is required"},
		{"a keys directory in use", homes, "user foo: give a password, or mount a public key file ending in .pub in " + filepath.Join(homes, "foo", ".ssh", "keys")},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			_, err := Load(Options{Users: []string{"foo::1001"}, MountedHomeDir: tt.home, LookupEnv: noEnv})
			if err == nil || err.Error() != tt.want {
				t.Errorf("Load error = %v, want %q", err, tt.want)
			}
		})
	}
}

func TestLoadKeepsThePasswordOfAListedUserWithKeys(t *testing.T) {
	homes := t.TempDir()
	keys := writeMountedKeys(t, homes, "foo", "id.pub")

	cfg, err := Load(Options{Users: []string{"foo:pass"}, MountedHomeDir: homes, LookupEnv: noEnv})
	if err != nil {
		t.Fatalf("Load: %v", err)
	}
	if want := []sshfront.User{{Name: "foo", Password: "pass", AuthorizedKeys: keys, Home: "/", Root: "/home/foo"}}; !reflect.DeepEqual(cfg.Users, want) {
		t.Errorf("Users = %+v, want %+v", cfg.Users, want)
	}
}

func TestLoadLeavesConfiguredUsersToTheirOwnKeys(t *testing.T) {
	homes := t.TempDir()
	writeMountedKeys(t, homes, "configured", "id.pub")
	config := testutil.WriteFile(t, filepath.Join(t.TempDir(), "sftpit.yaml"), "schema_version: 1\nusers:\n  - {name: configured, password_env: P}\n")

	cfg, err := Load(Options{ConfigFile: config, MountedHomeDir: homes, LookupEnv: fakeEnv{"P": "password"}.lookup})
	if err != nil {
		t.Fatalf("Load: %v", err)
	}
	if want := []sshfront.User{{Name: "configured", Password: "password", Home: "/"}}; !reflect.DeepEqual(cfg.Users, want) {
		t.Errorf("Users = %+v, want %+v", cfg.Users, want)
	}
}
