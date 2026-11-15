package sshfront_test

import (
	"fmt"
	"os"
	"path/filepath"
	"slices"
	"strings"
	"sync"
	"testing"

	"golang.org/x/crypto/ssh"

	"github.com/nebarg/sftpit/internal/sshfront"
)

func TestLoadOrCreateHostKeysCreatesThenReloads(t *testing.T) {
	dir := filepath.Join(t.TempDir(), "identity")

	created, err := sshfront.LoadOrCreateHostKeys(dir)
	if err != nil {
		t.Fatalf("first call: %v", err)
	}
	if got := keyTypes(created); !slices.Equal(got, []string{ssh.KeyAlgoED25519, ssh.KeyAlgoRSA}) {
		t.Fatalf("key types = %v, want ed25519 then RSA", got)
	}
	for _, name := range []string{"ssh_host_ed25519_key", "ssh_host_rsa_key"} {
		info, err := os.Stat(filepath.Join(dir, name))
		if err != nil {
			t.Fatalf("stat %s: %v", name, err)
		}
		if perm := info.Mode().Perm(); perm != 0o600 {
			t.Errorf("%s mode = %o, want 600", name, perm)
		}
	}

	rsaSigner, ok := created[1].(ssh.MultiAlgorithmSigner)
	if !ok {
		t.Fatal("RSA host key does not restrict its signature algorithms")
	}
	if got := rsaSigner.Algorithms(); !slices.Equal(got, []string{ssh.KeyAlgoRSASHA512, ssh.KeyAlgoRSASHA256}) {
		t.Errorf("RSA signature algorithms = %v, want rsa-sha2-512 and rsa-sha2-256 only", got)
	}

	reloaded, err := sshfront.LoadOrCreateHostKeys(dir)
	if err != nil {
		t.Fatalf("second call: %v", err)
	}
	if got, want := fingerprints(reloaded), fingerprints(created); !slices.Equal(got, want) {
		t.Errorf("reloaded fingerprints %v, want the saved %v", got, want)
	}
}

// Two servers can share a configured host key directory and start at once.
// Each must serve the keys that end up saved, not ones the other replaced.
func TestLoadOrCreateHostKeysAgreesWhenCreatingAtOnce(t *testing.T) {
	dir := filepath.Join(t.TempDir(), "identity")
	const starts = 4
	got := make([][]string, starts)
	var wg sync.WaitGroup
	for i := range starts {
		wg.Go(func() {
			signers, err := sshfront.LoadOrCreateHostKeys(dir)
			if err != nil {
				t.Errorf("start %d: %v", i, err)
				return
			}
			got[i] = fingerprints(signers)
		})
	}
	wg.Wait()
	saved, err := sshfront.LoadOrCreateHostKeys(dir)
	if err != nil {
		t.Fatal(err)
	}
	for i, prints := range got {
		if prints != nil && !slices.Equal(prints, fingerprints(saved)) {
			t.Errorf("start %d serves %v, but %v are saved", i, prints, fingerprints(saved))
		}
	}
}

func TestLoadOrCreateHostKeysRejectsBadFiles(t *testing.T) {
	validDir := t.TempDir()
	if _, err := sshfront.LoadOrCreateHostKeys(validDir); err != nil {
		t.Fatalf("create valid keys: %v", err)
	}
	rsaPEM, err := os.ReadFile(filepath.Join(validDir, "ssh_host_rsa_key"))
	if err != nil {
		t.Fatalf("read RSA key: %v", err)
	}

	tests := []struct {
		name     string
		contents []byte
		wantErr  string
	}{
		{name: "corrupt key", contents: []byte("not a key"), wantErr: "parse host key"},
		{name: "wrong key type", contents: rsaPEM, wantErr: "is ssh-rsa, want ssh-ed25519"},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			dir := t.TempDir()
			if err := os.WriteFile(filepath.Join(dir, "ssh_host_ed25519_key"), tt.contents, 0o600); err != nil {
				t.Fatalf("write key file: %v", err)
			}
			_, err := sshfront.LoadOrCreateHostKeys(dir)
			if err == nil || !strings.Contains(err.Error(), tt.wantErr) {
				t.Fatalf("error = %v, want it to contain %q", err, tt.wantErr)
			}
		})
	}
}

// savedHostKeys returns a directory holding the host keys that
// LoadOrCreateHostKeys makes, for a test to copy from.
func savedHostKeys(t *testing.T) string {
	t.Helper()
	dir := t.TempDir()
	if _, err := sshfront.LoadOrCreateHostKeys(dir); err != nil {
		t.Fatalf("create host keys: %v", err)
	}
	return dir
}

func copyHostKey(t *testing.T, from, to, name string) {
	t.Helper()
	contents, err := os.ReadFile(filepath.Join(from, name))
	if err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(to, name), contents, 0o600); err != nil {
		t.Fatal(err)
	}
}

func TestLoadHostKeysServesOnlyTheKeysThatArePresent(t *testing.T) {
	saved := savedHostKeys(t)
	all, err := sshfront.LoadHostKeys(saved)
	if err != nil {
		t.Fatal(err)
	}
	savedPrints := make(map[string]string)
	for _, signer := range all {
		savedPrints[signer.PublicKey().Type()] = ssh.FingerprintSHA256(signer.PublicKey())
	}
	tests := []struct {
		name  string
		files []string
		want  []string
	}{
		{"both", []string{"ssh_host_ed25519_key", "ssh_host_rsa_key"}, []string{ssh.KeyAlgoED25519, ssh.KeyAlgoRSA}},
		{"Ed25519 only", []string{"ssh_host_ed25519_key"}, []string{ssh.KeyAlgoED25519}},
		{"RSA only", []string{"ssh_host_rsa_key"}, []string{ssh.KeyAlgoRSA}},
		{"neither", nil, []string{}},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			dir := t.TempDir()
			for _, name := range tt.files {
				copyHostKey(t, saved, dir, name)
			}
			signers, err := sshfront.LoadHostKeys(dir)
			if err != nil {
				t.Fatalf("LoadHostKeys: %v", err)
			}
			if got := keyTypes(signers); !slices.Equal(got, tt.want) {
				t.Fatalf("key types = %v, want %v", got, tt.want)
			}
			for _, signer := range signers {
				keyType := signer.PublicKey().Type()
				if got, want := ssh.FingerprintSHA256(signer.PublicKey()), savedPrints[keyType]; got != want {
					t.Errorf("%s fingerprint = %s, want the saved key's %s", keyType, got, want)
				}
			}
			for _, signer := range signers {
				if signer.PublicKey().Type() != ssh.KeyAlgoRSA {
					continue
				}
				rsaSigner, ok := signer.(ssh.MultiAlgorithmSigner)
				if !ok {
					t.Fatal("RSA host key does not restrict its signature algorithms")
				}
				if got := rsaSigner.Algorithms(); !slices.Equal(got, []string{ssh.KeyAlgoRSASHA512, ssh.KeyAlgoRSASHA256}) {
					t.Errorf("RSA signature algorithms = %v, want rsa-sha2-512 and rsa-sha2-256 only", got)
				}
			}
			entries, err := os.ReadDir(dir)
			if err != nil {
				t.Fatal(err)
			}
			if len(entries) != len(tt.files) {
				t.Errorf("directory holds %d files after loading, want the %d put there", len(entries), len(tt.files))
			}
		})
	}
}

func TestLoadHostKeysWithoutTheDirectoryServesNone(t *testing.T) {
	signers, err := sshfront.LoadHostKeys(filepath.Join(t.TempDir(), "missing"))
	if err != nil || len(signers) != 0 {
		t.Fatalf("LoadHostKeys = %v, %v; want no keys and no error", keyTypes(signers), err)
	}
}

func TestLoadHostKeysRejectsBadFilesNamingThem(t *testing.T) {
	saved := savedHostKeys(t)
	rsaPEM, err := os.ReadFile(filepath.Join(saved, "ssh_host_rsa_key"))
	if err != nil {
		t.Fatal(err)
	}
	tests := []struct {
		name, file string
		contents   []byte
		wantErr    string
	}{
		{"corrupt key", "ssh_host_ed25519_key", []byte("not a key"), "sshfront: parse host key %s: "},
		{"wrong key type", "ssh_host_ed25519_key", rsaPEM, "sshfront: host key %s is ssh-rsa, want ssh-ed25519"},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			dir := t.TempDir()
			path := filepath.Join(dir, tt.file)
			if err := os.WriteFile(path, tt.contents, 0o600); err != nil {
				t.Fatal(err)
			}
			_, err := sshfront.LoadHostKeys(dir)
			if want := fmt.Sprintf(tt.wantErr, path); err == nil || !strings.Contains(err.Error(), want) {
				t.Fatalf("error = %v, want it to contain %q", err, want)
			}
			entries, _ := os.ReadDir(dir)
			if len(entries) != 1 {
				t.Errorf("directory holds %d files, want only the one put there", len(entries))
			}
		})
	}
}

func TestLoadHostKeysExplainsAnUnreadableKey(t *testing.T) {
	if os.Geteuid() == 0 {
		t.Skip("root reads any file")
	}
	dir := t.TempDir()
	copyHostKey(t, savedHostKeys(t), dir, "ssh_host_rsa_key")
	path := filepath.Join(dir, "ssh_host_rsa_key")
	if err := os.Chmod(path, 0); err != nil {
		t.Fatal(err)
	}
	_, err := sshfront.LoadHostKeys(dir)
	want := "sshfront: host key " + path + ": permission denied; the user running sftpit must be able to read it"
	if err == nil || err.Error() != want {
		t.Fatalf("error = %v, want %q", err, want)
	}
}

func keyTypes(signers []ssh.Signer) []string {
	types := make([]string, len(signers))
	for i, s := range signers {
		types[i] = s.PublicKey().Type()
	}
	return types
}

func fingerprints(signers []ssh.Signer) []string {
	prints := make([]string, len(signers))
	for i, s := range signers {
		prints[i] = ssh.FingerprintSHA256(s.PublicKey())
	}
	return prints
}
