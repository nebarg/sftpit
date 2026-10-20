package sshfront_test

import (
	"os"
	"path/filepath"
	"slices"
	"strings"
	"testing"

	"golang.org/x/crypto/ssh"

	"sftpit/internal/sshfront"
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
