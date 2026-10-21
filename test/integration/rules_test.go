package integration

import (
	"errors"
	"io/fs"
	"log/slog"
	"testing"

	"golang.org/x/crypto/ssh"

	"github.com/nebarg/sftpit/internal/faults"
	"github.com/nebarg/sftpit/internal/sftpproxy"
	"github.com/nebarg/sftpit/internal/sftpwire"
)

// TestRulesMatchTheKeyAClientLoggedInWith denies directories to the client
// that logs in with the test key, and checks that the same user logged in
// with a password is unaffected.
func TestRulesMatchTheKeyAClientLoggedInWith(t *testing.T) {
	signer, err := ssh.NewSignerFromKey(clientKey)
	if err != nil {
		t.Fatal(err)
	}
	rules, err := faults.New([]faults.Rule{{
		ID: "deny-key",
		Match: faults.Match{
			User:           testUser,
			KeyFingerprint: ssh.FingerprintSHA256(signer.PublicKey()),
			Operations:     []faults.Operation{faults.Mkdir},
		},
		Action: sftpproxy.Fail{When: sftpproxy.Before, Status: sftpwire.StatusPermissionDenied},
	}}, slog.New(slog.DiscardHandler))
	if err != nil {
		t.Fatalf("faults.New: %v", err)
	}
	srv := startServerWithRules(t, rules, sftpproxy.Options{})

	byKey := pkgSFTPClient(t, srv, ssh.PublicKeys(signer))
	defer byKey.Close()
	if err := byKey.Mkdir("/by-key"); !errors.Is(err, fs.ErrPermission) {
		t.Errorf("Mkdir after a key login = %v, want permission denied", err)
	}
	byPassword := pkgSFTPClient(t, srv, ssh.Password(testPassword))
	defer byPassword.Close()
	if err := byPassword.Mkdir("/by-password"); err != nil {
		t.Errorf("Mkdir after a password login = %v, want it to succeed", err)
	}
}
