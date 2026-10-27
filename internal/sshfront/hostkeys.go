package sshfront

import (
	"crypto"
	"crypto/ed25519"
	"crypto/rand"
	"crypto/rsa"
	"encoding/pem"
	"errors"
	"fmt"
	"io/fs"
	"os"
	"path/filepath"

	"golang.org/x/crypto/ssh"
)

const (
	ed25519HostKeyFile = "ssh_host_ed25519_key"
	rsaHostKeyFile     = "ssh_host_rsa_key"
	rsaHostKeyBits     = 3072
)

// LoadOrCreateHostKeys returns an Ed25519 and an RSA host key stored in dir,
// generating and saving any that are missing so the server keeps the same
// identity across restarts. Keys are stored in OpenSSH format with mode 0600.
// The RSA key signs only with rsa-sha2-512 and rsa-sha2-256, never SHA-1.
func LoadOrCreateHostKeys(dir string) ([]ssh.Signer, error) {
	if err := os.MkdirAll(dir, 0o700); err != nil {
		return nil, fmt.Errorf("sshfront: create host key directory: %w", err)
	}

	ed25519Signer, err := loadOrCreateHostKey(filepath.Join(dir, ed25519HostKeyFile), ssh.KeyAlgoED25519, generateEd25519Key)
	if err != nil {
		return nil, err
	}
	rsaSigner, err := loadOrCreateHostKey(filepath.Join(dir, rsaHostKeyFile), ssh.KeyAlgoRSA, generateRSAKey)
	if err != nil {
		return nil, err
	}

	algorithmSigner, ok := rsaSigner.(ssh.AlgorithmSigner)
	if !ok {
		return nil, errors.New("sshfront: RSA host key cannot choose signature algorithms")
	}
	rsaSHA2Signer, err := ssh.NewSignerWithAlgorithms(algorithmSigner, []string{ssh.KeyAlgoRSASHA512, ssh.KeyAlgoRSASHA256})
	if err != nil {
		return nil, fmt.Errorf("sshfront: restrict RSA host key algorithms: %w", err)
	}
	return []ssh.Signer{ed25519Signer, rsaSHA2Signer}, nil
}

func loadOrCreateHostKey(path, keyType string, generate func() (crypto.PrivateKey, error)) (ssh.Signer, error) {
	pemBytes, err := os.ReadFile(path)
	if errors.Is(err, fs.ErrNotExist) {
		pemBytes, err = createHostKeyFile(path, generate)
		// Another process sharing the directory saved its key first, and
		// both must serve that one.
		if errors.Is(err, fs.ErrExist) {
			pemBytes, err = os.ReadFile(path)
		}
	}
	if err != nil {
		return nil, fmt.Errorf("sshfront: host key %s: %w", path, err)
	}

	signer, err := ssh.ParsePrivateKey(pemBytes)
	if err != nil {
		return nil, fmt.Errorf("sshfront: parse host key %s: %w", path, err)
	}
	if got := signer.PublicKey().Type(); got != keyType {
		return nil, fmt.Errorf("sshfront: host key %s is %s, want %s", path, got, keyType)
	}
	return signer, nil
}

func createHostKeyFile(path string, generate func() (crypto.PrivateKey, error)) ([]byte, error) {
	key, err := generate()
	if err != nil {
		return nil, fmt.Errorf("generate: %w", err)
	}
	block, err := ssh.MarshalPrivateKey(key, "")
	if err != nil {
		return nil, fmt.Errorf("marshal: %w", err)
	}
	pemBytes := pem.EncodeToMemory(block)
	if err := writeFileAtomic(path, pemBytes); err != nil {
		return nil, fmt.Errorf("write: %w", err)
	}
	return pemBytes, nil
}

func generateEd25519Key() (crypto.PrivateKey, error) {
	_, key, err := ed25519.GenerateKey(rand.Reader)
	return key, err
}

func generateRSAKey() (crypto.PrivateKey, error) {
	return rsa.GenerateKey(rand.Reader, rsaHostKeyBits)
}

// writeFileAtomic writes data to a new file at path, so that a reader sees
// either all of it or none. It fails with fs.ErrExist if path exists.
func writeFileAtomic(path string, data []byte) error {
	f, err := os.CreateTemp(filepath.Dir(path), "."+filepath.Base(path)+".tmp-*")
	if err != nil {
		return err
	}
	tmpPath := f.Name()
	defer os.Remove(tmpPath)

	if _, err := f.Write(data); err != nil {
		f.Close()
		return err
	}
	if err := f.Sync(); err != nil {
		f.Close()
		return err
	}
	if err := f.Close(); err != nil {
		return err
	}
	// Unlike a rename, a link never replaces a file that is already there.
	return os.Link(tmpPath, path)
}
