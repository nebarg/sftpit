package main

import (
	"bytes"
	"encoding/json"
	"errors"
	"fmt"
	"io/fs"
	"os"
	"path/filepath"

	"golang.org/x/crypto/ssh"
)

// readyFile is what serve writes to --ready-file once it listens, so that a
// test harness, or another sftpit command, can find it. It holds only what
// stays the same while serve runs, and no secrets; the current run comes
// from the control API.
type readyFile struct {
	SFTPAddress string    `json:"sftp_address"`
	HTTPAddress string    `json:"http_address"`
	Workspace   string    `json:"workspace"`
	HostKeys    []hostKey `json:"host_keys"`
}

type hostKey struct {
	Type        string `json:"type"`
	Fingerprint string `json:"fingerprint"`
}

func newReadyFile(sftpAddr, httpAddr, workspace string, hostKeys []ssh.Signer) readyFile {
	rf := readyFile{SFTPAddress: sftpAddr, HTTPAddress: httpAddr, Workspace: workspace}
	for _, key := range hostKeys {
		rf.HostKeys = append(rf.HostKeys, hostKey{Type: key.PublicKey().Type(), Fingerprint: ssh.FingerprintSHA256(key.PublicKey())})
	}
	return rf
}

// readReadyFile reads the ready file name.
func readReadyFile(name string) (readyFile, error) {
	b, err := os.ReadFile(name)
	if err != nil {
		return readyFile{}, err
	}
	var rf readyFile
	dec := json.NewDecoder(bytes.NewReader(b))
	dec.DisallowUnknownFields()
	if err := dec.Decode(&rf); err != nil || rf.HTTPAddress == "" {
		return readyFile{}, fmt.Errorf("%s is not a ready file that sftpit serve wrote", name)
	}
	return rf, nil
}

// prepareReadyFile checks that serve can write a ready file at name, and
// removes one that an earlier serve left there, so that it cannot be taken
// for this one's. It refuses to remove any other file.
func prepareReadyFile(name string) error {
	if info, err := os.Stat(filepath.Dir(name)); err != nil || !info.IsDir() {
		return fmt.Errorf("the directory of %s does not exist", name)
	}
	if _, err := os.Lstat(name); errors.Is(err, fs.ErrNotExist) {
		return nil
	}
	if _, err := readReadyFile(name); err != nil {
		return fmt.Errorf("%s already exists and is not a ready file, so sftpit will not replace it", name)
	}
	return os.Remove(name)
}

// writeReadyFile writes rf to name through a temporary file in the same
// directory, so that a reader sees either all of it or none.
func writeReadyFile(name string, rf readyFile) (err error) {
	b, err := json.MarshalIndent(rf, "", "  ")
	if err != nil {
		return fmt.Errorf("write ready file: %w", err)
	}
	f, err := os.CreateTemp(filepath.Dir(name), ".sftpit-ready-*")
	if err != nil {
		return fmt.Errorf("write ready file: %w", err)
	}
	defer func() {
		if err != nil {
			os.Remove(f.Name())
		}
	}()
	_, err = f.Write(append(b, '\n'))
	// CreateTemp makes the file readable only by its owner, and a harness
	// in another container may run as another user.
	err = errors.Join(err, f.Chmod(0o644), f.Close())
	if err == nil {
		err = os.Rename(f.Name(), name)
	}
	if err != nil {
		return fmt.Errorf("write ready file: %w", err)
	}
	return nil
}
