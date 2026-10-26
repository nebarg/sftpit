package main

import (
	"bytes"
	"encoding/json"
	"errors"
	"fmt"
	"io"
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

// readReadyFile reads the ready file name. It fails with a "not a ready
// file" error for anything serve could not have written, such as JSON with
// other fields, without one of serve's or with more after it, so that
// prepareReadyFile never takes another file for one.
func readReadyFile(name string) (readyFile, error) {
	b, err := os.ReadFile(name)
	if err != nil {
		return readyFile{}, err
	}
	var rf readyFile
	dec := json.NewDecoder(bytes.NewReader(b))
	dec.DisallowUnknownFields()
	if dec.Decode(&rf) != nil || !errors.Is(dec.Decode(new(json.RawMessage)), io.EOF) || !rf.complete() {
		return readyFile{}, fmt.Errorf("%s is not a ready file that sftpit serve wrote", name)
	}
	return rf, nil
}

// complete reports whether rf has every field that serve writes.
func (rf readyFile) complete() bool {
	return rf.SFTPAddress != "" && rf.HTTPAddress != "" && rf.Workspace != "" && len(rf.HostKeys) > 0
}

// prepareReadyFile checks that serve can write a ready file at name, and
// removes one that an earlier serve left there, so that it cannot be taken
// for this one's. It refuses to remove any other file.
func prepareReadyFile(name string) error {
	dir := filepath.Dir(name)
	switch info, err := os.Stat(dir); {
	case errors.Is(err, fs.ErrNotExist):
		return fmt.Errorf("the directory of %s does not exist", name)
	case err != nil:
		return err
	case !info.IsDir():
		return fmt.Errorf("%s is not a directory", dir)
	}
	// The ready file is written as writeReadyFile writes it, through a
	// temporary file in the same directory.
	probe, err := os.CreateTemp(dir, ".sftpit-ready-*")
	if err != nil {
		return err
	}
	probe.Close()
	if err := os.Remove(probe.Name()); err != nil {
		return err
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
