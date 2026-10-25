package sshfront_test

import (
	"bytes"
	"context"
	"crypto/ed25519"
	"crypto/rand"
	"encoding/pem"
	"fmt"
	"net"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"testing"

	"golang.org/x/crypto/ssh"
	"golang.org/x/crypto/ssh/knownhosts"

	"github.com/nebarg/sftpit/internal/sshfront"
)

func TestOpenSSHClientTransfer(t *testing.T) {
	if testing.Short() {
		t.Skip("runs the OpenSSH sftp client")
	}
	sftpPath, err := exec.LookPath("sftp")
	if err != nil {
		t.Skip("OpenSSH sftp client not installed")
	}

	dir := t.TempDir()
	clientPublicKey, keyFile := writeClientKey(t, dir)
	addr, _ := startServer(t, sshfront.Config{
		Users:   []sshfront.User{{Name: "partner-b", AuthorizedKeys: []ssh.PublicKey{clientPublicKey}}},
		Handler: inMemorySFTP,
	})
	knownHostsFile := writeKnownHosts(t, dir, addr)

	want := make([]byte, 1<<20)
	rand.Read(want)
	upload := filepath.Join(dir, "upload.bin")
	download := filepath.Join(dir, "download.bin")
	writeFile(t, upload, want)
	batch := filepath.Join(dir, "batch")
	writeFile(t, batch, fmt.Appendf(nil, "put %s /orders.bin\nget /orders.bin %s\n", upload, download))

	_, port, err := net.SplitHostPort(addr)
	if err != nil {
		t.Fatalf("SplitHostPort: %v", err)
	}
	ctx, cancel := context.WithTimeout(t.Context(), waitTimeout*2)
	defer cancel()
	cmd := exec.CommandContext(ctx, sftpPath,
		"-b", batch,
		"-P", port,
		"-F", os.DevNull,
		"-i", keyFile,
		"-o", "IdentitiesOnly=yes",
		"-o", "IdentityAgent=none",
		"-o", "BatchMode=yes",
		"-o", "StrictHostKeyChecking=yes",
		"-o", "UserKnownHostsFile="+knownHostsFile,
		"-o", "GlobalKnownHostsFile="+os.DevNull,
		"partner-b@127.0.0.1",
	)
	if out, err := cmd.CombinedOutput(); err != nil {
		t.Fatalf("sftp failed: %v\n%s", err, out)
	}

	got, err := os.ReadFile(download)
	if err != nil {
		t.Fatalf("read download: %v", err)
	}
	if !bytes.Equal(got, want) {
		t.Fatalf("downloaded %d bytes that differ from the %d uploaded", len(got), len(want))
	}
}

func writeClientKey(t *testing.T, dir string) (ssh.PublicKey, string) {
	t.Helper()
	_, key, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatalf("generate client key: %v", err)
	}
	block, err := ssh.MarshalPrivateKey(key, "")
	if err != nil {
		t.Fatalf("marshal client key: %v", err)
	}
	path := filepath.Join(dir, "id_ed25519")
	writeFile(t, path, pem.EncodeToMemory(block))

	signer, err := ssh.NewSignerFromKey(key)
	if err != nil {
		t.Fatalf("client signer: %v", err)
	}
	return signer.PublicKey(), path
}

func writeKnownHosts(t *testing.T, dir, addr string) string {
	t.Helper()
	var lines []string
	for _, hostKey := range hostKeys {
		lines = append(lines, knownhosts.Line([]string{addr}, hostKey.PublicKey()))
	}
	path := filepath.Join(dir, "known_hosts")
	writeFile(t, path, []byte(strings.Join(lines, "\n")+"\n"))
	return path
}

func writeFile(t *testing.T, path string, data []byte) {
	t.Helper()
	if err := os.WriteFile(path, data, 0o600); err != nil {
		t.Fatalf("write %s: %v", path, err)
	}
}
