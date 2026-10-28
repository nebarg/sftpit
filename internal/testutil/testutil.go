// Package testutil holds helpers that the tests of several packages share.
// Only tests import it.
package testutil

import (
	"bytes"
	"encoding/binary"
	"io/fs"
	"os"
	"path/filepath"
	"sync"
	"testing"
	"time"
)

// WaitTimeout bounds how long a test waits for something that should happen
// promptly, so that a regression fails the test rather than hanging it.
const WaitTimeout = 5 * time.Second

// Receive returns the next value from ch, failing the test if none comes
// within WaitTimeout.
func Receive[T any](tb testing.TB, ch <-chan T) T {
	tb.Helper()
	select {
	case v := <-ch:
		return v
	case <-time.After(WaitTimeout):
		tb.Fatal("timed out waiting")
		var zero T
		return zero
	}
}

// ReceiveUntil receives from ch until it receives want, failing the test if
// any value takes longer than WaitTimeout to come.
func ReceiveUntil[T comparable](tb testing.TB, ch <-chan T, want T) {
	tb.Helper()
	for {
		if Receive(tb, ch) == want {
			return
		}
	}
}

// SyncBuffer is a bytes.Buffer that is safe for concurrent use, for output
// that goroutines write while a test reads it.
type SyncBuffer struct {
	mu  sync.Mutex
	buf bytes.Buffer
}

func (b *SyncBuffer) Write(p []byte) (int, error) {
	b.mu.Lock()
	defer b.mu.Unlock()
	return b.buf.Write(p)
}

func (b *SyncBuffer) String() string {
	b.mu.Lock()
	defer b.mu.Unlock()
	return b.buf.String()
}

// WriteFile writes content to the file name, making its directory if need
// be, readable only by its owner, and returns name.
func WriteFile(tb testing.TB, name, content string) string {
	tb.Helper()
	if err := os.MkdirAll(filepath.Dir(name), 0o755); err != nil {
		tb.Fatal(err)
	}
	if err := os.WriteFile(name, []byte(content), 0o600); err != nil {
		tb.Fatal(err)
	}
	return name
}

// SetMetadata sets the permission bits and the access and modification
// times of the file name.
func SetMetadata(tb testing.TB, name string, mode fs.FileMode, mtime time.Time) {
	tb.Helper()
	if err := os.Chmod(name, mode); err != nil {
		tb.Fatal(err)
	}
	if err := os.Chtimes(name, mtime, mtime); err != nil {
		tb.Fatal(err)
	}
}

// Wire builds an SFTP packet field by field, for packets that the sftpwire
// encoders would not write.
type Wire []byte

// Byte appends v.
func (w Wire) Byte(v byte) Wire { return append(w, v) }

// U32 appends v, big-endian.
func (w Wire) U32(v uint32) Wire { return binary.BigEndian.AppendUint32(w, v) }

// U64 appends v, big-endian.
func (w Wire) U64(v uint64) Wire { return binary.BigEndian.AppendUint64(w, v) }

// Str appends s with its length before it.
func (w Wire) Str(s string) Wire { return append(w.U32(uint32(len(s))), s...) }

// Raw appends s as it is.
func (w Wire) Raw(s string) Wire { return append(w, s...) }

// Framed returns the packet with its length before it.
func (w Wire) Framed() []byte {
	return append(binary.BigEndian.AppendUint32(nil, uint32(len(w))), w...)
}
