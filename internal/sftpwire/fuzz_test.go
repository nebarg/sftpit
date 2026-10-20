package sftpwire_test

import (
	"bytes"
	"testing"

	"github.com/nebarg/sftpit/internal/sftpwire"
)

// The fuzz targets check that decoding never panics and that re-encoding a
// decoded packet reproduces the bytes it was decoded from, apart from any
// trailing bytes the decoder ignored.

func FuzzDecodeRequest(f *testing.F) {
	for _, p := range requests {
		f.Add(sftpwire.AppendPacket(nil, 1, p)[4:])
	}
	f.Fuzz(func(t *testing.T, b []byte) {
		id, p, err := sftpwire.DecodeRequest(b)
		if err != nil {
			return
		}
		assertPrefix(t, sftpwire.AppendPacket(nil, id, p)[4:], b)
	})
}

func FuzzDecodeReply(f *testing.F) {
	for _, p := range replies {
		f.Add(sftpwire.AppendPacket(nil, 1, p)[4:])
	}
	f.Fuzz(func(t *testing.T, b []byte) {
		id, p, err := sftpwire.DecodeReply(b)
		if err != nil {
			return
		}
		assertPrefix(t, sftpwire.AppendPacket(nil, id, p)[4:], b)
	})
}

func FuzzDecodeVersion(f *testing.F) {
	f.Add(sftpwire.AppendVersion(nil, sftpwire.Version{
		Version:    3,
		Extensions: []sftpwire.Extension{{Name: sftpwire.ExtPosixRename, Data: "1"}},
	})[4:])
	f.Fuzz(func(t *testing.T, b []byte) {
		p, err := sftpwire.DecodeVersion(b)
		if err != nil {
			return
		}
		assertPrefix(t, sftpwire.AppendVersion(nil, p)[4:], b)
	})
}

func assertPrefix(t *testing.T, encoded, input []byte) {
	t.Helper()
	if !bytes.HasPrefix(input, encoded) {
		t.Fatalf("re-encoded\n%x\nis not a prefix of the input\n%x", encoded, input)
	}
}
