// Package sftpwire encodes and decodes the SFTP version 3 packets that sftpit
// supports, as described in draft-ietf-secsh-filexfer-02, plus the
// posix-rename@openssh.com and statvfs@openssh.com extensions.
//
// Decoding follows OpenSSH's sftp-server: bytes after a packet's last field
// are ignored, and a path containing a NUL byte makes the packet malformed.
package sftpwire

import (
	"encoding/binary"
	"errors"
	"fmt"
	"io"
)

// PacketType identifies an SFTP packet, the SSH_FXP_* values.
type PacketType uint8

// Packet types.
const (
	TypeInit          PacketType = 1
	TypeVersion       PacketType = 2
	TypeOpen          PacketType = 3
	TypeClose         PacketType = 4
	TypeRead          PacketType = 5
	TypeWrite         PacketType = 6
	TypeLStat         PacketType = 7
	TypeFStat         PacketType = 8
	TypeSetStat       PacketType = 9
	TypeFSetStat      PacketType = 10
	TypeOpenDir       PacketType = 11
	TypeReadDir       PacketType = 12
	TypeRemove        PacketType = 13
	TypeMkdir         PacketType = 14
	TypeRmdir         PacketType = 15
	TypeRealPath      PacketType = 16
	TypeStat          PacketType = 17
	TypeRename        PacketType = 18
	TypeReadLink      PacketType = 19
	TypeSymlink       PacketType = 20
	TypeStatus        PacketType = 101
	TypeHandle        PacketType = 102
	TypeData          PacketType = 103
	TypeName          PacketType = 104
	TypeAttrs         PacketType = 105
	TypeExtended      PacketType = 200
	TypeExtendedReply PacketType = 201
)

var typeNames = map[PacketType]string{
	TypeInit:          "SSH_FXP_INIT",
	TypeVersion:       "SSH_FXP_VERSION",
	TypeOpen:          "SSH_FXP_OPEN",
	TypeClose:         "SSH_FXP_CLOSE",
	TypeRead:          "SSH_FXP_READ",
	TypeWrite:         "SSH_FXP_WRITE",
	TypeLStat:         "SSH_FXP_LSTAT",
	TypeFStat:         "SSH_FXP_FSTAT",
	TypeSetStat:       "SSH_FXP_SETSTAT",
	TypeFSetStat:      "SSH_FXP_FSETSTAT",
	TypeOpenDir:       "SSH_FXP_OPENDIR",
	TypeReadDir:       "SSH_FXP_READDIR",
	TypeRemove:        "SSH_FXP_REMOVE",
	TypeMkdir:         "SSH_FXP_MKDIR",
	TypeRmdir:         "SSH_FXP_RMDIR",
	TypeRealPath:      "SSH_FXP_REALPATH",
	TypeStat:          "SSH_FXP_STAT",
	TypeRename:        "SSH_FXP_RENAME",
	TypeReadLink:      "SSH_FXP_READLINK",
	TypeSymlink:       "SSH_FXP_SYMLINK",
	TypeStatus:        "SSH_FXP_STATUS",
	TypeHandle:        "SSH_FXP_HANDLE",
	TypeData:          "SSH_FXP_DATA",
	TypeName:          "SSH_FXP_NAME",
	TypeAttrs:         "SSH_FXP_ATTRS",
	TypeExtended:      "SSH_FXP_EXTENDED",
	TypeExtendedReply: "SSH_FXP_EXTENDED_REPLY",
}

func (t PacketType) String() string {
	if name, ok := typeNames[t]; ok {
		return name
	}
	return fmt.Sprintf("SSH_FXP_UNKNOWN(%d)", t)
}

// StatusCode is the result carried by a StatusReply, the SSH_FX_* values.
type StatusCode uint32

// Status codes.
const (
	StatusOK               StatusCode = 0
	StatusEOF              StatusCode = 1
	StatusNoSuchFile       StatusCode = 2
	StatusPermissionDenied StatusCode = 3
	StatusFailure          StatusCode = 4
	StatusBadMessage       StatusCode = 5
	StatusNoConnection     StatusCode = 6
	StatusConnectionLost   StatusCode = 7
	StatusOpUnsupported    StatusCode = 8
)

var statusNames = map[StatusCode]string{
	StatusOK:               "SSH_FX_OK",
	StatusEOF:              "SSH_FX_EOF",
	StatusNoSuchFile:       "SSH_FX_NO_SUCH_FILE",
	StatusPermissionDenied: "SSH_FX_PERMISSION_DENIED",
	StatusFailure:          "SSH_FX_FAILURE",
	StatusBadMessage:       "SSH_FX_BAD_MESSAGE",
	StatusNoConnection:     "SSH_FX_NO_CONNECTION",
	StatusConnectionLost:   "SSH_FX_CONNECTION_LOST",
	StatusOpUnsupported:    "SSH_FX_OP_UNSUPPORTED",
}

func (c StatusCode) String() string {
	if name, ok := statusNames[c]; ok {
		return name
	}
	return fmt.Sprintf("SSH_FX_UNKNOWN(%d)", c)
}

var statusMessages = map[StatusCode]string{
	StatusOK:               "Success",
	StatusEOF:              "End of file",
	StatusNoSuchFile:       "No such file",
	StatusPermissionDenied: "Permission denied",
	StatusFailure:          "Failure",
	StatusBadMessage:       "Bad message",
	StatusNoConnection:     "No connection",
	StatusConnectionLost:   "Connection lost",
	StatusOpUnsupported:    "Operation unsupported",
}

// Message returns the message OpenSSH's sftp-server sends with c.
func (c StatusCode) Message() string {
	if msg, ok := statusMessages[c]; ok {
		return msg
	}
	return "Unknown error"
}

// Open flags, the SSH_FXF_* bits of Open.Flags.
const (
	OpenRead      = 0x01
	OpenWrite     = 0x02
	OpenAppend    = 0x04
	OpenCreate    = 0x08
	OpenTruncate  = 0x10
	OpenExclusive = 0x20
)

// Extended request names that sftpit implements.
const (
	ExtPosixRename = "posix-rename@openssh.com"
	ExtStatVFS     = "statvfs@openssh.com"
)

// ErrMalformed reports a packet whose fields do not match its type.
var ErrMalformed = errors.New("sftpwire: malformed packet")

// UnsupportedError reports a well-formed request that sftpit does not
// implement. A server answers it with StatusOpUnsupported.
type UnsupportedError struct {
	ID   uint32
	Type PacketType

	// Extension is the extended-request name when Type is TypeExtended.
	Extension string
}

func (e *UnsupportedError) Error() string {
	if e.Type == TypeExtended {
		return fmt.Sprintf("sftpwire: unsupported extended request %q", e.Extension)
	}
	return fmt.Sprintf("sftpwire: unsupported request %v", e.Type)
}

// Packet is a request or reply that carries a request ID. INIT and VERSION
// carry none, so they are the separate Init and Version types.
type Packet interface {
	// Type returns the packet's type byte. Extended requests all return
	// TypeExtended.
	Type() PacketType

	appendBody(b []byte) []byte
}

// ReadPacket reads one length-prefixed packet from r and returns it without
// the length: the type byte, then the rest. It returns io.EOF only if r ends
// before a packet starts, and an error for a packet longer than maxLength.
func ReadPacket(r io.Reader, maxLength uint32) ([]byte, error) {
	var prefix [4]byte
	if _, err := io.ReadFull(r, prefix[:]); err != nil {
		return nil, err
	}
	n := binary.BigEndian.Uint32(prefix[:])
	if n == 0 {
		return nil, fmt.Errorf("%w: empty packet", ErrMalformed)
	}
	if n > maxLength {
		return nil, fmt.Errorf("sftpwire: %d-byte packet exceeds the %d-byte limit", n, maxLength)
	}
	b := make([]byte, n)
	if _, err := io.ReadFull(r, b); err != nil {
		if errors.Is(err, io.EOF) {
			err = io.ErrUnexpectedEOF
		}
		return nil, err
	}
	return b, nil
}

// AppendPacket appends p to b as a complete packet with request ID id.
func AppendPacket(b []byte, id uint32, p Packet) []byte {
	b, start := startPacket(b, p.Type())
	b = binary.BigEndian.AppendUint32(b, id)
	b = p.appendBody(b)
	return finishPacket(b, start)
}

func startPacket(b []byte, t PacketType) ([]byte, int) {
	return append(b, 0, 0, 0, 0, byte(t)), len(b)
}

func finishPacket(b []byte, start int) []byte {
	binary.BigEndian.PutUint32(b[start:], uint32(len(b)-start-4))
	return b
}

func malformed(t PacketType) error {
	return fmt.Errorf("%w: %v", ErrMalformed, t)
}
