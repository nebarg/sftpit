package backend

import (
	"errors"
	"io"
	"io/fs"
	"syscall"

	"github.com/pkg/sftp"

	"sftpit/internal/sftpwire"
)

// status is an error that pkg/sftp reports to the client with code, carrying
// OpenSSH's message for that code. pkg/sftp otherwise sends the error's text,
// which names the file by its name on the host.
type status struct {
	code sftpwire.StatusCode
	fx   error
}

func (s *status) Error() string { return s.code.Message() }

// Unwrap returns pkg/sftp's error for the code, which it reads the status
// code from.
func (s *status) Unwrap() error { return s.fx }

var (
	errNoSuchFile       = &status{sftpwire.StatusNoSuchFile, sftp.ErrSSHFxNoSuchFile}
	errPermissionDenied = &status{sftpwire.StatusPermissionDenied, sftp.ErrSSHFxPermissionDenied}
	errFailure          = &status{sftpwire.StatusFailure, sftp.ErrSSHFxFailure}
	errBadMessage       = &status{sftpwire.StatusBadMessage, sftp.ErrSSHFxBadMessage}
	errOpUnsupported    = &status{sftpwire.StatusOpUnsupported, sftp.ErrSSHFxOpUnsupported}
)

// statusError maps err to the status OpenSSH's sftp-server sends for the
// same error number. nil and io.EOF are returned as they are, because
// pkg/sftp compares errors with them directly.
func statusError(err error) error {
	switch {
	case err == nil:
		return nil
	case errors.Is(err, io.EOF):
		return io.EOF
	}
	if s, ok := errors.AsType[*status](err); ok {
		return s
	}
	if errno, ok := errors.AsType[syscall.Errno](err); ok {
		switch errno {
		case syscall.ENOENT, syscall.ENOTDIR, syscall.EBADF, syscall.ELOOP:
			return errNoSuchFile
		case syscall.EPERM, syscall.EACCES, syscall.EFAULT:
			return errPermissionDenied
		case syscall.ENAMETOOLONG, syscall.EINVAL:
			return errBadMessage
		case syscall.ENOSYS:
			return errOpUnsupported
		}
	}
	// Windows reports most errors with its own error numbers, which match
	// these instead.
	switch {
	case errors.Is(err, fs.ErrNotExist):
		return errNoSuchFile
	case errors.Is(err, fs.ErrPermission):
		return errPermissionDenied
	}
	return errFailure
}
