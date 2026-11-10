package sftpproxy

import "sync/atomic"

// Transfers counts the file handles open in the sessions that share it,
// each from the reply that opens it until its session has recorded its
// transfer, or has ended without recording one. A count of zero therefore
// means that every transfer that will be recorded has been, which the
// backend's own count of open files cannot say: a session that ends closes
// its backend, and so its files, before it records the transfers they
// ended. The zero value is ready to use.
type Transfers struct {
	open atomic.Int64
}

// Open returns how many file handles are open.
func (t *Transfers) Open() int64 { return t.open.Load() }
