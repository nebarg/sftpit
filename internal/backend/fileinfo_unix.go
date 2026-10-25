//go:build unix

package backend

import (
	"io/fs"
	"syscall"
)

// ownerOf returns the user and group IDs that own the file info describes.
func ownerOf(info fs.FileInfo) (uid, gid uint32, ok bool) {
	st, ok := info.Sys().(*syscall.Stat_t)
	if !ok {
		return 0, 0, false
	}
	return st.Uid, st.Gid, true
}

// linked reports whether the file info describes is still in the tree,
// rather than removed or replaced while a handle kept it open.
func linked(info fs.FileInfo) bool {
	st, ok := info.Sys().(*syscall.Stat_t)
	return !ok || st.Nlink > 0
}
