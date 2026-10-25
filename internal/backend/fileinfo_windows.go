package backend

import "io/fs"

// ownerOf reports that no file has an owner, because Windows describes
// ownership with security identifiers rather than user and group IDs.
func ownerOf(fs.FileInfo) (uid, gid uint32, ok bool) { return 0, 0, false }

// linked reports that every file is in the tree, since file info on Windows
// carries no link count.
func linked(fs.FileInfo) bool { return true }
