//go:build unix

package detectors

import (
	"io/fs"
	"syscall"
)

func ownershipOf(info fs.FileInfo) (uint32, uint32, bool) {
	stat, ok := info.Sys().(*syscall.Stat_t)
	if !ok || stat == nil {
		return 0, 0, false
	}
	return stat.Uid, stat.Gid, true
}
