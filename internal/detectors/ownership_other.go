//go:build !unix

package detectors

import "io/fs"

func ownershipOf(fs.FileInfo) (uint32, uint32, bool) {
	return 0, 0, false
}
