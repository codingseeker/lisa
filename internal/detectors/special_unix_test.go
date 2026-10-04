//go:build unix

package detectors

import "syscall"

func mkfifo(path string) error {
	return syscall.Mkfifo(path, 0o666)
}
