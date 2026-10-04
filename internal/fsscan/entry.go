package fsscan

import (
	"io/fs"
	"os"
	"time"
)

type Entry struct {
	Path  string
	Root  string
	Depth int
	Info  os.FileInfo
}

func (e Entry) Name() string {
	return e.Info.Name()
}

func (e Entry) Size() int64 {
	return e.Info.Size()
}

func (e Entry) Mode() fs.FileMode {
	return e.Info.Mode()
}

func (e Entry) ModTime() time.Time {
	return e.Info.ModTime()
}

func (e Entry) IsDir() bool {
	return e.Info.IsDir()
}

func (e Entry) IsRegular() bool {
	return e.Info.Mode().IsRegular()
}

func (e Entry) IsSymlink() bool {
	return e.Info.Mode()&fs.ModeSymlink != 0
}

func (e Entry) IsSpecial() bool {
	mode := e.Info.Mode()
	return mode&fs.ModeType != 0 && !mode.IsDir() && mode&fs.ModeSymlink == 0
}

func (e Entry) PermissionBits() uint32 {
	mode := e.Info.Mode()
	bits := uint32(mode.Perm())
	if mode&fs.ModeSetuid != 0 {
		bits |= 0o4000
	}
	if mode&fs.ModeSetgid != 0 {
		bits |= 0o2000
	}
	if mode&fs.ModeSticky != 0 {
		bits |= 0o1000
	}
	return bits
}

func (e Entry) PermissionString() string {
	return formatOctal(e.PermissionBits())
}
