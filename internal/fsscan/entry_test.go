package fsscan

import (
	"os"
	"path/filepath"
	"testing"
)

func entryFor(t *testing.T, path string) Entry {
	t.Helper()
	info, err := os.Lstat(path)
	if err != nil {
		t.Fatalf("lstat %s failed: %v", path, err)
	}
	return Entry{Path: path, Root: filepath.Dir(path), Info: info}
}

func TestEntryPermissionBits(t *testing.T) {
	root := t.TempDir()

	cases := []struct {
		name string
		mode os.FileMode
		want string
	}{
		{"owner read write only", os.FileMode(0o600), "0600"},
		{"owner read write execute", os.FileMode(0o700), "0700"},
		{"world readable", os.FileMode(0o644), "0644"},
		{"world writable", os.FileMode(0o666), "0666"},
		{"all permission bits", os.FileMode(0o777), "0777"},
		{"sticky bit", os.FileMode(0o777) | os.ModeSticky, "1777"},
		{"setuid", os.FileMode(0o755) | os.ModeSetuid, "4755"},
		{"setgid", os.FileMode(0o755) | os.ModeSetgid, "2755"},
		{"setuid and setgid", os.FileMode(0o755) | os.ModeSetuid | os.ModeSetgid, "6755"},
		{"setuid setgid and sticky", os.FileMode(0o755) | os.ModeSetuid | os.ModeSetgid | os.ModeSticky, "7755"},
		{"setuid without execute", os.FileMode(0o644) | os.ModeSetuid, "4644"},
		{"no permissions", os.FileMode(0o000), "0000"},
	}

	for _, testCase := range cases {
		t.Run(testCase.name, func(t *testing.T) {
			path := filepath.Join(root, "fixture")
			writeFile(t, path, "x", os.FileMode(0o600))
			setMode(t, path, testCase.mode)

			entry := entryFor(t, path)
			if got := entry.PermissionString(); got != testCase.want {
				t.Errorf("PermissionString() = %q, want %q", got, testCase.want)
			}
		})
	}
}

func TestEntryDirectoryPermissionBits(t *testing.T) {
	root := t.TempDir()
	sticky := makeDir(t, filepath.Join(root, "sticky"), 0o755)
	setMode(t, sticky, os.FileMode(0o777)|os.ModeSticky)

	entry := entryFor(t, sticky)
	if !entry.IsDir() {
		t.Error("IsDir() = false, want true")
	}
	if got := entry.PermissionString(); got != "1777" {
		t.Errorf("PermissionString() = %q, want %q", got, "1777")
	}
}

func TestEntryTypeClassification(t *testing.T) {
	root := t.TempDir()
	regular := writeFile(t, filepath.Join(root, "file"), "x", 0o644)
	directory := makeDir(t, filepath.Join(root, "dir"), 0o755)
	link := filepath.Join(root, "link")
	symlinkOrSkip(t, regular, link)

	regularEntry := entryFor(t, regular)
	if !regularEntry.IsRegular() || regularEntry.IsDir() || regularEntry.IsSymlink() || regularEntry.IsSpecial() {
		t.Errorf("regular file misclassified: regular=%v dir=%v symlink=%v special=%v",
			regularEntry.IsRegular(), regularEntry.IsDir(), regularEntry.IsSymlink(), regularEntry.IsSpecial())
	}

	dirEntry := entryFor(t, directory)
	if !dirEntry.IsDir() || dirEntry.IsRegular() || dirEntry.IsSymlink() || dirEntry.IsSpecial() {
		t.Errorf("directory misclassified: regular=%v dir=%v symlink=%v special=%v",
			dirEntry.IsRegular(), dirEntry.IsDir(), dirEntry.IsSymlink(), dirEntry.IsSpecial())
	}

	linkEntry := entryFor(t, link)
	if !linkEntry.IsSymlink() || linkEntry.IsRegular() || linkEntry.IsDir() || linkEntry.IsSpecial() {
		t.Errorf("symlink misclassified: regular=%v dir=%v symlink=%v special=%v",
			linkEntry.IsRegular(), linkEntry.IsDir(), linkEntry.IsSymlink(), linkEntry.IsSpecial())
	}
}

func TestEntrySpecialFiles(t *testing.T) {
	root := t.TempDir()
	fifo := filepath.Join(root, "pipe")
	makeFifoOrSkip(t, fifo)

	entry := entryFor(t, fifo)
	if !entry.IsSpecial() {
		t.Error("a FIFO should be reported as a special file")
	}
	if entry.IsRegular() || entry.IsDir() {
		t.Error("a FIFO must not be reported as a regular file or directory")
	}
}

func TestWalkClassifiesSpecialFilesWithoutBlocking(t *testing.T) {
	root := t.TempDir()
	makeFifoOrSkip(t, filepath.Join(root, "pipe"))
	makeFifoOrSkip(t, filepath.Join(root, "pipe2"))
	regular := writeFile(t, filepath.Join(root, "file.txt"), "x", 0o644)

	done := make(chan walkOutcome, 1)
	go func() {
		done <- runWalk(t, Options{Roots: []string{root}})
	}()

	select {
	case outcome := <-done:
		if outcome.err != nil {
			t.Fatalf("Walk returned error: %v", outcome.err)
		}
		if outcome.stats.SpecialFiles != 2 {
			t.Errorf("SpecialFiles = %d, want 2", outcome.stats.SpecialFiles)
		}
		if outcome.stats.Files != 1 {
			t.Errorf("Files = %d, want 1", outcome.stats.Files)
		}
		if _, ok := findEntry(outcome.entries, regular); !ok {
			t.Error("the regular file should still be reported")
		}
	case <-timeoutAfterSeconds(10):
		t.Fatal("Walk blocked while inspecting a FIFO")
	}
}

func TestWalkClassifiesUnixSocket(t *testing.T) {
	root := t.TempDir()
	socket := filepath.Join(root, "app.sock")
	listenUnixOrSkip(t, socket)

	outcome := runWalk(t, Options{Roots: []string{root}})
	if outcome.stats.SpecialFiles != 1 {
		t.Errorf("SpecialFiles = %d, want 1 for a unix socket", outcome.stats.SpecialFiles)
	}
	entry, ok := findEntry(outcome.entries, socket)
	if !ok {
		t.Fatal("the socket should be reported as an entry")
	}
	if !entry.IsSpecial() {
		t.Error("a unix socket should be classified as special")
	}
}

func TestEntryDeviceFileClassification(t *testing.T) {
	nullPath := "/dev/null"
	if _, err := os.Lstat(nullPath); err != nil {
		t.Skipf("device files are not available: %v", err)
	}
	entry := entryFor(t, nullPath)
	if !entry.IsSpecial() {
		t.Error("a character device should be classified as a special file")
	}
	if entry.IsRegular() {
		t.Error("a character device must not be reported as a regular file")
	}
}

func TestWalkTraversesDeviceTreeByDefault(t *testing.T) {
	if _, err := os.Lstat("/dev"); err != nil {
		t.Skip("/dev is not available")
	}
	outcome := runWalk(t, Options{Roots: []string{"/dev"}, MaxEntries: 4096})
	if outcome.err != nil {
		t.Fatalf("Walk returned error: %v", outcome.err)
	}
	if outcome.stats.Entries < 2 {
		t.Skip("/dev appears to be effectively empty in this environment")
	}
	if outcome.stats.SpecialFiles == 0 {
		t.Error("/dev should yield device nodes classified as special files")
	}
	special, regular := 0, 0
	for _, entry := range outcome.entries {
		switch {
		case entry.IsDir():
		case entry.IsSpecial():
			special++
		default:
			regular++
		}
	}
	if special == 0 {
		t.Error("no entry under /dev was classified as a special file")
	}
	if regular == 0 {
		t.Logf("note: /dev exposed no regular files in this environment")
	}
}
