package fsscan

import (
	"os"
	"path/filepath"
	"testing"
)

func symlinkOrSkip(t *testing.T, target, link string) {
	t.Helper()
	if err := os.Symlink(target, link); err != nil {
		t.Skipf("symlinks unavailable in this environment: %v", err)
	}
}

func TestSymlinksAreVisitedButNotFollowedByDefault(t *testing.T) {
	root := t.TempDir()
	realDir := makeDir(t, filepath.Join(root, "realdir"), 0o755)
	realFile := writeFile(t, filepath.Join(realDir, "real.txt"), "real", 0o644)
	linkToDir := filepath.Join(root, "linkdir")
	linkToFile := filepath.Join(root, "linkfile")
	symlinkOrSkip(t, realDir, linkToDir)
	symlinkOrSkip(t, realFile, linkToFile)

	outcome := runWalk(t, Options{Roots: []string{root}, Workers: 4})

	for _, link := range []string{linkToDir, linkToFile} {
		entry, ok := findEntry(outcome.entries, link)
		if !ok {
			t.Fatalf("symlink %s was not reported as an entry", link)
		}
		if !entry.IsSymlink() {
			t.Errorf("%s should be reported as a symlink", link)
		}
		if entry.IsDir() {
			t.Errorf("%s must not be reported as a directory; Lstat metadata was not used", link)
		}
		if entry.IsRegular() {
			t.Errorf("%s must not be reported as a regular file", link)
		}
	}

	if outcome.stats.Symlinks != 2 {
		t.Errorf("Symlinks = %d, want 2", outcome.stats.Symlinks)
	}
	if outcome.stats.Directories != 2 {
		t.Errorf("Directories = %d, want 2 (the root and realdir; a symlinked dir must not count)", outcome.stats.Directories)
	}
	if _, ok := findEntry(outcome.entries, realFile); !ok {
		t.Error("the real file behind the symlink should still be visited on its own path")
	}
}

func TestSymlinkTargetIsNotCountedAsADuplicate(t *testing.T) {
	root := t.TempDir()
	realDir := makeDir(t, filepath.Join(root, "realdir"), 0o755)
	inner := writeFile(t, filepath.Join(realDir, "inner.txt"), "inner", 0o644)
	link := filepath.Join(root, "link")
	symlinkOrSkip(t, realDir, link)

	outcome := runWalk(t, Options{Roots: []string{root}})
	counts := map[string]int{}
	for _, entry := range outcome.entries {
		counts[entry.Path]++
	}
	for path, count := range counts {
		if count != 1 {
			t.Errorf("path %s reported %d times", path, count)
		}
	}
	if _, ok := counts[inner]; !ok {
		t.Error("inner file should appear exactly once, via its real path")
	}
}

func TestBrokenSymlinkIsReportedWithoutError(t *testing.T) {
	root := t.TempDir()
	broken := filepath.Join(root, "broken")
	symlinkOrSkip(t, filepath.Join(root, "does-not-exist"), broken)

	outcome := runWalk(t, Options{Roots: []string{root}})

	entry, ok := findEntry(outcome.entries, broken)
	if !ok {
		t.Fatal("a broken symlink should still be reported as an entry")
	}
	if !entry.IsSymlink() {
		t.Error("a broken symlink should be reported as a symlink")
	}
	if outcome.stats.Errors != 0 {
		t.Errorf("Errors = %d, want 0 for a dangling symlink under Lstat semantics", outcome.stats.Errors)
	}
	if outcome.stats.Symlinks != 1 {
		t.Errorf("Symlinks = %d, want 1", outcome.stats.Symlinks)
	}
}

func TestSymlinkLoopDoesNotRecurse(t *testing.T) {
	root := t.TempDir()
	dir := makeDir(t, filepath.Join(root, "loop"), 0o755)
	first := filepath.Join(dir, "first")
	second := filepath.Join(dir, "second")
	symlinkOrSkip(t, second, first)
	symlinkOrSkip(t, first, second)

	done := make(chan walkOutcome, 1)
	go func() {
		done <- runWalk(t, Options{Roots: []string{root}, Workers: 4})
	}()

	outcome := <-done
	if outcome.err != nil {
		t.Fatalf("Walk returned error: %v", outcome.err)
	}
	if outcome.stats.Symlinks != 2 {
		t.Errorf("Symlinks = %d, want 2", outcome.stats.Symlinks)
	}
	if outcome.stats.Entries > 6 {
		t.Errorf("Entries = %d; traversal appears to have followed the loop", outcome.stats.Entries)
	}
}

func TestSymlinkEscapeIsNotFollowed(t *testing.T) {
	outside := t.TempDir()
	secret := writeFile(t, filepath.Join(outside, "secret.txt"), "secret", 0o600)
	root := t.TempDir()
	escape := filepath.Join(root, "escape")
	symlinkOrSkip(t, outside, escape)

	outcome := runWalk(t, Options{Roots: []string{root}, FollowSymlinks: true, Workers: 4})

	if _, ok := findEntry(outcome.entries, secret); ok {
		t.Fatal("traversal escaped the scan root through a symlink")
	}
	if outcome.stats.Errors == 0 {
		t.Error("a rejected escape should be recorded rather than silently ignored")
	}
	recorded := false
	for _, note := range outcome.stats.Inaccessible {
		if len(note) > 0 && note[:len(escape)] == escape {
			recorded = true
		}
	}
	if !recorded {
		t.Errorf("Inaccessible = %v, want a record naming the rejected symlink", outcome.stats.Inaccessible)
	}
}

func TestSymlinkInsideRootIsFollowedWhenEnabled(t *testing.T) {
	root := t.TempDir()
	realDir := makeDir(t, filepath.Join(root, "realdir"), 0o755)
	nested := writeFile(t, filepath.Join(realDir, "nested.txt"), "nested", 0o644)
	link := filepath.Join(root, "linkdir")
	symlinkOrSkip(t, realDir, link)

	outcome := runWalk(t, Options{Roots: []string{root}, FollowSymlinks: true, Workers: 2})

	if _, ok := findEntry(outcome.entries, nested); !ok {
		t.Fatal("the real file should be visited via its own path")
	}
	if !containsPath(outcome.entries, filepath.Join(link, "nested.txt")) {
		t.Error("with FollowSymlinks enabled the nested file should also be reachable through the link")
	}
}

func TestFollowSymlinksStillReportsTheLinkItself(t *testing.T) {
	root := t.TempDir()
	realDir := makeDir(t, filepath.Join(root, "realdir"), 0o755)
	link := filepath.Join(root, "linkdir")
	symlinkOrSkip(t, realDir, link)

	outcome := runWalk(t, Options{Roots: []string{root}, FollowSymlinks: true})
	entry, ok := findEntry(outcome.entries, link)
	if !ok {
		t.Fatal("the symlink itself should still be reported using Lstat metadata")
	}
	if !entry.IsSymlink() {
		t.Error("the link entry should remain a symlink even when following is enabled")
	}
}

func TestFollowSymlinksHandlesBrokenLink(t *testing.T) {
	root := t.TempDir()
	broken := filepath.Join(root, "broken")
	symlinkOrSkip(t, filepath.Join(root, "missing"), broken)

	outcome := runWalk(t, Options{Roots: []string{root}, FollowSymlinks: true})
	if outcome.err != nil {
		t.Fatalf("Walk returned error: %v", outcome.err)
	}
	if _, ok := findEntry(outcome.entries, broken); !ok {
		t.Error("a broken symlink should still be reported")
	}
	if outcome.stats.Errors == 0 {
		t.Error("a broken link should be recorded when following is enabled")
	}
}

func TestFollowSymlinksIsBoundedByMaxDepth(t *testing.T) {
	root := t.TempDir()
	current := root
	for i := 0; i < 5; i++ {
		current = makeDir(t, filepath.Join(current, "d"), 0o755)
	}
	link := filepath.Join(root, "loopback")
	symlinkOrSkip(t, current, link)

	outcome := runWalk(t, Options{Roots: []string{root}, FollowSymlinks: true, MaxDepth: 3})
	if outcome.err != nil {
		t.Fatalf("Walk returned error: %v", outcome.err)
	}
	if !outcome.stats.DepthLimitHit {
		t.Error("DepthLimitHit = false, want true")
	}
	if outcome.stats.MaxDepthReached > 3 {
		t.Errorf("MaxDepthReached = %d, want at most the configured MaxDepth of 3", outcome.stats.MaxDepthReached)
	}
}

func TestSymlinkToParentDoesNotEscapeWhenNotFollowing(t *testing.T) {
	root := t.TempDir()
	inner := makeDir(t, filepath.Join(root, "inner"), 0o755)
	writeFile(t, filepath.Join(inner, "f.txt"), "x", 0o644)
	up := filepath.Join(inner, "up")
	symlinkOrSkip(t, root, up)

	outcome := runWalk(t, Options{Roots: []string{root}, Workers: 4})
	if outcome.err != nil {
		t.Fatalf("Walk returned error: %v", outcome.err)
	}
	if outcome.stats.Entries > 5 {
		t.Errorf("Entries = %d; a symlink to the parent directory appears to have been traversed", outcome.stats.Entries)
	}
}

func containsPath(entries []Entry, path string) bool {
	_, ok := findEntry(entries, path)
	return ok
}
