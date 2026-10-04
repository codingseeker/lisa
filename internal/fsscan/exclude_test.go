package fsscan

import (
	"os"
	"path/filepath"
	"testing"
)

func TestWithinRoot(t *testing.T) {
	cases := []struct {
		name string
		root string
		path string
		want bool
	}{
		{"root equals path", "/a", "/a", true},
		{"direct child", "/a", "/a/b", true},
		{"deep descendant", "/a", "/a/b/c/d", true},
		{"sibling with shared prefix", "/a", "/ab", false},
		{"sibling under shared parent", "/a/b", "/a/bc", false},
		{"parent of root", "/a/b", "/a", false},
		{"unrelated absolute path", "/a", "/x/y", false},
		{"filesystem root contains everything", "/", "/anything/at/all", true},
		{"filesystem root contains itself", "/", "/", true},
		{"parent traversal escapes", "/a", "/a/../b", false},
		{"relative path against absolute root", "/a", "b", false},
		{"dot path inside root", "/a", "/a/./b", true},
		{"trailing slash is still inside", "/a", "/a/b/", true},
		{"root with spaces", "/a dir", "/a dir/child file", true},
		{"sibling of root with spaces", "/a dir", "/a dir2/x", false},
	}

	for _, testCase := range cases {
		t.Run(testCase.name, func(t *testing.T) {
			if got := withinRoot(testCase.root, testCase.path); got != testCase.want {
				t.Errorf("withinRoot(%q, %q) = %v, want %v", testCase.root, testCase.path, got, testCase.want)
			}
		})
	}
}

func TestExcludeSetExactAndDescendant(t *testing.T) {
	set := newExcludeSet([]string{"/tmp/skip"})

	cases := map[string]bool{
		"/tmp/skip":         true,
		"/tmp/skip/child":   true,
		"/tmp/skip/a/b/c":   true,
		"/tmp/skipper":      false,
		"/tmp/skip-other":   false,
		"/tmp":              false,
		"/tmp/ski":          false,
		"/var/tmp/skip":     false,
		"/tmp/skip/../keep": false,
	}
	for path, want := range cases {
		if got := set.excluded(path); got != want {
			t.Errorf("excluded(%q) = %v, want %v", path, got, want)
		}
	}
}

func TestExcludeSetSiblingPrefixIsolation(t *testing.T) {
	root := t.TempDir()
	keep := makeDir(t, filepath.Join(root, "data"), 0o755)
	drop := makeDir(t, filepath.Join(root, "data-old"), 0o755)
	keptFile := writeFile(t, filepath.Join(keep, "keep.txt"), "x", 0o644)
	droppedFile := writeFile(t, filepath.Join(drop, "drop.txt"), "x", 0o644)

	outcome := runWalk(t, Options{Roots: []string{root}, Excludes: []string{filepath.Join(root, "data")}})

	assertSamePaths(t, outcome.entries, []string{root, drop, droppedFile})
	if _, ok := findEntry(outcome.entries, keep); ok {
		t.Error("an excluded directory must not be emitted as an entry")
	}
	if _, ok := findEntry(outcome.entries, keptFile); ok {
		t.Error("descendants of an excluded directory must not be visited")
	}
	if outcome.stats.Excluded != 1 {
		t.Errorf("Excluded = %d, want 1", outcome.stats.Excluded)
	}
}

func TestExcludeSetExcludesDirectoryDescendants(t *testing.T) {
	root := t.TempDir()
	buildDir := makeDir(t, filepath.Join(root, "vendor"), 0o755)
	buildDir2 := makeDir(t, filepath.Join(buildDir, "lib"), 0o755)
	deepFile := writeFile(t, filepath.Join(buildDir2, "deep.so"), "x", 0o644)
	keptFile := writeFile(t, filepath.Join(root, "keep.txt"), "x", 0o644)

	outcome := runWalk(t, Options{Roots: []string{root}, Excludes: []string{filepath.Join(root, "vendor")}})

	if _, ok := findEntry(outcome.entries, deepFile); ok {
		t.Error("descendant of an excluded directory must not be visited")
	}
	if _, ok := findEntry(outcome.entries, keptFile); !ok {
		t.Error("non-excluded sibling must still be visited")
	}
}

func TestExcludeSingleFile(t *testing.T) {
	root := t.TempDir()
	drop := writeFile(t, filepath.Join(root, "secret.key"), "x", 0o600)
	keep := writeFile(t, filepath.Join(root, "public.key"), "x", 0o644)

	outcome := runWalk(t, Options{Roots: []string{root}, Excludes: []string{drop}})

	if _, ok := findEntry(outcome.entries, drop); ok {
		t.Error("excluded file must not be visited")
	}
	if _, ok := findEntry(outcome.entries, keep); !ok {
		t.Error("non-excluded file must still be visited")
	}
}

func TestExcludeRelativePathIsResolved(t *testing.T) {
	root := t.TempDir()
	dropDir := makeDir(t, filepath.Join(root, "skipme"), 0o755)
	dropFile := writeFile(t, filepath.Join(dropDir, "inner.txt"), "x", 0o644)
	keepFile := writeFile(t, filepath.Join(root, "keep.txt"), "x", 0o644)

	t.Chdir(root)

	outcome := runWalk(t, Options{Roots: []string{"."}, Excludes: []string{"skipme"}})

	if _, ok := findEntry(outcome.entries, dropFile); ok {
		t.Error("relative exclusion should have removed the subtree")
	}
	if _, ok := findEntry(outcome.entries, keepFile); !ok {
		t.Error("relative exclusion removed an unrelated file")
	}
}

func TestExcludePathWithSpaces(t *testing.T) {
	root := t.TempDir()
	spaced := makeDir(t, filepath.Join(root, "my dir with spaces"), 0o755)
	spacedFile := writeFile(t, filepath.Join(spaced, "file name.txt"), "x", 0o644)
	keepFile := writeFile(t, filepath.Join(root, "plain.txt"), "x", 0o644)

	outcome := runWalk(t, Options{Roots: []string{root}, Excludes: []string{spaced}})

	if _, ok := findEntry(outcome.entries, spacedFile); ok {
		t.Error("directory containing spaces should have been excluded")
	}
	if _, ok := findEntry(outcome.entries, keepFile); !ok {
		t.Error("unrelated file should still be visited")
	}
}

func TestExcludePathWithParentTraversal(t *testing.T) {
	root := t.TempDir()
	victim := makeDir(t, filepath.Join(root, "victim"), 0o755)
	victimFile := writeFile(t, filepath.Join(victim, "f.txt"), "x", 0o644)
	keepDir := makeDir(t, filepath.Join(root, "keep"), 0o755)
	keepFile := writeFile(t, filepath.Join(keepDir, "f.txt"), "x", 0o644)

	noisy := filepath.Join(root, "keep", "..", "victim")
	outcome := runWalk(t, Options{Roots: []string{root}, Excludes: []string{noisy}})

	if _, ok := findEntry(outcome.entries, victimFile); ok {
		t.Error("a .. containing exclusion should still resolve to the cleaned path")
	}
	if _, ok := findEntry(outcome.entries, keepFile); !ok {
		t.Error("cleaning the exclusion path must not remove unrelated siblings")
	}
}

func TestExcludeRootSlashExcludesEverything(t *testing.T) {
	set := newExcludeSet([]string{"/"})
	for _, path := range []string{"/", "/etc", "/etc/passwd", "/home/user/file"} {
		if !set.excluded(path) {
			t.Errorf("excluded(%q) = false, want true when / is excluded", path)
		}
	}
}

func TestExcludeRootSlashInWalkExcludesChildren(t *testing.T) {
	root := t.TempDir()
	child := writeFile(t, filepath.Join(root, "f.txt"), "x", 0o644)

	outcome := runWalk(t, Options{Roots: []string{root}, Excludes: []string{"/"}})

	if _, ok := findEntry(outcome.entries, child); ok {
		t.Error("excluding / should prevent traversal into the root's children")
	}
	if outcome.stats.Excluded == 0 {
		t.Error("Excluded should count the skipped children")
	}
}

func TestExcludeRequestedRootIsStillVisited(t *testing.T) {
	root := t.TempDir()
	writeFile(t, filepath.Join(root, "f.txt"), "x", 0o644)

	outcome := runWalk(t, Options{Roots: []string{root}, Excludes: []string{root}})

	if len(outcome.entries) != 1 || outcome.entries[0].Path != root {
		t.Errorf("entries = %v, want only the root itself", pathsOf(outcome.entries))
	}
}

func TestExcludeRejectsEmptyPath(t *testing.T) {
	if _, err := New(Options{Roots: []string{t.TempDir()}, Excludes: []string{"  "}}); err == nil {
		t.Error("New accepted a blank exclusion, want error")
	}
}

func TestExcludeDoesNotFollowSymlinkedExcludedDirectory(t *testing.T) {
	root := t.TempDir()
	real := makeDir(t, filepath.Join(root, "real"), 0o755)
	target := writeFile(t, filepath.Join(real, "target.txt"), "x", 0o644)
	link := filepath.Join(root, "link")
	if err := os.Symlink(real, link); err != nil {
		t.Skipf("symlinks unavailable: %v", err)
	}

	outcome := runWalk(t, Options{Roots: []string{root}, Excludes: []string{link}})

	if _, ok := findEntry(outcome.entries, target); !ok {
		t.Error("excluding a symlink must not exclude the directory it points at")
	}
	if _, ok := findEntry(outcome.entries, link); ok {
		t.Error("the excluded symlink entry itself should not be visited")
	}
}

func TestIsVirtualFilesystem(t *testing.T) {
	base := t.TempDir()
	opts := Options{SkipVirtualFilesystems: true}.withDefaults()
	explicit := map[string]struct{}{base: {}}

	cases := []struct {
		path string
		want bool
	}{
		{"/proc", true},
		{"/proc/self", true},
		{"/proc/self/fd", true},
		{"/sys", true},
		{"/sys/kernel", true},
		{"/etc", false},
		{"/", false},
		{"/procmium", false},
		{"/syslog", false},
	}
	for _, testCase := range cases {
		if got := opts.isVirtualFilesystem(testCase.path, explicit); got != testCase.want {
			t.Errorf("isVirtualFilesystem(%q) = %v, want %v", testCase.path, got, testCase.want)
		}
	}

	if opts.isVirtualFilesystem("/proc", map[string]struct{}{"/proc": {}}) {
		t.Error("an explicitly requested virtual filesystem root must not be skipped")
	}

	disabled := Options{SkipVirtualFilesystems: false}.withDefaults()
	if disabled.isVirtualFilesystem("/proc/self", explicit) {
		t.Error("isVirtualFilesystem must return false when skipping is disabled")
	}
}

func TestSkipVirtualFilesystemIntegration(t *testing.T) {
	if _, err := os.Lstat("/proc"); err != nil {
		t.Skip("/proc is not available")
	}

	skipped := runWalk(t, Options{Roots: []string{"/proc"}, SkipVirtualFilesystems: true})
	if len(skipped.entries) != 1 || skipped.entries[0].Path != "/proc" {
		t.Errorf("entries = %v, want only the /proc root itself", pathsOf(skipped.entries))
	}
	if skipped.stats.Excluded == 0 {
		t.Error("skipped procfs children should be counted as excluded")
	}

	traversed := runWalk(t, Options{
		Roots:                  []string{"/proc"},
		SkipVirtualFilesystems: false,
		MaxEntries:             64,
	})
	if traversed.stats.Excluded != 0 {
		t.Errorf("Excluded = %d, want 0 when skipping is disabled", traversed.stats.Excluded)
	}
	if traversed.stats.Entries < 2 {
		t.Errorf("Entries = %d, want procfs contents to be traversed", traversed.stats.Entries)
	}
}

func TestSkipVirtualFilesystemsKeepsNormalTrees(t *testing.T) {
	base := t.TempDir()
	real := makeDir(t, filepath.Join(base, "real"), 0o755)
	realFile := writeFile(t, filepath.Join(real, "f.txt"), "x", 0o644)
	outcome := runWalk(t, Options{Roots: []string{base}, SkipVirtualFilesystems: true})
	if _, ok := findEntry(outcome.entries, realFile); !ok {
		t.Error("normal directories must still be traversed when virtual filesystems are skipped")
	}
}
