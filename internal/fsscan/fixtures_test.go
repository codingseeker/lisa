package fsscan

import (
	"context"
	"os"
	"path/filepath"
	"sort"
	"sync"
	"testing"
)

func setMode(t *testing.T, path string, mode os.FileMode) {
	t.Helper()
	if err := os.Chmod(path, mode); err != nil {
		t.Skipf("cannot set mode %v on %s: %v", mode, path, err)
	}
}

func writeFile(t *testing.T, path string, body string, mode os.FileMode) string {
	t.Helper()
	if err := os.MkdirAll(filepath.Dir(path), 0o755); err != nil {
		t.Fatalf("creating parent of %s failed: %v", path, err)
	}
	if err := os.WriteFile(path, []byte(body), mode); err != nil {
		t.Fatalf("writing %s failed: %v", path, err)
	}
	if err := os.Chmod(path, mode); err != nil {
		t.Fatalf("chmod %s failed: %v", path, err)
	}
	return path
}

func makeDir(t *testing.T, path string, mode os.FileMode) string {
	t.Helper()
	if err := os.MkdirAll(path, mode); err != nil {
		t.Fatalf("creating %s failed: %v", path, err)
	}
	if err := os.Chmod(path, mode); err != nil {
		t.Fatalf("chmod %s failed: %v", path, err)
	}
	return path
}

func newTestWalker(t *testing.T, opts Options) *Walker {
	t.Helper()
	walker, err := New(opts)
	if err != nil {
		t.Fatalf("New returned error: %v", err)
	}
	return walker
}

type walkOutcome struct {
	entries []Entry
	stats   Stats
	err     error
}

func runWalk(t *testing.T, opts Options) walkOutcome {
	t.Helper()
	walker := newTestWalker(t, opts)

	var mu sync.Mutex
	var entries []Entry

	err := walker.Walk(context.Background(), func(entry Entry) {
		mu.Lock()
		entries = append(entries, entry)
		mu.Unlock()
	})

	return walkOutcome{entries: entries, stats: walker.Stats(), err: err}
}

func pathsOf(entries []Entry) []string {
	paths := make([]string, 0, len(entries))
	for _, entry := range entries {
		paths = append(paths, entry.Path)
	}
	sort.Strings(paths)
	return paths
}

func assertSamePaths(t *testing.T, got []Entry, want []string) {
	t.Helper()
	gotPaths := pathsOf(got)
	sorted := append([]string(nil), want...)
	sort.Strings(sorted)
	if len(gotPaths) != len(sorted) {
		t.Fatalf("visited %d entries, want %d\n got: %v\nwant: %v", len(gotPaths), len(sorted), gotPaths, sorted)
	}
	for i := range gotPaths {
		if gotPaths[i] != sorted[i] {
			t.Fatalf("entry mismatch at %d\n got: %s\nwant: %s", i, gotPaths[i], sorted[i])
		}
	}
}

func findEntry(entries []Entry, path string) (Entry, bool) {
	for _, entry := range entries {
		if entry.Path == path {
			return entry, true
		}
	}
	return Entry{}, false
}

func runningAsRoot() bool {
	return os.Geteuid() == 0
}

func buildWideTree(t *testing.T, root string, dirs, filesPerDir int) []string {
	t.Helper()
	expected := make([]string, 0, dirs*(filesPerDir+1))
	for d := 0; d < dirs; d++ {
		dirPath := filepath.Join(root, "dir"+string(rune('a'+d%26))+string(rune('0'+d/26)))
		makeDir(t, dirPath, 0o755)
		expected = append(expected, dirPath)
		for f := 0; f < filesPerDir; f++ {
			filePath := filepath.Join(dirPath, "file"+itoaTest(f)+".txt")
			writeFile(t, filePath, "content", 0o644)
			expected = append(expected, filePath)
		}
	}
	return expected
}

func itoaTest(value int) string {
	if value == 0 {
		return "0"
	}
	digits := ""
	for value > 0 {
		digits = string(rune('0'+value%10)) + digits
		value /= 10
	}
	return digits
}

func buildDeepTree(t *testing.T, root string, depth int) []string {
	t.Helper()
	expected := []string{}
	current := root
	for d := 0; d < depth; d++ {
		current = filepath.Join(current, "level"+itoaTest(d))
		makeDir(t, current, 0o755)
		expected = append(expected, current)
		writeFile(t, filepath.Join(current, "leaf"+itoaTest(d)), "x", 0o644)
		expected = append(expected, filepath.Join(current, "leaf"+itoaTest(d)))
	}
	return expected
}
