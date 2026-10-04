package fsscan

import (
	"context"
	"os"
	"path/filepath"
	"runtime"
	"strings"
	"sync/atomic"
	"testing"
)

func TestNewAppliesDefaults(t *testing.T) {
	root := t.TempDir()
	walker, err := New(Options{Roots: []string{root}})
	if err != nil {
		t.Fatalf("New(Options{Roots: ...}) must be usable without explicit tuning, got: %v", err)
	}
	opts := walker.Options()
	if opts.Workers < 1 || opts.Workers > DefaultWorkers {
		t.Errorf("Workers = %d, want between 1 and %d", opts.Workers, DefaultWorkers)
	}
	if opts.MaxEntries != DefaultMaxEntries {
		t.Errorf("MaxEntries = %d, want %d", opts.MaxEntries, DefaultMaxEntries)
	}
	if opts.MaxInaccessible != DefaultMaxInaccessible {
		t.Errorf("MaxInaccessible = %d, want %d", opts.MaxInaccessible, DefaultMaxInaccessible)
	}
	if opts.ProgressInterval != DefaultProgressInterval {
		t.Errorf("ProgressInterval = %s, want %s", opts.ProgressInterval, DefaultProgressInterval)
	}
}

func TestNewWithoutDefaultsScansEverything(t *testing.T) {
	root := t.TempDir()
	expected := []string{root}
	expected = append(expected, buildWideTree(t, root, 4, 3)...)

	walker := newTestWalker(t, Options{Roots: []string{root}})
	var seen []string
	if err := walker.Walk(context.Background(), func(e Entry) { seen = append(seen, e.Path) }); err != nil {
		t.Fatalf("Walk returned error: %v", err)
	}
	if len(seen) != len(expected) {
		t.Fatalf("visited %d entries, want %d", len(seen), len(expected))
	}
	if walker.Stats().EntryLimitHit {
		t.Error("EntryLimitHit = true with default limits on a small tree")
	}
}

func TestNewRejectsInvalidOptions(t *testing.T) {
	root := t.TempDir()
	regular := writeFile(t, filepath.Join(root, "file"), "x", 0o644)

	cases := []struct {
		name string
		opts Options
	}{
		{"no roots", Options{}},
		{"empty root list", Options{Roots: []string{}}},
		{"blank root", Options{Roots: []string{"   "}}},
		{"missing root", Options{Roots: []string{filepath.Join(root, "absent")}}},
		{"root is a regular file", Options{Roots: []string{regular}}},
		{"zero workers", Options{Roots: []string{root}, Workers: -1}},
		{"workers above maximum", Options{Roots: []string{root}, Workers: MaxWorkers + 1}},
		{"negative max depth", Options{Roots: []string{root}, MaxDepth: -1}},
		{"negative max entries", Options{Roots: []string{root}, MaxEntries: -1}},
		{"negative max inaccessible", Options{Roots: []string{root}, MaxInaccessible: -1}},
		{"negative progress interval", Options{Roots: []string{root}, ProgressInterval: -1}},
	}

	for _, testCase := range cases {
		t.Run(testCase.name, func(t *testing.T) {
			if _, err := New(testCase.opts); err == nil {
				t.Error("New accepted invalid options, want error")
			}
		})
	}
}

func TestNewAcceptsBoundaryOptions(t *testing.T) {
	root := t.TempDir()
	cases := []struct {
		name string
		opts Options
	}{
		{"minimum workers", Options{Roots: []string{root}, Workers: 1}},
		{"maximum workers", Options{Roots: []string{root}, Workers: MaxWorkers}},
		{"depth of one", Options{Roots: []string{root}, MaxDepth: 1}},
		{"zero max depth means unlimited", Options{Roots: []string{root}, MaxDepth: 0}},
		{"minimum max entries", Options{Roots: []string{root}, MaxEntries: 1}},
		{"zero max inaccessible", Options{Roots: []string{root}, MaxInaccessible: 0}},
	}
	for _, testCase := range cases {
		t.Run(testCase.name, func(t *testing.T) {
			if _, err := New(testCase.opts); err != nil {
				t.Errorf("New rejected valid options: %v", err)
			}
		})
	}
}

func TestMaxDepthIsHonouredExactly(t *testing.T) {
	cases := []struct {
		maxDepth  int
		wantDepth int
	}{
		{0, 5},
		{1, 1},
		{2, 2},
		{3, 3},
		{5, 5},
		{9, 5},
	}

	for _, testCase := range cases {
		t.Run("maxdepth"+itoaTest(testCase.maxDepth), func(t *testing.T) {
			root := t.TempDir()
			buildDeepTree(t, root, 4)

			outcome := runWalk(t, Options{Roots: []string{root}, Workers: 1, MaxDepth: testCase.maxDepth})
			if outcome.err != nil {
				t.Fatalf("Walk returned error: %v", outcome.err)
			}

			for _, entry := range outcome.entries {
				if entry.Depth > testCase.wantDepth {
					t.Errorf("entry %s has depth %d, exceeding the effective limit %d",
						entry.Path, entry.Depth, testCase.wantDepth)
				}
			}

			deepest := 0
			for _, entry := range outcome.entries {
				if entry.Depth > deepest {
					deepest = entry.Depth
				}
			}
			if deepest != testCase.wantDepth {
				t.Errorf("deepest visited entry = %d, want %d", deepest, testCase.wantDepth)
			}
			if outcome.stats.MaxDepthReached != testCase.wantDepth {
				t.Errorf("MaxDepthReached = %d, want %d", outcome.stats.MaxDepthReached, testCase.wantDepth)
			}

			want := expectedWithinDepth(root, testCase.wantDepth)
			assertSamePaths(t, outcome.entries, want)

			if testCase.maxDepth > 0 && testCase.maxDepth < 5 {
				if !outcome.stats.DepthLimitHit {
					t.Errorf("DepthLimitHit = false, want true for MaxDepth %d", testCase.maxDepth)
				}
			}
		})
	}
}

func expectedWithinDepth(root string, maxDepth int) []string {
	kept := []string{}
	for _, path := range fullDeepExpectation(root) {
		relative, err := filepath.Rel(root, path)
		if err != nil {
			continue
		}
		depth := 0
		if relative != "." {
			depth = strings.Count(relative, string(filepath.Separator)) + 1
		}
		if depth <= maxDepth {
			kept = append(kept, path)
		}
	}
	return kept
}

func fullDeepExpectation(root string) []string {
	expected := []string{root}
	current := root
	for d := 0; d < 4; d++ {
		current = filepath.Join(current, "level"+itoaTest(d))
		expected = append(expected, current)
		leaf := filepath.Join(current, "leaf"+itoaTest(d))
		expected = append(expected, leaf)
	}
	return expected
}

func TestMaxEntriesIsHonouredExactly(t *testing.T) {
	for _, limit := range []int{1, 2, 5, 17, 40} {
		root := t.TempDir()
		buildWideTree(t, root, 6, 6)
		total := 6 + 6*6 + 1

		outcome := runWalk(t, Options{Roots: []string{root}, Workers: 4, MaxEntries: limit})

		if outcome.stats.Entries != int64(limit) {
			t.Errorf("limit %d: Entries = %d, want exactly %d", limit, outcome.stats.Entries, limit)
		}
		if !outcome.stats.EntryLimitHit {
			t.Errorf("limit %d: EntryLimitHit = false, want true", limit)
		}
		if outcome.err != nil {
			t.Errorf("limit %d: Walk returned error %v; hitting a limit is not a failure", limit, outcome.err)
		}
		if outcome.stats.Cancelled {
			t.Errorf("limit %d: Cancelled = true; hitting a limit is not a cancellation", limit)
		}
		if total <= limit {
			t.Errorf("limit %d: fixture has only %d entries; the limit was not actually exercised", limit, total)
		}
	}
}

func TestMaxEntriesAboveTreeSizeIsNotTriggered(t *testing.T) {
	root := t.TempDir()
	buildWideTree(t, root, 3, 3)
	outcome := runWalk(t, Options{Roots: []string{root}, MaxEntries: 10_000})
	if outcome.stats.EntryLimitHit {
		t.Error("EntryLimitHit = true, want false")
	}
}

func TestMaxInaccessibleCapsRecordedPaths(t *testing.T) {
	if runningAsRoot() {
		t.Skip("permission bits are not enforced for root")
	}
	root := t.TempDir()
	created := 0
	for i := 0; i < 6; i++ {
		locked := filepath.Join(root, "locked"+itoaTest(i))
		makeDir(t, locked, 0o755)
		writeFile(t, filepath.Join(locked, "f.txt"), "x", 0o644)
		if err := os.Chmod(locked, 0o000); err != nil {
			t.Fatalf("chmod failed: %v", err)
		}
		defer os.Chmod(locked, 0o755)
		created++
	}

	outcome := runWalk(t, Options{Roots: []string{root}, Workers: 4, MaxInaccessible: 3})

	if outcome.stats.PermissionDenied != int64(created) {
		t.Errorf("PermissionDenied = %d, want %d", outcome.stats.PermissionDenied, created)
	}
	if len(outcome.stats.Inaccessible) != 3 {
		t.Errorf("Inaccessible holds %d records, want the configured cap of 3", len(outcome.stats.Inaccessible))
	}
	if !outcome.stats.InaccessibleTruncated {
		t.Error("InaccessibleTruncated = false, want true when the cap is reached")
	}
}

func TestMaxInaccessibleZeroMeansUnlimitedAfterDefaulting(t *testing.T) {
	if runningAsRoot() {
		t.Skip("permission bits are not enforced for root")
	}
	root := t.TempDir()
	locked := filepath.Join(root, "locked")
	makeDir(t, locked, 0o755)
	if err := os.Chmod(locked, 0o000); err != nil {
		t.Fatalf("chmod failed: %v", err)
	}
	defer os.Chmod(locked, 0o755)

	outcome := runWalk(t, Options{Roots: []string{root}, MaxInaccessible: 0})
	if len(outcome.stats.Inaccessible) != 1 {
		t.Errorf("Inaccessible = %v, want one record; zero must fall back to the default cap", outcome.stats.Inaccessible)
	}
}

func TestNoGoroutineLeakOnNormalCompletion(t *testing.T) {
	root := t.TempDir()
	buildWideTree(t, root, 20, 10)
	walker := newTestWalker(t, Options{Roots: []string{root}, Workers: 8})

	if err := walker.Walk(context.Background(), func(Entry) {}); err != nil {
		t.Fatalf("Walk returned error: %v", err)
	}

	baseline := runtime.NumGoroutine()
	for i := 0; i < 100; i++ {
		runWalk(t, Options{Roots: []string{root}, Workers: 8})
	}
	for i := 0; i < 100; i++ {
		runtime.Gosched()
	}
	settled := runtime.NumGoroutine()
	if settled > baseline+10 {
		t.Errorf("goroutines grew from %d to %d across 100 walks", baseline, settled)
	}
}

func TestWaitGroupCounterCannotReachZeroWithWorkPending(t *testing.T) {
	root := t.TempDir()
	expected := []string{root}
	expected = append(expected, buildDeepTree(t, root, 6)...)

	for _, workers := range []int{1, 2, 8, 32} {
		walker := newTestWalker(t, Options{Roots: []string{root}, Workers: workers})
		var visits int64
		if err := walker.Walk(context.Background(), func(Entry) { atomic.AddInt64(&visits, 1) }); err != nil {
			t.Fatalf("workers=%d Walk returned error: %v", workers, err)
		}
		if visits != int64(len(expected)) {
			t.Errorf("workers=%d visited %d entries, want %d", workers, visits, len(expected))
		}
		if got := walker.Stats().Entries; got != int64(len(expected)) {
			t.Errorf("workers=%d Stats.Entries = %d, want %d", workers, got, len(expected))
		}
	}
}

func TestStatsAccountingIsInternallyConsistent(t *testing.T) {
	root := t.TempDir()
	expected := []string{root}
	expected = append(expected, buildWideTree(t, root, 8, 5)...)
	makeFifoOrSkip(t, filepath.Join(root, "pipe"))
	listenUnixOrSkip(t, filepath.Join(root, "sock"))

	outcome := runWalk(t, Options{Roots: []string{root}, Workers: 6})
	stats := outcome.stats

	if stats.Entries != stats.Directories+stats.Files+stats.Symlinks+stats.SpecialFiles {
		t.Errorf("Entries = %d but the per-type counts sum to %d",
			stats.Entries, stats.Directories+stats.Files+stats.Symlinks+stats.SpecialFiles)
	}
	if stats.Directories != 9 {
		t.Errorf("Directories = %d, want 9 (root plus eight fixture directories)", stats.Directories)
	}
	if stats.Files != 40 {
		t.Errorf("Files = %d, want 40", stats.Files)
	}
	if stats.SpecialFiles != 2 {
		t.Errorf("SpecialFiles = %d, want 2 (one FIFO, one socket)", stats.SpecialFiles)
	}
	if stats.Errors != 0 {
		t.Errorf("Errors = %d, want 0", stats.Errors)
	}
	if int64(len(outcome.entries)) != stats.Entries {
		t.Errorf("visit count %d does not match Stats.Entries %d", len(outcome.entries), stats.Entries)
	}
	if len(expected) == 0 {
		t.Fatal("fixture generation failed")
	}
}
