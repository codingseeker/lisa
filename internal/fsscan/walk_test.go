package fsscan

import (
	"context"
	"errors"
	"os"
	"path/filepath"
	"runtime"
	"sort"
	"sync/atomic"
	"testing"
	"time"
)

func TestWalkEmptyRootVisitsOnlyRoot(t *testing.T) {
	root := t.TempDir()
	outcome := runWalk(t, Options{Roots: []string{root}})

	if outcome.err != nil {
		t.Fatalf("Walk returned error: %v", outcome.err)
	}
	assertSamePaths(t, outcome.entries, []string{root})
	if outcome.stats.Directories != 1 {
		t.Errorf("Directories = %d, want 1", outcome.stats.Directories)
	}
	if outcome.stats.Files != 0 {
		t.Errorf("Files = %d, want 0", outcome.stats.Files)
	}
	if outcome.stats.Errors != 0 {
		t.Errorf("Errors = %d, want 0", outcome.stats.Errors)
	}
	if outcome.stats.Cancelled {
		t.Error("Cancelled = true, want false")
	}
}

func TestWalkSingleFile(t *testing.T) {
	root := t.TempDir()
	file := writeFile(t, filepath.Join(root, "only.txt"), "hello", 0o644)
	outcome := runWalk(t, Options{Roots: []string{root}})

	assertSamePaths(t, outcome.entries, []string{root, file})
	entry, ok := findEntry(outcome.entries, file)
	if !ok {
		t.Fatal("file entry missing")
	}
	if entry.Size() != 5 {
		t.Errorf("Size() = %d, want 5", entry.Size())
	}
	if !entry.IsRegular() {
		t.Error("file entry should be regular")
	}
	if entry.Depth != 1 {
		t.Errorf("Depth = %d, want 1", entry.Depth)
	}
	if entry.Root != root {
		t.Errorf("Root = %q, want %q", entry.Root, root)
	}
	if outcome.stats.Bytes != 5 {
		t.Errorf("Bytes = %d, want 5", outcome.stats.Bytes)
	}
}

func TestWalkNestedDirectories(t *testing.T) {
	root := t.TempDir()
	a := makeDir(t, filepath.Join(root, "a"), 0o755)
	b := makeDir(t, filepath.Join(a, "b"), 0o755)
	c := makeDir(t, filepath.Join(b, "c"), 0o755)
	file := writeFile(t, filepath.Join(c, "deep.txt"), "deep", 0o600)

	outcome := runWalk(t, Options{Roots: []string{root}})
	assertSamePaths(t, outcome.entries, []string{root, a, b, c, file})

	deep, ok := findEntry(outcome.entries, file)
	if !ok {
		t.Fatal("deep entry missing")
	}
	if deep.Depth != 4 {
		t.Errorf("Depth = %d, want 4", deep.Depth)
	}
	if got := deep.PermissionString(); got != "0600" {
		t.Errorf("PermissionString() = %q, want %q", got, "0600")
	}
	if outcome.stats.MaxDepthReached != 4 {
		t.Errorf("MaxDepthReached = %d, want 4", outcome.stats.MaxDepthReached)
	}
}

func TestWalkNoDuplicateEntries(t *testing.T) {
	root := t.TempDir()
	expected := []string{root}
	expected = append(expected, buildWideTree(t, root, 6, 4)...)

	outcome := runWalk(t, Options{Roots: []string{root}})
	assertSamePaths(t, outcome.entries, expected)

	seen := map[string]int{}
	for _, entry := range outcome.entries {
		seen[entry.Path]++
	}
	for path, count := range seen {
		if count != 1 {
			t.Errorf("path %s visited %d times, want 1", path, count)
		}
	}
}

func TestWalkMultipleRoots(t *testing.T) {
	base := t.TempDir()
	first := makeDir(t, filepath.Join(base, "first"), 0o755)
	second := makeDir(t, filepath.Join(base, "second"), 0o755)
	fileOne := writeFile(t, filepath.Join(first, "one.txt"), "1", 0o644)
	fileTwo := writeFile(t, filepath.Join(second, "two.txt"), "2", 0o644)

	outcome := runWalk(t, Options{Roots: []string{first, second}})
	assertSamePaths(t, outcome.entries, []string{first, fileOne, second, fileTwo})

	if len(outcome.stats.Roots) != 2 {
		t.Errorf("Roots = %v, want 2 entries", outcome.stats.Roots)
	}
	for _, entry := range outcome.entries {
		if entry.Root != first && entry.Root != second {
			t.Errorf("entry %s has root %q, want one of the requested roots", entry.Path, entry.Root)
		}
	}
}

func TestWalkDeduplicatesRepeatedRoots(t *testing.T) {
	root := t.TempDir()
	writeFile(t, filepath.Join(root, "a.txt"), "a", 0o644)

	outcome := runWalk(t, Options{Roots: []string{root, root, root}})
	assertSamePaths(t, outcome.entries, []string{root, filepath.Join(root, "a.txt")})
	if len(outcome.stats.Roots) != 1 {
		t.Errorf("Roots = %v, want a single deduplicated root", outcome.stats.Roots)
	}
}

func TestWalkSingleDirectoryOrderIsSorted(t *testing.T) {
	root := t.TempDir()
	for _, name := range []string{"c.txt", "a.txt", "b.txt"} {
		writeFile(t, filepath.Join(root, name), name, 0o644)
	}

	for _, workers := range []int{1, 2, 8} {
		walker := newTestWalker(t, Options{Roots: []string{root}, Workers: workers})
		var names []string
		if err := walker.Walk(context.Background(), func(entry Entry) {
			if !entry.IsDir() {
				names = append(names, entry.Name())
			}
		}); err != nil {
			t.Fatalf("workers=%d Walk returned error: %v", workers, err)
		}
		if !sort.StringsAreSorted(names) {
			t.Errorf("workers=%d names = %v, want sorted order", workers, names)
		}
	}
}

func TestWalkMembershipStableAcrossWorkerCounts(t *testing.T) {
	root := t.TempDir()
	expected := []string{root}
	expected = append(expected, buildWideTree(t, root, 8, 5)...)

	var reference []string
	for _, workers := range []int{1, 2, 4, 16, 64, MaxWorkers} {
		outcome := runWalk(t, Options{Roots: []string{root}, Workers: workers})
		if outcome.err != nil {
			t.Fatalf("workers=%d Walk returned error: %v", workers, outcome.err)
		}
		got := pathsOf(outcome.entries)
		if reference == nil {
			reference = got
			continue
		}
		if len(got) != len(reference) {
			t.Fatalf("workers=%d visited %d entries, want %d", workers, len(got), len(reference))
		}
		for i := range got {
			if got[i] != reference[i] {
				t.Fatalf("workers=%d entry %d = %s, want %s", workers, i, got[i], reference[i])
			}
		}
	}
}

func TestWalkVisitCallbackIsSerialized(t *testing.T) {
	root := t.TempDir()
	buildWideTree(t, root, 12, 6)

	walker := newTestWalker(t, Options{Roots: []string{root}, Workers: 16})

	var active int32
	var overlapped int32
	var calls int64

	if err := walker.Walk(context.Background(), func(Entry) {
		if atomic.AddInt32(&active, 1) != 1 {
			atomic.StoreInt32(&overlapped, 1)
		}
		atomic.AddInt64(&calls, 1)
		for i := 0; i < 32; i++ {
			runtime.Gosched()
		}
		atomic.AddInt32(&active, -1)
	}); err != nil {
		t.Fatalf("Walk returned error: %v", err)
	}

	if atomic.LoadInt32(&overlapped) != 0 {
		t.Error("visit callback was invoked concurrently; serialization is part of the contract")
	}
	if atomic.LoadInt64(&calls) == 0 {
		t.Error("visit callback was never invoked")
	}
}

func TestWalkIsReusableAcrossCalls(t *testing.T) {
	root := t.TempDir()
	writeFile(t, filepath.Join(root, "a.txt"), "a", 0o644)
	walker := newTestWalker(t, Options{Roots: []string{root}})

	first := 0
	if err := walker.Walk(context.Background(), func(Entry) { first++ }); err != nil {
		t.Fatalf("first Walk returned error: %v", err)
	}
	second := 0
	if err := walker.Walk(context.Background(), func(Entry) { second++ }); err != nil {
		t.Fatalf("second Walk returned error: %v", err)
	}

	if first != second {
		t.Errorf("consecutive Walks produced %d then %d visits, want equal counts", first, second)
	}
	if first != 2 {
		t.Errorf("visited %d entries, want 2 (root plus one file)", first)
	}
}

func TestWalkRequiresVisitCallback(t *testing.T) {
	walker := newTestWalker(t, Options{Roots: []string{t.TempDir()}})
	if err := walker.Walk(context.Background(), nil); err == nil {
		t.Fatal("Walk accepted a nil visit callback, want error")
	}
}

func TestWalkLargeTree(t *testing.T) {
	if testing.Short() {
		t.Skip("skipping large tree test in short mode")
	}
	root := t.TempDir()
	expected := []string{root}
	expected = append(expected, buildWideTree(t, root, 20, 25)...)

	outcome := runWalk(t, Options{Roots: []string{root}, Workers: 8})
	if outcome.err != nil {
		t.Fatalf("Walk returned error: %v", outcome.err)
	}
	assertSamePaths(t, outcome.entries, expected)
	if outcome.stats.Entries != int64(len(expected)) {
		t.Errorf("Entries = %d, want %d", outcome.stats.Entries, len(expected))
	}
}

func TestWalkCancellationBeforeStart(t *testing.T) {
	root := t.TempDir()
	buildWideTree(t, root, 10, 5)

	ctx, cancel := context.WithCancel(context.Background())
	cancel()

	walker := newTestWalker(t, Options{Roots: []string{root}})
	var visits int64
	err := walker.Walk(ctx, func(Entry) { atomic.AddInt64(&visits, 1) })

	if !errors.Is(err, context.Canceled) {
		t.Errorf("Walk returned %v, want context.Canceled", err)
	}
	if walker.Stats().Cancelled != true {
		t.Error("Stats.Cancelled = false, want true")
	}
	if visits > 2 {
		t.Errorf("visited %d entries after pre-cancellation, want at most the root", visits)
	}
}

func TestWalkCancellationDuringTraversal(t *testing.T) {
	root := t.TempDir()
	buildWideTree(t, root, 16, 8)
	total := 16*8 + 16 + 1

	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()

	walker := newTestWalker(t, Options{Roots: []string{root}, Workers: 4})
	var visits int64
	err := walker.Walk(ctx, func(Entry) {
		if atomic.AddInt64(&visits, 1) == 5 {
			cancel()
		}
	})

	if !errors.Is(err, context.Canceled) {
		t.Errorf("Walk returned %v, want context.Canceled", err)
	}
	if visits >= int64(total) {
		t.Errorf("visited %d of %d entries; cancellation did not stop traversal early", visits, total)
	}
	if walker.Stats().Cancelled != true {
		t.Error("Stats.Cancelled = false, want true")
	}
	if walker.Stats().Entries != visits {
		t.Errorf("Stats.Entries = %d but visit count = %d, want equal", walker.Stats().Entries, visits)
	}
}

func TestWalkCancellationLeavesNoGoroutines(t *testing.T) {
	root := t.TempDir()
	buildWideTree(t, root, 20, 10)

	settle := func() int {
		for i := 0; i < 50; i++ {
			runtime.Gosched()
			time.Sleep(time.Millisecond)
		}
		return runtime.NumGoroutine()
	}

	before := settle()

	ctx, cancel := context.WithCancel(context.Background())
	walker := newTestWalker(t, Options{Roots: []string{root}, Workers: 8})
	var visits int64
	_ = walker.Walk(ctx, func(Entry) {
		if atomic.AddInt64(&visits, 1) == 10 {
			cancel()
		}
	})
	cancel()

	after := settle()
	if after > before+2 {
		t.Errorf("goroutines grew from %d to %d across a cancelled walk; possible leak", before, after)
	}
}

func TestWalkUncancelledReturnsNilError(t *testing.T) {
	root := t.TempDir()
	buildWideTree(t, root, 5, 3)
	outcome := runWalk(t, Options{Roots: []string{root}})
	if outcome.err != nil {
		t.Errorf("Walk returned %v, want nil", outcome.err)
	}
	if outcome.stats.Cancelled {
		t.Error("Stats.Cancelled = true, want false")
	}
	if outcome.stats.FinishedAt.IsZero() {
		t.Error("Stats.FinishedAt was not set")
	}
	if outcome.stats.Duration() <= 0 {
		t.Errorf("Duration() = %v, want a positive duration", outcome.stats.Duration())
	}
}

func TestWalkProgressCallbackFiresWithFinalStats(t *testing.T) {
	root := t.TempDir()
	buildWideTree(t, root, 5, 3)

	var calls int64
	var last Stats
	walker := newTestWalker(t, Options{
		Roots:            []string{root},
		ProgressInterval: time.Millisecond,
		OnProgress:       func(stats Stats) { atomic.AddInt64(&calls, 1); last = stats },
	})

	if err := walker.Walk(context.Background(), func(Entry) {}); err != nil {
		t.Fatalf("Walk returned error: %v", err)
	}

	if atomic.LoadInt64(&calls) == 0 {
		t.Fatal("OnProgress was never invoked")
	}
	final := walker.Stats()
	if last.Entries != final.Entries {
		t.Errorf("final callback Entries = %d, want %d", last.Entries, final.Entries)
	}
	if last.FinishedAt.IsZero() {
		t.Error("final callback did not carry FinishedAt")
	}
}

func TestWalkProgressCallbackFiresForEmptyRoot(t *testing.T) {
	root := t.TempDir()
	var calls int64
	walker := newTestWalker(t, Options{
		Roots:      []string{root},
		OnProgress: func(Stats) { atomic.AddInt64(&calls, 1) },
	})
	if err := walker.Walk(context.Background(), func(Entry) {}); err != nil {
		t.Fatalf("Walk returned error: %v", err)
	}
	if atomic.LoadInt64(&calls) == 0 {
		t.Error("OnProgress should be invoked at least once, even for an empty root")
	}
}

func TestWalkProgressCallbackStopsAfterReturn(t *testing.T) {
	root := t.TempDir()
	buildWideTree(t, root, 10, 10)

	var calls int64
	walker := newTestWalker(t, Options{
		Roots:            []string{root},
		ProgressInterval: time.Millisecond,
		OnProgress:       func(Stats) { atomic.AddInt64(&calls, 1) },
	})
	if err := walker.Walk(context.Background(), func(Entry) {}); err != nil {
		t.Fatalf("Walk returned error: %v", err)
	}
	settled := atomic.LoadInt64(&calls)
	for i := 0; i < 20; i++ {
		runtime.Gosched()
		time.Sleep(time.Millisecond)
	}
	if after := atomic.LoadInt64(&calls); after != settled {
		t.Errorf("OnProgress fired %d more times after Walk returned", after-settled)
	}
}

func TestWalkProgressCallbackOnCancellation(t *testing.T) {
	root := t.TempDir()
	buildWideTree(t, root, 12, 8)

	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()

	var calls int64
	walker := newTestWalker(t, Options{
		Roots:            []string{root},
		ProgressInterval: time.Millisecond,
		OnProgress:       func(Stats) { atomic.AddInt64(&calls, 1) },
	})
	var visits int64
	_ = walker.Walk(ctx, func(Entry) {
		if atomic.AddInt64(&visits, 1) == 5 {
			cancel()
		}
	})

	if atomic.LoadInt64(&calls) == 0 {
		t.Error("OnProgress should still report the final state after cancellation")
	}
	settled := atomic.LoadInt64(&calls)
	for i := 0; i < 20; i++ {
		runtime.Gosched()
		time.Sleep(time.Millisecond)
	}
	if after := atomic.LoadInt64(&calls); after != settled {
		t.Errorf("OnProgress fired %d more times after a cancelled Walk returned", after-settled)
	}
}

func TestWalkRecordsUnreadableDirectory(t *testing.T) {
	if runningAsRoot() {
		t.Skip("permission bits are not enforced for root")
	}
	root := t.TempDir()
	locked := makeDir(t, filepath.Join(root, "locked"), 0o755)
	writeFile(t, filepath.Join(locked, "hidden.txt"), "x", 0o644)
	visible := writeFile(t, filepath.Join(root, "visible.txt"), "x", 0o644)
	if err := os.Chmod(locked, 0o000); err != nil {
		t.Fatalf("chmod failed: %v", err)
	}
	defer os.Chmod(locked, 0o755)

	outcome := runWalk(t, Options{Roots: []string{root}})

	if outcome.err != nil {
		t.Fatalf("Walk returned error: %v", outcome.err)
	}
	if outcome.stats.Errors != 1 {
		t.Errorf("Errors = %d, want 1", outcome.stats.Errors)
	}
	if outcome.stats.PermissionDenied != 1 {
		t.Errorf("PermissionDenied = %d, want 1", outcome.stats.PermissionDenied)
	}
	if len(outcome.stats.Inaccessible) != 1 {
		t.Fatalf("Inaccessible = %v, want one record", outcome.stats.Inaccessible)
	}
	if outcome.stats.Inaccessible[0][:len(locked)] != locked {
		t.Errorf("Inaccessible record %q does not name the unreadable directory", outcome.stats.Inaccessible[0])
	}
	if outcome.stats.InaccessibleTruncated {
		t.Error("InaccessibleTruncated = true, want false")
	}
	if _, ok := findEntry(outcome.entries, visible); !ok {
		t.Error("the readable sibling should still have been visited")
	}
}

func TestWalkUnreadableNestedDirectoryDoesNotAbortSiblings(t *testing.T) {
	if runningAsRoot() {
		t.Skip("permission bits are not enforced for root")
	}
	root := t.TempDir()
	locked := makeDir(t, filepath.Join(root, "locked"), 0o755)
	writeFile(t, filepath.Join(locked, "x"), "x", 0o644)
	if err := os.Chmod(locked, 0o000); err != nil {
		t.Fatalf("chmod failed: %v", err)
	}
	defer os.Chmod(locked, 0o755)

	visible := writeFile(t, filepath.Join(root, "after.txt"), "x", 0o644)

	outcome := runWalk(t, Options{Roots: []string{root}, Workers: 4})
	if _, ok := findEntry(outcome.entries, visible); !ok {
		t.Error("a later sibling should still be visited after an unreadable directory")
	}
	if _, ok := findEntry(outcome.entries, filepath.Join(locked, "x")); ok {
		t.Error("contents of an unreadable directory must not be reported")
	}
}

func TestWalkRecordsMissingRoot(t *testing.T) {
	base := t.TempDir()
	gone := filepath.Join(base, "gone")
	makeDir(t, gone, 0o755)
	walker := newTestWalker(t, Options{Roots: []string{gone}})
	if err := os.RemoveAll(gone); err != nil {
		t.Fatalf("removing root failed: %v", err)
	}

	var visits int64
	err := walker.Walk(context.Background(), func(Entry) { atomic.AddInt64(&visits, 1) })

	if err != nil {
		t.Errorf("Walk returned %v, want nil for a root that disappeared after construction", err)
	}
	if visits != 0 {
		t.Errorf("visited %d entries, want 0", visits)
	}
	stats := walker.Stats()
	if stats.Errors != 1 {
		t.Errorf("Errors = %d, want 1", stats.Errors)
	}
	if len(stats.Inaccessible) != 1 {
		t.Errorf("Inaccessible = %v, want one record", stats.Inaccessible)
	}
}

func TestWalkHandlesEntryRemovedDuringTraversal(t *testing.T) {
	if testing.Short() {
		t.Skip("skipping timing dependent test in short mode")
	}
	root := t.TempDir()
	buildWideTree(t, root, 10, 20)

	walker := newTestWalker(t, Options{Roots: []string{root}, Workers: 4})

	go func() {
		entries, err := os.ReadDir(root)
		if err != nil {
			return
		}
		for _, entry := range entries {
			os.RemoveAll(filepath.Join(root, entry.Name()))
		}
	}()

	var mu = make(chan struct{}, 1)
	mu <- struct{}{}
	visited := 0
	err := walker.Walk(context.Background(), func(Entry) {
		select {
		case <-mu:
			visited++
			mu <- struct{}{}
		default:
		}
	})
	if err != nil {
		t.Fatalf("Walk returned error: %v", err)
	}
	if walker.Stats().Entries != int64(visited) && visited > 0 {
		t.Logf("note: %d of %d entries were visited before removal", visited, walker.Stats().Entries)
	}
}
