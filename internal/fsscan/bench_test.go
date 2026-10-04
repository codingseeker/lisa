package fsscan

import (
	"context"
	"os"
	"path/filepath"
	"sync"
	"testing"
)

type benchFixture struct {
	root  string
	files int
	dirs  int
}

var (
	benchOnce   sync.Once
	benchTree   string
	benchFlat   string
	benchCounts = struct {
		files, dirs int
	}{}
)

func buildBenchTree(tb testing.TB) benchFixture {
	benchOnce.Do(func() {
		root, err := os.MkdirTemp("", "lisa-bench-")
		if err != nil {
			tb.Fatalf("creating benchmark root failed: %v", err)
		}
		benchTree = root

		const dirs = 32
		const perDir = 64
		for d := 0; d < dirs; d++ {
			dir := filepath.Join(root, "d"+pad(d))
			if err := os.MkdirAll(dir, 0o755); err != nil {
				tb.Fatalf("mkdir failed: %v", err)
			}
			for f := 0; f < perDir; f++ {
				path := filepath.Join(dir, "f"+pad(f)+".txt")
				if err := os.WriteFile(path, []byte("benchmark fixture content"), 0o644); err != nil {
					tb.Fatalf("write failed: %v", err)
				}
			}
			benchCounts.files += perDir
			benchCounts.dirs++
		}

		benchFlat = filepath.Join(root, "flat")
		if err := os.MkdirAll(benchFlat, 0o755); err != nil {
			tb.Fatalf("mkdir failed: %v", err)
		}
		for f := 0; f < 512; f++ {
			if err := os.WriteFile(filepath.Join(benchFlat, "f"+pad(f)+".txt"), []byte("x"), 0o644); err != nil {
				tb.Fatalf("write failed: %v", err)
			}
			benchCounts.files++
		}
		benchCounts.dirs++
	})

	return benchFixture{root: benchTree, files: benchCounts.files, dirs: benchCounts.dirs}
}

func pad(value int) string {
	if value == 0 {
		return "0000"
	}
	text := ""
	for value > 0 {
		text = string(rune('0'+value%10)) + text
		value /= 10
	}
	for len(text) < 4 {
		text = "0" + text
	}
	return text
}

func BenchmarkWalkTraversal(b *testing.B) {
	fixture := buildBenchTree(b)
	opts := Options{Roots: []string{fixture.root}, Workers: 8}

	b.ReportAllocs()
	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		walker, err := New(opts)
		if err != nil {
			b.Fatalf("New failed: %v", err)
		}
		visited := 0
		if err := walker.Walk(context.Background(), func(Entry) { visited++ }); err != nil {
			b.Fatalf("Walk failed: %v", err)
		}
		if visited == 0 {
			b.Fatal("walk visited no entries")
		}
	}
}

func BenchmarkWalkMetadata(b *testing.B) {
	fixture := buildBenchTree(b)
	opts := Options{Roots: []string{filepath.Join(fixture.root, "flat")}, Workers: 4}

	var sinkBits uint32
	var sinkSize int64

	b.ReportAllocs()
	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		b.StopTimer()
		walker, err := New(opts)
		if err != nil {
			b.Fatalf("New failed: %v", err)
		}
		b.StartTimer()

		if err := walker.Walk(context.Background(), func(entry Entry) {
			sinkBits |= entry.PermissionBits()
			sinkSize += entry.Size()
			_ = entry.IsRegular()
			_ = entry.IsSymlink()
			_ = entry.IsDir()
			_ = entry.ModTime()
		}); err != nil {
			b.Fatalf("Walk failed: %v", err)
		}
	}
	b.StopTimer()

	if sinkBits == 0 && sinkSize == 0 {
		b.Fatal("metadata sink was never written")
	}
}

func BenchmarkWalkTraversalSerial(b *testing.B) {
	fixture := buildBenchTree(b)
	opts := Options{Roots: []string{fixture.root}, Workers: 1}

	b.ReportAllocs()
	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		b.StopTimer()
		walker, err := New(opts)
		if err != nil {
			b.Fatalf("New failed: %v", err)
		}
		b.StartTimer()

		visited := 0
		if err := walker.Walk(context.Background(), func(Entry) { visited++ }); err != nil {
			b.Fatalf("Walk failed: %v", err)
		}
		if visited == 0 {
			b.Fatal("walk visited no entries")
		}
	}
}

func BenchmarkWalkSingleWorker(b *testing.B) {
	fixture := buildBenchTree(b)
	opts := Options{Roots: []string{filepath.Join(fixture.root, "flat")}, Workers: 1}

	b.ReportAllocs()
	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		b.StopTimer()
		walker, err := New(opts)
		if err != nil {
			b.Fatalf("New failed: %v", err)
		}
		b.StartTimer()

		if err := walker.Walk(context.Background(), func(Entry) {}); err != nil {
			b.Fatalf("Walk failed: %v", err)
		}
	}
}
