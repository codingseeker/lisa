package fsscan

import (
	"context"
	"errors"
	"os"
	"path/filepath"
	"sync"
	"syscall"
	"time"
)

type Walker struct {
	opts     Options
	excludes excludeSet
	explicit map[string]struct{}

	mu      sync.Mutex
	visitMu sync.Mutex
	stats   Stats
	cancel  context.CancelFunc
	stopped bool
}

func New(opts Options) (*Walker, error) {
	opts.applyDefaults()
	if err := opts.validate(); err != nil {
		return nil, err
	}
	roots, err := opts.resolveRoots()
	if err != nil {
		return nil, err
	}
	excludes, err := opts.resolveExcludes()
	if err != nil {
		return nil, err
	}
	opts.Roots = roots
	opts.Excludes = excludes

	explicit := make(map[string]struct{}, len(roots))
	for _, root := range roots {
		explicit[root] = struct{}{}
	}

	return &Walker{
		opts:     opts,
		excludes: newExcludeSet(excludes),
		explicit: explicit,
	}, nil
}

func (w *Walker) Options() Options {
	return w.opts
}

func (w *Walker) Stats() Stats {
	w.mu.Lock()
	defer w.mu.Unlock()
	return w.stats.Clone()
}

func (w *Walker) Walk(ctx context.Context, visit func(Entry)) error {
	if visit == nil {
		return errors.New("fsscan: a visit callback is required")
	}

	runCtx, cancel := context.WithCancel(ctx)
	defer cancel()

	w.begin(cancel)
	progressDone := w.startProgress(runCtx)
	semaphore := make(chan struct{}, w.opts.Workers)

	var wg sync.WaitGroup
	for _, root := range w.opts.Roots {
		info, err := os.Lstat(root)
		if err != nil {
			w.recordInaccessible(root, err)
			continue
		}
		w.accept(Entry{Path: root, Root: root, Depth: 0, Info: info})
		w.emit(runCtx, visit, Entry{Path: root, Root: root, Depth: 0, Info: info})
		wg.Add(1)
		go w.walkDir(runCtx, root, 0, semaphore, &wg, visit)
	}
	wg.Wait()

	cancel()
	<-progressDone
	w.finish(ctx)

	return ctx.Err()
}

func (w *Walker) walkDir(ctx context.Context, path string, depth int, semaphore chan struct{}, wg *sync.WaitGroup, visit func(Entry)) {
	defer wg.Done()

	select {
	case semaphore <- struct{}{}:
		defer func() { <-semaphore }()
	case <-ctx.Done():
		return
	}

	items, err := os.ReadDir(path)
	if err != nil {
		w.recordInaccessible(path, err)
		return
	}

	for _, item := range items {
		if ctx.Err() != nil {
			return
		}
		child := filepath.Join(path, item.Name())

		if w.excludes.excluded(child) {
			w.mutate(func(s *Stats) { s.Excluded++ })
			continue
		}
		if w.opts.isVirtualFilesystem(child, w.explicit) {
			w.mutate(func(s *Stats) { s.Excluded++ })
			continue
		}

		info, err := item.Info()
		if err != nil {
			w.recordInaccessible(child, err)
			continue
		}

		entry := Entry{Path: child, Root: w.rootFor(child), Depth: depth + 1, Info: info}
		if w.opts.MaxDepth > 0 && entry.Depth > w.opts.MaxDepth {
			w.mutate(func(s *Stats) { s.DepthLimitHit = true })
			return
		}
		if !w.accept(entry) {
			return
		}
		w.emit(ctx, visit, entry)

		if w.descend(entry) {
			wg.Add(1)
			go w.walkDir(ctx, child, entry.Depth, semaphore, wg, visit)
		}
	}
}

func (w *Walker) descend(entry Entry) bool {
	if entry.IsDir() {
		return true
	}
	if !entry.IsSymlink() || !w.opts.FollowSymlinks {
		return false
	}

	target, err := filepath.EvalSymlinks(entry.Path)
	if err != nil {
		w.recordInaccessible(entry.Path, err)
		return false
	}
	info, err := os.Stat(target)
	if err != nil {
		w.recordInaccessible(entry.Path, err)
		return false
	}
	if !info.IsDir() {
		return false
	}
	if !withinRoot(entry.Root, target) {
		w.mutate(func(s *Stats) { s.Errors++ })
		w.note(entry.Path, "symlink target resolves outside the scan root")
		return false
	}
	return true
}

func (w *Walker) accept(entry Entry) bool {
	w.mu.Lock()
	defer w.mu.Unlock()
	if w.stopped {
		return false
	}
	if w.stats.Entries >= int64(w.opts.MaxEntries) {
		w.stats.EntryLimitHit = true
		w.stopped = true
		if w.cancel != nil {
			w.cancel()
		}
		return false
	}
	w.countLocked(entry)
	return true
}

func (w *Walker) countLocked(entry Entry) {
	w.stats.Entries++
	switch {
	case entry.IsDir():
		w.stats.Directories++
	case entry.IsSymlink():
		w.stats.Symlinks++
	case entry.IsSpecial():
		w.stats.SpecialFiles++
	default:
		w.stats.Files++
		w.stats.Bytes += entry.Size()
	}
	if entry.Depth > w.stats.MaxDepthReached {
		w.stats.MaxDepthReached = entry.Depth
	}
}

func (w *Walker) emit(ctx context.Context, visit func(Entry), entry Entry) {
	if ctx.Err() != nil {
		return
	}
	w.visitMu.Lock()
	defer w.visitMu.Unlock()
	visit(entry)
}

func (w *Walker) rootFor(path string) string {
	for _, root := range w.opts.Roots {
		if withinRoot(root, path) {
			return root
		}
	}
	return path
}

func (w *Walker) begin(cancel context.CancelFunc) {
	w.mu.Lock()
	defer w.mu.Unlock()
	w.cancel = cancel
	w.stopped = false
	w.stats = Stats{
		Roots:     append([]string(nil), w.opts.Roots...),
		StartedAt: time.Now().UTC(),
	}
}

func (w *Walker) finish(ctx context.Context) {
	w.mu.Lock()
	w.stats.FinishedAt = time.Now().UTC()
	w.stats.Cancelled = ctx.Err() != nil
	w.mu.Unlock()
	if w.opts.OnProgress != nil {
		w.opts.OnProgress(w.Stats())
	}
}

func (w *Walker) startProgress(ctx context.Context) chan struct{} {
	done := make(chan struct{})
	if w.opts.OnProgress == nil {
		close(done)
		return done
	}
	go func() {
		defer close(done)
		ticker := time.NewTicker(w.opts.ProgressInterval)
		defer ticker.Stop()
		for {
			select {
			case <-ctx.Done():
				return
			case <-ticker.C:
				if snapshot := w.Stats(); snapshot.Entries > 0 {
					w.opts.OnProgress(snapshot)
				}
			}
		}
	}()
	return done
}

func (w *Walker) recordInaccessible(path string, err error) {
	denied := errors.Is(err, syscall.EACCES) || errors.Is(err, syscall.EPERM)
	w.mutate(func(s *Stats) {
		s.Errors++
		if denied {
			s.PermissionDenied++
		}
	})
	w.note(path, err.Error())
}

func (w *Walker) note(path, reason string) {
	w.mu.Lock()
	defer w.mu.Unlock()
	if len(w.stats.Inaccessible) >= w.opts.MaxInaccessible {
		w.stats.InaccessibleTruncated = true
		return
	}
	w.stats.Inaccessible = append(w.stats.Inaccessible, path+" ("+reason+")")
}

func (w *Walker) mutate(apply func(*Stats)) {
	w.mu.Lock()
	defer w.mu.Unlock()
	apply(&w.stats)
}
