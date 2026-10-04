package fsscan

import (
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"time"
)

const (
	DefaultWorkers          = 8
	MaxWorkers              = 256
	DefaultMaxEntries       = 4_000_000
	DefaultMaxInaccessible  = 100
	DefaultProgressInterval = 750 * time.Millisecond
)

var virtualFilesystems = []string{"/proc", "/sys"}

type Options struct {
	Roots                  []string
	Workers                int
	Excludes               []string
	MaxDepth               int
	FollowSymlinks         bool
	SkipVirtualFilesystems bool
	MaxEntries             int
	MaxInaccessible        int
	ProgressInterval       time.Duration
	OnProgress             func(Stats)
}

func (o *Options) applyDefaults() {
	if o.Workers == 0 {
		o.Workers = DefaultWorkers
	}
	if o.MaxEntries == 0 {
		o.MaxEntries = DefaultMaxEntries
	}
	if o.MaxInaccessible == 0 {
		o.MaxInaccessible = DefaultMaxInaccessible
	}
	if o.ProgressInterval == 0 {
		o.ProgressInterval = DefaultProgressInterval
	}
}

func (o Options) validate() error {
	if len(o.Roots) == 0 {
		return errors.New("fsscan: at least one root is required")
	}
	if o.Workers < 1 || o.Workers > MaxWorkers {
		return fmt.Errorf("fsscan: workers must be between 1 and %d, got %d", MaxWorkers, o.Workers)
	}
	if o.MaxEntries < 1 {
		return fmt.Errorf("fsscan: max entries must be positive, got %d", o.MaxEntries)
	}
	if o.MaxDepth < 0 {
		return fmt.Errorf("fsscan: max depth must not be negative, got %d", o.MaxDepth)
	}
	if o.MaxInaccessible < 0 {
		return fmt.Errorf("fsscan: max inaccessible must not be negative, got %d", o.MaxInaccessible)
	}
	if o.ProgressInterval < 0 {
		return fmt.Errorf("fsscan: progress interval must not be negative, got %s", o.ProgressInterval)
	}
	for _, root := range o.Roots {
		if strings.TrimSpace(root) == "" {
			return errors.New("fsscan: root paths must not be empty")
		}
	}
	return nil
}

func (o Options) resolveRoots() ([]string, error) {
	resolved := make([]string, 0, len(o.Roots))
	seen := make(map[string]struct{}, len(o.Roots))
	for _, root := range o.Roots {
		absolute, err := filepath.Abs(root)
		if err != nil {
			return nil, fmt.Errorf("fsscan: root %q: %w", root, err)
		}
		absolute = filepath.Clean(absolute)
		if _, duplicate := seen[absolute]; duplicate {
			continue
		}
		info, err := os.Lstat(absolute)
		if err != nil {
			return nil, fmt.Errorf("fsscan: root %q is not accessible: %w", absolute, err)
		}
		if !info.IsDir() {
			return nil, fmt.Errorf("fsscan: root %q is not a directory", absolute)
		}
		seen[absolute] = struct{}{}
		resolved = append(resolved, absolute)
	}
	return resolved, nil
}

func (o Options) resolveExcludes() ([]string, error) {
	resolved := make([]string, 0, len(o.Excludes))
	for _, exclude := range o.Excludes {
		if strings.TrimSpace(exclude) == "" {
			return nil, errors.New("fsscan: excluded paths must not be empty")
		}
		absolute, err := filepath.Abs(exclude)
		if err != nil {
			return nil, fmt.Errorf("fsscan: excluded path %q: %w", exclude, err)
		}
		resolved = append(resolved, filepath.Clean(absolute))
	}
	return resolved, nil
}

func (o Options) isVirtualFilesystem(path string, roots map[string]struct{}) bool {
	if !o.SkipVirtualFilesystems {
		return false
	}
	if _, explicit := roots[path]; explicit {
		return false
	}
	for _, virtual := range virtualFilesystems {
		if path == virtual || strings.HasPrefix(path, virtual+"/") {
			return true
		}
	}
	return false
}

func (o Options) withDefaults() Options {
	o.applyDefaults()
	return o
}
