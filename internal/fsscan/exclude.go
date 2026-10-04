package fsscan

import (
	"path/filepath"
	"strings"
)

type excludeSet struct {
	prefixes []string
}

func newExcludeSet(paths []string) excludeSet {
	prefixes := make([]string, 0, len(paths))
	for _, path := range paths {
		cleaned := filepath.Clean(path)
		if cleaned == "/" {
			return excludeSet{prefixes: []string{"/"}}
		}
		prefixes = append(prefixes, cleaned)
	}
	return excludeSet{prefixes: prefixes}
}

func (s excludeSet) excluded(path string) bool {
	if len(s.prefixes) == 0 {
		return false
	}
	cleaned := filepath.Clean(path)
	for _, prefix := range s.prefixes {
		if prefix == "/" {
			return true
		}
		if cleaned == prefix {
			return true
		}
		if strings.HasPrefix(cleaned, prefix+string(filepath.Separator)) {
			return true
		}
	}
	return false
}

func withinRoot(root, path string) bool {
	if root == "/" {
		return strings.HasPrefix(path, "/")
	}
	if path == root {
		return true
	}
	if !strings.HasPrefix(path, root+string(filepath.Separator)) {
		return false
	}
	relative, err := filepath.Rel(root, path)
	if err != nil {
		return false
	}
	return relative != ".." && !strings.HasPrefix(relative, ".."+string(filepath.Separator))
}
