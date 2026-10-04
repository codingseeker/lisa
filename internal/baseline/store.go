package baseline

import (
	"encoding/json"
	"errors"
	"fmt"
	"io/fs"
	"os"
	"path/filepath"
	"strings"
	"time"

	"lisa/internal/model"
)

const (
	fileMode fs.FileMode = 0o600
	dirMode  fs.FileMode = 0o700
)

const maxDocumentBytes = 64 << 20

type LoadOptions struct {
	MaxBytes int64
}

type WriteOptions struct {
	Overwrite bool

	FileMode fs.FileMode
}

func Load(path string, opts LoadOptions) (*Document, error) {
	if err := checkPath(path); err != nil {
		return nil, err
	}
	info, err := os.Stat(path)
	if err != nil {
		if errors.Is(err, fs.ErrNotExist) {
			return nil, fmt.Errorf("baseline %s: %w", path, ErrNotFound)
		}
		return nil, fmt.Errorf("baseline %s: %w", path, err)
	}
	if info.IsDir() {
		return nil, fmt.Errorf("baseline %s: expected a file, found a directory", path)
	}

	limit := opts.MaxBytes
	if limit <= 0 {
		limit = maxDocumentBytes
	}
	if info.Size() > limit {
		return nil, fmt.Errorf("baseline %s: %w: file is %d bytes, limit is %d bytes",
			path, ErrSchema, info.Size(), limit)
	}

	content, err := os.ReadFile(path)
	if err != nil {
		return nil, fmt.Errorf("baseline %s: %w", path, err)
	}
	document, err := Parse(content)
	if err != nil {
		return nil, fmt.Errorf("baseline %s: %w", path, err)
	}
	return document, nil
}

func Parse(content []byte) (*Document, error) {
	if len(content) == 0 {
		return nil, fmt.Errorf("%w: file is empty", ErrSchema)
	}
	if int64(len(content)) > maxDocumentBytes {
		return nil, fmt.Errorf("%w: file is %d bytes, limit is %d bytes", ErrSchema, len(content), maxDocumentBytes)
	}

	var document Document
	if err := json.Unmarshal(content, &document); err != nil {

		var syntax *json.SyntaxError
		if errors.As(err, &syntax) {
			return nil, fmt.Errorf("%w: malformed JSON at byte %d", ErrSchema, syntax.Offset)
		}
		var typeErr *json.UnmarshalTypeError
		if errors.As(err, &typeErr) {
			field := typeErr.Field
			if field == "" {
				field = "(document root)"
			}
			return nil, fmt.Errorf("%w: field %q has the wrong JSON type", ErrSchema, field)
		}
		return nil, fmt.Errorf("%w: not a valid baseline document", ErrSchema)
	}

	if err := document.Validate(); err != nil {
		return nil, err
	}
	return &document, nil
}

func (d *Document) Validate() error {
	if d.Schema != Schema {
		return fmt.Errorf("%w: found schema %q, this build understands %q", ErrSchema, clip(d.Schema), Schema)
	}
	if d.Version != Version {
		return fmt.Errorf("%w: found version %d, this build understands version %d", ErrSchema, d.Version, Version)
	}
	if strings.TrimSpace(d.Tool.Name) == "" {
		return fmt.Errorf("%w: tool.name is required", ErrInvalidDocument)
	}
	if _, err := model.ParseSeverity(d.MinSeverity); err != nil {
		return fmt.Errorf("%w: %w", ErrInvalidDocument, err)
	}
	if _, err := time.Parse(time.RFC3339, d.CreatedAt); err != nil {
		return fmt.Errorf("%w: created_at must be an RFC 3339 timestamp", ErrInvalidDocument)
	}

	seen := make(map[string]int, len(d.Findings))
	for index, entry := range d.Findings {
		if err := entry.Validate(index); err != nil {
			return fmt.Errorf("%w: %w", ErrInvalidDocument, err)
		}
		if first, duplicate := seen[entry.ID]; duplicate {
			return fmt.Errorf("%w: %w: %s at %s repeats the identity of entry %d",
				ErrInvalidDocument, ErrAmbiguousIdentity, entry.RuleID, entry.Path, first)
		}
		seen[entry.ID] = index
	}

	for _, root := range d.Roots {
		if !filepath.IsAbs(root) {
			return fmt.Errorf("%w: root %q must be absolute", ErrInvalidDocument, clip(root))
		}
	}
	if err := d.Coverage.validate(); err != nil {
		return err
	}
	if d.Summary.Findings != len(d.Findings) {
		return fmt.Errorf("%w: summary counts %d findings but the document holds %d",
			ErrInvalidDocument, d.Summary.Findings, len(d.Findings))
	}
	return nil
}

func (c Coverage) validate() error {
	switch c.ScanStatus {
	case "complete", "partial", "cancelled":
	default:
		return fmt.Errorf("%w: coverage.scan_status %q is not one of complete, partial, cancelled",
			ErrInvalidDocument, clip(c.ScanStatus))
	}
	if c.Complete != (c.ScanStatus == "complete") {
		return fmt.Errorf("%w: coverage.complete disagrees with scan_status %q", ErrInvalidDocument, clip(c.ScanStatus))
	}
	for _, name := range c.FailedDetectors {
		if strings.TrimSpace(name) == "" {
			return fmt.Errorf("%w: coverage.failed_detectors contains an empty name", ErrInvalidDocument)
		}
	}
	for _, path := range c.InaccessiblePaths {
		if !filepath.IsAbs(path) {
			return fmt.Errorf("%w: inaccessible path %q must be absolute", ErrInvalidDocument, clip(path))
		}
	}
	return nil
}

func Write(document *Document, path string, opts WriteOptions) error {
	if document == nil {
		return fmt.Errorf("baseline: a document is required")
	}
	if err := document.Validate(); err != nil {
		return err
	}
	if err := checkPath(path); err != nil {
		return err
	}
	if !opts.Overwrite {
		if _, err := os.Lstat(path); err == nil {
			return fmt.Errorf("baseline %s: %w, pass --overwrite to replace it", path, ErrExists)
		} else if !errors.Is(err, fs.ErrNotExist) {
			return fmt.Errorf("baseline %s: %w", path, err)
		}
	}

	content, err := document.Marshal()
	if err != nil {
		return err
	}

	mode := opts.FileMode
	if mode == 0 {
		mode = fileMode
	}

	directory := filepath.Dir(path)
	if err := os.MkdirAll(directory, dirMode); err != nil {
		return fmt.Errorf("baseline %s: creating the destination directory: %w", path, err)
	}

	temporary, err := os.CreateTemp(directory, ".lisa-baseline-*")
	if err != nil {
		return fmt.Errorf("baseline %s: creating a temporary file: %w", path, err)
	}
	temporaryPath := temporary.Name()
	cleanup := func(cause error) error {
		temporary.Close()
		os.Remove(temporaryPath)
		return cause
	}

	if _, err := temporary.Write(content); err != nil {
		return cleanup(fmt.Errorf("baseline %s: writing a temporary file: %w", path, err))
	}
	if err := temporary.Sync(); err != nil {
		return cleanup(fmt.Errorf("baseline %s: flushing a temporary file: %w", path, err))
	}
	if err := temporary.Chmod(mode); err != nil {
		return cleanup(fmt.Errorf("baseline %s: restricting permissions: %w", path, err))
	}
	if err := temporary.Close(); err != nil {
		os.Remove(temporaryPath)
		return fmt.Errorf("baseline %s: closing a temporary file: %w", path, err)
	}

	if err := os.Rename(temporaryPath, path); err != nil {
		os.Remove(temporaryPath)
		return fmt.Errorf("baseline %s: installing the baseline: %w", path, err)
	}
	return nil
}

func checkPath(path string) error {
	if strings.TrimSpace(path) == "" {
		return fmt.Errorf("%w: path is empty", ErrUnsafePath)
	}
	if strings.ContainsRune(path, 0) {
		return fmt.Errorf("%w: path contains a NUL byte", ErrUnsafePath)
	}
	return nil
}

func clip(value string) string {
	const limit = 64
	if len(value) <= limit {
		return value
	}
	return value[:limit] + "..."
}
