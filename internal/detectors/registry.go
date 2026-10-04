package detectors

import (
	"os"
	"strings"
	"sync/atomic"
	"time"

	"lisa/internal/fsscan"
	"lisa/internal/model"
)

type FileReader interface {
	Read(path string, limit int64) ([]byte, error)
}

type limitedFileReader struct {
	limit      int64
	maxFileLen int64
}

func newLimitedFileReader(limit, maxFileLen int64) FileReader {
	return limitedFileReader{limit: limit, maxFileLen: maxFileLen}
}

func (r limitedFileReader) Read(path string, limit int64) ([]byte, error) {
	if limit <= 0 || limit > r.limit {
		limit = r.limit
	}
	info, err := os.Lstat(path)
	if err != nil {
		return nil, err
	}
	if !info.Mode().IsRegular() {
		return nil, nil
	}
	if info.Size() > r.maxFileLen {
		return nil, nil
	}
	file, err := os.Open(path)
	if err != nil {
		return nil, err
	}
	defer file.Close()

	buffer := make([]byte, limit)
	read, err := file.Read(buffer)
	if err != nil && read == 0 {
		return nil, err
	}
	return buffer[:read], nil
}

type Context struct {
	Entry     fsscan.Entry
	Identity  *Identity
	ReadFile  FileReader
	Now       time.Time
	GTFOBins  bool
	User      string
	Group     string
	UID       uint32
	GID       uint32
	HaveOwner bool

	headerBudget *int64
}

func newContext(entry fsscan.Entry, opts Options) Context {
	ctx := Context{
		Entry:        entry,
		Identity:     opts.Identity,
		ReadFile:     opts.ReadFile,
		Now:          opts.Now,
		GTFOBins:     opts.GTFOBins,
		headerBudget: opts.headerBudget,
	}
	if uid, gid, ok := ownershipOf(entry.Info); ok {
		ctx.UID, ctx.GID, ctx.HaveOwner = uid, gid, true
		if name, found := opts.Identity.userName(uid); found {
			ctx.User = name
		}
		if name, found := opts.Identity.groupName(gid); found {
			ctx.Group = name
		}
	}
	return ctx
}

func (c Context) base(rule model.Rule) model.Finding {
	finding := rule.Finding(c.Entry.Path).WithDescription(rule.Title)
	finding.DetectedAt = c.Now
	if c.HaveOwner {
		finding = finding.WithOwner(c.ownerLabel()).WithGroup(c.groupLabel())
	}
	finding = finding.WithMode(c.Entry.PermissionBits())
	return finding
}

func (c Context) ownerLabel() string {
	if c.User != "" {
		return c.User
	}
	return "uid:" + itoa(c.UID)
}

func (c Context) groupLabel() string {
	if c.Group != "" {
		return c.Group
	}
	return "gid:" + itoa(c.GID)
}

func (c Context) allowHeaderRead() bool {
	if c.headerBudget == nil {
		return true
	}
	for {
		remaining := atomic.LoadInt64(c.headerBudget)
		if remaining <= 0 {
			return false
		}
		if atomic.CompareAndSwapInt64(c.headerBudget, remaining, remaining-1) {
			return true
		}
	}
}

type Detector interface {
	Name() string
	Detect(ctx Context) []model.Finding
}

type Registry struct {
	detectors []Detector
}

func NewRegistry(detectors ...Detector) *Registry {
	return &Registry{detectors: detectors}
}

func DefaultRegistry() *Registry {
	return NewRegistry(
		worldWritableDetector{},
		sensitivePermissionDetector{},
		sshKeyDetector{},
		suidDetector{},
		ownershipDetector{},
		systemdDetector{},
		cronDetector{},
		shellProfileDetector{},
		initDetector{},
		preloadDetector{},
		persistenceContentDetector{},
		sshdConfigDetector{},
		sudoersDetector{},
		secretExposureDetector{},
		temporaryExecutableDetector{},
		masqueradeDetector{},
	)
}

func (r *Registry) Names() []string {
	names := make([]string, 0, len(r.detectors))
	for _, detector := range r.detectors {
		names = append(names, detector.Name())
	}
	return names
}

func (r *Registry) Len() int {
	return len(r.detectors)
}

func (r *Registry) Select(names []string) (*Registry, error) {
	if len(names) == 0 {
		return r, nil
	}
	wanted := make(map[string]struct{}, len(names))
	for _, name := range names {
		wanted[strings.TrimSpace(name)] = struct{}{}
	}
	selected := make([]Detector, 0, len(names))
	var unknown []string
	for _, detector := range r.detectors {
		if _, ok := wanted[detector.Name()]; ok {
			selected = append(selected, detector)
			delete(wanted, detector.Name())
		}
	}
	for name := range wanted {
		unknown = append(unknown, name)
	}
	if len(unknown) > 0 {
		return nil, &UnknownDetectorError{Names: unknown, Available: r.Names()}
	}
	return NewRegistry(selected...), nil
}

type UnknownDetectorError struct {
	Names     []string
	Available []string
}

func (e *UnknownDetectorError) Error() string {
	return "unknown detector(s): " + strings.Join(e.Names, ", ") +
		"; available: " + strings.Join(e.Available, ", ")
}

func itoa(value uint32) string {
	if value == 0 {
		return "0"
	}
	digits := make([]byte, 0, 10)
	for value > 0 {
		digits = append([]byte{byte('0' + value%10)}, digits...)
		value /= 10
	}
	return string(digits)
}
