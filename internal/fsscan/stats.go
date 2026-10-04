package fsscan

import (
	"fmt"
	"time"
)

type Stats struct {
	Roots                 []string  `json:"roots"`
	StartedAt             time.Time `json:"started_at"`
	FinishedAt            time.Time `json:"finished_at"`
	Directories           int64     `json:"directories"`
	Files                 int64     `json:"files"`
	Symlinks              int64     `json:"symlinks"`
	SpecialFiles          int64     `json:"special_files"`
	Entries               int64     `json:"entries"`
	Bytes                 int64     `json:"bytes"`
	Excluded              int64     `json:"excluded"`
	Errors                int64     `json:"errors"`
	PermissionDenied      int64     `json:"permission_denied"`
	Inaccessible          []string  `json:"inaccessible,omitempty"`
	InaccessibleTruncated bool      `json:"inaccessible_truncated,omitempty"`
	MaxDepthReached       int       `json:"max_depth_reached"`
	DepthLimitHit         bool      `json:"depth_limit_hit"`
	EntryLimitHit         bool      `json:"entry_limit_hit"`
	Cancelled             bool      `json:"cancelled"`
}

func (s Stats) Duration() time.Duration {
	if s.StartedAt.IsZero() || s.FinishedAt.IsZero() {
		return 0
	}
	return s.FinishedAt.Sub(s.StartedAt)
}

func (s Stats) Clone() Stats {
	clone := s
	clone.Roots = append([]string(nil), s.Roots...)
	clone.Inaccessible = append([]string(nil), s.Inaccessible...)
	return clone
}

func formatOctal(bits uint32) string {
	return fmt.Sprintf("%04o", bits)
}
