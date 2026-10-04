package baseline

import (
	"crypto/sha256"
	"encoding/hex"
	"fmt"
	"path/filepath"
	"strings"

	"lisa/internal/model"
)

const Schema = "lisa/baseline/v1"

const Version = 1

const identityPrefix = "lisa/baseline/identity/v1"

const identityDigestLength = 16

const maxSummaryLength = 240

type Identity struct {
	RuleID   string         `json:"rule_id"`
	Category model.Category `json:"category"`
	Path     string         `json:"path"`
}

type Reference struct {
	Source   string         `json:"source"`
	Binary   string         `json:"binary"`
	Category string         `json:"category"`
	Summary  string         `json:"summary,omitempty"`
	Severity model.Severity `json:"severity"`
}

type Entry struct {
	ID       string         `json:"id"`
	RuleID   string         `json:"rule_id"`
	Category model.Category `json:"category"`
	Path     string         `json:"path"`
	Title    string         `json:"title"`

	Severity   model.Severity   `json:"severity"`
	Confidence model.Confidence `json:"confidence"`
	Mode       string           `json:"mode,omitempty"`
	Owner      string           `json:"owner,omitempty"`
	Group      string           `json:"group,omitempty"`
	Reference  *Reference       `json:"reference,omitempty"`
}

func IdentityID(ruleID string, category model.Category, path string) string {
	digest := sha256.Sum256([]byte(identityPrefix + "\x00" + ruleID + "\x00" + string(category) + "\x00" + path))
	return ruleID + "-" + hex.EncodeToString(digest[:])[:identityDigestLength]
}

func IdentityOf(finding model.Finding) Identity {
	return Identity{RuleID: finding.RuleID, Category: finding.Category, Path: finding.Path}
}

func EntryOf(finding model.Finding) Entry {
	identity := IdentityOf(finding)
	entry := Entry{
		ID:         IdentityID(identity.RuleID, identity.Category, identity.Path),
		RuleID:     identity.RuleID,
		Category:   identity.Category,
		Path:       identity.Path,
		Title:      finding.Title,
		Severity:   finding.Severity,
		Confidence: finding.Confidence,
		Owner:      finding.OwnerName(),
		Group:      finding.GroupName(),
	}
	if finding.Mode != nil {
		entry.Mode = finding.PermissionString()
	}
	if finding.Reference != nil {
		entry.Reference = &Reference{
			Source:   finding.Reference.Source,
			Binary:   finding.Reference.Binary,
			Category: finding.Reference.Category,
			Summary:  truncate(finding.Reference.Summary, maxSummaryLength),
			Severity: finding.Reference.Severity,
		}
	}
	return entry
}

func truncate(value string, limit int) string {
	if len(value) <= limit {
		return value
	}
	return value[:limit]
}

func (e Entry) Validate(index int) error {
	where := fmt.Sprintf("entry %d", index)
	if strings.TrimSpace(e.RuleID) == "" {
		return fmt.Errorf("%s: rule_id is required", where)
	}
	if !e.Category.IsValid() {
		return fmt.Errorf("%s (%s): unknown category %q", where, e.RuleID, string(e.Category))
	}
	if strings.TrimSpace(e.Path) == "" {
		return fmt.Errorf("%s (%s): path is required", where, e.RuleID)
	}
	if !filepath.IsAbs(e.Path) {
		return fmt.Errorf("%s (%s): path must be absolute", where, e.RuleID)
	}
	if strings.ContainsAny(e.Path, "\n\r\x00") {
		return fmt.Errorf("%s (%s): path contains control characters", where, e.RuleID)
	}
	if !e.Severity.IsValid() {
		return fmt.Errorf("%s (%s): invalid severity %d", where, e.RuleID, int(e.Severity))
	}
	if !e.Confidence.IsValid() {
		return fmt.Errorf("%s (%s): invalid confidence %d", where, e.RuleID, int(e.Confidence))
	}
	if e.Mode != "" && !isOctal(e.Mode) {
		return fmt.Errorf("%s (%s): mode %q must be octal digits", where, e.RuleID, e.Mode)
	}
	if want := IdentityID(e.RuleID, e.Category, e.Path); e.ID != want {
		return fmt.Errorf("%s (%s): id %q does not match its identity, expected %q", where, e.RuleID, e.ID, want)
	}
	return e.Reference.validate(where, e.RuleID)
}

func (r *Reference) validate(where, ruleID string) error {
	if r == nil {
		return nil
	}
	if strings.TrimSpace(r.Source) == "" {
		return fmt.Errorf("%s (%s): reference requires a source", where, ruleID)
	}
	if strings.TrimSpace(r.Binary) == "" {
		return fmt.Errorf("%s (%s): reference requires a binary name", where, ruleID)
	}
	if strings.TrimSpace(r.Category) == "" {
		return fmt.Errorf("%s (%s): reference for %s requires a category", where, ruleID, r.Binary)
	}
	if !r.Severity.IsValid() {
		return fmt.Errorf("%s (%s): reference for %s has invalid severity %d", where, ruleID, r.Binary, int(r.Severity))
	}
	return nil
}

func isOctal(value string) bool {
	if value == "" || len(value) > 8 {
		return false
	}
	for _, r := range value {
		if r < '0' || r > '7' {
			return false
		}
	}
	return true
}
