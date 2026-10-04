package model

import (
	"crypto/sha256"
	"encoding/hex"
	"errors"
	"fmt"
	"time"
)

const permissionMask = 0o7777

type Finding struct {
	ID          string            `json:"id"`
	RuleID      string            `json:"rule_id"`
	Title       string            `json:"title"`
	Description string            `json:"description"`
	Severity    Severity          `json:"severity"`
	Confidence  Confidence        `json:"confidence"`
	Category    Category          `json:"category"`
	Path        string            `json:"path"`
	Evidence    []string          `json:"evidence,omitempty"`
	Owner       *string           `json:"owner,omitempty"`
	Group       *string           `json:"group,omitempty"`
	Mode        *uint32           `json:"mode,omitempty"`
	DetectedAt  time.Time         `json:"detected_at"`
	Remediation string            `json:"remediation,omitempty"`
	Technique   *Technique        `json:"technique,omitempty"`
	RelatedIDs  []string          `json:"related_ids,omitempty"`
	Reference   *ReferenceContext `json:"reference,omitempty"`

	Risk *Risk `json:"risk,omitempty"`
}

func FindingID(ruleID, path string) string {
	digest := sha256.Sum256([]byte(ruleID + "\x00" + path))
	return ruleID + "-" + hex.EncodeToString(digest[:])[:12]
}

func (f Finding) Validate() error {
	if f.ID == "" {
		return errors.New("finding id is required")
	}
	if f.RuleID == "" {
		return errors.New("finding rule id is required")
	}
	if f.Title == "" {
		return fmt.Errorf("finding %s requires a title", f.ID)
	}
	if !f.Severity.IsValid() {
		return fmt.Errorf("finding %s has invalid severity %d", f.ID, int(f.Severity))
	}
	if !f.Confidence.IsValid() {
		return fmt.Errorf("finding %s has invalid confidence %d", f.ID, int(f.Confidence))
	}
	if !f.Category.IsValid() {
		return fmt.Errorf("finding %s has unknown category %q", f.ID, string(f.Category))
	}
	if f.Path == "" {
		return fmt.Errorf("finding %s requires a path", f.ID)
	}
	if f.DetectedAt.IsZero() {
		return fmt.Errorf("finding %s requires a detection timestamp", f.ID)
	}
	if err := f.Technique.Validate(); err != nil {
		return err
	}
	if err := f.Risk.Validate(); err != nil {
		return err
	}
	return f.Reference.Validate()
}

func (f Finding) WithDescription(description string) Finding {
	f.Description = description
	return f
}

func (f Finding) WithEvidence(lines ...string) Finding {
	f.Evidence = append(f.Evidence, lines...)
	return f
}

func (f Finding) WithOwner(owner string) Finding {
	f.Owner = &owner
	return f
}

func (f Finding) WithGroup(group string) Finding {
	f.Group = &group
	return f
}

func (f Finding) WithMode(mode uint32) Finding {
	masked := mode & permissionMask
	f.Mode = &masked
	return f
}

func (f Finding) WithRemediation(remediation string) Finding {
	f.Remediation = remediation
	return f
}

func (f Finding) WithSeverity(severity Severity) Finding {
	f.Severity = severity
	return f
}

func (f Finding) WithReference(reference *ReferenceContext) Finding {
	f.Reference = reference
	return f
}

func (f Finding) HasReference() bool {
	return f.Reference != nil
}

func (f Finding) WithRelated(ids ...string) Finding {
	f.RelatedIDs = append(f.RelatedIDs, ids...)
	return f
}

func (f Finding) PermissionString() string {
	if f.Mode == nil {
		return ""
	}
	return fmt.Sprintf("%04o", *f.Mode)
}

func (f Finding) OwnerName() string {
	if f.Owner == nil {
		return ""
	}
	return *f.Owner
}

func (f Finding) GroupName() string {
	if f.Group == nil {
		return ""
	}
	return *f.Group
}
