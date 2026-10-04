package correlation

import (
	"crypto/sha256"
	"encoding/hex"
	"fmt"
	"sort"
	"strings"

	"lisa/internal/attack"
	"lisa/internal/detectors"
	"lisa/internal/model"
	"lisa/internal/scan"
)

type Options struct {
	Attack *attack.Set
}

type Rule struct {
	ID string

	Title string

	Confidence model.CorrelationConfidence

	Match func(findings []model.Finding) [][]string

	Explain func(related []model.Finding) string

	Assumption string
}

var rules = []Rule{
	{
		ID:         "LS-COR-001",
		Title:      "Automatically executed configuration is writable by other users",
		Confidence: model.CorrelationHigh,
		Assumption: "Both findings describe the same file. Write access and automatic execution are separately measured properties of that one file; the rule does not claim anyone wrote to it.",
		Match: func(findings []model.Finding) [][]string {
			return pairByPath(findings, isPersistence, grantsWrite)
		},
		Explain: func(related []model.Finding) string {
			return fmt.Sprintf(
				"%s is read by the host to run commands and its recorded mode lets %s write to it. "+
					"The two findings describe one file, so the write access applies to configuration that "+
					"takes effect without an operator. No change to the file was observed.",
				pathOf(related), writerOf(related))
		},
	},
	{
		ID:         "LS-COR-002",
		Title:      "Privilege-escalating binary is owned by an unprivileged account",
		Confidence: model.CorrelationHigh,
		Assumption: "Both findings describe the same file. The rule does not claim the binary was executed or that the owner used it.",
		Match: func(findings []model.Finding) [][]string {
			return pairByPath(findings, hasPrivilegeBit, hasUntrustedOwnership)
		},
		Explain: func(related []model.Finding) string {
			return fmt.Sprintf(
				"%s carries a setuid or setgid bit and is owned by %s rather than root, "+
					"so whoever controls the file controls the elevated identity it runs with. "+
					"The tool observed the mode and the owner; it did not execute the binary.",
				pathOf(related), ownerOf(related))
		},
	},
	{
		ID:         "LS-COR-003",
		Title:      "Payload-shaped artifact in a world-writable staging location",
		Confidence: model.CorrelationHigh,
		Assumption: "Both findings describe the same file. Neither finding identifies the file as malicious; both describe a property that a legitimately deployed file could also have.",
		Match: func(findings []model.Finding) [][]string {
			return pairByPath(findings, isStagedExecutable, isPayloadShaped)
		},
		Explain: func(related []model.Finding) string {
			return fmt.Sprintf(
				"%s is an executable in a directory other users can write to, and its content and name "+
					"match a pattern associated with staged tooling. Either property alone is common; "+
					"together they are worth reviewing. The file was not classified as malicious.",
				pathOf(related))
		},
	},
	{
		ID:         "LS-COR-004",
		Title:      "Weakened remote access policy alongside broadly permitted key material",
		Confidence: model.CorrelationMedium,
		Assumption: "The findings need not share a path. They are related because both weaken the same trust path, SSH access to this host. The tool cannot show that the key material and the policy are connected.",
		Match: func(findings []model.Finding) [][]string {
			return pair(findings, weakensRemoteAccess, broadensKeyPermissions)
		},
		Explain: func(related []model.Finding) string {
			return fmt.Sprintf(
				"%s reports a weakened remote access policy and %s reports key material whose "+
					"permissions are broader than the owning user needs. Both weaken the same SSH trust "+
					"path, but the tool cannot show that the keys are reachable under this policy, and no "+
					"credential access was observed.",
				ruleIDsOf(related, weakensRemoteAccess), ruleIDsOf(related, broadensKeyPermissions))
		},
	},
}

func Rules() []Rule {
	return append([]Rule(nil), rules...)
}

func RuleByID(id string) (Rule, bool) {
	for _, rule := range rules {
		if rule.ID == id {
			return rule, true
		}
	}
	return Rule{}, false
}

func Analyse(result *scan.Result, opts Options) []model.Correlation {
	if result == nil {
		return nil
	}
	findings := result.Findings
	if len(findings) < 2 {
		return nil
	}

	scope := scopeOf(result)
	records := make([]model.Correlation, 0, 4)
	seen := make(map[string]struct{}, 4)

	for _, rule := range rules {
		for _, group := range rule.Match(findings) {
			ids := normalizeIDs(group)
			if len(ids) < 2 {
				continue
			}
			record := build(rule, ids, findings, scope, opts)
			if _, duplicate := seen[record.ID]; duplicate {
				continue
			}
			seen[record.ID] = struct{}{}
			records = append(records, record)
		}
	}

	model.SortCorrelations(records)
	return records
}

func build(rule Rule, ids []string, findings []model.Finding,
	scope model.CorrelationScope, opts Options) model.Correlation {

	related := findingsByID(findings, ids)
	record := model.Correlation{
		ID:          CorrelationID(rule.ID, ids),
		RuleID:      rule.ID,
		Title:       rule.Title,
		FindingIDs:  ids,
		Confidence:  rule.Confidence,
		Explanation: rule.Explain(related),
		Scope:       scope,
	}

	if opts.Attack != nil {
		if mapping, ok := opts.Attack.Lookup(rule.ID); ok {
			technique := mapping.Technique
			record.Technique = &technique
			record.AttackRelevance = mapping.Relevance
		}
	}
	return record
}

func CorrelationID(ruleID string, findingIDs []string) string {
	digest := sha256.New()
	digest.Write([]byte(ruleID))
	for _, id := range normalizeIDs(findingIDs) {
		digest.Write([]byte{0})
		digest.Write([]byte(id))
	}
	return ruleID + "-" + hex.EncodeToString(digest.Sum(nil))[:12]
}

func normalizeIDs(ids []string) []string {
	if len(ids) == 0 {
		return nil
	}
	sorted := append([]string(nil), ids...)
	sort.Strings(sorted)

	out := make([]string, 0, len(sorted))
	for i, id := range sorted {
		if id == "" {
			continue
		}
		if i > 0 && id == sorted[i-1] {
			continue
		}
		out = append(out, id)
	}
	return out
}

func findingsByID(findings []model.Finding, ids []string) []model.Finding {
	byID := make(map[string]model.Finding, len(findings))
	for _, finding := range findings {
		byID[finding.ID] = finding
	}
	related := make([]model.Finding, 0, len(ids))
	for _, id := range ids {
		if finding, ok := byID[id]; ok {
			related = append(related, finding)
		}
	}
	return related
}

func scopeOf(result *scan.Result) model.CorrelationScope {
	var notes []string

	if result.Status == scan.StatusCancelled {
		notes = append(notes, "the scan was cancelled, so related findings may be missing")
	}
	if result.Status == scan.StatusPartial {
		notes = append(notes,
			"the scan covered only part of the target, so related findings may be missing")
	}
	if result.Files.EntryLimitHit || result.Files.DepthLimitHit {
		notes = append(notes, "a traversal limit stopped the walk, so related findings may be missing")
	}
	if len(result.Detectors.DetectorFailures) > 0 {
		notes = append(notes, fmt.Sprintf("detector(s) %s failed, so related findings may be missing",
			strings.Join(sortedNames(result.Detectors.DetectorFailures), ", ")))
	}
	if len(result.Files.Inaccessible) > 0 {
		notes = append(notes, fmt.Sprintf("%d path(s) could not be read, so related findings may be missing",
			len(result.Files.Inaccessible)))
	}
	if selected := result.Detectors.Selected; len(selected) > 0 && len(selected) < len(allDetectorNames()) {
		notes = append(notes, fmt.Sprintf(
			"only %d of the %d available detectors ran, so relationships needing the others are not reported",
			len(selected), len(allDetectorNames())))
	}

	if len(notes) == 0 {
		return model.CorrelationScope{Complete: true}
	}
	return model.CorrelationScope{Complete: false, Note: capitalize(strings.Join(notes, "; ")) + "."}
}

func allDetectorNames() []string {
	names := detectors.DefaultRegistry().Names()
	sort.Strings(names)
	return names
}

func sortedNames(counts map[string]int64) []string {
	names := make([]string, 0, len(counts))
	for name, count := range counts {
		if count > 0 {
			names = append(names, name)
		}
	}
	sort.Strings(names)
	return names
}

func capitalize(value string) string {
	if value == "" {
		return value
	}
	return strings.ToUpper(value[:1]) + value[1:]
}

func pairByPath(findings []model.Finding, first, second func(model.Finding) bool) [][]string {
	firstByPath := map[string][]string{}
	secondByPath := map[string][]string{}

	for _, finding := range findings {
		if finding.Path == "" || finding.ID == "" {
			continue
		}
		if first(finding) {
			firstByPath[finding.Path] = append(firstByPath[finding.Path], finding.ID)
		}
		if second(finding) {
			secondByPath[finding.Path] = append(secondByPath[finding.Path], finding.ID)
		}
	}

	paths := make([]string, 0, len(firstByPath))
	for path := range firstByPath {
		if len(secondByPath[path]) > 0 {
			paths = append(paths, path)
		}
	}
	sort.Strings(paths)

	groups := make([][]string, 0, len(paths))
	for _, path := range paths {
		groups = append(groups, append(firstByPath[path], secondByPath[path]...))
	}
	return groups
}

func pair(findings []model.Finding, first, second func(model.Finding) bool) [][]string {
	var firstIDs, secondIDs []string
	for _, finding := range findings {
		if finding.ID == "" {
			continue
		}
		if first(finding) {
			firstIDs = append(firstIDs, finding.ID)
		}
		if second(finding) {
			secondIDs = append(secondIDs, finding.ID)
		}
	}
	if len(firstIDs) == 0 || len(secondIDs) == 0 {
		return nil
	}

	groups := make([][]string, 0, len(secondIDs))
	for _, id := range normalizeIDs(secondIDs) {
		groups = append(groups, append(append([]string(nil), firstIDs...), id))
	}
	return groups
}

func isPersistence(finding model.Finding) bool {
	return finding.Category == model.CategoryPersistence
}

func hasPrivilegeBit(finding model.Finding) bool {
	if finding.Mode == nil {
		return false
	}
	const privilegeBits = 0o6000
	return *finding.Mode&privilegeBits != 0
}

func hasUntrustedOwnership(finding model.Finding) bool {
	switch finding.RuleID {
	case "LS-OWN-001", "LS-OWN-002", "LS-OWN-003", "LS-OWN-004":
		return true
	}
	return false
}

func grantsWrite(finding model.Finding) bool {
	if finding.Mode == nil {
		return false
	}
	const writeBits = 0o022
	return *finding.Mode&writeBits != 0
}

func isStagedExecutable(finding model.Finding) bool {
	return finding.RuleID == "LS-IND-001"
}

func isPayloadShaped(finding model.Finding) bool {
	switch finding.RuleID {
	case "LS-IND-002", "LS-IND-003", "LS-IND-004", "LS-IND-005":
		return true
	}
	return false
}

func weakensRemoteAccess(finding model.Finding) bool {
	switch finding.RuleID {
	case "LS-SENS-001", "LS-SENS-002", "LS-SENS-003":
		return true
	}
	return false
}

func broadensKeyPermissions(finding model.Finding) bool {
	switch finding.RuleID {
	case "LS-PERM-005", "LS-PERM-006":
		return true
	}
	return false
}

func pathOf(related []model.Finding) string {
	if len(related) == 0 {
		return "the affected file"
	}
	return related[0].Path
}

func ruleIDsOf(related []model.Finding, matches func(model.Finding) bool) string {
	var ids []string
	for _, finding := range related {
		if matches(finding) {
			ids = append(ids, finding.RuleID)
		}
	}
	ids = normalizeIDs(ids)
	if len(ids) == 0 {
		return "a related finding"
	}
	return strings.Join(ids, " and ")
}

func ownerOf(related []model.Finding) string {
	for _, finding := range related {
		if owner := finding.OwnerName(); owner != "" {
			return owner
		}
	}
	return "an unprivileged account"
}

func writerOf(related []model.Finding) string {
	for _, finding := range related {
		if finding.Mode == nil {
			continue
		}
		const otherWrite = 0o002
		if *finding.Mode&otherWrite != 0 {
			return "other users"
		}
	}
	return "the owning group"
}
