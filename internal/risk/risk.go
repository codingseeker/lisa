package risk

import (
	"fmt"
	"sort"
	"strings"

	"lisa/internal/model"
)

const (
	informationalMax = 19
	lowMax           = 39
	mediumMax        = 59
	highMax          = 79
)

var severityBase = map[model.Severity]int{
	model.SeverityInfo:     8,
	model.SeverityLow:      22,
	model.SeverityMedium:   42,
	model.SeverityHigh:     60,
	model.SeverityCritical: 80,
}

const fallbackBase = 8

func baseReason(severity model.Severity) string {
	if severity.IsValid() {
		return fmt.Sprintf("the detector rates this finding %s", severity)
	}
	return "the detector severity is outside the known scale, so the lowest base was assumed"
}

func modeOf(finding model.Finding) uint32 {
	if finding.Mode == nil {
		return 0
	}
	return *finding.Mode
}

type factor struct {
	name    string
	points  int
	reason  string
	applies func(model.Finding) bool
}

const (
	otherWrite  = 0o002
	otherRead   = 0o004
	groupWrite  = 0o020
	setuidBit   = 0o4000
	setgidBit   = 0o2000
	rootOwner   = "root"
	elevatedRun = "the recorded mode includes the setuid or setgid bit, so the file runs with the privileges of its owner"
)

var factors = []factor{
	{
		name:   "setuid-or-setgid-bit",
		points: 20,
		reason: elevatedRun,
		applies: func(f model.Finding) bool {
			mode := modeOf(f)
			return mode&(setuidBit|setgidBit) != 0
		},
	},
	{
		name:   "world-writable",
		points: 15,
		reason: "the recorded mode grants write permission to other users",
		applies: func(f model.Finding) bool {
			return modeOf(f)&otherWrite != 0
		},
	},
	{

		name:   "group-writable",
		points: 8,
		reason: "the recorded mode grants write permission to the owning group",
		applies: func(f model.Finding) bool {
			mode := modeOf(f)
			return mode&groupWrite != 0 && mode&otherWrite == 0
		},
	},
	{

		name:   "non-root-owner",
		points: 10,
		reason: "the recorded owner is not root, so the owner already holds privileges over this resource",
		applies: func(f model.Finding) bool {
			owner := f.OwnerName()
			return owner != "" && owner != rootOwner
		},
	},
	{

		name:   "access-config-readable-by-others",
		points: 5,
		reason: "the recorded mode grants read permission to other users on a file that governs host access",
		applies: func(f model.Finding) bool {
			return f.Category == model.CategorySensitiveConfig && modeOf(f)&otherRead != 0
		},
	},
	{

		name:   "automatic-execution",
		points: 10,
		reason: "the host reads this file to run commands, so its content takes effect without an operator choosing to run it",
		applies: func(f model.Finding) bool {
			return f.Category == model.CategoryPersistence
		},
	},
	{
		name:   "access-control-configuration",
		points: 8,
		reason: "the finding concerns configuration that governs access to the host",
		applies: func(f model.Finding) bool {
			return f.Category == model.CategorySensitiveConfig
		},
	},
	{
		name:   "high-evidence",
		points: 5,
		reason: "the detector is highly confident the condition is present",
		applies: func(f model.Finding) bool {
			return f.Confidence == model.ConfidenceHigh
		},
	},
}

func FactorNames() []string {
	names := make([]string, 0, len(factors))
	for _, entry := range factors {
		names = append(names, entry.name)
	}
	return names
}

var scoredCategories = []model.Category{
	model.CategoryPermissions,
	model.CategoryOwnership,
	model.CategorySensitiveConfig,
	model.CategoryPersistence,
	model.CategoryIndicator,
}

func Applies(finding model.Finding) bool {
	for _, category := range scoredCategories {
		if finding.Category == category {
			return true
		}
	}
	return false
}

func BandFor(score int) model.RiskBand {
	switch {
	case score <= informationalMax:
		return model.RiskBandInformational
	case score <= lowMax:
		return model.RiskBandLow
	case score <= mediumMax:
		return model.RiskBandMedium
	case score <= highMax:
		return model.RiskBandHigh
	default:
		return model.RiskBandCritical
	}
}

func clamp(total int) int {
	if total > model.MaxRiskScore {
		return model.MaxRiskScore
	}
	if total < model.MinRiskScore {
		return model.MinRiskScore
	}
	return total
}

func Base(severity model.Severity) int {
	if base, known := severityBase[severity]; known {
		return base
	}
	return fallbackBase
}

func Score(finding model.Finding) model.Risk {
	base := Base(finding.Severity)
	contributions := make([]model.RiskFactor, 0, len(factors)+2)
	contributions = append(contributions, model.RiskFactor{
		Name:   "severity-base",
		Points: base,
		Reason: baseReason(finding.Severity),
	})

	for _, entry := range factors {
		if !entry.applies(finding) {
			continue
		}
		contributions = append(contributions, model.RiskFactor{
			Name:   entry.name,
			Points: entry.points,
			Reason: entry.reason,
		})
	}

	total := 0
	for _, contribution := range contributions {
		total += contribution.Points
	}
	score := clamp(total)
	if score != total {

		contributions = append(contributions, model.RiskFactor{
			Name:   "score-cap",
			Points: score - total,
			Reason: "the factor total was capped at the maximum score of 100",
		})
	}

	return model.Risk{
		Score:       score,
		Band:        BandFor(score),
		Severity:    finding.Severity,
		Base:        base,
		Factors:     contributions,
		Explanation: explain(base, finding.Severity, contributions),
	}
}

func explain(base int, severity model.Severity, contributions []model.RiskFactor) string {
	var adjustments []string
	for _, contribution := range contributions {
		if contribution.Name == "severity-base" {
			continue
		}
		adjustments = append(adjustments, fmt.Sprintf("%+d %s", contribution.Points, contribution.Name))
	}

	detail := "no additional factors applied"
	if len(adjustments) > 0 {
		detail = strings.Join(adjustments, ", ")
	}
	if !severity.IsValid() {
		return fmt.Sprintf(
			"Base %d assumed because the detector severity is outside the known scale. %s. "+
				"The score indicates review priority, not evidence of exploitation.",
			base, capitalize(detail))
	}
	return fmt.Sprintf(
		"Base %d from detector severity %s; %s. "+
			"The score indicates review priority, not evidence of exploitation.",
		base, severity, detail)
}

func capitalize(value string) string {
	if value == "" {
		return value
	}
	return strings.ToUpper(value[:1]) + value[1:]
}

func Attach(findings []model.Finding) []model.Finding {
	out := make([]model.Finding, len(findings))
	copy(out, findings)
	for i := range out {
		if !Applies(out[i]) {
			continue
		}
		assessment := Score(out[i])
		out[i].Risk = &assessment
	}
	return out
}

func Sort(findings []model.Finding) {
	sort.SliceStable(findings, func(i, j int) bool {
		left, right := findings[i], findings[j]
		if leftScore, rightScore := scoreOf(left), scoreOf(right); leftScore != rightScore {
			return leftScore > rightScore
		}
		if left.Severity != right.Severity {
			return left.Severity > right.Severity
		}
		if left.Path != right.Path {
			return left.Path < right.Path
		}
		if left.RuleID != right.RuleID {
			return left.RuleID < right.RuleID
		}
		return left.ID < right.ID
	})
}

func scoreOf(finding model.Finding) int {
	if finding.Risk == nil {
		return 0
	}
	return finding.Risk.Score
}

func Summarise(findings []model.Finding) map[string]int {
	counts := make(map[string]int, len(model.RiskBands()))
	for _, band := range model.RiskBands() {
		counts[string(band)] = 0
	}
	for _, finding := range findings {
		if finding.Risk == nil {
			continue
		}
		counts[string(finding.Risk.Band)]++
	}
	return counts
}
