package detectors

import (
	"fmt"

	"lisa/internal/gtfo"
	"lisa/internal/model"
)

const gtfoCaveat = "Contextual risk information from a curated GTFOBins subset. A match does not indicate that the binary was exploited, that the host is compromised, or that the binary is malicious. Absence from the dataset is not evidence that a binary is safe."

type gtfoReference struct {
	set *gtfo.Set
}

func newGtfoReference() gtfoReference {
	return gtfoReference{set: gtfo.Default()}
}

func (g gtfoReference) lookup(path string) (model.ReferenceContext, bool) {
	entry, ok := g.set.Lookup(path)
	if !ok {
		return model.ReferenceContext{}, false
	}
	return model.ReferenceContext{
		Source:      gtfo.SourceName,
		Binary:      entry.Binary,
		Category:    entry.Category,
		Summary:     entry.Summary,
		Attribution: gtfo.Attribution,
		Severity:    ruleGtfoBinsCandidate.Severity,
		Caveat:      gtfoCaveat,
	}, true
}

func (g gtfoReference) evidence(reference model.ReferenceContext, bits uint32) []string {
	return []string{
		fmt.Sprintf("mode=%04o", bits),
		fmt.Sprintf("curated binary=%s", reference.Binary),
		fmt.Sprintf("curated category=%s", reference.Category),
		"curated context: " + reference.Summary,
	}
}
