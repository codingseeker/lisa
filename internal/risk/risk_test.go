package risk

import (
	"encoding/json"
	"math/rand"
	"strings"
	"testing"
	"time"

	"lisa/internal/model"
)

var referenceTime = time.Date(2026, 3, 4, 5, 6, 7, 0, time.UTC)

func finding(mutate ...func(*model.Finding)) model.Finding {
	base := model.Finding{
		ID:          model.FindingID("LS-PERM-001", "/srv/app"),
		RuleID:      "LS-PERM-001",
		Title:       "World-writable regular file",
		Description: "World-writable regular file /srv/app",
		Severity:    model.SeverityMedium,
		Confidence:  model.ConfidenceHigh,
		Category:    model.CategoryPermissions,
		Path:        "/srv/app",
		DetectedAt:  referenceTime,
	}
	for _, apply := range mutate {
		apply(&base)
	}
	return base
}

func withSeverity(severity model.Severity) func(*model.Finding) {
	return func(f *model.Finding) { f.Severity = severity }
}

func withConfidence(confidence model.Confidence) func(*model.Finding) {
	return func(f *model.Finding) { f.Confidence = confidence }
}

func withCategory(category model.Category) func(*model.Finding) {
	return func(f *model.Finding) { f.Category = category }
}

func withMode(mode uint32) func(*model.Finding) {
	return func(f *model.Finding) { f.Mode = &mode }
}

func withOwner(owner string) func(*model.Finding) {
	return func(f *model.Finding) { f.Owner = &owner }
}

func distinct(subject model.Finding, ruleID, path string) model.Finding {
	subject.RuleID = ruleID
	subject.Path = path
	subject.ID = model.FindingID(ruleID, path)
	return subject
}

func scored(t *testing.T, assessment model.Risk, name string) (int, bool) {
	t.Helper()
	for _, factor := range assessment.Factors {
		if factor.Name == name {
			return factor.Points, true
		}
	}
	return 0, false
}

func TestEverySeverityScoresAtItsBandFloor(t *testing.T) {
	cases := []struct {
		severity model.Severity
		base     int
		band     model.RiskBand
	}{
		{model.SeverityInfo, 8, model.RiskBandInformational},
		{model.SeverityLow, 22, model.RiskBandLow},
		{model.SeverityMedium, 42, model.RiskBandMedium},
		{model.SeverityHigh, 60, model.RiskBandHigh},
		{model.SeverityCritical, 80, model.RiskBandCritical},
	}

	for _, testCase := range cases {
		t.Run(testCase.severity.String(), func(t *testing.T) {

			bare := finding(withSeverity(testCase.severity), withConfidence(model.ConfidenceLow))
			assessment := Score(bare)

			if assessment.Base != testCase.base {
				t.Errorf("Base = %d, want %d", assessment.Base, testCase.base)
			}
			if assessment.Score != testCase.base {
				t.Errorf("Score = %d, want the base %d with no modifiers", assessment.Score, testCase.base)
			}
			if assessment.Band != testCase.band {
				t.Errorf("Band = %q, want %q", assessment.Band, testCase.band)
			}
			if assessment.Severity != testCase.severity {
				t.Errorf("Severity = %q, want the original %q preserved",
					assessment.Severity, testCase.severity)
			}
		})
	}
}

func TestBaseLandsInTheBandItsSeverityImplies(t *testing.T) {

	ordered := model.RiskBands()

	for _, severity := range model.Severities() {
		base := Base(severity)
		band := BandFor(base)

		if base < model.MinRiskScore || base > model.MaxRiskScore {
			t.Errorf("Base(%s) = %d, which is outside the published scale", severity, base)
		}

		var position int
		for i, candidate := range ordered {
			if candidate == band {
				position = i
			}
		}

		want := ordered[int(severity)]
		if band != want {
			t.Errorf("Base(%s) = %d lands in band %q, want %q", severity, base, band, want)
		}
		if position < int(severity) {
			t.Errorf("severity %s landed below its own band", severity)
		}
	}
}

func TestFactorsNeverLowerTheBand(t *testing.T) {
	modes := []uint32{0o0000, 0o0007, 0o0060, 0o0600, 0o0644, 0o0664, 0o0666, 0o2755, 0o4755, 0o6755, 0o7777}
	owners := []string{"", "root", "nobody"}
	categories := []model.Category{
		model.CategoryPermissions, model.CategoryOwnership, model.CategorySensitiveConfig,
		model.CategoryPersistence, model.CategoryIndicator,
	}
	confidences := []model.Confidence{model.ConfidenceLow, model.ConfidenceMedium, model.ConfidenceHigh}

	for _, severity := range model.Severities() {
		floor := BandFor(Base(severity))
		for _, mode := range modes {
			for _, owner := range owners {
				for _, category := range categories {
					for _, confidence := range confidences {
						subject := finding(withSeverity(severity), withMode(mode),
							withOwner(owner), withCategory(category), withConfidence(confidence))
						got := Score(subject).Band
						if BandPosition(got) < BandPosition(floor) {
							t.Errorf("factors lowered a %s finding from band %q to %q "+
								"(mode %04o, owner %q, category %q, confidence %s)",
								severity, floor, got, mode, owner, category, confidence)
						}
					}
				}
			}
		}
	}
}

func BandPosition(band model.RiskBand) int {
	for i, candidate := range model.RiskBands() {
		if candidate == band {
			return i
		}
	}
	return -1
}

func TestBandBoundaries(t *testing.T) {
	cases := []struct {
		score int
		band  model.RiskBand
	}{
		{model.MinRiskScore, model.RiskBandInformational},
		{informationalMax, model.RiskBandInformational},
		{informationalMax + 1, model.RiskBandLow},
		{lowMax, model.RiskBandLow},
		{lowMax + 1, model.RiskBandMedium},
		{mediumMax, model.RiskBandMedium},
		{mediumMax + 1, model.RiskBandHigh},
		{highMax, model.RiskBandHigh},
		{highMax + 1, model.RiskBandCritical},
		{model.MaxRiskScore, model.RiskBandCritical},
	}

	for _, testCase := range cases {
		if got := BandFor(testCase.score); got != testCase.band {
			t.Errorf("BandFor(%d) = %q, want %q", testCase.score, got, testCase.band)
		}
	}
}

func TestBandForClampsOutOfRangeScores(t *testing.T) {
	if got := BandFor(-50); got != model.RiskBandInformational {
		t.Errorf("BandFor(-50) = %q, want the lowest band", got)
	}
	if got := BandFor(10_000); got != model.RiskBandCritical {
		t.Errorf("BandFor(10000) = %q, want the highest band", got)
	}
}

func TestClampBoundsBothEnds(t *testing.T) {
	cases := []struct {
		total int
		want  int
	}{
		{-25, model.MinRiskScore},
		{model.MinRiskScore, model.MinRiskScore},
		{57, 57},
		{model.MaxRiskScore, model.MaxRiskScore},
		{101, model.MaxRiskScore},
		{1_000, model.MaxRiskScore},
	}
	for _, testCase := range cases {
		if got := clamp(testCase.total); got != testCase.want {
			t.Errorf("clamp(%d) = %d, want %d", testCase.total, got, testCase.want)
		}
	}
}

func TestMaximumScoreIsCappedAndTheCapIsRecorded(t *testing.T) {
	everything := finding(
		withSeverity(model.SeverityCritical),
		withConfidence(model.ConfidenceHigh),
		withCategory(model.CategorySensitiveConfig),
		withMode(0o4757),
		withOwner("nobody"),
	)
	assessment := Score(everything)

	if assessment.Score != model.MaxRiskScore {
		t.Errorf("Score = %d, want the cap %d", assessment.Score, model.MaxRiskScore)
	}
	if assessment.Band != model.RiskBandCritical {
		t.Errorf("Band = %q, want critical", assessment.Band)
	}
	points, ok := scored(t, assessment, "score-cap")
	if !ok {
		t.Fatal("a capped score must record a score-cap factor")
	}
	if points >= 0 {
		t.Errorf("score-cap = %d, want a negative reduction", points)
	}
	if total := assessment.Sum(); total != assessment.Score {
		t.Errorf("factors total %d but the score is %d", total, assessment.Score)
	}
}

func TestFactorsAlwaysSumToTheScore(t *testing.T) {
	cases := map[string]model.Finding{
		"bare":            finding(withConfidence(model.ConfidenceLow)),
		"typical":         finding(withMode(0o777), withOwner("someone")),
		"maximal":         finding(withSeverity(model.SeverityCritical), withCategory(model.CategorySensitiveConfig), withMode(0o6755), withOwner("someone")),
		"persistence":     finding(withCategory(model.CategoryPersistence), withMode(0o4777), withOwner("someone")),
		"unknownSeverity": finding(withSeverity(model.Severity(99)), withConfidence(model.ConfidenceLow)),
	}
	for name, subject := range cases {
		t.Run(name, func(t *testing.T) {
			assessment := Score(subject)
			if total := assessment.Sum(); total != assessment.Score {
				t.Errorf("factors total %d but the score is %d", total, assessment.Score)
			}
			if err := assessment.Validate(); err != nil {
				t.Errorf("the assessment is not internally consistent: %v", err)
			}
		})
	}
}

func TestEachFactorAppliesOnceAndOnlyWhenMeasured(t *testing.T) {
	cases := []struct {
		name    string
		subject model.Finding
		absent  model.Finding
	}{
		{
			name:    "setuid-or-setgid-bit",
			subject: finding(withMode(0o4755)),
			absent:  finding(withMode(0o0755)),
		},
		{
			name:    "world-writable",
			subject: finding(withMode(0o0666)),
			absent:  finding(withMode(0o0644)),
		},
		{
			name:    "group-writable",
			subject: finding(withMode(0o0664)),
			absent:  finding(withMode(0o0644)),
		},
		{
			name:    "non-root-owner",
			subject: finding(withOwner("nobody")),
			absent:  finding(withOwner("root")),
		},
		{
			name:    "access-config-readable-by-others",
			subject: finding(withCategory(model.CategorySensitiveConfig), withMode(0o0644)),
			absent:  finding(withCategory(model.CategorySensitiveConfig), withMode(0o0600)),
		},
		{
			name:    "automatic-execution",
			subject: finding(withCategory(model.CategoryPersistence)),
			absent:  finding(withCategory(model.CategoryPermissions)),
		},
		{
			name:    "access-control-configuration",
			subject: finding(withCategory(model.CategorySensitiveConfig)),
			absent:  finding(withCategory(model.CategoryPermissions)),
		},
		{
			name:    "high-evidence",
			subject: finding(withConfidence(model.ConfidenceHigh)),
			absent:  finding(withConfidence(model.ConfidenceMedium)),
		},
	}

	for _, testCase := range cases {
		t.Run(testCase.name, func(t *testing.T) {
			present := Score(testCase.subject)
			missing := Score(testCase.absent)

			if _, ok := scored(t, present, testCase.name); !ok {
				t.Errorf("%s did not apply to a finding that has the property", testCase.name)
			}
			if _, ok := scored(t, missing, testCase.name); ok {
				t.Errorf("%s applied to a finding that does not have the property", testCase.name)
			}
			want := factorPoints(t, testCase.name)
			if got := present.Score - missing.Score; got != want {
				t.Errorf("the %s factor moved the score by %d, want its weight %d "+
					"(%d with the property, %d without)",
					testCase.name, got, want, present.Score, missing.Score)
			}
		})
	}
}

func mustEncode(t *testing.T, assessment model.Risk) string {
	t.Helper()
	encoded, err := json.Marshal(assessment)
	if err != nil {
		t.Fatalf("Marshal: %v", err)
	}
	return string(encoded)
}

func factorPoints(t *testing.T, name string) int {
	t.Helper()
	for _, entry := range factors {
		if entry.name == name {
			return entry.points
		}
	}
	t.Fatalf("no factor named %q exists", name)
	return 0
}

func TestReadableByOthersIsOnlyCountedForAccessConfiguration(t *testing.T) {
	permissions := finding(withCategory(model.CategoryPermissions), withMode(0o0644))
	if _, ok := scored(t, Score(permissions), "access-config-readable-by-others"); ok {
		t.Error("read exposure was counted for a plain permissions finding")
	}
}

func TestGroupWritableIsNotCountedAlongsideWorldWritable(t *testing.T) {
	both := finding(withMode(0o0666))
	assessment := Score(both)

	if _, ok := scored(t, assessment, "world-writable"); !ok {
		t.Error("world-writable should apply to a world-writable file")
	}
	if _, ok := scored(t, assessment, "group-writable"); ok {
		t.Error("group-writable must not apply to a file that is also world-writable")
	}
	if err := assessment.Validate(); err != nil {
		t.Errorf("assessment is not internally consistent: %v", err)
	}
}

func TestNoFactorIsCountedTwice(t *testing.T) {
	stress := []model.Finding{
		finding(withSeverity(model.SeverityCritical), withConfidence(model.ConfidenceHigh),
			withCategory(model.CategorySensitiveConfig), withMode(0o6755), withOwner("someone")),
		finding(withCategory(model.CategoryPersistence), withMode(0o7777), withOwner("root")),
		finding(withMode(0o0007)),
	}
	for i, subject := range stress {
		assessment := Score(subject)
		seen := map[string]bool{}
		for _, factor := range assessment.Factors {
			if seen[factor.Name] {
				t.Errorf("case %d recorded factor %s twice", i, factor.Name)
			}
			seen[factor.Name] = true
		}
		if err := assessment.Validate(); err != nil {
			t.Errorf("case %d: %v", i, err)
		}
	}
}

func TestGTFOBinsContextDoesNotChangeTheScore(t *testing.T) {
	plain := finding(withMode(0o4755), withOwner("root"))
	enriched := plain
	enriched.RuleID = "LS-PRIV-004"
	enriched.Category = model.CategoryIndicator
	enriched.Confidence = model.ConfidenceMedium
	enriched.Reference = &model.ReferenceContext{
		Source:   "gtfobins-curated",
		Binary:   "find",
		Category: "GTFOBins SUID",
		Summary:  "Limited SUID execution environments.",
		Severity: model.SeverityHigh,
		Caveat:   "A match is a reason to look closer, nothing more.",
	}

	withoutReference := enriched
	withoutReference.Reference = nil

	withScore := Score(enriched)
	withoutScore := Score(withoutReference)
	if withScore.Score != withoutScore.Score {
		t.Errorf("a GTFOBins match changed the score from %d to %d",
			withoutScore.Score, withScore.Score)
	}
	if len(withScore.Factors) != len(withoutScore.Factors) {
		t.Errorf("a GTFOBins match changed the factor count from %d to %d",
			len(withoutScore.Factors), len(withScore.Factors))
	}

	criticalReference := enriched
	criticalReference.Reference = &model.ReferenceContext{
		Source: "gtfobins-curated", Binary: "find", Category: "GTFOBins SUID",
		Summary: "x", Severity: model.SeverityCritical, Caveat: "y",
	}
	if got := Score(criticalReference).Score; got != withScore.Score {
		t.Errorf("a critical curated severity changed the score to %d, want %d", got, withScore.Score)
	}
}

func TestUnknownAndIncompleteAttributes(t *testing.T) {
	t.Run("severity outside the scale falls back to the lowest base", func(t *testing.T) {
		assessment := Score(finding(withSeverity(model.Severity(99)), withConfidence(model.ConfidenceLow)))
		if assessment.Base != fallbackBase {
			t.Errorf("Base = %d, want the fallback %d", assessment.Base, fallbackBase)
		}
		if assessment.Band != model.RiskBandInformational {
			t.Errorf("Band = %q, want informational", assessment.Band)
		}
		if !strings.Contains(assessment.Explanation, "outside the known scale") {
			t.Errorf("explanation %q should say the severity was not recognised",
				assessment.Explanation)
		}
		if assessment.Severity != model.Severity(99) {
			t.Errorf("Severity = %d, want the original value preserved unmodified",
				int(assessment.Severity))
		}
	})

	t.Run("absent mode contributes nothing", func(t *testing.T) {
		assessment := Score(finding(withConfidence(model.ConfidenceLow)))
		if _, ok := scored(t, assessment, "world-writable"); ok {
			t.Error("world-writable applied without a recorded mode")
		}
		if _, ok := scored(t, assessment, "setuid-or-setgid-bit"); ok {
			t.Error("setuid-or-setgid-bit applied without a recorded mode")
		}
	})

	t.Run("absent owner is not treated as a non root owner", func(t *testing.T) {
		assessment := Score(finding(withConfidence(model.ConfidenceLow)))
		if _, ok := scored(t, assessment, "non-root-owner"); ok {
			t.Error("non-root-owner applied without a recorded owner")
		}
	})

	t.Run("unknown category earns no category factor", func(t *testing.T) {
		assessment := Score(finding(withCategory(model.Category("invented")), withConfidence(model.ConfidenceLow)))
		for _, name := range []string{"automatic-execution", "access-control-configuration",
			"access-config-readable-by-others"} {
			if _, ok := scored(t, assessment, name); ok {
				t.Errorf("%s applied to an unknown category", name)
			}
		}
	})

	t.Run("unknown confidence earns no evidence factor", func(t *testing.T) {
		assessment := Score(finding(withConfidence(model.Confidence(42))))
		if _, ok := scored(t, assessment, "high-evidence"); ok {
			t.Error("high-evidence applied to an unrecognised confidence")
		}
	})

	t.Run("a zero valued finding is still assessed", func(t *testing.T) {
		assessment := Score(model.Finding{})
		if assessment.Score < model.MinRiskScore {
			t.Errorf("Score = %d, want at least the minimum", assessment.Score)
		}
		if assessment.Band != model.RiskBandInformational {
			t.Errorf("Band = %q, want informational", assessment.Band)
		}
		if len(assessment.Factors) == 0 {
			t.Error("an assessment must always record at least the base factor")
		}
	})
}

func TestScoringPreservesOriginalSeverityAndTheFinding(t *testing.T) {
	for _, severity := range model.Severities() {
		subject := finding(withSeverity(severity))
		assessment := Score(subject)

		if assessment.Severity != severity {
			t.Errorf("assessment severity = %q, want %q", assessment.Severity, severity)
		}
		if subject.Severity != severity {
			t.Errorf("Score modified the severity of the finding it was given")
		}
	}
}

func TestAttachDoesNotModifyTheInput(t *testing.T) {
	original := finding(withMode(0o0666))
	before, err := json.Marshal(original)
	if err != nil {
		t.Fatalf("Marshal: %v", err)
	}

	attached := Attach([]model.Finding{original})
	if original.Risk != nil {
		t.Error("Attach modified the caller's finding")
	}
	after, err := json.Marshal(original)
	if err != nil {
		t.Fatalf("Marshal: %v", err)
	}
	if string(before) != string(after) {
		t.Error("Attach changed a field of the caller's finding")
	}
	if len(attached) != 1 || attached[0].Risk == nil {
		t.Fatal("Attach did not assess the finding it returned")
	}
	if attached[0].Risk.Score != Score(original).Score {
		t.Error("the attached score does not match the score for the same finding")
	}
}

func TestAppliesOnlyToDetectorObservations(t *testing.T) {
	scoredCategories := []model.Category{
		model.CategoryPermissions, model.CategoryOwnership, model.CategorySensitiveConfig,
		model.CategoryPersistence, model.CategoryIndicator,
	}
	for _, category := range scoredCategories {
		if !Applies(finding(withCategory(category))) {
			t.Errorf("category %q should be scored", category)
		}
	}
	for _, category := range []model.Category{model.CategoryBaseline, model.CategoryCorrelation} {
		if Applies(finding(withCategory(category))) {
			t.Errorf("category %q is a derived record and should not be scored", category)
		}
	}

	attached := Attach([]model.Finding{
		finding(withCategory(model.CategoryCorrelation)),
		finding(withCategory(model.CategoryPermissions)),
	})
	if attached[0].Risk != nil {
		t.Error("a correlation record was scored")
	}
	if attached[1].Risk == nil {
		t.Error("a detector observation was not scored")
	}
}

func TestExplanationMatchesTheFactors(t *testing.T) {
	subject := finding(withMode(0o4777), withOwner("someone"))
	assessment := Score(subject)

	for _, factor := range assessment.Factors {
		if factor.Name == "severity-base" {
			continue
		}
		if !strings.Contains(assessment.Explanation, factor.Name) {
			t.Errorf("explanation %q does not mention the %s factor",
				assessment.Explanation, factor.Name)
		}
	}
	if !strings.Contains(assessment.Explanation, "not evidence of exploitation") {
		t.Errorf("explanation %q must not overstate what the score means", assessment.Explanation)
	}
	if strings.Contains(assessment.Explanation, "exploitable") {
		t.Errorf("explanation %q claims exploitability", assessment.Explanation)
	}

	bare := Score(finding(withConfidence(model.ConfidenceLow)))
	if !strings.Contains(bare.Explanation, "no additional factors applied") {
		t.Errorf("explanation %q should say no factors applied", bare.Explanation)
	}
}

func TestScoringIsDeterministic(t *testing.T) {
	subject := finding(withMode(0o4755), withOwner("someone"), withCategory(model.CategoryPersistence))
	first := mustEncode(t, Score(subject))
	for i := 0; i < 100; i++ {
		if got := mustEncode(t, Score(subject)); got != first {
			t.Fatalf("run %d produced a different assessment", i)
		}
	}

	findings := []model.Finding{
		distinct(finding(withMode(0o4755), withOwner("someone")), "LS-PRIV-001", "/srv/a"),
		distinct(finding(withSeverity(model.SeverityHigh), withMode(0o0644)), "LS-PERM-001", "/srv/b"),
		distinct(finding(withCategory(model.CategoryPersistence), withMode(0o0666), withOwner("root")), "LS-PERS-001", "/srv/c"),
		distinct(finding(), "LS-IND-001", "/srv/d"),
		distinct(finding(withSeverity(model.SeverityCritical), withMode(0o0777), withOwner("someone")), "LS-OWN-002", "/srv/e"),
	}

	reference := Attach(findings)

	permutation := rand.New(rand.NewSource(1))
	for round := 0; round < 50; round++ {
		permutation.Shuffle(len(findings), func(i, j int) {
			findings[i], findings[j] = findings[j], findings[i]
		})
		shuffled := Attach(findings)
		byID := map[string]int{}
		for _, assessment := range shuffled {
			byID[assessment.ID] = assessment.Risk.Score
		}
		for _, expected := range reference {
			if got := byID[expected.ID]; got != expected.Risk.Score {
				t.Fatalf("shuffling changed the score for %s from %d to %d",
					expected.RuleID, expected.Risk.Score, got)
			}
		}
	}
}

func TestRiskMetadataDoesNotAffectFindingIdentity(t *testing.T) {
	subject := finding()
	identityBefore := subject.ID

	assessed := Attach([]model.Finding{subject})[0]
	if assessed.ID != identityBefore {
		t.Errorf("identity changed from %s to %s when risk was attached", identityBefore, assessed.ID)
	}
	if got := model.FindingID(assessed.RuleID, assessed.Path); got != identityBefore {
		t.Errorf("identity is not reproducible from the rule and path: %s vs %s", got, identityBefore)
	}
	if assessed.Risk == nil {
		t.Fatal("no risk was attached, so the check would be vacuous")
	}
}

func TestSortOrdersByRiskWithTotalTieBreakers(t *testing.T) {
	high := finding(withSeverity(model.SeverityHigh), withMode(0o0666), withOwner("someone"))
	high.Path = "/z/high"
	high.ID = model.FindingID(high.RuleID, high.Path)

	lowA := finding(withMode(0o0644))
	lowA.Path = "/a/low"
	lowA.ID = model.FindingID(lowA.RuleID, lowA.Path)

	lowB := finding(withMode(0o0644))
	lowB.Path = "/b/low"
	lowB.ID = model.FindingID(lowB.RuleID, lowB.Path)

	sameScoreDifferentSeverity := finding(withSeverity(model.SeverityHigh))
	sameScoreDifferentSeverity.Path = "/c/other"
	sameScoreDifferentSeverity.ID = model.FindingID(sameScoreDifferentSeverity.RuleID,
		sameScoreDifferentSeverity.Path)

	findings := Attach([]model.Finding{lowB, high, lowA, sameScoreDifferentSeverity})
	Sort(findings)

	order := make([]string, len(findings))
	for i, subject := range findings {
		order[i] = subject.Path
	}
	want := []string{"/z/high", "/c/other", "/a/low", "/b/low"}
	for i := range want {
		if order[i] != want[i] {
			t.Fatalf("order = %v, want %v", order, want)
		}
	}
	for i := 1; i < len(findings); i++ {
		if findings[i-1].Risk.Score < findings[i].Risk.Score {
			t.Fatalf("findings are not ordered by descending risk: %v", order)
		}
	}
}

func TestSortIsAPermutation(t *testing.T) {
	findings := Attach([]model.Finding{
		distinct(finding(withMode(0o4755), withOwner("someone")), "LS-PRIV-001", "/srv/a"),
		distinct(finding(withSeverity(model.SeverityInfo), withMode(0o0777)), "LS-PERM-002", "/srv/b"),
		distinct(finding(withSeverity(model.SeverityCritical), withMode(0o0644), withOwner("root")), "LS-PERM-004", "/etc/shadow"),
		distinct(finding(withCategory(model.CategoryPersistence), withMode(0o0666)), "LS-PERS-001", "/etc/cron.d/x"),
	})
	before := map[string]int{}
	for _, subject := range findings {
		before[subject.ID] = subject.Risk.Score
	}

	Sort(findings)
	if len(findings) != len(before) {
		t.Fatalf("sorting changed the finding count from %d to %d", len(before), len(findings))
	}
	for _, subject := range findings {
		if want, ok := before[subject.ID]; !ok {
			t.Errorf("sorting introduced %s", subject.ID)
		} else if want != subject.Risk.Score {
			t.Errorf("sorting changed the score for %s", subject.ID)
		}
	}
}

func TestSortHandlesUnassessedFindings(t *testing.T) {
	findings := []model.Finding{
		{ID: "b", RuleID: "R", Path: "/b", Severity: model.SeverityLow},
		{ID: "a", RuleID: "R", Path: "/a", Severity: model.SeverityLow},
	}
	Sort(findings)
	if findings[0].ID != "a" {
		t.Errorf("unassessed findings were not ordered by their tie-breakers: %s first", findings[0].ID)
	}
}

func TestSummariseCountsEveryBandAndIgnoresUnscoredFindings(t *testing.T) {
	findings := Attach([]model.Finding{
		finding(withSeverity(model.SeverityCritical), withMode(0o0644), withOwner("root")),
		finding(withSeverity(model.SeverityInfo), withMode(0o0600), withOwner("root")),
		finding(withCategory(model.CategoryCorrelation)),
		{RuleID: "raw", Path: "/raw"},
	})

	counts := Summarise(findings)
	for _, band := range model.RiskBands() {
		if _, present := counts[string(band)]; !present {
			t.Errorf("band %q is missing from the summary", band)
		}
	}
	if counts[string(model.RiskBandCritical)] != 1 {
		t.Errorf("critical = %d, want 1", counts[string(model.RiskBandCritical)])
	}
	if counts[string(model.RiskBandInformational)] != 1 {
		t.Errorf("informational = %d, want 1", counts[string(model.RiskBandInformational)])
	}
	if got := counts[string(model.RiskBandHigh)]; got != 0 {
		t.Errorf("high = %d, want 0", got)
	}
}

func TestFactorCatalogueIsNamedAndOrdered(t *testing.T) {
	names := FactorNames()
	if len(names) != len(factors) {
		t.Fatalf("FactorNames returned %d names for %d factors", len(names), len(factors))
	}
	seen := map[string]bool{}
	for i, name := range names {
		if seen[name] {
			t.Errorf("factor %s appears twice in the catalogue", name)
		}
		seen[name] = true
		if factors[i].points <= 0 {
			t.Errorf("factor %s has non positive weight %d", name, factors[i].points)
		}
		if factors[i].reason == "" {
			t.Errorf("factor %s has no reason", name)
		}
		if factors[i].applies == nil {
			t.Errorf("factor %s has no application rule", name)
		}
	}
}

func TestFactorReasonsDoNotOverstate(t *testing.T) {
	forbidden := []string{"exploit", "attacker", "will be", "is vulnerable", "compromis"}
	for _, entry := range factors {
		lowered := strings.ToLower(entry.reason)
		for _, phrase := range forbidden {
			if strings.Contains(lowered, phrase) {
				t.Errorf("factor %s reason %q asserts %q", entry.name, entry.reason, phrase)
			}
		}
	}
}

func TestAssessmentSerialises(t *testing.T) {
	assessment := Score(finding(withMode(0o0666), withOwner("someone")))
	encoded, err := json.Marshal(assessment)
	if err != nil {
		t.Fatalf("Marshal: %v", err)
	}

	var decoded model.Risk
	if err := json.Unmarshal(encoded, &decoded); err != nil {
		t.Fatalf("Unmarshal: %v", err)
	}
	if decoded.Score != assessment.Score || decoded.Band != assessment.Band {
		t.Errorf("round trip lost the score: %+v", decoded)
	}
	if decoded.Severity != assessment.Severity {
		t.Errorf("round trip lost the original severity: %q", decoded.Severity)
	}
	if len(decoded.Factors) != len(assessment.Factors) {
		t.Errorf("round trip changed the factor count to %d", len(decoded.Factors))
	}
	if !strings.Contains(string(encoded), `"band":"`+string(assessment.Band)+`"`) {
		t.Errorf("encoded risk %s does not carry a readable band", encoded)
	}
}
