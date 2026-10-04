package attack

import (
	"strings"
	"testing"
)

func TestEmbeddedDatasetLoads(t *testing.T) {
	set := Dataset()
	if set.Len() == 0 {
		t.Fatal("the embedded mapping dataset is empty")
	}
	if set.Version() == "" {
		t.Error("the dataset does not record a version")
	}
	if Framework == "" || DatasetName == "" || Attribution == "" {
		t.Error("the dataset provenance constants are incomplete")
	}
}

func TestDefaultFailsClosedOnABrokenDataset(t *testing.T) {
	set, err := Parse("this is not a dataset\n")
	if err == nil {
		t.Fatal("Parse accepted a broken dataset")
	}
	if set != nil {
		t.Error("Parse returned a set alongside an error")
	}

	broken := &Set{}
	if broken.Len() != 0 {
		t.Error("an empty set reports mappings")
	}
	if _, ok := broken.Lookup("LS-COR-001"); ok {
		t.Error("an empty set resolves a lookup")
	}
	if len(broken.Mappings()) != 0 || len(broken.Techniques()) != 0 {
		t.Error("an empty set reports contents")
	}
}

func TestParseRejectsMalformedRecords(t *testing.T) {
	cases := []struct {
		name    string
		content string
		mustErr string
	}{
		{
			name:    "missing fields",
			content: "# dataset_version: v1\nLS-COR-001\tT1543.002\tName\n",
			mustErr: "expected 6 tab-separated fields",
		},
		{
			name:    "extra fields",
			content: "# dataset_version: v1\nLS-COR-001\tT1543.002\tName\tTactic\thttps://attack.mitre.org/techniques/T1543/002/\trelevance\textra\n",
			mustErr: "expected 6 tab-separated fields",
		},
		{
			name:    "no dataset version",
			content: "LS-COR-001\tT1543.002\tName\tTactic\thttps://attack.mitre.org/techniques/T1543/002/\trelevance\n",
			mustErr: "does not record a dataset_version",
		},
		{
			name:    "empty rule",
			content: "# dataset_version: v1\n\tT1543.002\tName\tTactic\thttps://attack.mitre.org/techniques/T1543/002/\trelevance\n",
			mustErr: "empty correlation rule",
		},
		{
			name:    "rule outside the correlation namespace",
			content: "# dataset_version: v1\nLS-PERM-001\tT1543.002\tName\tTactic\thttps://attack.mitre.org/techniques/T1543/002/\trelevance\n",
			mustErr: "is not an LS-COR-* correlation rule",
		},
		{
			name:    "invalid technique identifier",
			content: "# dataset_version: v1\nLS-COR-001\tNOTATECHNIQUE\tName\tTactic\thttps://attack.mitre.org/techniques/T1543/002/\trelevance\n",
			mustErr: "not a valid ATT&CK identifier",
		},
		{
			name:    "technique without a name",
			content: "# dataset_version: v1\nLS-COR-001\tT1543.002\t\tTactic\thttps://attack.mitre.org/techniques/T1543/002/\trelevance\n",
			mustErr: "requires a name",
		},
		{
			name:    "missing relevance",
			content: "# dataset_version: v1\nLS-COR-001\tT1543.002\tName\tTactic\thttps://attack.mitre.org/techniques/T1543/002/\t\n",
			mustErr: "no relevance explanation",
		},
		{
			name:    "missing reference",
			content: "# dataset_version: v1\nLS-COR-001\tT1543.002\tName\tTactic\t\trelevance\n",
			mustErr: "no technique reference",
		},
		{
			name:    "reference away from the framework documentation",
			content: "# dataset_version: v1\nLS-COR-001\tT1543.002\tName\tTactic\thttps://example.invalid/technique\trelevance\n",
			mustErr: "does not match technique T1543.002",
		},
		{
			name:    "reference to a different technique",
			content: "# dataset_version: v1\nLS-COR-001\tT1543.002\tName\tTactic\thttps://attack.mitre.org/techniques/T1548/001/\trelevance\n",
			mustErr: "does not match technique T1543.002",
		},
		{
			name:    "duplicate rule",
			content: "# dataset_version: v1\nLS-COR-001\tT1543.002\tName\tTactic\thttps://attack.mitre.org/techniques/T1543/002/\trelevance\nLS-COR-001\tT1548.001\tOther\tPrivilege Escalation\thttps://attack.mitre.org/techniques/T1548/001/\trelevance\n",
			mustErr: "duplicate mapping for LS-COR-001",
		},
		{
			name:    "no records at all",
			content: "# dataset_version: v1\n",
			mustErr: "no mappings",
		},
	}

	for _, testCase := range cases {
		t.Run(testCase.name, func(t *testing.T) {
			_, err := Parse(testCase.content)
			if err == nil {
				t.Fatalf("Parse accepted a dataset with %s", testCase.name)
			}
			if !strings.Contains(err.Error(), testCase.mustErr) {
				t.Errorf("Parse error = %q, want it to mention %q", err, testCase.mustErr)
			}
		})
	}
}

func TestParseRejectsAnOverlongRelevanceNote(t *testing.T) {
	content := "# dataset_version: v1\nLS-COR-001\tT1543.002\tName\tTactic\thttps://attack.mitre.org/techniques/T1543/002/\t" +
		strings.Repeat("x", 401) + "\n"
	if _, err := Parse(content); err == nil {
		t.Error("Parse accepted an overlong relevance note")
	}
}

func TestParseAcceptsAWellFormedDataset(t *testing.T) {
	content := "# dataset_version: test v1\n" +
		"LS-COR-002\tT1548.001\tSetuid and Setgid\tPrivilege Escalation\thttps://attack.mitre.org/techniques/T1548/001/\tBecause ownership controls the elevated identity.\n" +
		"LS-COR-001\tT1543.002\tSystemd Service\tPersistence\thttps://attack.mitre.org/techniques/T1543/002/\tBecause the host starts the unit.\n"

	set, err := Parse(content)
	if err != nil {
		t.Fatalf("Parse: %v", err)
	}
	if set.Version() != "test v1" {
		t.Errorf("Version() = %q, want %q", set.Version(), "test v1")
	}
	if set.Len() != 2 {
		t.Errorf("Len() = %d, want 2", set.Len())
	}

	mappings := set.Mappings()
	if mappings[0].CorrelationRule != "LS-COR-001" || mappings[1].CorrelationRule != "LS-COR-002" {
		t.Errorf("Mappings() is not sorted by rule: %s, %s",
			mappings[0].CorrelationRule, mappings[1].CorrelationRule)
	}

	mapping, ok := set.Lookup("LS-COR-002")
	if !ok {
		t.Fatal("Lookup did not find LS-COR-002")
	}
	if mapping.Technique.ID != "T1548.001" || mapping.Technique.Tactic != "Privilege Escalation" {
		t.Errorf("Lookup returned %+v", mapping.Technique)
	}
	if _, ok := set.Lookup("LS-COR-999"); ok {
		t.Error("Lookup invented a mapping for an unknown rule")
	}
	if _, ok := set.Lookup(""); ok {
		t.Error("Lookup resolved an empty rule")
	}
}

func TestEveryEmbeddedMappingIsDefensible(t *testing.T) {
	for _, mapping := range Dataset().Mappings() {
		t.Run(mapping.CorrelationRule, func(t *testing.T) {
			if err := mapping.Technique.Validate(); err != nil {
				t.Errorf("the technique is not valid: %v", err)
			}
			if mapping.Technique.Tactic == "" {
				t.Error("the mapping records no tactic")
			}
			if !strings.HasPrefix(mapping.Reference, techniqueReferencePrefix) {
				t.Errorf("reference %q is not framework documentation", mapping.Reference)
			}
			if mapping.Relevance == "" {
				t.Error("the mapping has no relevance note")
			}
			for _, forbidden := range []string{"was used", "was executed", "the attacker", "was compromised"} {
				if strings.Contains(strings.ToLower(mapping.Relevance), forbidden) {
					t.Errorf("the relevance note asserts adversary activity: %q", mapping.Relevance)
				}
			}
		})
	}
}

func TestDatasetStaysSmall(t *testing.T) {
	set := Dataset()
	if set.Len() > 32 {
		t.Errorf("the dataset holds %d mappings; it should stay small and reviewable", set.Len())
	}
	if len(set.Techniques()) == 0 {
		t.Error("the dataset references no techniques")
	}
}

func TestTechniquesAreSortedAndDistinct(t *testing.T) {
	techniques := Dataset().Techniques()
	for i := 1; i < len(techniques); i++ {
		if techniques[i-1].ID >= techniques[i].ID {
			t.Fatalf("techniques are not sorted by identifier: %s then %s",
				techniques[i-1].ID, techniques[i].ID)
		}
	}
}

func TestNilSetIsUsable(t *testing.T) {
	var set *Set
	if set.Len() != 0 || set.Version() != "" {
		t.Error("a nil set does not behave as empty")
	}
	if _, ok := set.Lookup("LS-COR-001"); ok {
		t.Error("a nil set resolved a lookup")
	}
	if set.Mappings() != nil || set.Techniques() != nil {
		t.Error("a nil set returned contents")
	}
}

func TestMappingRecordsCarryNoUnexpectedLinks(t *testing.T) {
	for _, mapping := range Dataset().Mappings() {
		if strings.Count(mapping.Relevance, "http") > 0 {
			t.Errorf("the relevance note for %s embeds a link: %q",
				mapping.CorrelationRule, mapping.Relevance)
		}

		want := techniqueReferencePrefix + strings.ReplaceAll(mapping.Technique.ID, ".", "/") + "/"
		if mapping.Reference != want {
			t.Errorf("the reference for %s is %q, want the page for %s: %q",
				mapping.CorrelationRule, mapping.Reference, mapping.Technique.ID, want)
		}
	}
}
