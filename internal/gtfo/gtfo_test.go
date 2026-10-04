package gtfo

import (
	"sort"
	"strings"
	"testing"
)

func TestEmbeddedDatasetParses(t *testing.T) {
	set := Default()
	if set.Len() == 0 {
		t.Fatal("the embedded dataset produced no entries")
	}
	if set.Len() < 40 {
		t.Errorf("dataset holds %d entries, expected the curated set", set.Len())
	}
	if len(set.byName) != set.Len() {
		t.Errorf("map holds %d entries, slice holds %d", len(set.byName), set.Len())
	}
}

func TestEmbeddedDatasetHasRequiredFields(t *testing.T) {
	for _, entry := range Default().Entries() {
		if entry.Binary == "" {
			t.Error("entry with empty binary name")
		}
		if entry.Category == "" {
			t.Errorf("%s has no category", entry.Binary)
		}
		if entry.Summary == "" {
			t.Errorf("%s has no summary", entry.Binary)
		}
		if len(entry.Summary) > 240 {
			t.Errorf("%s has an over-long summary", entry.Binary)
		}
		if strings.ContainsAny(entry.Binary, "/\\ \t") {
			t.Errorf("%s contains a path separator or whitespace", entry.Binary)
		}
		if strings.ToLower(entry.Binary) != entry.Binary {
			t.Errorf("%s is not lower case", entry.Binary)
		}
	}
}

func TestEmbeddedDatasetIsDeterministicAndSorted(t *testing.T) {
	first := Default().Entries()
	second := Default().Entries()

	if len(first) != len(second) {
		t.Fatalf("dataset sizes differ: %d then %d", len(first), len(second))
	}
	for i := range first {
		if first[i] != second[i] {
			t.Fatalf("entry %d differs between loads", i)
		}
	}
	if !sort.SliceIsSorted(first, func(i, j int) bool { return first[i].Binary < first[j].Binary }) {
		t.Error("entries are not sorted by binary name")
	}
}

func TestEmbeddedDatasetProvenanceIsDocumented(t *testing.T) {
	if !strings.Contains(Attribution, "GTFOBins") {
		t.Error("attribution does not name the source project")
	}
	if !strings.Contains(Attribution, "MIT") {
		t.Error("attribution does not state the upstream licence")
	}
	if SourceName == "" {
		t.Error("SourceName is empty")
	}
}

func TestEmbeddedDatasetCategoriesAreKnown(t *testing.T) {
	allowed := map[string]struct{}{
		"shell": {}, "interpreter": {}, "editor": {}, "archive": {},
		"filesystem": {}, "network": {}, "system": {},
	}
	for _, category := range Default().Categories() {
		if _, ok := allowed[category]; !ok {
			t.Errorf("unexpected category %q", category)
		}
	}
}

func TestLookupKnownBinaries(t *testing.T) {
	cases := []struct {
		path string
		want string
	}{
		{"/usr/bin/find", "find"},
		{"/bin/find", "find"},
		{"/usr/bin/sudo", "sudo"},
		{"/usr/bin/passwd", "passwd"},
		{"/usr/bin/wget", "wget"},
		{"/usr/bin/env", "env"},
		{"/usr/bin/vim", "vim"},
		{"/usr/bin/tar", "tar"},
		{"/usr/bin/nc", "nc"},
		{"/usr/bin/systemctl", "systemctl"},
		{"/usr/bin/dd", "dd"},
	}
	for _, testCase := range cases {
		entry, ok := Default().Lookup(testCase.path)
		if !ok {
			t.Errorf("Lookup(%q) found no entry", testCase.path)
			continue
		}
		if entry.Binary != testCase.want {
			t.Errorf("Lookup(%q) = %q, want %q", testCase.path, entry.Binary, testCase.want)
		}
		if entry.Summary == "" || entry.Category == "" {
			t.Errorf("Lookup(%q) returned an incomplete entry: %+v", testCase.path, entry)
		}
	}
}

func TestLookupUnknownBinaries(t *testing.T) {
	for _, path := range []string{
		"/usr/bin/ordinary-binary", "/opt/app/our-service", "/usr/lib/systemd/systemd",
		"totally-made-up", "/usr/bin/", "bashful", "/opt/vendor/compile",
	} {
		if _, ok := Default().Lookup(path); ok {
			t.Errorf("Lookup(%q) unexpectedly matched", path)
		}
	}
}

func TestLookupRejectsSubstringAndPrefixMatches(t *testing.T) {
	for _, path := range []string{
		"/usr/bin/findutils", "/usr/bin/findx", "/usr/bin/xfind", "/usr/bin/ind",
		"/usr/bin/notbash", "/usr/bin/bashrc", "/usr/bin/envsubst",
		"/usr/bin/vimdiff", "/usr/bin/tarball", "/usr/bin/gpasswd2",
	} {
		if entry, ok := Default().Lookup(path); ok {
			t.Errorf("Lookup(%q) matched %q; only exact base names may match", path, entry.Binary)
		}
	}
}

func TestLookupHandlesEmptyAndMalformedPaths(t *testing.T) {
	for _, path := range []string{"", "   ", "/", ".", "..", "./", "////"} {
		if entry, ok := Default().Lookup(path); ok {
			t.Errorf("Lookup(%q) matched %q", path, entry.Binary)
		}
	}
}

func TestLookupIsCaseSensitive(t *testing.T) {
	if _, ok := Default().Lookup("/usr/bin/BASH"); ok {
		t.Error("upper-case name matched; the documented policy is exact case-sensitive matching")
	}
	if _, ok := Default().Lookup("/usr/bin/Bash"); ok {
		t.Error("mixed-case name matched; the documented policy is exact case-sensitive matching")
	}
	if _, ok := Default().Lookup("/usr/bin/bash"); !ok {
		t.Error("lower-case name failed to match")
	}
}

func TestLookupTrimsSurroundingWhitespace(t *testing.T) {
	if _, ok := Default().Lookup("  /usr/bin/find  "); !ok {
		t.Error("a path with surrounding whitespace failed to match")
	}
}

func TestLookupIsDeterministic(t *testing.T) {
	set := Default()
	first, okFirst := set.Lookup("/usr/bin/find")
	for i := 0; i < 100; i++ {
		entry, ok := set.Lookup("/usr/bin/find")
		if ok != okFirst || entry != first {
			t.Fatal("Lookup returned inconsistent results")
		}
	}
}

func TestNilSetIsSafe(t *testing.T) {
	var set *Set
	if _, ok := set.Lookup("/usr/bin/find"); ok {
		t.Error("a nil set matched")
	}
	if set.Len() != 0 {
		t.Error("a nil set reported entries")
	}
	if set.Entries() != nil {
		t.Error("a nil set returned entries")
	}
	if set.Categories() != nil {
		t.Error("a nil set returned categories")
	}
}

func TestParseAcceptsAValidDataset(t *testing.T) {
	set, err := Parse("sh\tshell\tA shell.\nfind\tfilesystem\tA walker.\n")
	if err != nil {
		t.Fatalf("Parse returned error: %v", err)
	}
	if set.Len() != 2 {
		t.Errorf("Len = %d, want 2", set.Len())
	}
	if entry, ok := set.Lookup("find"); !ok || entry.Category != "filesystem" {
		t.Errorf("lookup failed: %+v ok=%v", entry, ok)
	}
}

func TestParseSortsRegardlessOfInputOrder(t *testing.T) {
	first, err := Parse("sh\tshell\tS\nfind\tfilesystem\tF\nnc\tnetwork\tN\n")
	if err != nil {
		t.Fatalf("Parse failed: %v", err)
	}
	second, err := Parse("nc\tnetwork\tN\nsh\tshell\tS\nfind\tfilesystem\tF\n")
	if err != nil {
		t.Fatalf("Parse failed: %v", err)
	}
	for i := range first.Entries() {
		if first.Entries()[i] != second.Entries()[i] {
			t.Fatalf("entry %d differs by input order", i)
		}
	}
}

func TestParseIgnoresCommentsAndBlankLines(t *testing.T) {
	set, err := Parse("# a comment\n\n   \nsh\tshell\tS\n\n# trailing comment\n")
	if err != nil {
		t.Fatalf("Parse failed: %v", err)
	}
	if set.Len() != 1 {
		t.Errorf("Len = %d, want 1", set.Len())
	}
}

func TestParseRejectsMalformedData(t *testing.T) {
	cases := map[string]string{
		"too few fields":      "sh\tshell\n",
		"too many fields":     "sh\tshell\tS\textra\n",
		"empty name":          "\tshell\tS\n",
		"blank name":          " \tshell\tS\n",
		"empty category":      "sh\t\tS\n",
		"empty summary":       "sh\tshell\t\n",
		"whitespace summary":  "sh\tshell\t   \n",
		"name with separator": "/bin/sh\tshell\tS\n",
		"name with space":     "my sh\tshell\tS\n",
		"upper case name":     "SH\tshell\tS\n",
		"over-long summary":   "sh\tshell\t" + strings.Repeat("x", 241) + "\n",
		"duplicate name":      "sh\tshell\tS\nsh\tshell\tS again\n",
		"empty dataset":       "# only comments\n",
		"completely empty":    "",
	}
	for name, content := range cases {
		t.Run(name, func(t *testing.T) {
			if _, err := Parse(content); err == nil {
				t.Error("Parse accepted malformed data, want error")
			}
		})
	}
}

func TestParseRejectsMaximalSummary(t *testing.T) {
	summary := strings.Repeat("x", 240)
	if _, err := Parse("sh\tshell\t" + summary + "\n"); err != nil {
		t.Errorf("Parse rejected a 240 character summary: %v", err)
	}
}

func TestParseErrorNamesTheLine(t *testing.T) {
	_, err := Parse("sh\tshell\tS\nbroken line\n")
	if err == nil {
		t.Fatal("Parse accepted malformed data")
	}
	if !strings.Contains(err.Error(), "line 2") {
		t.Errorf("error %q should name the offending line", err)
	}
}

func TestDefaultFailsClosedOnABrokenDataset(t *testing.T) {
	broken, err := Parse("this is not a dataset")
	if err == nil {
		t.Fatal("Parse accepted malformed data")
	}
	if broken != nil {
		t.Error("Parse returned a set alongside an error")
	}
	if Default().Len() == 0 {
		t.Skip("the embedded dataset is unavailable in this build")
	}
}

func TestEntriesReturnsACopy(t *testing.T) {
	set := Default()
	entries := set.Entries()
	entries[0] = Entry{Binary: "tampered"}

	if set.Entries()[0].Binary == "tampered" {
		t.Error("mutating the returned slice changed the set")
	}
}

func TestCategoriesAreDeterministic(t *testing.T) {
	first := Default().Categories()
	for i := 0; i < 10; i++ {
		next := Default().Categories()
		if len(next) != len(first) {
			t.Fatalf("category count differs: %d then %d", len(first), len(next))
		}
		for j := range next {
			if next[j] != first[j] {
				t.Fatalf("category %d differs between calls", j)
			}
		}
	}
}
