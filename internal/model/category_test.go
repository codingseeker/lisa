package model

import "testing"

func TestCategoryIsValid(t *testing.T) {
	for _, category := range Categories() {
		if !category.IsValid() {
			t.Errorf("category %q reported as invalid", category)
		}
	}
	for _, category := range []Category{"", "unknown", "Permissions", "filesystem"} {
		if category.IsValid() {
			t.Errorf("category %q reported as valid", category)
		}
	}
}

func TestCategoriesCoverDetectorVocabulary(t *testing.T) {
	want := map[Category]bool{
		CategoryPermissions:     false,
		CategoryOwnership:       false,
		CategorySensitiveConfig: false,
		CategoryPersistence:     false,
		CategoryIndicator:       false,
		CategoryBaseline:        false,
		CategoryCorrelation:     false,
	}
	for _, category := range Categories() {
		if _, tracked := want[category]; !tracked {
			t.Errorf("unexpected category %q in Categories()", category)
			continue
		}
		want[category] = true
	}
	for category, seen := range want {
		if !seen {
			t.Errorf("category %q missing from Categories()", category)
		}
	}
}
