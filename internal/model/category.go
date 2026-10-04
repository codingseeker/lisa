package model

type Category string

const (
	CategoryPermissions     Category = "permissions"
	CategoryOwnership       Category = "ownership"
	CategorySensitiveConfig Category = "sensitive-config"
	CategoryPersistence     Category = "persistence"
	CategoryIndicator       Category = "indicator"
	CategoryBaseline        Category = "baseline"
	CategoryCorrelation     Category = "correlation"
)

func Categories() []Category {
	return []Category{
		CategoryPermissions,
		CategoryOwnership,
		CategorySensitiveConfig,
		CategoryPersistence,
		CategoryIndicator,
		CategoryBaseline,
		CategoryCorrelation,
	}
}

func (c Category) IsValid() bool {
	for _, known := range Categories() {
		if c == known {
			return true
		}
	}
	return false
}
