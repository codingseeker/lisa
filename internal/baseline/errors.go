package baseline

import "errors"

var (
	ErrExists = errors.New("baseline already exists")

	ErrNotFound = errors.New("baseline not found")

	ErrSchema = errors.New("baseline schema is not supported")

	ErrAmbiguousIdentity = errors.New("ambiguous baseline identity")

	ErrInvalidDocument = errors.New("baseline document is invalid")

	ErrUnsafePath = errors.New("baseline path is unusable")
)
