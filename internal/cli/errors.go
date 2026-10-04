package cli

import (
	"errors"
	"fmt"
)

const (
	ExitOK          = 0
	ExitFindings    = 1
	ExitUsage       = 2
	ExitOperational = 3
)

type Error struct {
	Code    int
	Message string
	Usage   string
	Err     error
}

func (e *Error) Error() string {
	if e.Err != nil {
		return fmt.Sprintf("%s: %v", e.Message, e.Err)
	}
	return e.Message
}

func (e *Error) Unwrap() error {
	return e.Err
}

func usageErrorf(format string, args ...any) *Error {
	return &Error{Code: ExitUsage, Message: fmt.Sprintf(format, args...)}
}

func usageErrorWithUsagef(usage, format string, args ...any) *Error {
	return &Error{Code: ExitUsage, Message: fmt.Sprintf(format, args...), Usage: usage}
}

func operationalErrorf(format string, args ...any) *Error {
	return &Error{Code: ExitOperational, Message: fmt.Sprintf(format, args...)}
}

func ExitCodeFor(err error) int {
	if err == nil {
		return ExitOK
	}
	var coded *Error
	if errors.As(err, &coded) {
		return coded.Code
	}
	var findings *FindingsError
	if errors.As(err, &findings) {
		return ExitFindings
	}
	return ExitOperational
}
