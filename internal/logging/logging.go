package logging

import (
	"io"
	"log/slog"
)

type Level int

const (
	LevelQuiet Level = iota
	LevelNormal
	LevelVerbose
)

func LevelFor(verbose, quiet bool) Level {
	switch {
	case quiet:
		return LevelQuiet
	case verbose:
		return LevelVerbose
	default:
		return LevelNormal
	}
}

func (l Level) slogLevel() slog.Level {
	switch l {
	case LevelQuiet:
		return slog.LevelError
	case LevelVerbose:
		return slog.LevelDebug
	default:
		return slog.LevelWarn
	}
}

func New(w io.Writer, level Level) *slog.Logger {
	return slog.New(slog.NewTextHandler(w, &slog.HandlerOptions{Level: level.slogLevel()}))
}
