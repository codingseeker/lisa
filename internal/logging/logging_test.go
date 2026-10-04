package logging

import (
	"bytes"
	"strings"
	"testing"
)

func TestLevelFor(t *testing.T) {
	if got := LevelFor(false, false); got != LevelNormal {
		t.Errorf("LevelFor(false,false) = %v, want LevelNormal", got)
	}
	if got := LevelFor(true, false); got != LevelVerbose {
		t.Errorf("LevelFor(true,false) = %v, want LevelVerbose", got)
	}
	if got := LevelFor(false, true); got != LevelQuiet {
		t.Errorf("LevelFor(false,true) = %v, want LevelQuiet", got)
	}
	if got := LevelFor(true, true); got != LevelQuiet {
		t.Errorf("LevelFor(true,true) = %v, want LevelQuiet (quiet must win)", got)
	}
}

func TestQuietSuppressesDebugAndWarn(t *testing.T) {
	var buffer bytes.Buffer
	log := New(&buffer, LevelQuiet)
	log.Debug("debug message")
	log.Warn("warn message")
	if buffer.Len() != 0 {
		t.Errorf("quiet logger wrote %q, want nothing", buffer.String())
	}
}

func TestNormalSuppressesDebug(t *testing.T) {
	var buffer bytes.Buffer
	log := New(&buffer, LevelNormal)
	log.Debug("debug message")
	if buffer.Len() != 0 {
		t.Errorf("normal logger wrote %q for a debug record, want nothing", buffer.String())
	}
	log.Warn("warn message")
	if !strings.Contains(buffer.String(), "warn message") {
		t.Errorf("normal logger dropped a warning, got %q", buffer.String())
	}
}

func TestVerboseEmitsDebug(t *testing.T) {
	var buffer bytes.Buffer
	log := New(&buffer, LevelVerbose)
	log.Debug("target", "path", "/home")
	if !strings.Contains(buffer.String(), "target") {
		t.Errorf("verbose logger dropped a debug record, got %q", buffer.String())
	}
	if !strings.Contains(buffer.String(), "/home") {
		t.Errorf("verbose logger dropped attributes, got %q", buffer.String())
	}
}

func TestNewWritesOnlyToSuppliedWriter(t *testing.T) {
	var sink bytes.Buffer
	log := New(&sink, LevelVerbose)
	log.Error("boom")
	if !strings.Contains(sink.String(), "boom") {
		t.Errorf("logger did not write to the supplied writer, got %q", sink.String())
	}
}

func TestSlogLevelMapping(t *testing.T) {
	cases := map[Level]string{
		LevelQuiet:   "ERROR",
		LevelNormal:  "WARN",
		LevelVerbose: "DEBUG",
	}
	for level, expected := range cases {
		if got := level.slogLevel().String(); got != expected {
			t.Errorf("Level(%d).slogLevel() = %q, want %q", int(level), got, expected)
		}
	}
}
