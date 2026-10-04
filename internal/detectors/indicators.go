package detectors

import (
	"bytes"
	"fmt"
	"path"
	"strings"

	"lisa/internal/model"
)

const headerReadBytes = 256

var elfMagic = []byte{0x7f, 'E', 'L', 'F'}

type temporaryExecutableDetector struct{}

func (temporaryExecutableDetector) Name() string { return "temp-executables" }

func (temporaryExecutableDetector) Detect(ctx Context) []model.Finding {
	if !ctx.Entry.IsRegular() || !inTemporaryDirectory(ctx.Entry.Path) {
		return nil
	}
	bits := ctx.Entry.PermissionBits()
	if !isExecutableMode(bits) {
		return nil
	}

	return []model.Finding{ctx.base(ruleTemporaryExecutable).
		WithDescription(fmt.Sprintf("Executable file %s resides in a temporary directory (mode %04o). Temporary directories are writable by other local users and are commonly used to stage payloads.", ctx.Entry.Path, bits)).
		WithEvidence(
			fmt.Sprintf("mode=%04o", bits),
			fmt.Sprintf("size=%d", ctx.Entry.Size()),
			"located in a world-writable temporary directory",
		)}
}

type masqueradeDetector struct{}

func (masqueradeDetector) Name() string { return "masquerade" }

func (masqueradeDetector) Detect(ctx Context) []model.Finding {
	if !ctx.Entry.IsRegular() {
		return nil
	}

	extension := extensionOf(path.Base(ctx.Entry.Path))
	_, document := documentExtensions[extension]
	_, image := imageExtensions[extension]
	_, text := textExtensions[extension]

	userFolder := inUserSensitiveDirectory(ctx.Entry.Path)

	if !document && !image && !text && !(userFolder && extension == "") {
		return nil
	}
	if !ctx.allowHeaderRead() {
		return nil
	}

	header, err := ctx.ReadFile.Read(ctx.Entry.Path, headerReadBytes)
	if err != nil || len(header) == 0 {
		return nil
	}

	kind := executableKind(header)
	if kind == "" {
		return nil
	}

	switch {
	case document || image:
		return []model.Finding{ctx.base(ruleMasqueradeDocumentOrImage).
			WithDescription(fmt.Sprintf("%s is a %s but carries the %s extension, so a file manager or an upload filter sees a document while the content is executable.", ctx.Entry.Path, kind, extension)).
			WithEvidence(
				fmt.Sprintf("extension=%s", extension),
				fmt.Sprintf("content=%s", kind),
				fmt.Sprintf("mode=%04o", ctx.Entry.PermissionBits()),
			)}
	case text:
		return []model.Finding{ctx.base(ruleMasqueradeText).
			WithDescription(fmt.Sprintf("%s is a %s but carries the %s extension.", ctx.Entry.Path, kind, extension)).
			WithEvidence(
				fmt.Sprintf("extension=%s", extension),
				fmt.Sprintf("content=%s", kind),
			)}
	case userFolder && strings.HasPrefix(kind, "an interpreted"):
		return []model.Finding{ctx.base(ruleScriptInUserFolder).
			WithDescription(fmt.Sprintf("%s is %s with no script extension in a user downloads folder, where an executable is unexpected.", ctx.Entry.Path, kind)).
			WithEvidence(
				"extension=none",
				fmt.Sprintf("content=%s", kind),
				"directory element matches a user download location",
			)}
	case userFolder:
		return []model.Finding{ctx.base(ruleExecutableInUserFolder).
			WithDescription(fmt.Sprintf("%s is %s stored without an extension in a user downloads folder.", ctx.Entry.Path, kind)).
			WithEvidence(
				"extension=none",
				fmt.Sprintf("content=%s", kind),
				"directory element matches a user download location",
			)}
	}

	return nil
}

func executableKind(header []byte) string {
	switch {
	case bytes.HasPrefix(header, elfMagic):
		return "an ELF binary"
	case bytes.HasPrefix(header, []byte("#!")):
		return "an interpreted script"
	default:
		return ""
	}
}
