package detectors

import (
	"fmt"

	"lisa/internal/model"
)

type suidDetector struct{}

func (suidDetector) Name() string { return "suid" }

func (suidDetector) Detect(ctx Context) []model.Finding {
	if !ctx.Entry.IsRegular() {
		return nil
	}

	reference := gtfoReference{}
	if ctx.GTFOBins {
		reference = newGtfoReference()
	}

	bits := ctx.Entry.PermissionBits()
	setuid := isSetuid(bits)
	setgid := isSetgid(bits)
	if !setuid && !setgid {
		return nil
	}

	var findings []model.Finding

	enrich := func(finding model.Finding) model.Finding {
		if !ctx.GTFOBins || finding.HasReference() {
			return finding
		}
		match, ok := reference.lookup(ctx.Entry.Path)
		if !ok {
			return finding
		}
		return finding.
			WithReference(&match).
			WithEvidence(reference.evidence(match, bits)...)
	}

	if setuid {
		rule := ruleSetuidBinary
		if !isSystemBinaryDirectory(ctx.Entry.Path) {
			rule = ruleSetuidOutsideSystemDirectories
		}
		findings = append(findings, enrich(ctx.base(rule).
			WithDescription(fmt.Sprintf("File %s carries the SUID bit (mode %04o). It runs with the privileges of its owner.", ctx.Entry.Path, bits)).
			WithEvidence(
				fmt.Sprintf("mode=%04o", bits),
				"setuid=yes",
				"privilege is inherited from the file owner at exec time",
			)))
	}

	if setgid {
		findings = append(findings, enrich(ctx.base(ruleSetgidBinary).
			WithDescription(fmt.Sprintf("File %s carries the SGID bit (mode %04o). It runs with the privileges of its group.", ctx.Entry.Path, bits)).
			WithEvidence(
				fmt.Sprintf("mode=%04o", bits),
				"setgid=yes",
				"privilege is inherited from the file group at exec time",
			)))
	}

	return findings
}
