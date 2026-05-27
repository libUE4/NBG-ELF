package main

import (
	"encoding/json"
	"flag"
	"os"
	"path/filepath"
	"testing"

	"nbg-elf/internal/elfstr"
)

func TestResolveManifestOutputPath(t *testing.T) {
	dir := t.TempDir()
	manifestPath := filepath.Join(dir, "manifest.json")
	outputPath := filepath.Join(dir, "out.vmp")
	if err := os.WriteFile(outputPath, []byte("elf"), 0o644); err != nil {
		t.Fatalf("write output: %v", err)
	}
	if got := resolveManifestOutputPath(manifestPath, "out.vmp"); got != outputPath {
		t.Fatalf("relative output resolved to %q want %q", got, outputPath)
	}
	abs := filepath.Join(dir, "abs.vmp")
	if got := resolveManifestOutputPath(manifestPath, abs); got != abs {
		t.Fatalf("absolute output resolved to %q want %q", got, abs)
	}
	if got := resolveManifestOutputPath(manifestPath, "missing.vmp"); got != "missing.vmp" {
		t.Fatalf("missing output resolved to %q want original", got)
	}
}

func TestResolveManifestInputPath(t *testing.T) {
	dir := t.TempDir()
	manifestPath := filepath.Join(dir, "manifest.json")
	inputPath := filepath.Join(dir, "input.elf")
	if err := os.WriteFile(inputPath, []byte("elf"), 0o644); err != nil {
		t.Fatalf("write input: %v", err)
	}
	if got := resolveManifestInputPath(manifestPath, "input.elf"); got != inputPath {
		t.Fatalf("relative input resolved to %q want %q", got, inputPath)
	}
	abs := filepath.Join(dir, "abs.elf")
	if got := resolveManifestInputPath(manifestPath, abs); got != abs {
		t.Fatalf("absolute input resolved to %q want %q", got, abs)
	}
	if got := resolveManifestInputPath(manifestPath, "missing.elf"); got != "missing.elf" {
		t.Fatalf("missing input resolved to %q want original", got)
	}
}

func TestFlagWasSet(t *testing.T) {
	fs := flag.NewFlagSet("test", flag.ContinueOnError)
	_ = fs.Bool("lazy-callsite", false, "")
	if err := fs.Parse([]string{"-lazy-callsite"}); err != nil {
		t.Fatalf("parse flags: %v", err)
	}
	if !flagWasSet(fs, "lazy-callsite") {
		t.Fatalf("expected lazy-callsite to be marked set")
	}
	if flagWasSet(fs, "preset") {
		t.Fatalf("unexpected preset flag")
	}
}

func TestApplyEncryptFlagOverridesOnlyVisitsExplicitFlags(t *testing.T) {
	fs := flag.NewFlagSet("test", flag.ContinueOnError)
	limit := fs.Int("lazy-callsite-limit", 0, "")
	keepSections := fs.Bool("keep-sections", false, "")
	if err := fs.Parse([]string{"-lazy-callsite-limit", "5"}); err != nil {
		t.Fatalf("parse flags: %v", err)
	}
	opts := elfstr.Options{KeepSections: true}
	applyEncryptFlagOverrides(fs, &opts, map[string]func(){
		"lazy-callsite-limit": func() { opts.LazyCallsiteLimit = *limit },
		"keep-sections":       func() { opts.KeepSections = *keepSections },
	})
	if opts.LazyCallsiteLimit != 5 {
		t.Fatalf("lazy limit got %d want 5", opts.LazyCallsiteLimit)
	}
	if !opts.KeepSections {
		t.Fatalf("keep-sections should not be overridden by an implicit default")
	}
}

func TestValidateEncryptReportFlagsRejectsJSONWithoutReport(t *testing.T) {
	if err := validateEncryptReportFlags(false, true); err == nil {
		t.Fatalf("expected -json without -report to fail")
	}
	if err := validateEncryptReportFlags(true, true); err != nil {
		t.Fatalf("expected -report -json to pass: %v", err)
	}
	if err := validateEncryptReportFlags(false, false); err != nil {
		t.Fatalf("expected default flags to pass: %v", err)
	}
}

func TestWriteJSONFileCreatesParentAndWritesIndentedJSON(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "nested", "audit.json")
	audit := manifestAudit{
		Schema: "test",
		Summary: auditSummary{
			Grade: "hardened",
			Score: 88,
		},
		Checks: []auditCheck{{Name: "manifest_sha256", Status: "ok"}},
	}
	if err := writeJSONFile(path, audit, 0o644); err != nil {
		t.Fatalf("write json file: %v", err)
	}
	raw, err := os.ReadFile(path)
	if err != nil {
		t.Fatalf("read json file: %v", err)
	}
	var decoded map[string]any
	if err := json.Unmarshal(raw, &decoded); err != nil {
		t.Fatalf("unmarshal audit json: %v", err)
	}
	if _, ok := decoded["summary"]; !ok {
		t.Fatalf("audit json missing summary: %s", raw)
	}
	if _, ok := decoded["checks"]; !ok {
		t.Fatalf("audit json missing checks: %s", raw)
	}
	if raw[len(raw)-1] != '\n' {
		t.Fatalf("audit json should end with newline")
	}
}

func TestBuildManifestAuditReportsMissingOutputAsStructuredChecks(t *testing.T) {
	dir := t.TempDir()
	manifestPath := filepath.Join(dir, "out.manifest.json")
	m := &elfstr.Manifest{
		Schema:     elfstr.Schema,
		InputPath:  "input.elf",
		OutputPath: "missing.vmp",
		Report: elfstr.ProtectionReport{
			Preset: elfstr.PresetAggressive,
		},
		RuntimeStub: elfstr.RuntimeStubInfo{
			SHA256: "unexpected",
		},
		Protection: elfstr.ProtectionProfile{
			ControlFlow:  "test-cfg",
			CallsiteMode: "aarch64-lazy-decrypt-patch",
		},
	}
	audit := buildManifestAudit(manifestPath, m)
	if audit.Preset != elfstr.PresetAggressive || audit.ControlFlow != "test-cfg" {
		t.Fatalf("audit metadata = %+v", audit)
	}
	checks := map[string]auditCheck{}
	for _, check := range audit.Checks {
		checks[check.Name] = check
	}
	if checks["output_sha256"].Status != "unavailable" {
		t.Fatalf("output_sha256 check = %+v", checks["output_sha256"])
	}
	if checks["manifest_sha256"].Status != "unavailable" {
		t.Fatalf("manifest_sha256 check = %+v", checks["manifest_sha256"])
	}
	if checks["input_sha256"].Status != "unavailable" {
		t.Fatalf("input_sha256 check = %+v", checks["input_sha256"])
	}
	if checks["runtime_stub"].Status != "invalid" {
		t.Fatalf("runtime_stub check = %+v", checks["runtime_stub"])
	}
	if checks["runtime_payload"].Status != "skipped" {
		t.Fatalf("runtime_payload check = %+v", checks["runtime_payload"])
	}
	if checks["runtime_dispatch"].Status != "skipped" {
		t.Fatalf("runtime_dispatch check = %+v", checks["runtime_dispatch"])
	}
	if audit.Summary.Grade != "blocked" || len(audit.Summary.Blockers) == 0 {
		t.Fatalf("audit summary = %+v", audit.Summary)
	}
	raw, err := json.Marshal(audit)
	if err != nil {
		t.Fatalf("marshal audit: %v", err)
	}
	var decoded map[string]any
	if err := json.Unmarshal(raw, &decoded); err != nil {
		t.Fatalf("unmarshal audit: %v", err)
	}
	if _, ok := decoded["checks"]; !ok {
		t.Fatalf("audit json missing checks: %s", raw)
	}
	if _, ok := decoded["summary"]; !ok {
		t.Fatalf("audit json missing summary: %s", raw)
	}
	if _, ok := decoded["artifact"]; !ok {
		t.Fatalf("audit json missing artifact: %s", raw)
	}
	if _, ok := decoded["capabilities"]; !ok {
		t.Fatalf("audit json missing capabilities: %s", raw)
	}
}

func TestBuildManifestAuditValidatesInputSHA256(t *testing.T) {
	dir := t.TempDir()
	inputPath := filepath.Join(dir, "input.elf")
	if err := os.WriteFile(inputPath, []byte("source artifact"), 0o644); err != nil {
		t.Fatalf("write input: %v", err)
	}
	m := &elfstr.Manifest{
		Schema:      elfstr.Schema,
		InputPath:   inputPath,
		OutputPath:  "missing-output.vmp",
		InputSHA256: "wrong",
	}
	audit := buildManifestAudit(filepath.Join(dir, "out.manifest.json"), m)
	checks := map[string]auditCheck{}
	for _, check := range audit.Checks {
		checks[check.Name] = check
	}
	if checks["input_sha256"].Status != "mismatch" {
		t.Fatalf("input_sha256 mismatch check = %+v", checks["input_sha256"])
	}
	m.InputSHA256 = checks["input_sha256"].Detail
	audit = buildManifestAudit(filepath.Join(dir, "out.manifest.json"), m)
	checks = map[string]auditCheck{}
	for _, check := range audit.Checks {
		checks[check.Name] = check
	}
	if checks["input_sha256"].Status != "ok" {
		t.Fatalf("input_sha256 ok check = %+v", checks["input_sha256"])
	}
}

func TestBuildManifestAuditValidatesManifestSelfHash(t *testing.T) {
	dir := t.TempDir()
	manifestPath := filepath.Join(dir, "out.manifest.json")
	m := &elfstr.Manifest{
		Schema:     elfstr.Schema,
		InputPath:  "missing-input.elf",
		OutputPath: "missing-output.vmp",
	}
	sum, err := elfstr.ComputeManifestSHA256(m)
	if err != nil {
		t.Fatalf("compute manifest hash: %v", err)
	}
	m.ManifestSHA256 = sum
	audit := buildManifestAudit(manifestPath, m)
	checks := map[string]auditCheck{}
	for _, check := range audit.Checks {
		checks[check.Name] = check
	}
	if checks["manifest_sha256"].Status != "ok" {
		t.Fatalf("manifest_sha256 check = %+v", checks["manifest_sha256"])
	}
	m.OutputPath = "tampered.vmp"
	audit = buildManifestAudit(manifestPath, m)
	checks = map[string]auditCheck{}
	for _, check := range audit.Checks {
		checks[check.Name] = check
	}
	if checks["manifest_sha256"].Status != "invalid" {
		t.Fatalf("manifest_sha256 tamper check = %+v", checks["manifest_sha256"])
	}
}

func TestBuildAuditSummaryGradesCommercialReadyManifest(t *testing.T) {
	audit := manifestAudit{
		Checks: []auditCheck{
			{Name: "manifest_sha256", Status: "ok"},
			{Name: "runtime_stub", Status: "ok"},
			{Name: "input_sha256", Status: "ok"},
			{Name: "runtime_payload", Status: "ok"},
			{Name: "output_sha256", Status: "ok"},
			{Name: "output_structure", Status: "ok"},
			{Name: "plaintext_slots", Status: "ok"},
			{Name: "runtime_table", Status: "ok"},
			{Name: "runtime_dispatch", Status: "ok"},
		},
	}
	m := &elfstr.Manifest{
		EntryCount: 4,
		Report: elfstr.ProtectionReport{
			Preset: elfstr.PresetAggressive,
		},
		Protection: elfstr.ProtectionProfile{
			RuntimeSelfCheck:       true,
			ControlFlow:            "opaque-branches-per-entry-loop; runtime-state-dispatch; aarch64-callsite-lazy-decrypt",
			CallsiteMode:           "aarch64-lazy-decrypt-patch",
			CallsiteLazySelected:   2,
			CallsiteLazyCandidates: 2,
		},
	}
	summary := buildAuditSummary(audit, m)
	if summary.Grade != "commercial-ready" || summary.Score < 90 {
		t.Fatalf("summary = %+v", summary)
	}
	if len(summary.Blockers) != 0 {
		t.Fatalf("unexpected blockers: %+v", summary.Blockers)
	}
}

func TestAuditCapabilitiesReportsCommercialFeatures(t *testing.T) {
	m := &elfstr.Manifest{
		ManifestSHA256: "manifest",
		InputSHA256:    "input",
		RuntimeStub: elfstr.RuntimeStubInfo{
			SHA256: "runtime",
		},
		RuntimePayload: elfstr.RuntimePayloadInfo{
			SHA256: "payload",
		},
		Protection: elfstr.ProtectionProfile{
			RuntimeSelfCheck:       true,
			RuntimeTable:           "encrypted-per-entry-row-resealed",
			PlaintextAudit:         "protected-entry-residue-scan-before-write",
			AntiDebug:              "ptrace",
			AntiFrida:              "maps",
			Watermarked:            true,
			CallsiteMode:           "aarch64-lazy-decrypt-patch",
			CallsiteLazySelected:   1,
			CallsiteLazyCandidates: 1,
		},
	}
	got := auditCapabilities(m)
	if !got.RuntimeSelfCheck || !got.RuntimeTableAudit || !got.RuntimeDispatch || !got.RuntimePayload || !got.InputSealed || !got.PlaintextAudit || !got.SectionStripped || !got.AntiDebug || !got.AntiFrida || !got.ManifestSealed || !got.Watermarked {
		t.Fatalf("capabilities = %+v", got)
	}
	m.Options.KeepSections = true
	if auditCapabilities(m).SectionStripped {
		t.Fatalf("section_stripped should be false when keep_sections is set")
	}
}

func TestBuildAuditSummaryBlocksInvalidChecks(t *testing.T) {
	audit := manifestAudit{
		Checks: []auditCheck{
			{Name: "manifest_sha256", Status: "invalid"},
			{Name: "runtime_stub", Status: "ok"},
			{Name: "input_sha256", Status: "ok"},
			{Name: "runtime_payload", Status: "ok"},
			{Name: "output_sha256", Status: "ok"},
		},
	}
	m := &elfstr.Manifest{
		EntryCount: 1,
		Protection: elfstr.ProtectionProfile{
			RuntimeSelfCheck: true,
			ControlFlow:      "runtime-state-dispatch",
		},
	}
	summary := buildAuditSummary(audit, m)
	if summary.Grade != "blocked" || len(summary.Blockers) == 0 {
		t.Fatalf("summary = %+v", summary)
	}
}

func TestBuildAuditSummaryRequiresPatchedLazyCallsitesForCommercialReady(t *testing.T) {
	audit := manifestAudit{
		Checks: []auditCheck{
			{Name: "manifest_sha256", Status: "ok"},
			{Name: "runtime_stub", Status: "ok"},
			{Name: "input_sha256", Status: "ok"},
			{Name: "runtime_payload", Status: "ok"},
			{Name: "output_sha256", Status: "ok"},
			{Name: "output_structure", Status: "ok"},
			{Name: "plaintext_slots", Status: "ok"},
			{Name: "runtime_table", Status: "ok"},
		},
	}
	m := &elfstr.Manifest{
		EntryCount: 2,
		Report: elfstr.ProtectionReport{
			Preset: elfstr.PresetBalanced,
		},
		Protection: elfstr.ProtectionProfile{
			RuntimeSelfCheck: true,
			ControlFlow:      "opaque-branches-per-entry-loop; runtime-state-dispatch",
			CallsiteMode:     "aarch64-lazy-dry-run-no-patch",
		},
	}
	summary := buildAuditSummary(audit, m)
	if summary.Grade == "commercial-ready" {
		t.Fatalf("dry-run summary should not be commercial-ready: %+v", summary)
	}
}

func TestEnforceMinimumAuditGrade(t *testing.T) {
	audit := manifestAudit{Summary: auditSummary{Grade: "hardened"}}
	if err := enforceMinimumAuditGrade(audit, "review-needed"); err != nil {
		t.Fatalf("review-needed threshold should pass: %v", err)
	}
	if err := enforceMinimumAuditGrade(audit, "hardened"); err != nil {
		t.Fatalf("hardened threshold should pass: %v", err)
	}
	if err := enforceMinimumAuditGrade(audit, "commercial-ready"); err == nil {
		t.Fatalf("commercial-ready threshold should fail for hardened audit")
	}
	if err := enforceMinimumAuditGrade(audit, "unknown"); err == nil {
		t.Fatalf("unknown threshold should fail")
	}
	if err := enforceMinimumAuditGrade(manifestAudit{Summary: auditSummary{Grade: "unknown"}}, "hardened"); err == nil {
		t.Fatalf("unknown audit grade should fail")
	}
}

func TestEnforceMinimumAuditGradeErrorMentionsActualAndRequiredGrade(t *testing.T) {
	err := enforceMinimumAuditGrade(manifestAudit{Summary: auditSummary{Grade: "hardened"}}, "commercial-ready")
	if err == nil {
		t.Fatalf("expected grade gate failure")
	}
	if got := err.Error(); got != "manifest audit grade hardened is below required commercial-ready" {
		t.Fatalf("unexpected error %q", got)
	}
}

func TestAuditGradeRankOrdering(t *testing.T) {
	if !(auditGradeRank("blocked") < auditGradeRank("review-needed") &&
		auditGradeRank("review-needed") < auditGradeRank("hardened") &&
		auditGradeRank("hardened") < auditGradeRank("commercial-ready")) {
		t.Fatalf("unexpected grade order")
	}
}

func TestProtectionReportJSONFieldNames(t *testing.T) {
	report := elfstr.ProtectionReport{
		Preset:             elfstr.PresetBalanced,
		ControlFlowLevel:   2,
		FailurePolicy:      "safe-exit",
		Strings:            3,
		Bytes:              42,
		CallsiteCandidates: 5,
		CallsiteSelected:   2,
		CallsiteSkipped:    3,
		CallsiteMode:       "aarch64-lazy-dry-run-no-patch",
	}
	raw, err := json.Marshal(report)
	if err != nil {
		t.Fatalf("marshal report: %v", err)
	}
	var decoded map[string]any
	if err := json.Unmarshal(raw, &decoded); err != nil {
		t.Fatalf("unmarshal report: %v", err)
	}
	for _, key := range []string{"preset", "control_flow_level", "failure_policy", "strings", "bytes", "callsite_candidates", "callsite_selected", "callsite_skipped", "callsite_mode"} {
		if _, ok := decoded[key]; !ok {
			t.Fatalf("report json missing %s: %s", key, raw)
		}
	}
}
