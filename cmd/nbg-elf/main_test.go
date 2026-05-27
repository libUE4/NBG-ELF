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
	if checks["runtime_dispatch"].Status != "skipped" {
		t.Fatalf("runtime_dispatch check = %+v", checks["runtime_dispatch"])
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
