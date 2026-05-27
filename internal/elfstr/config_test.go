package elfstr

import (
	"encoding/binary"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

func TestLoadProtectionConfigPresetDefaults(t *testing.T) {
	cfg, err := LoadProtectionConfig("", PresetAggressive)
	if err != nil {
		t.Fatalf("load aggressive preset: %v", err)
	}
	if cfg.Preset != PresetAggressive || !cfg.LazyCallsite || cfg.LazyCallsiteLimit != 128 {
		t.Fatalf("aggressive config = %+v", cfg)
	}
	if cfg.ControlFlowLevel != 3 || cfg.FailurePolicy != "safe-exit" {
		t.Fatalf("aggressive protection policy = %+v", cfg)
	}
}

func TestLoadProtectionConfigJSONOverridesPreset(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "protection.json")
	raw := []byte(`{
		"preset": "safe",
		"control_flow_level": 2,
		"lazy_callsite": true,
		"lazy_callsite_limit": 7,
		"safe_scan": false
	}`)
	if err := os.WriteFile(path, raw, 0o644); err != nil {
		t.Fatalf("write config: %v", err)
	}
	cfg, err := LoadProtectionConfig(path, "")
	if err != nil {
		t.Fatalf("load config: %v", err)
	}
	if cfg.Preset != PresetSafe || cfg.ControlFlowLevel != 2 || !cfg.LazyCallsite || cfg.LazyCallsiteLimit != 7 || cfg.SafeScan {
		t.Fatalf("merged config = %+v", cfg)
	}
}

func TestLoadProtectionConfigExplicitPresetWinsOverJSONPreset(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "protection.json")
	if err := os.WriteFile(path, []byte(`{"preset":"safe","lazy_callsite_limit":9}`), 0o644); err != nil {
		t.Fatalf("write config: %v", err)
	}
	cfg, err := LoadProtectionConfig(path, PresetAggressive)
	if err != nil {
		t.Fatalf("load config: %v", err)
	}
	if cfg.Preset != PresetAggressive || cfg.ControlFlowLevel != 3 || !cfg.LazyCallsite || cfg.LazyCallsiteLimit != 9 {
		t.Fatalf("merged config = %+v", cfg)
	}
}

func TestLoadProtectionConfigRejectsInvalidValues(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "bad.json")
	if err := os.WriteFile(path, []byte(`{"control_flow_level": 9}`), 0o644); err != nil {
		t.Fatalf("write config: %v", err)
	}
	_, err := LoadProtectionConfig(path, PresetBalanced)
	if err == nil || !strings.Contains(err.Error(), "control_flow_level") {
		t.Fatalf("expected control_flow_level error, got %v", err)
	}
}

func TestProtectionConfigApplyToOptions(t *testing.T) {
	cfg := ProtectionConfig{
		Preset:            PresetAggressive,
		ControlFlowLevel:  3,
		LazyCallsite:      true,
		LazyCallsiteLimit: 12,
		FailurePolicy:     "safe-exit",
		NoAntiFridaExtra:  true,
	}
	var opts Options
	cfg.ApplyToOptions(&opts)
	if opts.Preset != PresetAggressive || opts.ControlFlowLevel != 3 || !opts.LazyCallsite || opts.LazyCallsiteLimit != 12 || !opts.NoAntiFridaExtra {
		t.Fatalf("options = %+v", opts)
	}
}

func TestProtectionWarningsIncludeSkippedCallsites(t *testing.T) {
	warnings := protectionWarnings(Options{LazyCallsiteLimit: 2}, 5, 2)
	if len(warnings) != 1 || !strings.Contains(warnings[0], "上限") {
		t.Fatalf("warnings = %#v", warnings)
	}
}

func TestPlanProtectionFallbackDoesNotReportLazyPatchWithoutCandidates(t *testing.T) {
	raw := syntheticPlanELF([]byte("protected fixture string\x00"))
	report, err := PlanProtectionBytes(raw, Options{LazyCallsite: true, LazyCallsiteLimit: 8})
	if err != nil {
		t.Fatalf("plan protection: %v", err)
	}
	if report.CallsiteMode != callsiteModeAArch64ScanOnly {
		t.Fatalf("callsite mode got %q want %q", report.CallsiteMode, callsiteModeAArch64ScanOnly)
	}
	if report.CallsiteSelected != 0 {
		t.Fatalf("selected got %d want 0", report.CallsiteSelected)
	}
	if len(report.Warnings) == 0 {
		t.Fatalf("expected warning for lazy request without candidates")
	}
}

func syntheticPlanELF(rodataContent []byte) []byte {
	shstrtab := []byte("\x00.shstrtab\x00.rodata\x00")
	ehdr := make([]byte, 64)
	ehdr[0] = 0x7f
	ehdr[1], ehdr[2], ehdr[3], ehdr[4], ehdr[5], ehdr[6] = 'E', 'L', 'F', 2, 1, 1
	binary.LittleEndian.PutUint16(ehdr[0x10:], 3)
	binary.LittleEndian.PutUint16(ehdr[0x12:], 183)
	binary.LittleEndian.PutUint32(ehdr[0x14:], 1)
	binary.LittleEndian.PutUint64(ehdr[0x20:], 0x40)
	binary.LittleEndian.PutUint16(ehdr[0x36:], 56)
	binary.LittleEndian.PutUint16(ehdr[0x38:], 1)
	phdr := make([]byte, 56)
	binary.LittleEndian.PutUint32(phdr[0:], ptLoad)
	binary.LittleEndian.PutUint32(phdr[4:], pfR)
	binary.LittleEndian.PutUint64(phdr[32:], 0x200)
	binary.LittleEndian.PutUint64(phdr[40:], 0x200)
	binary.LittleEndian.PutUint64(phdr[48:], 0x1000)
	rodataOff := len(ehdr) + len(phdr)
	shstrtabOff := alignInt(rodataOff+len(rodataContent), 8)
	sectionsOff := shstrtabOff + len(shstrtab)
	sections := make([]byte, 3*64)
	binary.LittleEndian.PutUint32(sections[64:], 1)
	binary.LittleEndian.PutUint32(sections[64+4:], 3)
	binary.LittleEndian.PutUint64(sections[64+24:], uint64(shstrtabOff))
	binary.LittleEndian.PutUint64(sections[64+32:], uint64(len(shstrtab)))
	binary.LittleEndian.PutUint32(sections[128:], 11)
	binary.LittleEndian.PutUint32(sections[128+4:], 1)
	binary.LittleEndian.PutUint64(sections[128+8:], 2)
	binary.LittleEndian.PutUint64(sections[128+16:], 0x1000)
	binary.LittleEndian.PutUint64(sections[128+24:], uint64(rodataOff))
	binary.LittleEndian.PutUint64(sections[128+32:], uint64(len(rodataContent)))
	binary.LittleEndian.PutUint64(ehdr[0x28:], uint64(sectionsOff))
	binary.LittleEndian.PutUint16(ehdr[0x3a:], 64)
	binary.LittleEndian.PutUint16(ehdr[0x3c:], 3)
	binary.LittleEndian.PutUint16(ehdr[0x3e:], 1)
	raw := make([]byte, 0, sectionsOff+len(sections))
	raw = append(raw, ehdr...)
	raw = append(raw, phdr...)
	raw = append(raw, rodataContent...)
	for len(raw) < shstrtabOff {
		raw = append(raw, 0)
	}
	raw = append(raw, shstrtab...)
	raw = append(raw, sections...)
	return raw
}

func alignInt(v, align int) int {
	return (v + align - 1) &^ (align - 1)
}
