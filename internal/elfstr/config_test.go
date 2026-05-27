package elfstr

import (
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
	if len(warnings) != 1 || !strings.Contains(warnings[0], "limited") {
		t.Fatalf("warnings = %#v", warnings)
	}
}
