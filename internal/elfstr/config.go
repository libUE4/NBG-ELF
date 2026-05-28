package elfstr

import (
	"bytes"
	"encoding/json"
	"fmt"
	"io"
	"os"
)

const (
	PresetSafe       = "safe"
	PresetBalanced   = "balanced"
	PresetAggressive = "aggressive"
)

type ProtectionConfig struct {
	Preset             string `json:"preset"`
	ControlFlowLevel   int    `json:"control_flow_level"`
	LazyCallsite       bool   `json:"lazy_callsite"`
	LazyCallsiteDryRun bool   `json:"lazy_callsite_dry_run"`
	LazyCallsiteLimit  int    `json:"lazy_callsite_limit"`
	SafeScan           bool   `json:"safe_scan"`
	KeepSections       bool   `json:"keep_sections"`
	NoAntiFridaExtra   bool   `json:"no_anti_frida_extra"`
	FailurePolicy      string `json:"failure_policy"`
}

type protectionConfigJSON struct {
	Preset             *string `json:"preset"`
	ControlFlowLevel   *int    `json:"control_flow_level"`
	LazyCallsite       *bool   `json:"lazy_callsite"`
	LazyCallsiteDryRun *bool   `json:"lazy_callsite_dry_run"`
	LazyCallsiteLimit  *int    `json:"lazy_callsite_limit"`
	SafeScan           *bool   `json:"safe_scan"`
	KeepSections       *bool   `json:"keep_sections"`
	NoAntiFridaExtra   *bool   `json:"no_anti_frida_extra"`
	FailurePolicy      *string `json:"failure_policy"`
}

type ProtectionReport struct {
	Preset              string   `json:"preset"`
	ControlFlowLevel    int      `json:"control_flow_level"`
	FailurePolicy       string   `json:"failure_policy"`
	Strings             int      `json:"strings"`
	Bytes               int      `json:"bytes"`
	RuntimeTableEntries int      `json:"runtime_table_entries"`
	RuntimeDecoys       int      `json:"runtime_decoys"`
	RuntimeDecoyRatio   float64  `json:"runtime_decoy_ratio"`
	LazyCoveragePercent int      `json:"lazy_coverage_percent,omitempty"`
	CallsiteCandidates  int      `json:"callsite_candidates"`
	CallsiteSelected    int      `json:"callsite_selected"`
	CallsiteSkipped     int      `json:"callsite_skipped"`
	CallsiteMode        string   `json:"callsite_mode"`
	CallsiteLimit       int      `json:"callsite_limit,omitempty"`
	Warnings            []string `json:"warnings,omitempty"`
}

func DefaultProtectionConfig(preset string) (ProtectionConfig, error) {
	if preset == "" {
		preset = PresetBalanced
	}
	switch preset {
	case PresetSafe:
		return ProtectionConfig{
			Preset:             PresetSafe,
			ControlFlowLevel:   1,
			LazyCallsiteDryRun: true,
			SafeScan:           true,
			FailurePolicy:      "safe-exit",
		}, nil
	case PresetBalanced:
		return ProtectionConfig{
			Preset:             PresetBalanced,
			ControlFlowLevel:   2,
			LazyCallsiteDryRun: true,
			LazyCallsiteLimit:  32,
			FailurePolicy:      "safe-exit",
		}, nil
	case PresetAggressive:
		return ProtectionConfig{
			Preset:            PresetAggressive,
			ControlFlowLevel:  3,
			LazyCallsite:      true,
			LazyCallsiteLimit: 128,
			FailurePolicy:     "safe-exit",
		}, nil
	default:
		return ProtectionConfig{}, fmt.Errorf("unsupported protection preset %q", preset)
	}
}

func LoadProtectionConfig(path, preset string) (ProtectionConfig, error) {
	cfg, err := DefaultProtectionConfig(preset)
	if err != nil {
		return ProtectionConfig{}, err
	}
	if path == "" {
		return cfg, nil
	}
	raw, err := os.ReadFile(path)
	if err != nil {
		return ProtectionConfig{}, err
	}
	var fileCfg protectionConfigJSON
	dec := json.NewDecoder(bytes.NewReader(raw))
	dec.DisallowUnknownFields()
	if err := dec.Decode(&fileCfg); err != nil {
		return ProtectionConfig{}, err
	}
	var extra json.RawMessage
	if err := dec.Decode(&extra); err != io.EOF {
		if err != nil {
			return ProtectionConfig{}, err
		}
		return ProtectionConfig{}, fmt.Errorf("protection config must contain a single JSON object")
	}
	if fileCfg.Preset != nil && preset == "" {
		cfg, err = DefaultProtectionConfig(*fileCfg.Preset)
		if err != nil {
			return ProtectionConfig{}, err
		}
	}
	applyProtectionConfigJSON(&cfg, fileCfg)
	if cfg.FailurePolicy == "" {
		cfg.FailurePolicy = "safe-exit"
	}
	if cfg.LazyCallsiteLimit < 0 {
		return ProtectionConfig{}, fmt.Errorf("lazy_callsite_limit must be >= 0")
	}
	if cfg.ControlFlowLevel < 1 || cfg.ControlFlowLevel > 3 {
		return ProtectionConfig{}, fmt.Errorf("control_flow_level must be 1, 2, or 3")
	}
	if cfg.FailurePolicy != "safe-exit" {
		return ProtectionConfig{}, fmt.Errorf("unsupported failure_policy %q", cfg.FailurePolicy)
	}
	return cfg, nil
}

func applyProtectionConfigJSON(cfg *ProtectionConfig, fileCfg protectionConfigJSON) {
	if fileCfg.ControlFlowLevel != nil {
		cfg.ControlFlowLevel = *fileCfg.ControlFlowLevel
	}
	if fileCfg.LazyCallsite != nil {
		cfg.LazyCallsite = *fileCfg.LazyCallsite
	}
	if fileCfg.LazyCallsiteDryRun != nil {
		cfg.LazyCallsiteDryRun = *fileCfg.LazyCallsiteDryRun
	}
	if fileCfg.LazyCallsiteLimit != nil {
		cfg.LazyCallsiteLimit = *fileCfg.LazyCallsiteLimit
	}
	if fileCfg.SafeScan != nil {
		cfg.SafeScan = *fileCfg.SafeScan
	}
	if fileCfg.KeepSections != nil {
		cfg.KeepSections = *fileCfg.KeepSections
	}
	if fileCfg.NoAntiFridaExtra != nil {
		cfg.NoAntiFridaExtra = *fileCfg.NoAntiFridaExtra
	}
	if fileCfg.FailurePolicy != nil {
		cfg.FailurePolicy = *fileCfg.FailurePolicy
	}
}

func (cfg ProtectionConfig) ApplyToOptions(opts *Options) {
	opts.Preset = cfg.Preset
	opts.ControlFlowLevel = cfg.ControlFlowLevel
	opts.FailurePolicy = cfg.FailurePolicy
	opts.LazyCallsite = cfg.LazyCallsite
	opts.LazyCallsiteDryRun = cfg.LazyCallsiteDryRun
	opts.LazyCallsiteLimit = cfg.LazyCallsiteLimit
	opts.SafeScan = cfg.SafeScan
	opts.KeepSections = cfg.KeepSections
	opts.NoAntiFridaExtra = cfg.NoAntiFridaExtra
}

func PlanProtectionFile(inputPath string, opts Options) (*ProtectionReport, error) {
	raw, err := os.ReadFile(inputPath)
	if err != nil {
		return nil, err
	}
	return PlanProtectionBytes(raw, opts)
}

func PlanProtectionBytes(raw []byte, opts Options) (*ProtectionReport, error) {
	minLen := effectiveMinLen(opts)
	entries, err := scan(raw, minLen, opts.IncludeData, opts.SafeScan)
	if err != nil {
		return nil, err
	}
	entries, err = prepareRuntimeEntries(entries)
	if err != nil {
		return nil, err
	}
	runtimeEntries, decoyCount, err := prepareRuntimeTableEntries(entries)
	if err != nil {
		return nil, err
	}
	manifestEntries := realRuntimeEntries(runtimeEntries)
	callsiteCandidates, err := discoverAArch64Callsites(raw, manifestEntries)
	if err != nil {
		return nil, err
	}
	callsiteCandidates = filterLazyCallsiteCandidates(raw, runtimeEntries, callsiteCandidates)
	mode, selectedCandidates, err := selectCallsiteProtection(opts, callsiteCandidates)
	if err != nil {
		return nil, err
	}
	selected := len(selectedCandidates)
	lazyCoverage := callsiteCoveragePercent(selected, len(callsiteCandidates))
	total := 0
	for _, e := range manifestEntries {
		total += e.Length
	}
	warnings := protectionWarnings(opts, len(callsiteCandidates), selected)
	return &ProtectionReport{
		Preset:              effectivePreset(opts.Preset),
		ControlFlowLevel:    effectiveControlFlowLevel(opts.ControlFlowLevel),
		FailurePolicy:       effectiveFailurePolicy(opts.FailurePolicy),
		Strings:             len(manifestEntries),
		Bytes:               total,
		RuntimeTableEntries: len(runtimeEntries),
		RuntimeDecoys:       decoyCount,
		RuntimeDecoyRatio:   runtimeDecoyRatio(decoyCount, len(runtimeEntries)),
		LazyCoveragePercent: lazyCoverage,
		CallsiteCandidates:  len(callsiteCandidates),
		CallsiteSelected:    selected,
		CallsiteSkipped:     len(callsiteCandidates) - selected,
		CallsiteMode:        mode,
		CallsiteLimit:       opts.LazyCallsiteLimit,
		Warnings:            warnings,
	}, nil
}

func effectiveMinLen(opts Options) int {
	minLen := opts.MinLen
	if minLen == 0 {
		minLen = defaultMinLen
	}
	if minLen < minStringLen {
		minLen = minStringLen
	}
	if opts.SafeScan && opts.MinLen == 0 {
		minLen = safeScanMinLen
	}
	return minLen
}

func effectivePreset(preset string) string {
	if preset == "" {
		return PresetBalanced
	}
	return preset
}

func effectiveControlFlowLevel(level int) int {
	if level == 0 {
		return 2
	}
	return level
}

func effectiveFailurePolicy(policy string) string {
	if policy == "" {
		return "safe-exit"
	}
	return policy
}

func protectionWarnings(opts Options, candidates, selected int) []string {
	var warnings []string
	if opts.LazyCallsite && selected == 0 {
		warnings = append(warnings, "已请求 lazy 调用点补丁，但没有选中保守候选")
	}
	if opts.LazyCallsiteLimit > 0 && candidates > selected {
		warnings = append(warnings, "lazy 调用点候选已被配置上限限制")
	}
	if opts.KeepSections {
		warnings = append(warnings, "为兼容性保留了节表，抗静态分析能力会降低")
	}
	return warnings
}
