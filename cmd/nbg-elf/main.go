package main

import (
	"bufio"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"flag"
	"fmt"
	"os"
	"path/filepath"
	"strings"

	"nbg-elf/internal/elfstr"
)

func main() {
	if len(os.Args) < 2 {
		runInteractive()
		return
	}
	switch os.Args[1] {
	case "inspect":
		runInspect(os.Args[2:])
	case "encrypt":
		runEncrypt(os.Args[2:])
	case "manifest":
		runManifest(os.Args[2:])
	case "verify":
		runVerify(os.Args[2:])
	case "decrypt":
		fatalText("运行时注入输出不支持解密；请保留原始 ELF 作为源产物")
	case "-h", "--help", "help":
		usage()
	default:
		runEncrypt(os.Args[1:])
	}
}

func runInspect(args []string) {
	fs := flag.NewFlagSet("inspect", flag.ExitOnError)
	minLen := fs.Int("min", 6, "最小字符串长度")
	includeData := fs.Bool("data", false, "同时扫描 .data 段")
	fs.Parse(args)
	if fs.NArg() != 1 {
		fmt.Fprintln(os.Stderr, "用法: nbg-elf inspect [选项] <输入.elf>")
		os.Exit(2)
	}
	entries, err := elfstr.ScanFile(fs.Arg(0), *minLen, *includeData)
	if err != nil {
		fatal(err)
	}
	total := 0
	for _, e := range entries {
		total += e.Length
		fmt.Printf("%-12s off=0x%08X va=0x%08X len=%d sha256=%s\n", e.Section, e.Offset, e.VAddr, e.Length, e.SHA256[:16])
	}
	fmt.Printf("[+] 字符串=%d 字节=%d\n", len(entries), total)
}

func runEncrypt(args []string) {
	fs := flag.NewFlagSet("encrypt", flag.ExitOnError)
	out := fs.String("o", "", "输出 ELF 路径（默认: 工具目录/basename.vmp）")
	manifest := fs.String("manifest", "", "manifest 输出路径")
	auditPath := fs.String("audit", "", "生成后输出 JSON 审计报告路径")
	preset := fs.String("preset", elfstr.PresetBalanced, "保护预设: safe, balanced, aggressive")
	configPath := fs.String("config", "", "JSON 保护配置路径")
	reportOnly := fs.Bool("report", false, "只打印保护计划，不写入输出文件")
	jsonOutput := fs.Bool("json", false, "以 JSON 输出保护计划；仅与 -report 一起使用")
	minGrade := fs.String("min-grade", "", "生成后要求最低审计等级: review-needed, hardened, commercial-ready")
	minLen := fs.Int("min", 6, "最小字符串长度")
	includeData := fs.Bool("data", false, "同时加密 .data 段")
	watermark := fs.String("watermark", "", "可选水印标识，将以哈希形式嵌入")
	manifestDetail := fs.Bool("manifest-detail", false, "在 manifest 中记录每个字符串的偏移和哈希（隐私性较弱）")
	keepSections := fs.Bool("keep-sections", false, "保留加密输出的节表（抗静态分析能力较弱）")
	noAntiFridaExtra := fs.Bool("no-anti-frida-extra", false, "兼容性测试: 禁用额外 Frida/Gum/Gadget maps 与 fd-link 运行时探测")
	safeScan := fs.Bool("safe-scan", false, "诊断模式: 仅加密保守识别的 .rodata 用户可见字符串")
	lazyCallsite := fs.Bool("lazy-callsite", false, "实验功能: 对选中的调用点启用按需解密/回封；需要 -lazy-callsite-limit")
	lazyCallsiteDryRun := fs.Bool("lazy-callsite-dry-run", false, "扫描并选择 lazy 调用点候选，但不修改指令")
	lazyCallsiteLimit := fs.Int("lazy-callsite-limit", 0, "lazy 调用点候选选择上限；0 表示全部候选")
	fs.Parse(args)
	if fs.NArg() != 1 {
		fmt.Fprintln(os.Stderr, "用法: nbg-elf [encrypt] [选项] <输入.elf>")
		os.Exit(2)
	}
	inputPath := fs.Arg(0)
	outputPath := *out
	if outputPath == "" {
		outputPath = defaultEncryptedOutputPath(inputPath)
	}
	manifestPath := *manifest
	if manifestPath == "" {
		manifestPath = outputPath + ".manifest.json"
	}
	configPreset := *preset
	if *configPath != "" && !flagWasSet(fs, "preset") {
		configPreset = ""
	}
	if err := validateEncryptReportFlags(*reportOnly, *jsonOutput); err != nil {
		fatal(err)
	}
	cfg, err := elfstr.LoadProtectionConfig(*configPath, configPreset)
	if err != nil {
		fatal(err)
	}
	opts := elfstr.Options{
		MinLen:         *minLen,
		IncludeData:    *includeData,
		Watermark:      *watermark,
		ManifestDetail: *manifestDetail,
	}
	cfg.ApplyToOptions(&opts)
	applyEncryptFlagOverrides(fs, &opts, map[string]func(){
		"keep-sections":         func() { opts.KeepSections = *keepSections },
		"no-anti-frida-extra":   func() { opts.NoAntiFridaExtra = *noAntiFridaExtra },
		"safe-scan":             func() { opts.SafeScan = *safeScan },
		"lazy-callsite":         func() { opts.LazyCallsite = *lazyCallsite },
		"lazy-callsite-dry-run": func() { opts.LazyCallsiteDryRun = *lazyCallsiteDryRun },
		"lazy-callsite-limit":   func() { opts.LazyCallsiteLimit = *lazyCallsiteLimit },
	})
	if *reportOnly {
		report, err := elfstr.PlanProtectionFile(inputPath, opts)
		if err != nil {
			fatal(err)
		}
		if *jsonOutput {
			printProtectionReportJSON(report)
		} else {
			printProtectionReport(report)
		}
		return
	}
	m, err := elfstr.EncryptFile(inputPath, outputPath, manifestPath, opts)
	if err != nil {
		fatal(err)
	}
	if *minGrade != "" || *auditPath != "" {
		audit := buildManifestAudit(manifestPath, m)
		if *auditPath != "" {
			if err := writeJSONFile(*auditPath, audit, 0o644); err != nil {
				fatal(err)
			}
			fmt.Printf("[+] 审计报告: %s\n", *auditPath)
		}
		if err := enforceMinimumAuditGrade(audit, *minGrade); err != nil {
			fatal(err)
		}
		if *minGrade != "" {
			fmt.Printf("[+] 审计等级: %s score=%d\n", audit.Summary.Grade, audit.Summary.Score)
		}
	}
	fmt.Printf("[+] 已加密字符串: %d (%d 字节)\n", m.EntryCount, m.EncryptedSize)
	fmt.Printf("[+] 保护预设: %s 控制流等级=%d 失败策略=%s\n", m.Report.Preset, m.Report.ControlFlowLevel, m.Report.FailurePolicy)
	fmt.Printf("[+] 调用点: 候选=%d 选中=%d 跳过=%d 模式=%s\n", m.Report.CallsiteCandidates, m.Report.CallsiteSelected, m.Report.CallsiteSkipped, m.Report.CallsiteMode)
	fmt.Printf("[+] 输出文件: %s\n", m.OutputPath)
	fmt.Printf("[+] manifest: %s\n", manifestPath)
}

func runVerify(args []string) {
	args = append([]string{"-strict"}, args...)
	runManifest(args)
}

func applyEncryptFlagOverrides(fs *flag.FlagSet, opts *elfstr.Options, overrides map[string]func()) {
	fs.Visit(func(f *flag.Flag) {
		if apply, ok := overrides[f.Name]; ok {
			apply()
		}
	})
}

func validateEncryptReportFlags(reportOnly, jsonOutput bool) error {
	if jsonOutput && !reportOnly {
		return fmt.Errorf("-json 只能与 -report 一起使用")
	}
	return nil
}

func flagWasSet(fs *flag.FlagSet, name string) bool {
	seen := false
	fs.Visit(func(f *flag.Flag) {
		if f.Name == name {
			seen = true
		}
	})
	return seen
}

func printProtectionReport(report *elfstr.ProtectionReport) {
	fmt.Printf("保护预设: %s\n", report.Preset)
	fmt.Printf("控制流等级: %d\n", report.ControlFlowLevel)
	fmt.Printf("失败策略: %s\n", report.FailurePolicy)
	fmt.Printf("字符串: %d (%d 字节)\n", report.Strings, report.Bytes)
	fmt.Printf("调用点: 候选=%d 选中=%d 跳过=%d 模式=%s\n", report.CallsiteCandidates, report.CallsiteSelected, report.CallsiteSkipped, report.CallsiteMode)
	for _, warning := range report.Warnings {
		fmt.Printf("警告: %s\n", warning)
	}
}

func printProtectionReportJSON(report *elfstr.ProtectionReport) {
	raw, err := json.MarshalIndent(report, "", "  ")
	if err != nil {
		fatal(err)
	}
	fmt.Println(string(raw))
}

func writeJSONFile(path string, value any, perm os.FileMode) error {
	raw, err := json.MarshalIndent(value, "", "  ")
	if err != nil {
		return err
	}
	raw = append(raw, '\n')
	if err := os.MkdirAll(filepath.Dir(path), 0o755); err != nil {
		return err
	}
	return os.WriteFile(path, raw, perm)
}

type manifestAudit struct {
	Schema         string       `json:"schema"`
	InputPath      string       `json:"input_path"`
	InputResolved  string       `json:"input_resolved,omitempty"`
	OutputPath     string       `json:"output_path"`
	OutputResolved string       `json:"output_resolved,omitempty"`
	EntryCount     int          `json:"entry_count"`
	EncryptedSize  int          `json:"encrypted_size"`
	Preset         string       `json:"preset,omitempty"`
	ControlFlow    string       `json:"control_flow,omitempty"`
	CallsiteMode   string       `json:"callsite_mode,omitempty"`
	Summary        auditSummary `json:"summary"`
	Checks         []auditCheck `json:"checks"`
}

type auditSummary struct {
	Grade           string   `json:"grade"`
	Score           int      `json:"score"`
	Blockers        []string `json:"blockers,omitempty"`
	Recommendations []string `json:"recommendations,omitempty"`
}

type auditCheck struct {
	Name   string `json:"name"`
	Status string `json:"status"`
	Detail string `json:"detail,omitempty"`
}

func buildManifestAudit(manifestPath string, m *elfstr.Manifest) manifestAudit {
	inputPath := resolveManifestInputPath(manifestPath, m.InputPath)
	outputPath := resolveManifestOutputPath(manifestPath, m.OutputPath)
	audit := manifestAudit{
		Schema:        m.Schema,
		InputPath:     m.InputPath,
		OutputPath:    m.OutputPath,
		EntryCount:    m.EntryCount,
		EncryptedSize: m.EncryptedSize,
		Preset:        m.Report.Preset,
		ControlFlow:   m.Protection.ControlFlow,
		CallsiteMode:  m.Protection.CallsiteMode,
	}
	if inputPath != m.InputPath {
		audit.InputResolved = inputPath
	}
	if outputPath != m.OutputPath {
		audit.OutputResolved = outputPath
	}
	if err := elfstr.ValidateManifestSelfHash(m); err != nil {
		status := "invalid"
		if m.ManifestSHA256 == "" {
			status = "unavailable"
		}
		audit.Checks = append(audit.Checks, auditCheck{Name: "manifest_sha256", Status: status, Detail: err.Error()})
	} else {
		audit.Checks = append(audit.Checks, auditCheck{Name: "manifest_sha256", Status: "ok", Detail: m.ManifestSHA256})
	}
	raw, err := os.ReadFile(outputPath)
	if err != nil {
		audit.Checks = append(audit.Checks, auditCheck{Name: "output_sha256", Status: "unavailable", Detail: err.Error()})
		audit.Checks = append(audit.Checks, auditCheck{Name: "output_structure", Status: "skipped", Detail: "output unavailable"})
		audit.Checks = append(audit.Checks, auditCheck{Name: "plaintext_slots", Status: "skipped", Detail: "output unavailable"})
		audit.Checks = append(audit.Checks, auditCheck{Name: "runtime_table", Status: "skipped", Detail: "output unavailable"})
		if elfstr.ManifestRequiresRuntimeDispatchAudit(m) {
			audit.Checks = append(audit.Checks, auditCheck{Name: "runtime_dispatch", Status: "skipped", Detail: "output unavailable"})
		}
		return finalizeManifestAudit(audit, m)
	}
	sum := sha256.Sum256(raw)
	got := hex.EncodeToString(sum[:])
	if m.OutputSHA256 != "" && got != m.OutputSHA256 {
		audit.Checks = append(audit.Checks, auditCheck{Name: "output_sha256", Status: "mismatch", Detail: got})
	} else {
		audit.Checks = append(audit.Checks, auditCheck{Name: "output_sha256", Status: "ok", Detail: got})
	}
	if err := elfstr.ValidateEncryptedOutputBytes(raw, m.Options.KeepSections); err != nil {
		audit.Checks = append(audit.Checks, auditCheck{Name: "output_structure", Status: "invalid", Detail: err.Error()})
	} else {
		audit.Checks = append(audit.Checks, auditCheck{Name: "output_structure", Status: "ok"})
	}
	if err := elfstr.ValidateManifestPlaintextSlots(m, inputPath, outputPath); err != nil {
		status := "invalid"
		if isMissingPathError(err) {
			status = "unavailable"
		}
		audit.Checks = append(audit.Checks, auditCheck{Name: "plaintext_slots", Status: status, Detail: err.Error()})
	} else {
		audit.Checks = append(audit.Checks, auditCheck{Name: "plaintext_slots", Status: "ok"})
	}
	if err := elfstr.ValidateManifestRuntimeTable(m, outputPath); err != nil {
		audit.Checks = append(audit.Checks, auditCheck{Name: "runtime_table", Status: "invalid", Detail: err.Error()})
	} else {
		audit.Checks = append(audit.Checks, auditCheck{Name: "runtime_table", Status: "ok"})
	}
	if elfstr.ManifestRequiresRuntimeDispatchAudit(m) {
		if err := elfstr.ValidateManifestRuntimeDispatch(m, outputPath); err != nil {
			audit.Checks = append(audit.Checks, auditCheck{Name: "runtime_dispatch", Status: "invalid", Detail: err.Error()})
		} else {
			audit.Checks = append(audit.Checks, auditCheck{Name: "runtime_dispatch", Status: "ok"})
		}
	}
	return finalizeManifestAudit(audit, m)
}

func finalizeManifestAudit(audit manifestAudit, m *elfstr.Manifest) manifestAudit {
	audit.Summary = buildAuditSummary(audit, m)
	return audit
}

func buildAuditSummary(audit manifestAudit, m *elfstr.Manifest) auditSummary {
	score := 100
	var blockers []string
	var recommendations []string
	for _, check := range audit.Checks {
		switch check.Status {
		case "ok":
		case "skipped":
			if check.Name != "runtime_dispatch" {
				score -= 5
				recommendations = append(recommendations, check.Name+" skipped")
			}
		case "unavailable":
			score -= 25
			blockers = append(blockers, check.Name+" unavailable")
		case "mismatch", "invalid":
			score -= 35
			blockers = append(blockers, check.Name+" "+check.Status)
		default:
			score -= 20
			blockers = append(blockers, check.Name+" unknown-status")
		}
	}
	switch m.Report.Preset {
	case elfstr.PresetAggressive:
		score += 5
	case elfstr.PresetSafe:
		score -= 10
		recommendations = append(recommendations, "safe preset is for compatibility, not maximum protection")
	}
	if m.EntryCount == 0 {
		score -= 20
		blockers = append(blockers, "no protected entries")
	}
	if !m.Protection.RuntimeSelfCheck {
		score -= 15
		blockers = append(blockers, "runtime self-check disabled")
	}
	if m.Options.KeepSections {
		score -= 10
		recommendations = append(recommendations, "section table is preserved")
	}
	if m.Options.NoAntiFridaExtra {
		score -= 10
		recommendations = append(recommendations, "extra anti-frida probes disabled")
	}
	if m.Options.ManifestDetail {
		score -= 5
		recommendations = append(recommendations, "manifest detail exposes protected offsets")
	}
	if !strings.Contains(m.Protection.ControlFlow, "runtime-state-dispatch") {
		score -= 8
		recommendations = append(recommendations, "runtime state dispatch not enabled")
	}
	if m.Protection.CallsiteMode == "aarch64-lazy-decrypt-patch" && m.Protection.CallsiteLazySelected > 0 {
		score += 5
	} else if strings.Contains(m.Protection.CallsiteMode, "dry-run") {
		score -= 5
		recommendations = append(recommendations, "lazy callsite protection is dry-run only")
	}
	strongMode := m.Report.Preset == elfstr.PresetAggressive &&
		m.Protection.CallsiteMode == "aarch64-lazy-decrypt-patch" &&
		m.Protection.CallsiteLazySelected > 0
	if !strongMode {
		recommendations = append(recommendations, "aggressive preset with patched lazy callsites is required for commercial-ready grade")
	}
	if score < 0 {
		score = 0
	}
	if score > 100 {
		score = 100
	}
	grade := "blocked"
	if len(blockers) == 0 {
		switch {
		case score >= 90 && strongMode:
			grade = "commercial-ready"
		case score >= 75:
			grade = "hardened"
		default:
			grade = "review-needed"
		}
	}
	return auditSummary{
		Grade:           grade,
		Score:           score,
		Blockers:        blockers,
		Recommendations: recommendations,
	}
}

func printManifestAudit(audit manifestAudit, m *elfstr.Manifest) {
	fmt.Printf("清单版本: %s\n", audit.Schema)
	fmt.Printf("输入文件: %s\n", audit.InputPath)
	fmt.Printf("输出文件: %s\n", audit.OutputPath)
	if audit.InputResolved != "" {
		fmt.Printf("输入文件_解析后: %s\n", audit.InputResolved)
	}
	if audit.OutputResolved != "" {
		fmt.Printf("输出文件_解析后: %s\n", audit.OutputResolved)
	}
	fmt.Printf("审计评分: %s score=%d\n", audit.Summary.Grade, audit.Summary.Score)
	for _, blocker := range audit.Summary.Blockers {
		fmt.Printf("阻断项: %s\n", blocker)
	}
	for _, recommendation := range audit.Summary.Recommendations {
		fmt.Printf("建议: %s\n", recommendation)
	}
	for _, check := range audit.Checks {
		printAuditCheck(check)
	}
	fmt.Printf("条目: %d (%d 字节)\n", m.EntryCount, m.EncryptedSize)
	if m.Report.Preset != "" {
		fmt.Printf("保护预设: %s 控制流等级=%d 失败策略=%s\n", m.Report.Preset, m.Report.ControlFlowLevel, m.Report.FailurePolicy)
		fmt.Printf("报告_调用点: 候选=%d 选中=%d 跳过=%d 模式=%s\n", m.Report.CallsiteCandidates, m.Report.CallsiteSelected, m.Report.CallsiteSkipped, m.Report.CallsiteMode)
	}
	fmt.Printf("选项: keep_sections=%v safe_scan=%v lazy_callsite=%v lazy_dry_run=%v lazy_limit=%d no_anti_frida_extra=%v manifest_detail=%v\n", m.Options.KeepSections, m.Options.SafeScan, m.Options.LazyCallsite, m.Options.LazyCallsiteDryRun, m.Options.LazyCallsiteLimit, m.Options.NoAntiFridaExtra, m.Options.ManifestDetail)
	fmt.Printf("控制流: %s\n", m.Protection.ControlFlow)
	if m.Protection.PlaintextAudit != "" {
		fmt.Printf("明文审计: %s\n", m.Protection.PlaintextAudit)
	}
	if m.Protection.Honeypot != "" {
		fmt.Printf("诱饵: %s\n", m.Protection.Honeypot)
	}
	fmt.Printf("调用点: 候选=%d 选中=%d 模式=%s\n", m.Protection.CallsiteLazyCandidates, m.Protection.CallsiteLazySelected, m.Protection.CallsiteMode)
	if m.RuntimeStub.SHA256 != "" {
		fmt.Printf("运行时_stub: 大小=%d sha256=%s entry_off=0x%x lazy_entry_off=0x%x honeypot_off=0x%x\n", m.RuntimeStub.Size, m.RuntimeStub.SHA256, m.RuntimeStub.EntryOff, m.RuntimeStub.LazyEntryOff, m.RuntimeStub.HoneypotOff)
	}
}

func printAuditCheck(check auditCheck) {
	labels := map[string]string{
		"manifest_sha256":  "manifest_sha256",
		"output_sha256":    "输出_sha256",
		"output_structure": "输出结构",
		"plaintext_slots":  "明文槽位",
		"runtime_table":    "运行时表",
		"runtime_dispatch": "运行时分派",
	}
	label := labels[check.Name]
	if label == "" {
		label = check.Name
	}
	switch check.Status {
	case "ok":
		if (check.Name == "output_sha256" || check.Name == "manifest_sha256") && check.Detail != "" {
			fmt.Printf("%s: %s (ok)\n", label, check.Detail)
		} else {
			fmt.Printf("%s: ok\n", label)
		}
	case "mismatch":
		fmt.Printf("%s: %s (mismatch)\n", label, check.Detail)
	case "unavailable":
		fmt.Printf("%s: 不可用 (%s)\n", label, check.Detail)
	case "skipped":
		fmt.Printf("%s: 跳过 (%s)\n", label, check.Detail)
	default:
		fmt.Printf("%s: 无效 (%s)\n", label, check.Detail)
	}
}

func enforceManifestAudit(audit manifestAudit) {
	for _, check := range audit.Checks {
		switch check.Name {
		case "output_sha256":
			if check.Status != "ok" {
				fatalText("manifest 中的 output_sha256 不匹配或不可用")
			}
		default:
			if check.Status != "ok" && check.Status != "skipped" {
				fatalText("manifest 审计失败: " + check.Name)
			}
		}
	}
}

func auditGradeRank(grade string) int {
	switch grade {
	case "blocked":
		return 0
	case "review-needed":
		return 1
	case "hardened":
		return 2
	case "commercial-ready":
		return 3
	default:
		return -1
	}
}

func enforceMinimumAuditGrade(audit manifestAudit, minGrade string) error {
	if minGrade == "" {
		return nil
	}
	want := auditGradeRank(minGrade)
	if want < 0 {
		return fmt.Errorf("unsupported audit grade %q", minGrade)
	}
	got := auditGradeRank(audit.Summary.Grade)
	if got < 0 {
		return fmt.Errorf("unknown audit grade %q", audit.Summary.Grade)
	}
	if got < want {
		return fmt.Errorf("manifest audit grade %s is below required %s", audit.Summary.Grade, minGrade)
	}
	return nil
}

func runManifest(args []string) {
	fs := flag.NewFlagSet("manifest", flag.ExitOnError)
	strict := fs.Bool("strict", false, "当 output_sha256 不匹配或输出文件缺失时返回非零退出码")
	jsonOutput := fs.Bool("json", false, "以 JSON 输出 manifest 审计结果")
	minGrade := fs.String("min-grade", "", "要求最低审计等级: review-needed, hardened, commercial-ready")
	fs.Parse(args)
	if fs.NArg() != 1 {
		fmt.Fprintln(os.Stderr, "用法: nbg-elf manifest [-strict] [-json] [-min-grade hardened|commercial-ready] <manifest.json>")
		os.Exit(2)
	}
	m, err := elfstr.ReadManifest(fs.Arg(0))
	if err != nil {
		fatal(err)
	}
	audit := buildManifestAudit(fs.Arg(0), m)
	if *jsonOutput {
		raw, err := json.MarshalIndent(audit, "", "  ")
		if err != nil {
			fatal(err)
		}
		fmt.Println(string(raw))
	} else {
		printManifestAudit(audit, m)
	}
	if *strict {
		enforceManifestAudit(audit)
	}
	if err := enforceMinimumAuditGrade(audit, *minGrade); err != nil {
		fatal(err)
	}
}

func resolveManifestOutputPath(manifestPath, outputPath string) string {
	if outputPath == "" || filepath.IsAbs(outputPath) {
		return outputPath
	}
	if _, err := os.Stat(outputPath); err == nil {
		return outputPath
	}
	candidate := filepath.Join(filepath.Dir(manifestPath), outputPath)
	if _, err := os.Stat(candidate); err == nil {
		return candidate
	}
	return outputPath
}

func resolveManifestInputPath(manifestPath, inputPath string) string {
	if inputPath == "" || filepath.IsAbs(inputPath) {
		return inputPath
	}
	if _, err := os.Stat(inputPath); err == nil {
		return inputPath
	}
	candidate := filepath.Join(filepath.Dir(manifestPath), inputPath)
	if _, err := os.Stat(candidate); err == nil {
		return candidate
	}
	return inputPath
}

func isMissingPathError(err error) bool {
	return os.IsNotExist(err) || os.IsPermission(err)
}

func runDecrypt(args []string) {
	fs := flag.NewFlagSet("decrypt", flag.ExitOnError)
	out := fs.String("o", "", "输出 ELF 路径")
	manifest := fs.String("manifest", "", "manifest 路径")
	fs.Parse(args)
	if fs.NArg() != 1 || *manifest == "" {
		fmt.Fprintln(os.Stderr, "用法: nbg-elf decrypt -manifest <manifest.json> [选项] <已加密.elf>")
		os.Exit(2)
	}
	m, err := elfstr.DecryptFile(fs.Arg(0), *out, *manifest)
	if err != nil {
		fatal(err)
	}
	fmt.Printf("[+] 已解密字符串: %d\n", m.EntryCount)
	fmt.Printf("[+] 输出文件: %s\n", m.OutputPath)
}

func usage() {
	fmt.Fprintln(os.Stderr, `nbg-elf

用法:
  nbg-elf
  nbg-elf <input.elf>
  nbg-elf -o <output.vmp> <input.elf>

命令:
  inspect [选项] <input.elf>
  encrypt [-preset safe|balanced|aggressive] [-audit audit.json] [-min-grade hardened|commercial-ready] [选项] <input.elf>
  manifest [-strict] [-json] [-min-grade hardened|commercial-ready] <manifest.json>
  verify [-min-grade hardened|commercial-ready] <manifest.json>

说明:
  encrypt -report -json 会以机器可读 JSON 输出保护计划；encrypt -audit/-min-grade 会在生成后执行审计。
  运行时注入输出不支持 decrypt；请保留原始 ELF 作为源产物。
  manifest 会打印保护元数据、审计评分，并在输出文件可访问时校验 output_sha256。
  verify 等价于 manifest -strict。`)
}

func runInteractive() {
	reader := bufio.NewReader(os.Stdin)
	fmt.Println("========================================")
	fmt.Println("  NBG-ELF 字符串加密工具")
	fmt.Println("========================================")
	fmt.Print("请输入要加密的 ELF 文件路径: ")
	inputPath, err := reader.ReadString('\n')
	if err != nil {
		fatal(err)
	}
	inputPath = strings.Trim(strings.TrimSpace(inputPath), "\"")
	if inputPath == "" {
		fatalText("输入路径为空")
	}
	fmt.Print("请输入水印标识，可留空: ")
	watermark, err := reader.ReadString('\n')
	if err != nil {
		fatal(err)
	}
	watermark = strings.TrimSpace(watermark)
	args := []string{inputPath}
	if watermark != "" {
		args = []string{"-watermark", watermark, inputPath}
	}
	runEncrypt(args)
}

func defaultEncryptedOutputPath(inputPath string) string {
	exe, err := os.Executable()
	if err != nil || exe == "" {
		exe = os.Args[0]
	}
	outDir := filepath.Dir(exe)
	base := filepath.Base(inputPath)
	return filepath.Join(outDir, base+".vmp")
}

func fatal(err error) {
	fmt.Fprintf(os.Stderr, "[!] %v\n", err)
	os.Exit(1)
}

func fatalText(msg string) {
	fmt.Fprintf(os.Stderr, "[!] %s\n", msg)
	os.Exit(1)
}
