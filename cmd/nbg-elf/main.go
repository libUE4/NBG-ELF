package main

import (
	"bufio"
	"crypto/sha256"
	"encoding/hex"
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
	preset := fs.String("preset", elfstr.PresetBalanced, "保护预设: safe, balanced, aggressive")
	configPath := fs.String("config", "", "JSON 保护配置路径")
	reportOnly := fs.Bool("report", false, "只打印保护计划，不写入输出文件")
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
		printProtectionReport(report)
		return
	}
	m, err := elfstr.EncryptFile(inputPath, outputPath, manifestPath, opts)
	if err != nil {
		fatal(err)
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

func runManifest(args []string) {
	fs := flag.NewFlagSet("manifest", flag.ExitOnError)
	strict := fs.Bool("strict", false, "当 output_sha256 不匹配或输出文件缺失时返回非零退出码")
	fs.Parse(args)
	if fs.NArg() != 1 {
		fmt.Fprintln(os.Stderr, "用法: nbg-elf manifest [-strict] <manifest.json>")
		os.Exit(2)
	}
	m, err := elfstr.ReadManifest(fs.Arg(0))
	if err != nil {
		fatal(err)
	}
	fmt.Printf("清单版本: %s\n", m.Schema)
	fmt.Printf("输入文件: %s\n", m.InputPath)
	fmt.Printf("输出文件: %s\n", m.OutputPath)
	inputPath := resolveManifestInputPath(fs.Arg(0), m.InputPath)
	if inputPath != m.InputPath {
		fmt.Printf("输入文件_解析后: %s\n", inputPath)
	}
	outputPath := resolveManifestOutputPath(fs.Arg(0), m.OutputPath)
	if outputPath != m.OutputPath {
		fmt.Printf("输出文件_解析后: %s\n", outputPath)
	}
	outputAvailable := false
	if raw, err := os.ReadFile(outputPath); err == nil {
		outputAvailable = true
		sum := sha256.Sum256(raw)
		got := hex.EncodeToString(sum[:])
		status := "ok"
		if m.OutputSHA256 != "" && got != m.OutputSHA256 {
			status = "mismatch"
		}
		fmt.Printf("输出_sha256: %s (%s)\n", got, status)
		if *strict && status != "ok" {
			fatalText("manifest 中的 output_sha256 不匹配")
		}
		if err := elfstr.ValidateEncryptedOutputBytes(raw, m.Options.KeepSections); err != nil {
			fmt.Printf("输出结构: 无效 (%v)\n", err)
			if *strict {
				fatalText("manifest 输出结构校验失败")
			}
		} else {
			fmt.Println("输出结构: ok")
		}
	} else {
		fmt.Printf("输出_sha256: 不可用 (%v)\n", err)
		if *strict {
			fatalText("manifest 输出文件不可用")
		}
	}
	if outputAvailable {
		if err := elfstr.ValidateManifestPlaintextSlots(m, inputPath, outputPath); err != nil {
			if isMissingPathError(err) {
				fmt.Printf("明文槽位: 不可用 (%v)\n", err)
			} else {
				fmt.Printf("明文槽位: 无效 (%v)\n", err)
				if *strict {
					fatalText("manifest 明文槽位审计失败")
				}
			}
		} else {
			fmt.Println("明文槽位: ok")
		}
		if err := elfstr.ValidateManifestRuntimeTable(m, outputPath); err != nil {
			fmt.Printf("运行时表: 无效 (%v)\n", err)
			if *strict {
				fatalText("manifest 运行时表审计失败")
			}
		} else {
			fmt.Println("运行时表: ok")
		}
		if elfstr.ManifestRequiresRuntimeDispatchAudit(m) {
			if err := elfstr.ValidateManifestRuntimeDispatch(m, outputPath); err != nil {
				fmt.Printf("运行时分派: 无效 (%v)\n", err)
				if *strict {
					fatalText("manifest 运行时分派审计失败")
				}
			} else {
				fmt.Println("运行时分派: ok")
			}
		}
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
  encrypt [-preset safe|balanced|aggressive] [-config protection.json] [选项] <input.elf>
  manifest [-strict] <manifest.json>
  verify <manifest.json>

说明:
  -report 只打印保护计划，不写入输出文件。
  运行时注入输出不支持 decrypt；请保留原始 ELF 作为源产物。
  manifest 会打印保护元数据，并在输出文件可访问时校验 output_sha256。
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
