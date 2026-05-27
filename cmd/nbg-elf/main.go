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
		fatalText("decrypt is not supported for runtime-injected outputs; keep the original ELF as the source artifact")
	case "-h", "--help", "help":
		usage()
	default:
		runEncrypt(os.Args[1:])
	}
}

func runInspect(args []string) {
	fs := flag.NewFlagSet("inspect", flag.ExitOnError)
	minLen := fs.Int("min", 6, "minimum string length")
	includeData := fs.Bool("data", false, "also scan .data")
	fs.Parse(args)
	if fs.NArg() != 1 {
		fmt.Fprintln(os.Stderr, "usage: nbg-elf inspect [flags] <input.elf>")
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
	fmt.Printf("[+] strings=%d bytes=%d\n", len(entries), total)
}

func runEncrypt(args []string) {
	fs := flag.NewFlagSet("encrypt", flag.ExitOnError)
	out := fs.String("o", "", "output ELF path (default: tool directory/basename.vmp)")
	manifest := fs.String("manifest", "", "manifest output path")
	preset := fs.String("preset", elfstr.PresetBalanced, "protection preset: safe, balanced, aggressive")
	configPath := fs.String("config", "", "JSON protection config path")
	reportOnly := fs.Bool("report", false, "print protection plan without writing output")
	minLen := fs.Int("min", 6, "minimum string length")
	includeData := fs.Bool("data", false, "also encrypt .data")
	watermark := fs.String("watermark", "", "optional user watermark embedded as a hash")
	manifestDetail := fs.Bool("manifest-detail", false, "store per-string offsets and hashes in manifest (less private)")
	keepSections := fs.Bool("keep-sections", false, "keep section headers in encrypted output (less resistant to static analysis)")
	noAntiFridaExtra := fs.Bool("no-anti-frida-extra", false, "compat test: disable extra Frida/Gum/Gadget maps and fd-link runtime probes")
	safeScan := fs.Bool("safe-scan", false, "diagnostic test: encrypt only conservative .rodata user-facing strings")
	lazyCallsite := fs.Bool("lazy-callsite", false, "experimental: patch selected callsites for lazy decrypt/reseal; requires -lazy-callsite-limit")
	lazyCallsiteDryRun := fs.Bool("lazy-callsite-dry-run", false, "scan and select lazy callsite candidates without patching instructions")
	lazyCallsiteLimit := fs.Int("lazy-callsite-limit", 0, "maximum lazy callsite candidates to select in dry-run mode; 0 means all candidates")
	fs.Parse(args)
	if fs.NArg() != 1 {
		fmt.Fprintln(os.Stderr, "usage: nbg-elf [encrypt] [flags] <input.elf>")
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
	fmt.Printf("[+] encrypted strings: %d (%d bytes)\n", m.EntryCount, m.EncryptedSize)
	fmt.Printf("[+] preset: %s cfg_level=%d failure=%s\n", m.Report.Preset, m.Report.ControlFlowLevel, m.Report.FailurePolicy)
	fmt.Printf("[+] callsites: candidates=%d selected=%d skipped=%d mode=%s\n", m.Report.CallsiteCandidates, m.Report.CallsiteSelected, m.Report.CallsiteSkipped, m.Report.CallsiteMode)
	fmt.Printf("[+] output: %s\n", m.OutputPath)
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
	fmt.Printf("preset: %s\n", report.Preset)
	fmt.Printf("control_flow_level: %d\n", report.ControlFlowLevel)
	fmt.Printf("failure_policy: %s\n", report.FailurePolicy)
	fmt.Printf("strings: %d (%d bytes)\n", report.Strings, report.Bytes)
	fmt.Printf("callsites: candidates=%d selected=%d skipped=%d mode=%s\n", report.CallsiteCandidates, report.CallsiteSelected, report.CallsiteSkipped, report.CallsiteMode)
	for _, warning := range report.Warnings {
		fmt.Printf("warning: %s\n", warning)
	}
}

func runManifest(args []string) {
	fs := flag.NewFlagSet("manifest", flag.ExitOnError)
	strict := fs.Bool("strict", false, "exit non-zero when output_sha256 mismatches or output is missing")
	fs.Parse(args)
	if fs.NArg() != 1 {
		fmt.Fprintln(os.Stderr, "usage: nbg-elf manifest [-strict] <manifest.json>")
		os.Exit(2)
	}
	m, err := elfstr.ReadManifest(fs.Arg(0))
	if err != nil {
		fatal(err)
	}
	fmt.Printf("schema: %s\n", m.Schema)
	fmt.Printf("input: %s\n", m.InputPath)
	fmt.Printf("output: %s\n", m.OutputPath)
	inputPath := resolveManifestInputPath(fs.Arg(0), m.InputPath)
	if inputPath != m.InputPath {
		fmt.Printf("input_resolved: %s\n", inputPath)
	}
	outputPath := resolveManifestOutputPath(fs.Arg(0), m.OutputPath)
	if outputPath != m.OutputPath {
		fmt.Printf("output_resolved: %s\n", outputPath)
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
		fmt.Printf("output_sha256: %s (%s)\n", got, status)
		if *strict && status != "ok" {
			fatalText("manifest output_sha256 mismatch")
		}
		if err := elfstr.ValidateEncryptedOutputBytes(raw, m.Options.KeepSections); err != nil {
			fmt.Printf("output_structure: invalid (%v)\n", err)
			if *strict {
				fatalText("manifest output structure invalid")
			}
		} else {
			fmt.Println("output_structure: ok")
		}
	} else {
		fmt.Printf("output_sha256: unavailable (%v)\n", err)
		if *strict {
			fatalText("manifest output file is unavailable")
		}
	}
	if outputAvailable {
		if err := elfstr.ValidateManifestPlaintextSlots(m, inputPath, outputPath); err != nil {
			if isMissingPathError(err) {
				fmt.Printf("plaintext_slots: unavailable (%v)\n", err)
			} else {
				fmt.Printf("plaintext_slots: invalid (%v)\n", err)
				if *strict {
					fatalText("manifest plaintext slot audit invalid")
				}
			}
		} else {
			fmt.Println("plaintext_slots: ok")
		}
		if elfstr.ManifestRequiresRuntimeDispatchAudit(m) {
			if err := elfstr.ValidateManifestRuntimeDispatch(m, outputPath); err != nil {
				fmt.Printf("runtime_dispatch: invalid (%v)\n", err)
				if *strict {
					fatalText("manifest runtime dispatch audit invalid")
				}
			} else {
				fmt.Println("runtime_dispatch: ok")
			}
		}
	}
	fmt.Printf("entries: %d (%d bytes)\n", m.EntryCount, m.EncryptedSize)
	if m.Report.Preset != "" {
		fmt.Printf("preset: %s cfg_level=%d failure=%s\n", m.Report.Preset, m.Report.ControlFlowLevel, m.Report.FailurePolicy)
		fmt.Printf("report_callsites: candidates=%d selected=%d skipped=%d mode=%s\n", m.Report.CallsiteCandidates, m.Report.CallsiteSelected, m.Report.CallsiteSkipped, m.Report.CallsiteMode)
	}
	fmt.Printf("options: keep_sections=%v safe_scan=%v lazy_callsite=%v lazy_dry_run=%v lazy_limit=%d no_anti_frida_extra=%v manifest_detail=%v\n", m.Options.KeepSections, m.Options.SafeScan, m.Options.LazyCallsite, m.Options.LazyCallsiteDryRun, m.Options.LazyCallsiteLimit, m.Options.NoAntiFridaExtra, m.Options.ManifestDetail)
	fmt.Printf("control_flow: %s\n", m.Protection.ControlFlow)
	if m.Protection.PlaintextAudit != "" {
		fmt.Printf("plaintext_audit: %s\n", m.Protection.PlaintextAudit)
	}
	if m.Protection.Honeypot != "" {
		fmt.Printf("honeypot: %s\n", m.Protection.Honeypot)
	}
	fmt.Printf("callsites: candidates=%d selected=%d mode=%s\n", m.Protection.CallsiteLazyCandidates, m.Protection.CallsiteLazySelected, m.Protection.CallsiteMode)
	if m.RuntimeStub.SHA256 != "" {
		fmt.Printf("runtime_stub: size=%d sha256=%s entry_off=0x%x lazy_entry_off=0x%x honeypot_off=0x%x\n", m.RuntimeStub.Size, m.RuntimeStub.SHA256, m.RuntimeStub.EntryOff, m.RuntimeStub.LazyEntryOff, m.RuntimeStub.HoneypotOff)
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
	out := fs.String("o", "", "output ELF path")
	manifest := fs.String("manifest", "", "manifest path")
	fs.Parse(args)
	if fs.NArg() != 1 || *manifest == "" {
		fmt.Fprintln(os.Stderr, "usage: nbg-elf decrypt -manifest [-strict] <manifest.json> [flags] <encrypted.elf>")
		os.Exit(2)
	}
	m, err := elfstr.DecryptFile(fs.Arg(0), *out, *manifest)
	if err != nil {
		fatal(err)
	}
	fmt.Printf("[+] decrypted strings: %d\n", m.EntryCount)
	fmt.Printf("[+] output: %s\n", m.OutputPath)
}

func usage() {
	fmt.Fprintln(os.Stderr, `nbg-elf

usage:
  nbg-elf
  nbg-elf <input.elf>
  nbg-elf -o <output.vmp> <input.elf>

commands:
  inspect [flags] <input.elf>
  encrypt [-preset safe|balanced|aggressive] [-config protection.json] [flags] <input.elf>
  manifest [-strict] <manifest.json>
  verify <manifest.json>

notes:
  -report prints the planned protection profile without writing output.
  decrypt is intentionally unsupported for runtime-injected outputs; keep the original ELF as the source artifact.
  manifest prints protection metadata and verifies output_sha256 when the output file is accessible.
  verify is an alias for manifest -strict.`)
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
