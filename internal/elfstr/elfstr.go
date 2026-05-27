package elfstr

import (
	"bytes"
	crand "crypto/rand"
	"crypto/sha256"
	"debug/elf"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"math/big"
	"os"
	"path/filepath"
	"strings"
	"time"
	"unicode/utf8"

	"nbg-elf/internal/assets"
)

const (
	Schema                   = "nbg-elf-string-crypt-v6"
	minStringLen             = 4
	defaultMinLen            = 6
	runtimeStageCount        = 4
	plaintextResidueAuditMin = 8
)

type Options struct {
	MinLen             int
	IncludeData        bool
	Watermark          string
	Preset             string
	ControlFlowLevel   int
	FailurePolicy      string
	ManifestDetail     bool
	KeepSections       bool
	LazyCallsite       bool
	LazyCallsiteDryRun bool
	LazyCallsiteLimit  int
	NoAntiFridaExtra   bool
	SafeScan           bool
}

type Manifest struct {
	Schema        string            `json:"schema"`
	Tool          string            `json:"tool"`
	GeneratedUTC  string            `json:"generated_utc"`
	BuildID       string            `json:"build_id"`
	WatermarkHash string            `json:"watermark_hash,omitempty"`
	Protection    ProtectionProfile `json:"protection"`
	Config        ProtectionConfig  `json:"config,omitempty"`
	Report        ProtectionReport  `json:"report,omitempty"`
	Options       ManifestOptions   `json:"options,omitempty"`
	RuntimeStub   RuntimeStubInfo   `json:"runtime_stub,omitempty"`
	InputPath     string            `json:"input_path"`
	OutputPath    string            `json:"output_path"`
	InputSHA256   string            `json:"input_sha256"`
	OutputSHA256  string            `json:"output_sha256"`
	MinLen        int               `json:"min_len"`
	IncludeData   bool              `json:"include_data"`
	EntryCount    int               `json:"entry_count"`
	EncryptedSize int               `json:"encrypted_size"`
	Entries       []Entry           `json:"entries"`
}

type ManifestOptions struct {
	Preset             string `json:"preset,omitempty"`
	ControlFlowLevel   int    `json:"control_flow_level,omitempty"`
	FailurePolicy      string `json:"failure_policy,omitempty"`
	KeepSections       bool   `json:"keep_sections,omitempty"`
	SafeScan           bool   `json:"safe_scan,omitempty"`
	LazyCallsite       bool   `json:"lazy_callsite,omitempty"`
	LazyCallsiteDryRun bool   `json:"lazy_callsite_dry_run,omitempty"`
	LazyCallsiteLimit  int    `json:"lazy_callsite_limit,omitempty"`
	NoAntiFridaExtra   bool   `json:"no_anti_frida_extra,omitempty"`
	ManifestDetail     bool   `json:"manifest_detail,omitempty"`
}

type RuntimeStubInfo struct {
	SHA256        string `json:"sha256"`
	Size          int    `json:"size"`
	EntryOff      uint64 `json:"entry_off"`
	LazyEntryOff  uint64 `json:"lazy_entry_off,omitempty"`
	HoneypotOff   uint64 `json:"honeypot_off,omitempty"`
	LazyCountOff  uint64 `json:"lazy_count_off,omitempty"`
	LazyTableOff  uint64 `json:"lazy_table_off,omitempty"`
	LazyEntrySize int    `json:"lazy_entry_size,omitempty"`
}

type ProtectionProfile struct {
	Runtime                string   `json:"runtime"`
	RandomizedLayout       bool     `json:"randomized_layout"`
	Watermarked            bool     `json:"watermarked"`
	DecryptPhase           string   `json:"decrypt_phase"`
	StageCount             int      `json:"stage_count"`
	KeyScope               string   `json:"key_scope"`
	KeyMaterial            string   `json:"key_material"`
	RuntimeTable           string   `json:"runtime_table"`
	TableOrder             string   `json:"table_order"`
	DecoyCount             int      `json:"decoy_count,omitempty"`
	EntryEncoding          string   `json:"entry_encoding,omitempty"`
	RuntimeSelfCheck       bool     `json:"runtime_self_check"`
	AntiDebug              string   `json:"anti_debug,omitempty"`
	AntiFrida              string   `json:"anti_frida,omitempty"`
	ControlFlow            string   `json:"control_flow,omitempty"`
	PlaintextAudit         string   `json:"plaintext_audit,omitempty"`
	Honeypot               string   `json:"honeypot,omitempty"`
	MemoryWindow           string   `json:"memory_window,omitempty"`
	PageRestore            bool     `json:"page_restore"`
	ManifestDetail         bool     `json:"manifest_detail"`
	CallsiteMode           string   `json:"callsite_mode,omitempty"`
	CallsiteLazyCandidates int      `json:"callsite_lazy_candidates"`
	CallsiteLazySelected   int      `json:"callsite_lazy_selected,omitempty"`
	CallsiteLazyHashes     []string `json:"callsite_lazy_hashes,omitempty"`
}

type Entry struct {
	Section      string `json:"section"`
	Offset       uint64 `json:"offset"`
	VAddr        uint64 `json:"vaddr"`
	Length       int    `json:"length"`
	RuntimeIndex int    `json:"runtime_index"`
	Phase        string `json:"phase"`
	SHA256       string `json:"sha256"`
	Key          uint32 `json:"-"`
	SaltA        uint32 `json:"-"`
	SaltB        uint32 `json:"-"`
	Variant      uint8  `json:"-"`
}

func EncryptFile(inputPath, outputPath, manifestPath string, opts Options) (*Manifest, error) {
	raw, err := os.ReadFile(inputPath)
	if err != nil {
		return nil, err
	}
	minLen := effectiveMinLen(opts)
	entries, err := scan(raw, minLen, opts.IncludeData, opts.SafeScan)
	if err != nil {
		return nil, err
	}
	buildID, err := randomHex(16)
	if err != nil {
		return nil, err
	}
	watermarkHash := hashWatermark(buildID, opts.Watermark)
	padExtra, err := randomIndex(80)
	if err != nil {
		return nil, err
	}
	runtimePad, err := randomBytes(16 + padExtra)
	if err != nil {
		return nil, err
	}
	entries, err = prepareRuntimeEntries(entries)
	if err != nil {
		return nil, err
	}
	meta := RuntimeMeta{
		BuildID:          buildID,
		WatermarkHash:    watermarkHash,
		RandomPad:        runtimePad,
		NoAntiFridaExtra: opts.NoAntiFridaExtra,
	}
	meta.TableSeed, err = randomUint32()
	if err != nil {
		return nil, err
	}
	meta.KeySeed, err = randomUint32()
	if err != nil {
		return nil, err
	}
	if err := fillRuntimeParams(&meta); err != nil {
		return nil, err
	}
	runtimeEntries, decoyCount, err := prepareRuntimeTableEntries(entries)
	if err != nil {
		return nil, err
	}
	callsiteCandidates, err := discoverAArch64Callsites(raw, realRuntimeEntries(runtimeEntries))
	if err != nil {
		return nil, err
	}
	callsiteMode := callsiteModeAArch64ScanOnly
	callsiteSelected := 0
	var selectedLazyCandidates []CallsiteCandidate
	if opts.LazyCallsiteLimit < 0 {
		return nil, fmt.Errorf("lazy callsite limit must be >= 0")
	}
	if opts.LazyCallsiteDryRun || (opts.LazyCallsiteLimit > 0 && !opts.LazyCallsite) {
		callsiteMode = callsiteModeAArch64DryRun
		callsiteSelected = len(limitCallsiteCandidates(callsiteCandidates, opts.LazyCallsiteLimit))
	} else if opts.LazyCallsite {
		if opts.LazyCallsiteLimit <= 0 {
			return nil, fmt.Errorf("lazy callsite patch requires -lazy-callsite-limit > 0")
		}
		callsiteMode = callsiteModeAArch64LazyDecrypt
		selectedLazyCandidates = limitCallsiteCandidates(callsiteCandidates, opts.LazyCallsiteLimit)
		callsiteSelected = len(selectedLazyCandidates)
	}
	out := bytes.Clone(raw)
	var dispatchEntries []LazyDispatchEntry
	if callsiteMode == callsiteModeAArch64LazyDecrypt {
		dispatchEntries = buildLazyDispatchEntries(selectedLazyCandidates, runtimeEntries, meta)
		callsiteSelected = len(dispatchEntries)
	}
	lazyStringVAs := make(map[uint64]struct{})
	if callsiteMode == callsiteModeAArch64LazyDecrypt {
		lazyStringVAs = lazyDispatchStringEntryVAs(dispatchEntries, runtimeEntries)
	}
	for _, e := range runtimeEntries {
		if e.Length == 0 {
			continue
		}
		if _, ok := lazyStringVAs[e.VAddr]; ok {
			continue
		}
		cryptRuntimeString(out[e.Offset:uint64(e.Offset)+uint64(e.Length)], e.VAddr, uint32(e.RuntimeIndex), e.Key, meta.ParamStringPos, meta.ParamStringIndex, e.SaltA, e.SaltB, e.Variant)
	}
	out, err = injectRuntimeDecryptor(out, runtimeEntries, meta)
	if err != nil {
		return nil, err
	}

	// Lazy decrypt: patch callsite BLs and append dispatch table
	if callsiteMode == callsiteModeAArch64LazyDecrypt {
		if len(dispatchEntries) > 0 {
			patchedCallsites := 0
			// Find the runtime payload VA from the RWX LOAD segment that
			// injectRuntimeDecryptor already added.
			payloadVA := findPayloadSegmentVA(out)
			if payloadVA == 0 {
				return nil, fmt.Errorf("lazy callsite patch requested but runtime payload segment was not found")
			}
			trampolineVA := payloadVA + stubLazyEntryOff

			// Use raw ELF sections to map TextVA→file offset for BL patching.
			rawF, _ := elf.NewFile(bytes.NewReader(raw))
			if rawF != nil {
				for _, de := range dispatchEntries {
					for _, sec := range rawF.Sections {
						if sec.Addr <= de.TextVA && de.TextVA < sec.Addr+sec.Size {
							textOff := sec.Offset + (de.TextVA - sec.Addr)
							if patchCallsiteBLIfTarget(out, textOff, de.TextVA, de.OrigTarget, trampolineVA) {
								patchedCallsites++
							}
							break
						}
					}
				}
				rawF.Close()
			}
			if patchedCallsites != len(dispatchEntries) {
				return nil, fmt.Errorf("lazy callsite patch incomplete: patched %d/%d", patchedCallsites, len(dispatchEntries))
			}
			callsiteSelected = patchedCallsites
			out = appendLazyDispatchTable(out, dispatchEntries, payloadVA)
		}
	}

	if !opts.KeepSections {
		stripSectionHeaders(out)
	}
	if err := validateInjectedOutput(out, opts.KeepSections); err != nil {
		return nil, err
	}
	manifestEntries := realRuntimeEntries(runtimeEntries)
	if err := validateNoPlaintextResidue(raw, out, nonLazyRuntimeEntries(manifestEntries, lazyStringVAs)); err != nil {
		return nil, err
	}
	if outputPath == "" {
		outputPath = inputPath + ".vmp"
	}
	if manifestPath == "" {
		manifestPath = outputPath + ".manifest.json"
	}
	if err := writeFileAtomic(outputPath, out, 0o755); err != nil {
		return nil, err
	}
	inSum := sha256.Sum256(raw)
	outSum := sha256.Sum256(out)
	total := 0
	for _, e := range manifestEntries {
		total += e.Length
	}
	lazyHashes := lazyRuntimeEntryHashes(manifestEntries, lazyStringVAs)
	storedEntries := manifestEntries
	if !opts.ManifestDetail {
		storedEntries = nil
	}
	manifestPhase := "entrypoint-pre-main:staged; runtime-self-check; anti-debug-best-effort; anti-frida-maps-probe; core-dump-disabled; decrypted-pages-dontdump; runtime-payload-dontdump; runtime-payload-resealed; section-table-stripped"
	if opts.KeepSections {
		manifestPhase = "entrypoint-pre-main:staged; runtime-self-check; anti-debug-best-effort; anti-frida-maps-probe; core-dump-disabled; decrypted-pages-dontdump; runtime-payload-dontdump; runtime-payload-resealed"
	}
	antiFrida := "proc-self-maps-smaps-multichunk-frida-gum-gadget-probe-best-effort; proc-self-fd-link-frida-gum-gadget-probe-best-effort; proc-net-unix-frida-gum-gadget-probe-best-effort; proc-self-task-comm-frida-gum-gadget-probe-best-effort"
	if opts.NoAntiFridaExtra {
		antiFrida = "extra-frida-gum-gadget-probes-disabled-for-compat-test; tracerpid-status-probe-kept"
	}
	controlFlowLevel := effectiveControlFlowLevel(opts.ControlFlowLevel)
	controlFlow := callsiteControlFlowLabel(callsiteMode, controlFlowLevel)
	if opts.SafeScan {
		controlFlow += "; safe-scan-test"
	}
	runtimeTable := "encrypted-per-entry-row-resealed"
	if callsiteMode == callsiteModeAArch64LazyDecrypt {
		runtimeTable += "; lazy-dispatch-table-randomized"
	}
	report := ProtectionReport{
		Preset:             effectivePreset(opts.Preset),
		ControlFlowLevel:   controlFlowLevel,
		FailurePolicy:      effectiveFailurePolicy(opts.FailurePolicy),
		Strings:            len(manifestEntries),
		Bytes:              total,
		CallsiteCandidates: len(callsiteCandidates),
		CallsiteSelected:   callsiteSelected,
		CallsiteSkipped:    len(callsiteCandidates) - callsiteSelected,
		CallsiteMode:       callsiteMode,
		CallsiteLimit:      opts.LazyCallsiteLimit,
		Warnings:           protectionWarnings(opts, len(callsiteCandidates), callsiteSelected),
	}
	cfg := ProtectionConfig{
		Preset:             report.Preset,
		ControlFlowLevel:   report.ControlFlowLevel,
		LazyCallsite:       opts.LazyCallsite,
		LazyCallsiteDryRun: opts.LazyCallsiteDryRun,
		LazyCallsiteLimit:  opts.LazyCallsiteLimit,
		SafeScan:           opts.SafeScan,
		KeepSections:       opts.KeepSections,
		NoAntiFridaExtra:   opts.NoAntiFridaExtra,
		FailurePolicy:      report.FailurePolicy,
	}
	m := &Manifest{
		Schema:        Schema,
		Tool:          "nbg-elf",
		GeneratedUTC:  time.Now().UTC().Format(time.RFC3339),
		BuildID:       buildID,
		WatermarkHash: watermarkHash,
		Config:        cfg,
		Report:        report,
		Options: ManifestOptions{
			Preset:             report.Preset,
			ControlFlowLevel:   report.ControlFlowLevel,
			FailurePolicy:      report.FailurePolicy,
			KeepSections:       opts.KeepSections,
			SafeScan:           opts.SafeScan,
			LazyCallsite:       opts.LazyCallsite,
			LazyCallsiteDryRun: opts.LazyCallsiteDryRun,
			LazyCallsiteLimit:  opts.LazyCallsiteLimit,
			NoAntiFridaExtra:   opts.NoAntiFridaExtra,
			ManifestDetail:     opts.ManifestDetail,
		},
		RuntimeStub: RuntimeStubInfo{
			SHA256:        runtimeStubSHA256Hex(),
			Size:          len(assets.StrdecBlob),
			EntryOff:      stubEntryOff,
			LazyEntryOff:  stubLazyEntryOff,
			HoneypotOff:   stubHoneypotEntryOff,
			LazyCountOff:  stubLazyCountOff,
			LazyTableOff:  stubLazyTableOff,
			LazyEntrySize: stubLazyEntSize,
		},
		Protection: ProtectionProfile{
			Runtime:                "arm64-entrypoint-stub",
			RandomizedLayout:       true,
			Watermarked:            watermarkHash != "",
			DecryptPhase:           manifestPhase,
			StageCount:             runtimeStageCount + controlFlowLevel - 1,
			KeyScope:               "per-string-salted-variant",
			KeyMaterial:            "xorshift-split-runtime-seed-uint32-per-entry-salt",
			RuntimeTable:           runtimeTable,
			TableOrder:             "per-build-stage-shuffle-random-decoy-clusters",
			DecoyCount:             decoyCount,
			EntryEncoding:          "xorshift-arx-per-entry-salt-variant-cfg",
			RuntimeSelfCheck:       true,
			AntiDebug:              "prctl-dumpable-off; ptrace-traceme-best-effort; tracerpid-status-probe",
			AntiFrida:              antiFrida,
			ControlFlow:            controlFlow,
			PlaintextAudit:         "protected-entry-residue-scan-before-write",
			Honeypot:               "unreachable-fake-decryptor-and-fake-table",
			CallsiteMode:           callsiteMode,
			CallsiteLazyCandidates: len(callsiteCandidates),
			CallsiteLazySelected:   callsiteSelected,
			CallsiteLazyHashes:     lazyHashes,
			MemoryWindow:           "entry-row-resealed; seeds-wiped; procfs-scratch-wiped; pages-rx-restored; failure-policy-safe-exit",
			PageRestore:            true,
			ManifestDetail:         opts.ManifestDetail,
		},
		InputPath:     inputPath,
		OutputPath:    outputPath,
		InputSHA256:   hex.EncodeToString(inSum[:]),
		OutputSHA256:  hex.EncodeToString(outSum[:]),
		MinLen:        minLen,
		IncludeData:   opts.IncludeData,
		EntryCount:    len(manifestEntries),
		EncryptedSize: total,
		Entries:       storedEntries,
	}
	if err := writeManifest(manifestPath, m); err != nil {
		return nil, err
	}
	return m, nil
}

func callsiteControlFlowLabel(mode string, level int) string {
	base := "opaque-branches-per-entry-loop; aarch64-callsite-candidate-scan"
	switch effectiveControlFlowLevel(level) {
	case 1:
		base += "; cfg-level-safe"
	case 3:
		base += "; cfg-level-aggressive; runtime-state-dispatch; honeypot-branch-fanout"
	default:
		base += "; cfg-level-balanced; runtime-state-dispatch"
	}
	if mode == callsiteModeAArch64DryRun {
		return base + "; aarch64-callsite-lazy-dry-run"
	}
	if mode == callsiteModeAArch64LazyDecrypt {
		return base + "; aarch64-callsite-lazy-decrypt; lazy-dispatch-randomized"
	}
	return base
}

func runtimeStubSHA256Hex() string {
	sum := sha256.Sum256(assets.StrdecBlob)
	return hex.EncodeToString(sum[:])
}

func DecryptFile(inputPath, outputPath, manifestPath string) (*Manifest, error) {
	return nil, fmt.Errorf("decrypt is not supported for runtime-injected outputs; keep the original ELF as the source artifact")
}

func ScanFile(inputPath string, minLen int, includeData bool) ([]Entry, error) {
	raw, err := os.ReadFile(inputPath)
	if err != nil {
		return nil, err
	}
	if minLen == 0 {
		minLen = defaultMinLen
	}
	if minLen < minStringLen {
		minLen = minStringLen
	}
	return Scan(raw, minLen, includeData)
}

func Scan(raw []byte, minLen int, includeData bool) ([]Entry, error) {
	return scan(raw, minLen, includeData, false)
}

func scan(raw []byte, minLen int, includeData bool, safeScan bool) ([]Entry, error) {
	f, err := elf.NewFile(bytes.NewReader(raw))
	if err != nil {
		return nil, err
	}
	defer f.Close()
	if f.Class != elf.ELFCLASS64 {
		return nil, fmt.Errorf("only ELF64 is supported")
	}
	var entries []Entry
	for _, sec := range f.Sections {
		if sec.Size == 0 || sec.Offset == 0 {
			continue
		}
		if !wantedSection(sec.Name, includeData, safeScan) {
			continue
		}
		if sec.Offset+sec.Size > uint64(len(raw)) {
			continue
		}
		chunk := raw[sec.Offset : sec.Offset+sec.Size]
		entries = append(entries, scanSectionWithMode(sec.Name, sec.Offset, sec.Addr, chunk, minLen, safeScan)...)
	}
	return entries, nil
}

func ValidateEncryptedOutputBytes(data []byte, keepSections bool) error {
	return validateInjectedOutput(data, keepSections)
}

func ValidateEncryptedOutputFile(path string, keepSections bool) error {
	raw, err := os.ReadFile(path)
	if err != nil {
		return err
	}
	return ValidateEncryptedOutputBytes(raw, keepSections)
}

func ValidateManifestPlaintextSlots(m *Manifest, inputPath, outputPath string) error {
	inputRaw, err := os.ReadFile(inputPath)
	if err != nil {
		return err
	}
	outputRaw, err := os.ReadFile(outputPath)
	if err != nil {
		return err
	}
	minLen := m.MinLen
	if minLen == 0 {
		minLen = defaultMinLen
	}
	if minLen < minStringLen {
		minLen = minStringLen
	}
	entries, err := scan(inputRaw, minLen, m.IncludeData, m.Options.SafeScan)
	if err != nil {
		return err
	}
	if len(entries) != m.EntryCount {
		return fmt.Errorf("plaintext audit entry count mismatch: scan=%d manifest=%d", len(entries), m.EntryCount)
	}
	if len(m.Protection.CallsiteLazyHashes) > 0 {
		lazyHashes := make(map[string]struct{}, len(m.Protection.CallsiteLazyHashes))
		for _, h := range m.Protection.CallsiteLazyHashes {
			lazyHashes[h] = struct{}{}
		}
		filtered := entries[:0]
		for _, e := range entries {
			if _, ok := lazyHashes[e.SHA256]; ok {
				continue
			}
			filtered = append(filtered, e)
		}
		entries = filtered
	}
	return validateNoPlaintextResidue(inputRaw, outputRaw, entries)
}

func ValidateManifestRuntimeDispatch(m *Manifest, outputPath string) error {
	if m.Protection.CallsiteMode != callsiteModeAArch64LazyDecrypt {
		return nil
	}
	outputRaw, err := os.ReadFile(outputPath)
	if err != nil {
		return err
	}
	return validateInjectedOutputLazyDispatch(outputRaw)
}

func ManifestRequiresRuntimeDispatchAudit(m *Manifest) bool {
	return m.Protection.CallsiteMode == callsiteModeAArch64LazyDecrypt
}

func ValidateManifestRuntimeTable(m *Manifest, outputPath string) error {
	outputRaw, err := os.ReadFile(outputPath)
	if err != nil {
		return err
	}
	expectedEntries := m.EntryCount + m.Protection.DecoyCount
	return validateInjectedOutputRuntimeTable(outputRaw, expectedEntries)
}

func ReadManifest(path string) (*Manifest, error) {
	raw, err := os.ReadFile(path)
	if err != nil {
		return nil, err
	}
	var m Manifest
	if err := json.Unmarshal(raw, &m); err != nil {
		return nil, err
	}
	if m.Schema != Schema {
		return nil, fmt.Errorf("unsupported manifest schema %q", m.Schema)
	}
	return &m, nil
}

func wantedSection(name string, includeData bool, safeScan bool) bool {
	switch name {
	case ".rodata":
		return true
	case ".data.rel.ro":
		return !safeScan
	case ".data":
		return includeData && !safeScan
	default:
		return false
	}
}

func scanSection(name string, baseOff, baseVA uint64, data []byte, minLen int) []Entry {
	return scanSectionWithMode(name, baseOff, baseVA, data, minLen, false)
}

func scanSectionWithMode(name string, baseOff, baseVA uint64, data []byte, minLen int, safeScan bool) []Entry {
	var out []Entry
	for i := 0; i < len(data); {
		if data[i] == 0 || !isCandidateByte(data[i]) {
			i++
			continue
		}
		start := i
		for i < len(data) && data[i] != 0 && isCandidateByte(data[i]) {
			i++
		}
		terminated := i < len(data) && data[i] == 0
		if terminated {
			candidate := data[start:i]
			if safeScan {
				if isSafeStringCandidate(candidate, minLen) {
					out = appendString(out, name, baseOff, baseVA, data, start, i, minLen)
				}
			} else if isCompatStringCandidate(candidate, minLen) || isForcedShortStringCandidate(candidate) {
				out = appendString(out, name, baseOff, baseVA, data, start, i, minLen)
			}
		}
		if i < len(data) && data[i] == 0 {
			i++
		}
	}
	return out
}

const safeScanMinLen = 12

func isSafeStringCandidate(s []byte, minLen int) bool {
	if minLen < safeScanMinLen {
		minLen = safeScanMinLen
	}
	if !isCompatStringCandidate(s, minLen) {
		return false
	}
	if len(s) < safeScanMinLen {
		return false
	}
	if !utf8.Valid(s) {
		return false
	}
	// Avoid identifiers / protocol paths in the diagnostic build. Prefer strings
	// that look like user-facing text or format messages.
	text := string(s)
	lower := strings.ToLower(text)
	for _, marker := range []string{"/", ".so", "android", "linker", "jni", "env", "class", "method", "symbol"} {
		if strings.Contains(lower, marker) {
			return false
		}
	}
	for _, r := range text {
		if r >= 0x80 || r == ' ' || r == '%' || r == ':' || r == '?' || r == '!' || r == '！' || r == '？' || r == '：' || r == '，' || r == '。' {
			return true
		}
	}
	return false
}

func isForcedShortStringCandidate(s []byte) bool {
	if len(s) == 0 || len(s) > 5 {
		return false
	}
	alpha := 0
	upper := 0
	for _, b := range s {
		if (b >= 'A' && b <= 'Z') || (b >= 'a' && b <= 'z') {
			alpha++
			if b >= 'A' && b <= 'Z' {
				upper++
			}
			continue
		}
		if b >= '0' && b <= '9' {
			continue
		}
		return false
	}
	// Pick up compact ASCII identifiers such as product tags / short probes
	// that are below the normal minimum length, without exploding into every
	// low-value one or two byte token.
	return alpha >= 3 && upper >= 2
}

func appendString(out []Entry, section string, baseOff, baseVA uint64, data []byte, start, end, minLen int) []Entry {
	if end-start < minLen && !isForcedShortStringCandidate(data[start:end]) {
		return out
	}
	s := data[start:end]
	sum := sha256.Sum256(s)
	return append(out, Entry{
		Section: section,
		Offset:  baseOff + uint64(start),
		VAddr:   baseVA + uint64(start),
		Length:  len(s),
		SHA256:  hex.EncodeToString(sum[:]),
	})
}

func prepareRuntimeEntries(entries []Entry) ([]Entry, error) {
	shuffled := append([]Entry(nil), entries...)
	for i := len(shuffled) - 1; i > 0; i-- {
		j, err := randomIndex(i + 1)
		if err != nil {
			return nil, err
		}
		shuffled[i], shuffled[j] = shuffled[j], shuffled[i]
	}

	stages := make([][]Entry, runtimeStageCount)
	for i, e := range shuffled {
		stage := 0
		if runtimeStageCount > 1 {
			stage = i % runtimeStageCount
		}
		e.Phase = fmt.Sprintf("entrypoint-pre-main:stage-%d", stage)
		stages[stage] = append(stages[stage], e)
	}

	out := make([]Entry, 0, len(entries))
	for _, stageEntries := range stages {
		out = append(out, stageEntries...)
	}
	for i := range out {
		key, err := randomUint32()
		if err != nil {
			return nil, err
		}
		saltA, err := randomUint32()
		if err != nil {
			return nil, err
		}
		saltB, err := randomUint32()
		if err != nil {
			return nil, err
		}
		variant, err := randomIndex(16)
		if err != nil {
			return nil, err
		}
		out[i].RuntimeIndex = i
		out[i].Key = key
		out[i].SaltA = saltA
		out[i].SaltB = saltB
		out[i].Variant = uint8(variant)
	}
	return out, nil
}

func randomHex(n int) (string, error) {
	buf, err := randomBytes(n)
	if err != nil {
		return "", err
	}
	return hex.EncodeToString(buf), nil
}

func randomBytes(n int) ([]byte, error) {
	if n <= 0 {
		return nil, nil
	}
	buf := make([]byte, n)
	if _, err := crand.Read(buf); err != nil {
		return nil, err
	}
	return buf, nil
}

func randomIndex(n int) (int, error) {
	if n <= 0 {
		return 0, fmt.Errorf("invalid random bound %d", n)
	}
	v, err := crand.Int(crand.Reader, big.NewInt(int64(n)))
	if err != nil {
		return 0, err
	}
	return int(v.Int64()), nil
}

func randomUint32() (uint32, error) {
	var b [4]byte
	if _, err := crand.Read(b[:]); err != nil {
		return 0, err
	}
	v := uint32(b[0]) | uint32(b[1])<<8 | uint32(b[2])<<16 | uint32(b[3])<<24
	if v == 0 {
		v = 0x6d2b79f5
	}
	return v, nil
}

func randomNonZeroByte() (byte, error) {
	var b [1]byte
	for {
		if _, err := crand.Read(b[:]); err != nil {
			return 0, err
		}
		if b[0] != 0 {
			return b[0], nil
		}
	}
}

func hashWatermark(buildID, watermark string) string {
	watermark = strings.TrimSpace(watermark)
	if watermark == "" {
		return ""
	}
	sum := sha256.Sum256([]byte(buildID + "\x00" + watermark))
	return hex.EncodeToString(sum[:])
}

func isASCIIPrintable(b byte) bool {
	return b >= 0x20 && b <= 0x7e
}

func isCandidateByte(b byte) bool {
	return isASCIIPrintable(b) || b >= 0x80 || b == 0x1b || b == 0x09 || b == 0x0a || b == 0x0d
}

func isCompatStringCandidate(s []byte, minLen int) bool {
	if len(s) < minLen || len(s) > 256 {
		return false
	}
	hasAlpha := false
	hasHumanMark := false
	hasHigh := false
	for _, b := range s {
		if !isCandidateByte(b) {
			return false
		}
		if b >= 0x80 {
			hasHigh = true
		}
		if (b >= 65 && b <= 90) || (b >= 97 && b <= 122) || b >= 0x80 {
			hasAlpha = true
		}
		if b == 32 || b == 37 || b == 40 || b == 41 || b == 44 || b == 45 || b == 46 || b == 47 || b == 58 || b == 63 || b == 95 {
			hasHumanMark = true
		}
		switch b {
		case 92, 36, 123, 125, 60, 62, 38, 124, 96:
			return false
		}
	}
	if hasHigh && !utf8.Valid(s) {
		return false
	}
	if !hasAlpha {
		return false
	}
	if !hasHumanMark && !hasHigh {
		return false
	}
	lower := strings.ToLower(string(s))
	if lower == "/proc/self/maps" {
		return true
	}
	risky := []string{
		".so", "/system", "/proc", "/dev", "linker", "android",
		"json", "xml", "http:", "https:", "content-type", "user-agent",
		"usage", "permission", "exec", "mount", "ptrace", "selinux",
	}
	if !hasHigh {
		risky = append(risky, "/data")
	}
	for _, marker := range risky {
		if strings.Contains(lower, marker) {
			return false
		}
	}
	return true
}

func writeManifest(path string, m *Manifest) error {
	raw, err := json.MarshalIndent(m, "", "  ")
	if err != nil {
		return err
	}
	raw = append(raw, '\n')
	return writeFileAtomic(path, raw, 0o644)
}

func writeFileAtomic(path string, data []byte, perm os.FileMode) error {
	if err := os.MkdirAll(filepath.Dir(path), 0o755); err != nil {
		return err
	}
	dir := filepath.Dir(path)
	base := filepath.Base(path)
	tmp, err := os.CreateTemp(dir, "."+base+".tmp-*")
	if err != nil {
		return err
	}
	tmpName := tmp.Name()
	cleanup := true
	defer func() {
		if cleanup {
			_ = os.Remove(tmpName)
		}
	}()
	if _, err := tmp.Write(data); err != nil {
		_ = tmp.Close()
		return err
	}
	if err := tmp.Chmod(perm); err != nil {
		_ = tmp.Close()
		return err
	}
	if err := tmp.Close(); err != nil {
		return err
	}
	if err := os.Rename(tmpName, path); err != nil {
		return err
	}
	cleanup = false
	return nil
}

func trimKnownSuffix(path string) string {
	for _, suffix := range []string{".strenc", ".vmp", ".enc"} {
		if len(path) > len(suffix) && path[len(path)-len(suffix):] == suffix {
			return path[:len(path)-len(suffix)]
		}
	}
	return path
}
