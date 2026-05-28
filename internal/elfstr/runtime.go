package elfstr

import (
	"bytes"
	"debug/elf"
	"encoding/binary"
	"encoding/hex"
	"fmt"
	"sort"

	"nbg-elf/internal/assets"
)

const (
	stubEntryOff            = 0x50
	stubLazyEntryOff        = 0x1068
	stubHoneypotEntryOff    = 0x162c
	stubAnchorOff           = 0x16c8
	stubStaticVAOff         = 0x16d0
	stubOrigEntryOff        = 0x16d8
	stubPageVAOff           = 0x16e0
	stubPageLenOff          = 0x16e8
	stubPayloadLenOff       = 0x16f0
	stubEntryCountOff       = 0x16f8
	stubGuardSeedOff        = 0x16fc
	stubTableSeedOff        = 0x1700
	stubKeySeedOff          = 0x1704
	stubParamTableAOff      = 0x1708
	stubParamTableBOff      = 0x170c
	stubParamKeyIndexOff    = 0x1710
	stubParamStringPosOff   = 0x1714
	stubParamStringIndexOff = 0x1718
	stubGuardHashOff        = 0x171c
	stubOrigEntryKeyOff     = 0x1720
	stubTableOff            = 0x1728
	stubTableEntSize        = 24
	stubLazyCountOff        = 0x1740
	stubLazyHashOff         = 0x1744
	stubLazyTableOff        = 0x1748
	stubLazyEntSize         = 56
	stubRuntimeTableADROff  = 0xb98
	stubDataEndOff          = 0x1798
	stubLazyHashPlaceholder = 0x89abcdef
	lazyDispatchHashMask    = 0xa5c35a7e

	ptLoad     = uint32(1)
	ptNote     = uint32(4)
	ptGNUStack = uint32(0x6474e551)
	pfX        = uint32(1)
	pfW        = uint32(2)
	pfR        = uint32(4)
)

type RuntimeMeta struct {
	BuildID          string
	WatermarkHash    string
	RandomPad        []byte
	TableSeed        uint32
	KeySeed          uint32
	ParamTableA      uint32
	ParamTableB      uint32
	ParamKeyIndex    uint32
	ParamStringPos   uint32
	ParamStringIndex uint32
	GuardSeed        uint32
	GuardHash        uint32
	OrigEntryKey     uint64
	NoAntiFridaExtra bool
}

func injectRuntimeDecryptor(data []byte, entries []Entry, meta RuntimeMeta) ([]byte, error) {
	if len(entries) == 0 {
		return data, nil
	}
	if len(data) < 0x40 {
		return nil, fmt.Errorf("file too small")
	}
	if err := validateEmbeddedStubLayout(); err != nil {
		return nil, err
	}
	f, err := elf.NewFile(bytes.NewReader(data))
	if err != nil {
		return nil, err
	}
	defer f.Close()
	if f.Machine != elf.EM_AARCH64 {
		return nil, fmt.Errorf("runtime decryptor only supports ARM64 ELF")
	}
	if len(entries) > 0xffff {
		return nil, fmt.Errorf("too many string entries: %d", len(entries))
	}

	ehdr := readEhdr64(data)
	loadAlign := maxLoadAlign(data, ehdr)
	payloadOff := alignUp(uint64(len(data)), loadAlign)
	payloadVA := choosePayloadVA(data, ehdr, loadAlign, payloadOff)
	origEntry := binary.LittleEndian.Uint64(data[0x18:])

	stub := append([]byte(nil), assets.StrdecBlob...)
	if len(stub) < stubTableOff {
		return nil, fmt.Errorf("runtime stub too small")
	}
	if meta.TableSeed == 0 {
		meta.TableSeed, err = randomUint32()
		if err != nil {
			return nil, err
		}
	}
	if meta.KeySeed == 0 {
		meta.KeySeed, err = randomUint32()
		if err != nil {
			return nil, err
		}
	}
	if err := fillRuntimeParams(&meta); err != nil {
		return nil, err
	}
	table := buildRuntimeStringTable(entries, meta.KeySeed, meta.ParamKeyIndex)
	cryptRuntimeTable(table, meta.TableSeed, meta.ParamTableA, meta.ParamTableB)
	metaBlob := buildRuntimeMeta(meta)
	tableOff := alignUp(uint64(stubDataEndOff), 16)
	payload := make([]byte, 0, int(tableOff)+len(table)+len(metaBlob))
	payload = append(payload, stub...)
	for uint64(len(payload)) < tableOff {
		payload = append(payload, 0)
	}
	if err := patchADRToPayloadOffset(payload, stubRuntimeTableADROff, tableOff); err != nil {
		return nil, err
	}
	payload = append(payload, table...)
	payload = append(payload, metaBlob...)
	for len(payload)%16 != 0 {
		payload = append(payload, 0)
	}
	if meta.NoAntiFridaExtra {
		disableAntiFridaExtra(payload)
	}
	if err := randomizeStubPlaceholders(payload); err != nil {
		return nil, err
	}
	pageVA, pageLen := stringPageWindow(entries)
	binary.LittleEndian.PutUint64(payload[stubStaticVAOff:], payloadVA+stubAnchorOff)
	binary.LittleEndian.PutUint64(payload[stubOrigEntryOff:], origEntry^meta.OrigEntryKey)
	binary.LittleEndian.PutUint64(payload[stubOrigEntryKeyOff:], meta.OrigEntryKey)
	binary.LittleEndian.PutUint64(payload[stubPageVAOff:], pageVA)
	binary.LittleEndian.PutUint64(payload[stubPageLenOff:], pageLen)
	binary.LittleEndian.PutUint32(payload[stubEntryCountOff:], uint32(len(entries)))
	binary.LittleEndian.PutUint32(payload[stubTableSeedOff:], encodeTableSeed(meta.TableSeed))
	binary.LittleEndian.PutUint32(payload[stubKeySeedOff:], encodeKeySeed(meta.KeySeed))
	binary.LittleEndian.PutUint32(payload[stubParamTableAOff:], meta.ParamTableA)
	binary.LittleEndian.PutUint32(payload[stubParamTableBOff:], meta.ParamTableB)
	binary.LittleEndian.PutUint32(payload[stubParamKeyIndexOff:], meta.ParamKeyIndex)
	binary.LittleEndian.PutUint32(payload[stubParamStringPosOff:], meta.ParamStringPos)
	binary.LittleEndian.PutUint32(payload[stubParamStringIndexOff:], meta.ParamStringIndex)
	binary.LittleEndian.PutUint32(payload[stubGuardSeedOff:], meta.GuardSeed)
	meta.GuardHash = computeRuntimeGuardHash(payload[stubEntryOff:stubAnchorOff], meta.GuardSeed)
	binary.LittleEndian.PutUint32(payload[stubGuardHashOff:], meta.GuardHash)
	if len(payload)%16 != 0 {
		panic("runtime payload must stay 16-byte aligned")
	}
	binary.LittleEndian.PutUint64(payload[stubPayloadLenOff:], uint64(len(payload)))

	targetIdx := findReusablePhdr(data, ehdr)
	if targetIdx < 0 {
		return nil, fmt.Errorf("no reusable program header found (need PT_GNU_STACK or PT_NOTE)")
	}
	newData := append([]byte(nil), data...)
	if uint64(len(newData)) < payloadOff {
		padLen := int(payloadOff) - len(newData)
		pad, err := randomBytes(padLen)
		if err != nil {
			return nil, err
		}
		newData = append(newData, pad...)
	}
	newData = append(newData, payload...)

	phOff := ehdr.Phoff + uint64(targetIdx)*uint64(ehdr.Phentsize)
	writePhdr64(newData, phOff, elf64Phdr{
		Type:   ptLoad,
		Flags:  pfR | pfW | pfX,
		Off:    payloadOff,
		Vaddr:  payloadVA,
		Paddr:  payloadVA,
		Filesz: uint64(len(payload)),
		Memsz:  uint64(len(payload)),
		Align:  loadAlign,
	})
	sortLoadPhdrs(newData, ehdr)
	binary.LittleEndian.PutUint64(newData[0x18:], payloadVA+stubEntryOff)
	return newData, nil
}

type LazyDispatchEntry struct {
	TextVA     uint64
	StringVA   uint64
	Length     uint32
	KeyState   uint32
	PosParam   uint32
	IdxParam   uint32
	SaltA      uint32
	SaltB      uint32
	Variant    uint8
	OrigTarget uint64
}

func validateInjectedOutput(data []byte, keepSections bool) error {
	if len(data) < 0x40 || data[0] != 0x7f || data[1] != 'E' || data[2] != 'L' || data[3] != 'F' {
		return fmt.Errorf("output is not an ELF64 file")
	}
	ehdr := readEhdr64(data)
	entry := binary.LittleEndian.Uint64(data[0x18:])
	if !keepSections && (ehdr.Shoff != 0 || ehdr.Shentsize != 0 || ehdr.Shnum != 0 || ehdr.Shstrndx != 0) {
		return fmt.Errorf("section headers were not stripped")
	}
	var payload *elf64Phdr
	for i := 0; i < int(ehdr.Phnum); i++ {
		ph := readPhdr64(data, ehdr.Phoff+uint64(i)*uint64(ehdr.Phentsize))
		if ph.Type == ptLoad && ph.Flags == pfR|pfW|pfX {
			p := ph
			payload = &p
			break
		}
	}
	if payload == nil {
		return fmt.Errorf("injected runtime payload LOAD segment not found")
	}
	if payload.Off+payload.Filesz > uint64(len(data)) {
		return fmt.Errorf("runtime payload segment exceeds file size")
	}
	if entry != payload.Vaddr+stubEntryOff {
		return fmt.Errorf("entrypoint got %#x want %#x", entry, payload.Vaddr+stubEntryOff)
	}
	payloadRaw := data[payload.Off : payload.Off+payload.Filesz]
	if len(payloadRaw) <= stubPayloadLenOff+8 {
		return fmt.Errorf("runtime payload too small for payload length field")
	}
	declaredLen := binary.LittleEndian.Uint64(payloadRaw[stubPayloadLenOff:])
	if declaredLen == 0 || declaredLen > payload.Filesz {
		return fmt.Errorf("runtime payload length field invalid: %#x filesz=%#x", declaredLen, payload.Filesz)
	}
	if len(payloadRaw) <= stubGuardHashOff+4 || len(payloadRaw) <= stubGuardSeedOff+4 || len(payloadRaw) < stubAnchorOff {
		return fmt.Errorf("runtime payload too small for guard fields")
	}
	guardSeed := binary.LittleEndian.Uint32(payloadRaw[stubGuardSeedOff:])
	guardHash := binary.LittleEndian.Uint32(payloadRaw[stubGuardHashOff:])
	if want := computeRuntimeGuardHash(payloadRaw[stubEntryOff:stubAnchorOff], guardSeed); guardHash != want {
		return fmt.Errorf("runtime guard hash mismatch: got %#x want %#x", guardHash, want)
	}
	return nil
}

func validateInjectedOutputLazyDispatch(data []byte, expectedEntries int) error {
	ph, payloadRaw, declaredLen, err := findRuntimePayload(data)
	if err != nil {
		return err
	}
	entries, err := validateLazyDispatchMetadata(payloadRaw, ph.Vaddr, declaredLen, expectedEntries)
	if err != nil {
		return err
	}
	return validateLazyDispatchCallsites(data, ph.Vaddr+stubLazyEntryOff, entries)
}

func validateInjectedOutputRuntimeTable(data []byte, expectedEntries int) error {
	_, payloadRaw, _, err := findRuntimePayload(data)
	if err != nil {
		return err
	}
	return validateRuntimeTableMetadata(payloadRaw, expectedEntries)
}

func findRuntimePayload(data []byte) (elf64Phdr, []byte, uint64, error) {
	ehdr := readEhdr64(data)
	for i := 0; i < int(ehdr.Phnum); i++ {
		ph := readPhdr64(data, ehdr.Phoff+uint64(i)*uint64(ehdr.Phentsize))
		if ph.Type != ptLoad || ph.Flags != pfR|pfW|pfX {
			continue
		}
		if ph.Off+ph.Filesz > uint64(len(data)) {
			return elf64Phdr{}, nil, 0, fmt.Errorf("runtime payload segment exceeds file size")
		}
		payloadRaw := data[ph.Off : ph.Off+ph.Filesz]
		if len(payloadRaw) <= stubPayloadLenOff+8 {
			return elf64Phdr{}, nil, 0, fmt.Errorf("runtime payload too small for payload length field")
		}
		declaredLen := binary.LittleEndian.Uint64(payloadRaw[stubPayloadLenOff:])
		if declaredLen == 0 || declaredLen > ph.Filesz {
			return elf64Phdr{}, nil, 0, fmt.Errorf("runtime payload length field invalid: %#x filesz=%#x", declaredLen, ph.Filesz)
		}
		return ph, payloadRaw, declaredLen, nil
	}
	return elf64Phdr{}, nil, 0, fmt.Errorf("injected runtime payload LOAD segment not found")
}

func validateRuntimeTableMetadata(payloadRaw []byte, expectedEntries int) error {
	if expectedEntries < 0 {
		return fmt.Errorf("expected runtime entry count must be >= 0")
	}
	if len(payloadRaw) <= stubEntryCountOff+4 {
		return fmt.Errorf("runtime payload too small for entry count")
	}
	entryCount := binary.LittleEndian.Uint32(payloadRaw[stubEntryCountOff:])
	if uint64(entryCount) != uint64(expectedEntries) {
		return fmt.Errorf("runtime entry count got %d want %d", entryCount, expectedEntries)
	}
	tableOff := alignUp(uint64(stubDataEndOff), 16)
	tableLen := uint64(entryCount) * uint64(stubTableEntSize)
	if tableLen/uint64(stubTableEntSize) != uint64(entryCount) {
		return fmt.Errorf("runtime table length overflow: count=%d", entryCount)
	}
	if tableOff < uint64(stubLazyTableOff+8) {
		return fmt.Errorf("runtime table overlaps lazy metadata: table_off=%#x lazy_end=%#x", tableOff, stubLazyTableOff+8)
	}
	if tableOff > uint64(len(payloadRaw)) || tableLen > uint64(len(payloadRaw))-tableOff {
		return fmt.Errorf("runtime table outside payload: off=%#x len=%#x filesz=%#x", tableOff, tableLen, len(payloadRaw))
	}
	if len(payloadRaw) <= stubRuntimeTableADROff+4 {
		return fmt.Errorf("runtime payload too small for table ADR")
	}
	rd, targetOff, ok := decodeAArch64ADR(binary.LittleEndian.Uint32(payloadRaw[stubRuntimeTableADROff:]), stubRuntimeTableADROff)
	if !ok || rd != 25 {
		return fmt.Errorf("runtime table ADR is invalid")
	}
	if targetOff != tableOff {
		return fmt.Errorf("runtime table ADR target got %#x want %#x", targetOff, tableOff)
	}
	return nil
}

func validateLazyDispatchMetadata(payloadRaw []byte, payloadVA, declaredLen uint64, expectedEntries int) ([]LazyDispatchEntry, error) {
	if expectedEntries < 0 {
		return nil, fmt.Errorf("expected lazy dispatch count must be >= 0")
	}
	if len(payloadRaw) <= stubLazyCountOff+4 || len(payloadRaw) <= stubLazyHashOff+4 || len(payloadRaw) <= stubLazyTableOff+8 {
		return nil, fmt.Errorf("runtime payload too small for lazy dispatch metadata")
	}
	lazyCount := binary.LittleEndian.Uint32(payloadRaw[stubLazyCountOff:])
	lazyHash := binary.LittleEndian.Uint32(payloadRaw[stubLazyHashOff:]) ^ lazyDispatchHashMask
	if uint64(lazyCount) != uint64(expectedEntries) {
		return nil, fmt.Errorf("lazy dispatch entry count got %d want %d", lazyCount, expectedEntries)
	}
	lazyTableVA := binary.LittleEndian.Uint64(payloadRaw[stubLazyTableOff:])
	if lazyCount == 0 {
		if lazyTableVA != 0 && lazyTableVA != 0x123456789abcdef0 {
			return nil, fmt.Errorf("lazy dispatch table set without entries: %#x", lazyTableVA)
		}
		return nil, nil
	}
	if lazyTableVA < payloadVA {
		return nil, fmt.Errorf("lazy dispatch table VA before payload: %#x payload=%#x", lazyTableVA, payloadVA)
	}
	tableOff := lazyTableVA - payloadVA
	tableLen := uint64(lazyCount) * uint64(stubLazyEntSize)
	if tableLen/uint64(stubLazyEntSize) != uint64(lazyCount) {
		return nil, fmt.Errorf("lazy dispatch table length overflow: count=%d", lazyCount)
	}
	if tableOff > declaredLen || tableLen > declaredLen-tableOff {
		return nil, fmt.Errorf("lazy dispatch table outside payload: off=%#x len=%#x payload_len=%#x", tableOff, tableLen, declaredLen)
	}
	if tableOff+tableLen > uint64(len(payloadRaw)) {
		return nil, fmt.Errorf("lazy dispatch table outside payload file bytes: off=%#x len=%#x filesz=%#x", tableOff, tableLen, len(payloadRaw))
	}
	if got := hashLazyDispatchTable(payloadRaw[tableOff:tableOff+tableLen], lazyCount); got != lazyHash {
		return nil, fmt.Errorf("lazy dispatch table hash got %#x want %#x", got, lazyHash)
	}
	entries := make([]LazyDispatchEntry, 0, lazyCount)
	for i := uint32(0); i < lazyCount; i++ {
		off := int(tableOff) + int(i)*stubLazyEntSize
		de, tag, pad := decodeLazyDispatchEntry(payloadRaw[off:off+stubLazyEntSize], i)
		if de.TextVA == 0 {
			return nil, fmt.Errorf("lazy dispatch entry %d has empty text VA", i)
		}
		if de.StringVA == 0 {
			return nil, fmt.Errorf("lazy dispatch entry %d has empty string VA", i)
		}
		if de.Length == 0 {
			return nil, fmt.Errorf("lazy dispatch entry %d has empty length", i)
		}
		if de.OrigTarget == 0 {
			return nil, fmt.Errorf("lazy dispatch entry %d has empty original target", i)
		}
		if want := lazyDispatchTag(de); tag != want {
			return nil, fmt.Errorf("lazy dispatch entry %d tag mismatch: got %#x want %#x", i, tag, want)
		}
		for _, b := range pad {
			if b != 0 {
				return nil, fmt.Errorf("lazy dispatch entry %d padding is not zero", i)
			}
		}
		entries = append(entries, de)
	}
	return entries, nil
}

func validateLazyDispatchCallsites(data []byte, trampolineVA uint64, entries []LazyDispatchEntry) error {
	if len(entries) == 0 {
		return nil
	}
	ehdr := readEhdr64(data)
	for i, de := range entries {
		textOff, ok := fileOffsetForVA(data, ehdr, de.TextVA)
		if !ok {
			return fmt.Errorf("lazy dispatch entry %d text VA not mapped: %#x", i, de.TextVA)
		}
		if textOff+4 > uint64(len(data)) {
			return fmt.Errorf("lazy dispatch entry %d text instruction outside file: off=%#x", i, textOff)
		}
		target, ok := decodeAArch64BL(binary.LittleEndian.Uint32(data[textOff:]), de.TextVA)
		if !ok {
			return fmt.Errorf("lazy dispatch entry %d text instruction is not BL: va=%#x", i, de.TextVA)
		}
		if target != trampolineVA {
			return fmt.Errorf("lazy dispatch entry %d callsite target got %#x want %#x", i, target, trampolineVA)
		}
	}
	return nil
}

func fileOffsetForVA(data []byte, ehdr elf64Ehdr, va uint64) (uint64, bool) {
	for i := 0; i < int(ehdr.Phnum); i++ {
		ph := readPhdr64(data, ehdr.Phoff+uint64(i)*uint64(ehdr.Phentsize))
		if ph.Type != ptLoad || ph.Filesz == 0 {
			continue
		}
		if ph.Vaddr <= va && va < ph.Vaddr+ph.Filesz {
			return ph.Off + (va - ph.Vaddr), true
		}
	}
	return 0, false
}

func validateNoPlaintextResidue(raw, out []byte, entries []Entry) error {
	for _, e := range entries {
		if e.Length < plaintextResidueAuditMin {
			continue
		}
		end := e.Offset + uint64(e.Length)
		if end > uint64(len(raw)) {
			return fmt.Errorf("plaintext audit entry out of input range: off=%#x len=%d", e.Offset, e.Length)
		}
		if end > uint64(len(out)) {
			return fmt.Errorf("plaintext audit entry out of output range: off=%#x len=%d", e.Offset, e.Length)
		}
		plain := raw[e.Offset:end]
		if bytes.Equal(out[e.Offset:end], plain) {
			return fmt.Errorf("plaintext residue still present at protected slot: section=%s off=%#x vaddr=%#x len=%d sha256=%s", e.Section, e.Offset, e.VAddr, e.Length, e.SHA256)
		}
	}
	return nil
}

func validateEmbeddedStubLayout() error {
	if len(assets.StrdecBlob) < stubLazyTableOff+stubLazyEntSize {
		return fmt.Errorf("runtime stub too small: len=%#x need=%#x", len(assets.StrdecBlob), stubLazyTableOff+stubLazyEntSize)
	}
	if binary.LittleEndian.Uint32(assets.StrdecBlob[stubLazyCountOff:]) != 0x01234567 {
		return fmt.Errorf("runtime stub lazy count placeholder mismatch at %#x", stubLazyCountOff)
	}
	if binary.LittleEndian.Uint32(assets.StrdecBlob[stubLazyHashOff:]) != stubLazyHashPlaceholder {
		return fmt.Errorf("runtime stub lazy hash placeholder mismatch at %#x", stubLazyHashOff)
	}
	if binary.LittleEndian.Uint64(assets.StrdecBlob[stubLazyTableOff:]) != 0x123456789abcdef0 {
		return fmt.Errorf("runtime stub lazy table placeholder mismatch at %#x", stubLazyTableOff)
	}
	return nil
}

func buildLazyDispatchEntries(candidates []CallsiteCandidate, entries []Entry, meta RuntimeMeta) []LazyDispatchEntry {
	if len(candidates) == 0 {
		return nil
	}
	out := make([]LazyDispatchEntry, 0, len(candidates))
	for _, c := range candidates {
		e, ok := findRuntimeEntryForVA(entries, c.StringVAddr)
		if !ok {
			continue
		}
		// Compute initial decryption state: same as cryptRuntimeString init
		key := e.Key
		if key == 0 {
			key = 0x6d2b79f5
		}
		posParam := meta.ParamStringPos
		if posParam == 0 {
			posParam = 0x9d
		}
		idxParam := meta.ParamStringIndex
		if idxParam == 0 {
			idxParam = 0x7b
		}
		state := key ^ uint32(e.VAddr) ^ uint32(e.VAddr>>32) ^ uint32(e.Length) ^ (uint32(e.RuntimeIndex) * idxParam) ^ posParam ^ e.SaltA ^ e.SaltB ^ uint32(e.Variant&0x0f)
		out = append(out, LazyDispatchEntry{
			TextVA:     c.TextVAddr,
			StringVA:   e.VAddr,
			Length:     uint32(e.Length),
			KeyState:   state,
			PosParam:   posParam,
			IdxParam:   idxParam,
			SaltA:      e.SaltA,
			SaltB:      e.SaltB | (uint32(e.ContentTag) << 16),
			Variant:    e.Variant & 0x0f,
			OrigTarget: c.CallTarget,
		})
	}
	shuffleLazyDispatchEntries(out)
	return out
}

func shuffleLazyDispatchEntries(entries []LazyDispatchEntry) {
	for i := len(entries) - 1; i > 0; i-- {
		j, err := randomIndex(i + 1)
		if err != nil {
			continue
		}
		entries[i], entries[j] = entries[j], entries[i]
	}
}

func findRuntimeEntryForVA(entries []Entry, va uint64) (Entry, bool) {
	for _, e := range entries {
		if e.Length <= 0 || e.Section == "<decoy>" {
			continue
		}
		end := e.VAddr + uint64(e.Length)
		if e.VAddr <= va && va < end {
			return e, true
		}
	}
	return Entry{}, false
}

func lazyDispatchStringEntryVAs(dispatchEntries []LazyDispatchEntry, entries []Entry) map[uint64]struct{} {
	out := make(map[uint64]struct{})
	for _, de := range dispatchEntries {
		if e, ok := findRuntimeEntryForVA(entries, de.StringVA); ok {
			out[e.VAddr] = struct{}{}
		}
	}
	return out
}

func appendLazyDispatchTable(data []byte, dispatchEntries []LazyDispatchEntry, payloadVA uint64) []byte {
	if len(dispatchEntries) == 0 {
		return data
	}
	ehdr := readEhdr64(data)
	var payloadPh *elf64Phdr
	for i := 0; i < int(ehdr.Phnum); i++ {
		ph := readPhdr64(data, ehdr.Phoff+uint64(i)*uint64(ehdr.Phentsize))
		if ph.Type == ptLoad && ph.Flags == pfR|pfW|pfX {
			payloadPh = &ph
			break
		}
	}
	if payloadPh == nil {
		return data
	}

	payload := data[payloadPh.Off : payloadPh.Off+payloadPh.Filesz]
	tableStart := alignUp(uint64(len(payload)), 8)
	tableLen := uint64(stubLazyEntSize * len(dispatchEntries))
	newPayloadLen := int(tableStart + tableLen)

	if int(stubLazyCountOff)+4 > len(payload) || int(stubLazyHashOff)+4 > len(payload) || int(stubLazyTableOff)+8 > len(payload) {
		return data
	}
	binary.LittleEndian.PutUint32(payload[stubLazyCountOff:], uint32(len(dispatchEntries)))
	binary.LittleEndian.PutUint64(payload[stubLazyTableOff:], payloadVA+tableStart)
	for len(payload) < newPayloadLen {
		payload = append(payload, 0)
	}
	for i, de := range dispatchEntries {
		off := int(tableStart) + i*stubLazyEntSize
		encodeLazyDispatchEntry(payload[off:off+stubLazyEntSize], de, uint32(i))
	}
	lazyHash := hashLazyDispatchTable(payload[tableStart:tableStart+tableLen], uint32(len(dispatchEntries)))
	binary.LittleEndian.PutUint32(payload[stubLazyHashOff:], lazyHash^lazyDispatchHashMask)
	binary.LittleEndian.PutUint64(payload[stubPayloadLenOff:], uint64(len(payload)))

	// Rebuild the data array if payload grew
	if uint64(len(payload)) > payloadPh.Filesz {
		newData := make([]byte, 0, payloadPh.Off+uint64(newPayloadLen))
		newData = append(newData, data[:payloadPh.Off]...)
		newData = append(newData, payload...)
		// Update phdr
		phOff := ehdr.Phoff
		for i := 0; i < int(ehdr.Phnum); i++ {
			ph := readPhdr64(newData, phOff+uint64(i)*uint64(ehdr.Phentsize))
			if ph.Type == ptLoad && ph.Flags == pfR|pfW|pfX {
				writePhdr64(newData, phOff+uint64(i)*uint64(ehdr.Phentsize), elf64Phdr{
					Type: ptLoad, Flags: pfR | pfW | pfX,
					Off: ph.Off, Vaddr: ph.Vaddr, Paddr: ph.Paddr,
					Filesz: uint64(len(payload)), Memsz: uint64(len(payload)),
					Align: ph.Align,
				})
				break
			}
		}
		return newData
	}
	// Payload didn't grow, write back
	copy(data[payloadPh.Off:payloadPh.Off+uint64(len(payload))], payload)
	return data
}

func encodeLazyDispatchEntry(dst []byte, de LazyDispatchEntry, index uint32) {
	if len(dst) < stubLazyEntSize {
		return
	}
	var plain [stubLazyEntSize]byte
	binary.LittleEndian.PutUint64(plain[0:], de.TextVA)
	binary.LittleEndian.PutUint64(plain[8:], de.StringVA)
	binary.LittleEndian.PutUint32(plain[16:], de.Length)
	binary.LittleEndian.PutUint32(plain[20:], de.KeyState)
	binary.LittleEndian.PutUint32(plain[24:], de.PosParam)
	binary.LittleEndian.PutUint32(plain[28:], de.IdxParam)
	binary.LittleEndian.PutUint32(plain[32:], de.SaltA)
	binary.LittleEndian.PutUint32(plain[36:], de.SaltB)
	plain[40] = de.Variant
	binary.LittleEndian.PutUint32(plain[41:], lazyDispatchTag(de))
	binary.LittleEndian.PutUint64(plain[48:], de.OrigTarget)
	copy(dst, plain[:])
	cryptLazyDispatchEntry(dst[:stubLazyEntSize], index)
}

func decodeLazyDispatchEntry(src []byte, index uint32) (LazyDispatchEntry, uint32, [3]byte) {
	var raw [stubLazyEntSize]byte
	copy(raw[:], src[:stubLazyEntSize])
	cryptLazyDispatchEntry(raw[:], index)
	return LazyDispatchEntry{
		TextVA:     binary.LittleEndian.Uint64(raw[0:]),
		StringVA:   binary.LittleEndian.Uint64(raw[8:]),
		Length:     binary.LittleEndian.Uint32(raw[16:]),
		KeyState:   binary.LittleEndian.Uint32(raw[20:]),
		PosParam:   binary.LittleEndian.Uint32(raw[24:]),
		IdxParam:   binary.LittleEndian.Uint32(raw[28:]),
		SaltA:      binary.LittleEndian.Uint32(raw[32:]),
		SaltB:      binary.LittleEndian.Uint32(raw[36:]),
		Variant:    raw[40],
		OrigTarget: binary.LittleEndian.Uint64(raw[48:]),
	}, binary.LittleEndian.Uint32(raw[41:]), [3]byte{raw[45], raw[46], raw[47]}
}

func cryptLazyDispatchEntry(buf []byte, index uint32) {
	for i := 0; i < stubLazyEntSize; i++ {
		buf[i] ^= lazyDispatchMask(index, uint32(i))
	}
}

func lazyDispatchMask(index, pos uint32) byte {
	v := index*0x45d9f3b + pos*0x27d4eb2d + 0x6a09e667
	v ^= v << 13
	v ^= v >> 17
	v ^= v << 5
	v += (index + 1) * 0x9e3779b9
	v ^= pos << 11
	v ^= v >> 16
	return byte(v)
}

func hashLazyDispatchTable(table []byte, count uint32) uint32 {
	h := count ^ 0x6d2b79f5
	for i, b := range table {
		h += uint32(b) + uint32(i)*0x45d9f3b
		h ^= h << 13
		h ^= h >> 17
		h ^= h << 5
	}
	if h == 0 {
		return 0x6d2b79f5
	}
	return h
}

// findPayloadSegmentVA scans the ELF program headers and returns the virtual
// address of the first RWX LOAD segment (the injected runtime payload).  Returns
// 0 when no such segment is found.
func findPayloadSegmentVA(data []byte) uint64 {
	ehdr := readEhdr64(data)
	for i := 0; i < int(ehdr.Phnum); i++ {
		ph := readPhdr64(data, ehdr.Phoff+uint64(i)*uint64(ehdr.Phentsize))
		if ph.Type == ptLoad && ph.Flags == pfR|pfW|pfX {
			return ph.Vaddr
		}
	}
	return 0
}

func disableAntiFridaExtra(payload []byte) {
	// Compatibility test mode: skip only the newly added Frida/Gum/Gadget maps
	// and fd-link probes. Keep the older anti-debug/status probe and all runtime
	// decrypt/self-check logic intact so this build can isolate false positives
	// from the extra probes without becoming a fully unprotected control.
	patchAArch64B(payload, 0xc8, 0x270)
	patchAArch64B(payload, 0x3c8, 0x584)
}

func patchAArch64B(payload []byte, fromOff, toOff uint32) {
	if int(fromOff)+4 > len(payload) {
		return
	}
	delta := int64(toOff) - int64(fromOff)
	if delta%4 != 0 {
		return
	}
	imm26 := delta / 4
	if imm26 < -(1<<25) || imm26 >= (1<<25) {
		return
	}
	insn := uint32(0x14000000) | (uint32(imm26) & 0x03ffffff)
	binary.LittleEndian.PutUint32(payload[fromOff:], insn)
}

func patchADRToPayloadOffset(payload []byte, adrOff uint64, targetOff uint64) error {
	if adrOff+4 > uint64(len(payload)) {
		return fmt.Errorf("ADR patch offset outside payload: %#x", adrOff)
	}
	insn := binary.LittleEndian.Uint32(payload[adrOff:])
	rd, _, ok := decodeAArch64ADR(insn, adrOff)
	if !ok {
		return fmt.Errorf("instruction at %#x is not ADR", adrOff)
	}
	adr, ok := encodeAArch64ADR(rd, adrOff, targetOff)
	if !ok {
		return fmt.Errorf("ADR target out of range: pc=%#x target=%#x", adrOff, targetOff)
	}
	binary.LittleEndian.PutUint32(payload[adrOff:], adr)
	return nil
}

func randomizeStubPlaceholders(payload []byte) error {
	for _, span := range []struct {
		off int
		n   int
	}{
		{stubAnchorOff, 8},
		{stubStaticVAOff, 8},
		{stubOrigEntryOff, 8},
		{stubPageVAOff, 8},
		{stubPageLenOff, 8},
		{stubPayloadLenOff, 8},
		{stubEntryCountOff, 8},
		{stubTableSeedOff, 4},
		{stubKeySeedOff, 4},
		{stubParamTableAOff, 4},
		{stubParamTableBOff, 4},
		{stubParamKeyIndexOff, 4},
		{stubParamStringPosOff, 4},
		{stubParamStringIndexOff, 4},
		{stubOrigEntryKeyOff, 8},
	} {
		if span.off+span.n > len(payload) {
			return fmt.Errorf("runtime stub placeholder outside payload")
		}
		raw, err := randomBytes(span.n)
		if err != nil {
			return err
		}
		copy(payload[span.off:span.off+span.n], raw)
	}
	return nil
}

func buildRuntimeStringTable(entries []Entry, keySeed, keyIndexParam uint32) []byte {
	out := make([]byte, len(entries)*stubTableEntSize)
	for i, e := range entries {
		off := i * stubTableEntSize
		length := uint32(e.Length)
		saltB := e.SaltB & 0xffff
		contentTag := e.ContentTag
		tag := runtimeEntryTag(e.Key, e.VAddr, length, uint32(i), keySeed, keyIndexParam, e.SaltA, saltB, e.Variant)
		packedLen := packRuntimeLength(length, e.Variant, tag)
		binary.LittleEndian.PutUint64(out[off:], e.VAddr)
		binary.LittleEndian.PutUint32(out[off+8:], packedLen)
		binary.LittleEndian.PutUint32(out[off+12:], splitRuntimeKey(e.Key, e.VAddr, length, uint32(i), keySeed, keyIndexParam, e.SaltA, saltB, e.Variant))
		binary.LittleEndian.PutUint32(out[off+16:], e.SaltA)
		binary.LittleEndian.PutUint32(out[off+20:], saltB|(uint32(contentTag)<<16))
	}
	return out
}

func cryptRuntimeTable(table []byte, tableSeed, tableA, tableB uint32) {
	for pos := range table {
		mask := tableSeed ^ (uint32(pos) * tableA) ^ (uint32(pos>>3) * tableB) ^ 0x9e3779b9
		mask = mixXorShift32(mask)
		mask += uint32(pos >> 8)
		table[pos] ^= byte(mask)
	}
}

func splitRuntimeKey(key uint32, va uint64, length, index, keySeed, keyIndexParam, saltA, saltB uint32, variant uint8) uint32 {
	return key ^ runtimeKeySplitMask(va, length, index, keySeed, keyIndexParam, saltA, saltB, variant)
}

func runtimeKeySplitMask(va uint64, length, index, keySeed, keyIndexParam, saltA, saltB uint32, variant uint8) uint32 {
	mask := keySeed ^ uint32(va) ^ uint32(va>>32) ^ length ^ (index * keyIndexParam) ^ saltA ^ saltB ^ uint32(variant&0x0f) ^ 0x85ebca6b
	mask = mixXorShift32(mask)
	mask ^= uint32(va >> 7)
	mask += length * 0x045d9f3b
	return mask
}

func runtimeEntryTag(key uint32, va uint64, length, index, keySeed, keyIndexParam, saltA, saltB uint32, variant uint8) uint8 {
	tag := key ^ keySeed ^ uint32(va) ^ uint32(va>>32) ^ length ^ (index * keyIndexParam) ^ saltA ^ bitsRotateLeft32(saltB, 5)
	tag ^= uint32(variant&0x0f) * 0x045d9f3b
	tag ^= 0x7f4a7c15
	tag = mixXorShift32(tag)
	tag ^= tag >> 11
	tag += 0x9e3779b9
	return byte(tag ^ (tag >> 8) ^ (tag >> 16) ^ (tag >> 24))
}

func runtimeContentTag(e Entry) uint16 {
	tag := e.Key ^ uint32(e.VAddr) ^ uint32(e.VAddr>>32) ^ uint32(e.Length) ^ e.SaltA ^ bitsRotateLeft32(e.SaltB&0xffff, 11) ^ uint32(e.Variant&0x0f) ^ 0x9e3779b9
	plain := decodeEntryPlainForTag(e.Plain)
	for pos, b := range plain {
		tag ^= uint32(b) + uint32(pos)
		tag = mixXorShift32(tag)
	}
	return uint16(tag ^ (tag >> 16))
}

func decodeEntryPlainForTag(s string) []byte {
	if s == "" {
		return nil
	}
	raw, err := hex.DecodeString(s)
	if err == nil && len(raw) > 0 {
		return raw
	}
	return []byte(s)
}

func stripRuntimePlaintext(entries []Entry) []Entry {
	for i := range entries {
		entries[i].Plain = ""
	}
	return entries
}

func bitsRotateLeft32(v uint32, n uint) uint32 {
	n &= 31
	if n == 0 {
		return v
	}
	return (v << n) | (v >> (32 - n))
}

func packRuntimeLength(length uint32, variant uint8, tag uint8) uint32 {
	return (length & 0xffff) | (uint32(tag) << 16) | (uint32(variant&0x0f) << 24)
}

func encodeTableSeed(seed uint32) uint32 {
	return seed ^ 0xa5c35a7e
}

func encodeKeySeed(seed uint32) uint32 {
	return seed ^ 0x6d9e3b17
}

const runtimeKeyIndexParam = uint32(0x31)

func fillRuntimeParams(meta *RuntimeMeta) error {
	var err error
	if meta.ParamTableA == 0 {
		meta.ParamTableA, err = randomOddUint32(0x5d)
		if err != nil {
			return err
		}
	}
	if meta.ParamTableB == 0 {
		meta.ParamTableB, err = randomOddUint32(0x11)
		if err != nil {
			return err
		}
	}
	if meta.ParamKeyIndex == 0 {
		meta.ParamKeyIndex, err = randomOddUint32(0x31)
		if err != nil {
			return err
		}
	}
	if meta.ParamStringPos == 0 {
		meta.ParamStringPos, err = randomOddUint32(0x9d)
		if err != nil {
			return err
		}
	}
	if meta.ParamStringIndex == 0 {
		meta.ParamStringIndex, err = randomOddUint32(0x7b)
		if err != nil {
			return err
		}
	}
	if meta.OrigEntryKey == 0 {
		lo, err := randomUint32()
		if err != nil {
			return err
		}
		hi, err := randomUint32()
		if err != nil {
			return err
		}
		meta.OrigEntryKey = uint64(hi)<<32 | uint64(lo)
	}
	if meta.GuardSeed == 0 {
		meta.GuardSeed, err = randomUint32()
		if err != nil {
			return err
		}
	}
	return nil
}

func randomOddUint32(fallback uint32) (uint32, error) {
	v, err := randomUint32()
	if err != nil {
		return 0, err
	}
	v |= 1
	if v == 0 {
		v = fallback | 1
	}
	return v, nil
}

func prepareRuntimeTableEntries(entries []Entry) ([]Entry, int, error) {
	if len(entries) == 0 {
		return entries, 0, nil
	}
	pageVA, pageLen := stringPageWindow(entries)
	decoyCount := len(entries)/3 + 64
	if decoyCount > 1024 {
		decoyCount = 1024
	}
	out := make([]Entry, 0, len(entries)+decoyCount)
	decoyLeft := decoyCount
	for i := 0; i < len(entries); i++ {
		if decoyLeft > 0 {
			n, err := randomIndex(4)
			if err != nil {
				return nil, 0, err
			}
			for ; n > 0 && decoyLeft > 0; n-- {
				d, err := makeDecoyEntry(pageVA, pageLen)
				if err != nil {
					return nil, 0, err
				}
				out = append(out, d)
				decoyLeft--
			}
		}
		out = append(out, entries[i])
	}
	for decoyLeft > 0 {
		d, err := makeDecoyEntry(pageVA, pageLen)
		if err != nil {
			return nil, 0, err
		}
		out = append(out, d)
		decoyLeft--
	}
	for i := len(out) - 1; i > 0; i-- {
		j, err := randomIndex(i + 1)
		if err != nil {
			return nil, 0, err
		}
		out[i], out[j] = out[j], out[i]
	}
	for i := range out {
		out[i].RuntimeIndex = i
	}
	return out, decoyCount, nil
}

func withRuntimeContentTags(entries []Entry, enabledVAs map[uint64]struct{}) []Entry {
	out := append([]Entry(nil), entries...)
	overlap := make([]bool, len(out))
	for i := range out {
		if _, enabled := enabledVAs[out[i].VAddr]; !enabled {
			overlap[i] = true
			continue
		}
		if out[i].Length <= 0 || out[i].Plain == "" {
			overlap[i] = true
			continue
		}
		startI := out[i].VAddr
		endI := startI + uint64(out[i].Length)
		if endI <= startI {
			overlap[i] = true
			continue
		}
		for j := 0; j < i; j++ {
			startJ := out[j].VAddr
			endJ := startJ + uint64(out[j].Length)
			if endJ <= startJ {
				continue
			}
			if startI < endJ && startJ < endI {
				overlap[i] = true
				overlap[j] = true
			}
		}
	}
	for i := range out {
		if overlap[i] {
			out[i].ContentTag = 0
			continue
		}
		tag := runtimeContentTag(out[i])
		if tag == 0 {
			tag = 1
		}
		out[i].ContentTag = tag
	}
	return out
}

func realRuntimeEntries(entries []Entry) []Entry {
	out := make([]Entry, 0, len(entries))
	for _, e := range entries {
		if e.Length == 0 || e.Section == "<decoy>" {
			continue
		}
		out = append(out, e)
	}
	return out
}

func nonLazyRuntimeEntries(entries []Entry, lazyStringVAs map[uint64]struct{}) []Entry {
	if len(lazyStringVAs) == 0 {
		return entries
	}
	out := make([]Entry, 0, len(entries))
	for _, e := range entries {
		if _, ok := lazyStringVAs[e.VAddr]; ok {
			continue
		}
		out = append(out, e)
	}
	return out
}

func lazyRuntimeEntryHashes(entries []Entry, lazyStringVAs map[uint64]struct{}) []string {
	if len(lazyStringVAs) == 0 {
		return nil
	}
	out := make([]string, 0, len(lazyStringVAs))
	for _, e := range entries {
		if _, ok := lazyStringVAs[e.VAddr]; ok {
			out = append(out, e.SHA256)
		}
	}
	return out
}

func lazyDispatchTag(de LazyDispatchEntry) uint32 {
	tag := uint32(de.TextVA) ^ uint32(de.TextVA>>32) ^
		uint32(de.StringVA) ^ uint32(de.StringVA>>32) ^
		de.Length ^ de.KeyState ^ de.PosParam ^ bitsRotateLeft32(de.IdxParam, 3) ^
		de.SaltA ^ bitsRotateLeft32(de.SaltB, 7) ^
		(uint32(de.Variant&0x0f) * 0x9e3779b9) ^
		uint32(de.OrigTarget) ^ uint32(de.OrigTarget>>32) ^ 0x6a09e667
	tag = mixXorShift32(tag)
	tag += de.Length*0x045d9f3b + de.PosParam
	tag = mixXorShift32(tag)
	return tag
}

func makeDecoyEntry(pageVA, pageLen uint64) (Entry, error) {
	key, err := randomUint32()
	if err != nil {
		return Entry{}, err
	}
	noise, err := randomUint32()
	if err != nil {
		return Entry{}, err
	}
	lengthNoise, err := randomIndex(64)
	if err != nil {
		return Entry{}, err
	}
	saltA, err := randomUint32()
	if err != nil {
		return Entry{}, err
	}
	saltB, err := randomUint32()
	if err != nil {
		return Entry{}, err
	}
	variant, err := randomIndex(4)
	if err != nil {
		return Entry{}, err
	}
	decoyVA := decoyVAOutsideWindow(pageVA, pageLen, noise)
	return Entry{
		Section: "<decoy>",
		VAddr:   decoyVA,
		Length:  8 + lengthNoise,
		Phase:   "decoy",
		Key:     key,
		SaltA:   saltA,
		SaltB:   saltB & 0xffff,
		Variant: uint8(variant),
	}, nil
}

func decoyVAOutsideWindow(pageVA, pageLen uint64, noise uint32) uint64 {
	offset := 0x1000 + uint64(noise&0xffff)
	if pageVA != 0 && pageLen != 0 {
		windowEnd := pageVA + pageLen
		if windowEnd >= pageVA && windowEnd <= ^uint64(0)-offset {
			return windowEnd + offset
		}
		if pageVA > offset+0x1000 {
			return pageVA - offset - 0x1000
		}
	}
	return 0x100000000 + uint64(noise&0xfffff)
}

func buildRuntimeMeta(meta RuntimeMeta) []byte {
	out := make([]byte, 0, 8+16+32+4+len(meta.RandomPad))
	out = append(out, 0x91, 0xb7, 0x2d, 0x6c, 0x03, 0xda, 0x5e, 0xc4)
	out = append(out, decodeHexFixed(meta.BuildID, 16)...)
	out = append(out, decodeHexFixed(meta.WatermarkHash, 32)...)
	padLen := len(meta.RandomPad)
	if padLen > 255 {
		padLen = 255
	}
	out = append(out, byte(padLen), 0, 0, 0)
	out = append(out, meta.RandomPad[:padLen]...)

	state := meta.TableSeed ^ meta.KeySeed ^ uint32(len(out))*0x045d9f3b
	for i := range out {
		state += uint32(i)*0x9e3779b9 + 0x7f4a7c15
		state = mixXorShift32(state)
		out[i] ^= byte(state >> uint((i&3)*8))
	}
	// Second pass with reversed index and different constants: two-pass XOR
	// makes the meta blob statistically independent of any single-byte guess.
	n := uint32(len(out))
	for i := 0; i < len(out); i++ {
		ri := n - 1 - uint32(i)
		state = state ^ (ri * 0x3c6ef372) + meta.ParamTableA
		state ^= state << 11
		state ^= state >> 9
		state ^= meta.ParamTableB
		out[i] ^= byte(state>>uint((i&3)*8)) ^ byte(state>>16)
	}
	return out
}

func decodeHexFixed(s string, n int) []byte {
	out := make([]byte, n)
	if s == "" {
		return out
	}
	raw, err := hex.DecodeString(s)
	if err != nil {
		copy(out, []byte(s))
		return out
	}
	copy(out, raw)
	return out
}

func cryptRuntimeString(buf []byte, va uint64, index uint32, key, posParam, indexParam, saltA, saltB uint32, variant uint8) {
	if key == 0 {
		key = 0x6d2b79f5
	}
	if posParam == 0 {
		posParam = 0x9d
	}
	if indexParam == 0 {
		indexParam = 0x7b
	}
	state := key ^ uint32(va) ^ uint32(va>>32) ^ uint32(len(buf)) ^ (index * indexParam) ^ posParam ^ saltA ^ saltB ^ uint32(variant&0x0f)
	for pos := range buf {
		state += posParam
		state += saltB
		state ^= uint32(pos)*indexParam + saltA
		state = mixXorShift32(state)
		mask := state + uint32(pos)*posParam + uint32(va>>4)
		if variant&0x01 != 0 {
			mask ^= state >> 8
		}
		if variant&0x02 != 0 {
			mask ^= saltB
		}
		if variant&0x04 != 0 {
			mask ^= state << 7
		}
		if variant&0x08 != 0 {
			mask ^= state >> 11
		}
		mask ^= runtimeStringHardMask(state, va, uint32(pos), saltA, saltB, indexParam, variant)
		buf[pos] ^= byte(mask)
	}
}

func runtimeStringHardMask(state uint32, va uint64, pos, saltA, saltB, indexParam uint32, variant uint8) uint32 {
	mask := state ^ (pos*0x27d4eb2d + saltA) ^ uint32(va>>16) ^ saltB ^ ((pos + 1) * 0x165667b1)
	mask = mixXorShift32(mask)
	hard := (mask ^ (mask >> 16)) + (state << 3)

	aux := state ^ saltA ^ bitsRotateLeft32(saltB, 9) ^ uint32(va) ^ uint32(va>>32)
	aux += pos*0x7f4a7c15 + indexParam
	aux = mixXorShift32(aux)
	aux ^= bitsRotateLeft32(aux+(uint32(variant&0x0f)*0x9e3779b9), uint((pos&7)+5))
	aux ^= aux >> 13
	return hard ^ aux
}

func computeRuntimeGuardHash(code []byte, seed uint32) uint32 {
	h := seed
	for _, b := range code {
		h += uint32(b)
		h = mixXorShift32(h)
	}
	return h
}

func mixXorShift32(v uint32) uint32 {
	v ^= v << 13
	v ^= v >> 17
	v ^= v << 5
	return v
}

func stringPageWindow(entries []Entry) (uint64, uint64) {
	start := uint64(0)
	end := uint64(0)
	for _, e := range entries {
		if e.Length <= 0 || e.Section == "<decoy>" {
			continue
		}
		s := e.VAddr &^ 0xfff
		n := alignUp(e.VAddr+uint64(e.Length), 0x1000)
		if start == 0 || s < start {
			start = s
		}
		if n > end {
			end = n
		}
	}
	if start == 0 || end <= start {
		return 0, 0
	}
	return start, end - start
}

func maxLoadAlign(data []byte, ehdr elf64Ehdr) uint64 {
	align := uint64(0x1000)
	for i := 0; i < int(ehdr.Phnum); i++ {
		ph := readPhdr64(data, ehdr.Phoff+uint64(i)*uint64(ehdr.Phentsize))
		if ph.Type == ptLoad && ph.Align > align && ph.Align&(ph.Align-1) == 0 {
			align = ph.Align
		}
	}
	return align
}

func choosePayloadVA(data []byte, ehdr elf64Ehdr, loadAlign, payloadOff uint64) uint64 {
	var maxEnd uint64
	for i := 0; i < int(ehdr.Phnum); i++ {
		ph := readPhdr64(data, ehdr.Phoff+uint64(i)*uint64(ehdr.Phentsize))
		if ph.Type != ptLoad {
			continue
		}
		end := ph.Vaddr + ph.Memsz
		if ph.Memsz > ph.Filesz {
			end = alignUp(end, loadAlign)
		}
		if end > maxEnd {
			maxEnd = end
		}
	}
	payloadVA := alignUp(maxEnd, 0x10000)
	if payloadVA%loadAlign != payloadOff%loadAlign {
		payloadVA = alignUp(payloadVA, loadAlign) + (payloadOff % loadAlign)
	}
	return payloadVA
}

func findReusablePhdr(data []byte, ehdr elf64Ehdr) int {
	for want := 0; want < 2; want++ {
		target := ptGNUStack
		if want == 1 {
			target = ptNote
		}
		for i := 0; i < int(ehdr.Phnum); i++ {
			ph := readPhdr64(data, ehdr.Phoff+uint64(i)*uint64(ehdr.Phentsize))
			if ph.Type == target {
				return i
			}
		}
	}
	return -1
}

func sortLoadPhdrs(data []byte, ehdr elf64Ehdr) {
	type slot struct {
		idx int
		ph  elf64Phdr
	}
	var loads []slot
	for i := 0; i < int(ehdr.Phnum); i++ {
		off := ehdr.Phoff + uint64(i)*uint64(ehdr.Phentsize)
		ph := readPhdr64(data, off)
		if ph.Type == ptLoad {
			loads = append(loads, slot{idx: i, ph: ph})
		}
	}
	if len(loads) < 2 {
		return
	}
	sort.Slice(loads, func(i, j int) bool {
		if loads[i].ph.Vaddr == loads[j].ph.Vaddr {
			return loads[i].idx < loads[j].idx
		}
		return loads[i].ph.Vaddr < loads[j].ph.Vaddr
	})
	var indices []int
	for _, load := range loads {
		indices = append(indices, load.idx)
	}
	sort.Ints(indices)
	for i, idx := range indices {
		writePhdr64(data, ehdr.Phoff+uint64(idx)*uint64(ehdr.Phentsize), loads[i].ph)
	}
}
