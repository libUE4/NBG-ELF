package elfstr

import (
	"bytes"
	"debug/elf"
	"encoding/binary"
	"encoding/json"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"testing"

	"nbg-elf/internal/assets"
)

func TestRuntimeStringCryptRoundTrip(t *testing.T) {
	plain := []byte("频道验证失败！是否跳转频道？Y/n")
	buf := append([]byte(nil), plain...)
	cryptRuntimeString(buf, 0x123450, 7, 0x11223344, 0x9d, 0x7b, 0x13572468, 0x24681357, 3)
	if bytes.Equal(buf, plain) {
		t.Fatalf("string did not change after encryption")
	}
	cryptRuntimeString(buf, 0x123450, 7, 0x11223344, 0x9d, 0x7b, 0x13572468, 0x24681357, 3)
	if !bytes.Equal(buf, plain) {
		t.Fatalf("round-trip mismatch")
	}
}

func TestRuntimeStringCryptUsesHardMaskLayer(t *testing.T) {
	plain := []byte("commercial protection string fixture")
	hardened := append([]byte(nil), plain...)
	legacy := append([]byte(nil), plain...)
	va := uint64(0x123450)
	index := uint32(7)
	key := uint32(0x11223344)
	posParam := uint32(0x9d)
	indexParam := uint32(0x7b)
	saltA := uint32(0x13572468)
	saltB := uint32(0x24681357)
	variant := uint8(0x0f)

	cryptRuntimeString(hardened, va, index, key, posParam, indexParam, saltA, saltB, variant)
	cryptRuntimeStringLegacyForTest(legacy, va, index, key, posParam, indexParam, saltA, saltB, variant)
	if bytes.Equal(hardened, legacy) {
		t.Fatalf("hardened encryption matched legacy single-layer stream")
	}
	if bytes.Equal(hardened, cryptRuntimeStringHardMaskV1ForTest(plain, va, index, key, posParam, indexParam, saltA, saltB, variant)) {
		t.Fatalf("hardened encryption matched previous hard-mask stream")
	}
	if bytes.Equal(hardened, plain) {
		t.Fatalf("hardened encryption did not change plaintext")
	}
	cryptRuntimeString(hardened, va, index, key, posParam, indexParam, saltA, saltB, variant)
	if !bytes.Equal(hardened, plain) {
		t.Fatalf("hardened encryption failed round trip")
	}
}

func cryptRuntimeStringHardMaskV1ForTest(plain []byte, va uint64, index uint32, key, posParam, indexParam, saltA, saltB uint32, variant uint8) []byte {
	buf := append([]byte(nil), plain...)
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
		mask ^= runtimeStringHardMaskV1ForTest(state, va, uint32(pos), saltA, saltB)
		buf[pos] ^= byte(mask)
	}
	return buf
}

func runtimeStringHardMaskV1ForTest(state uint32, va uint64, pos, saltA, saltB uint32) uint32 {
	mask := state ^ (pos*0x27d4eb2d + saltA) ^ uint32(va>>16) ^ saltB ^ ((pos + 1) * 0x165667b1)
	mask = mixXorShift32(mask)
	return (mask ^ (mask >> 16)) + (state << 3)
}

func cryptRuntimeStringLegacyForTest(buf []byte, va uint64, index uint32, key, posParam, indexParam, saltA, saltB uint32, variant uint8) {
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
		buf[pos] ^= byte(mask)
	}
}

func TestCompatScannerSkipsNonNULTerminatedRuns(t *testing.T) {
	data := []byte("prefix visible but not nul terminated and should be skipped")
	if got := scanSection(".rodata", 0, 0, data, 6); len(got) != 0 {
		t.Fatalf("expected no entries, got %d", len(got))
	}
	data = append([]byte("频道验证失败！是否跳转频道？Y/n"), 0)
	if got := scanSection(".rodata", 0, 0x1000, data, 6); len(got) != 1 {
		t.Fatalf("expected one utf8 compat entry, got %d", len(got))
	}
	data = append([]byte("Channel verify failed: jump channel? Y_n"), 0)
	if got := scanSection(".rodata", 0, 0x1000, data, 6); len(got) != 1 {
		t.Fatalf("expected one compat entry, got %d", len(got))
	}
	data = append([]byte("帧率 %d fps"), 0)
	if got := scanSection(".rodata", 0, 0x1000, data, 6); len(got) != 1 {
		t.Fatalf("expected one utf8 format entry, got %d", len(got))
	}
	data = append([]byte("/data/local/tmp/弹道追踪.log"), 0)
	if got := scanSection(".rodata", 0, 0x1000, data, 6); len(got) != 1 {
		t.Fatalf("expected one utf8 path entry, got %d", len(got))
	}
	data = append([]byte("/proc/self/maps"), 0)
	if got := scanSection(".rodata", 0, 0x1000, data, 6); len(got) != 1 {
		t.Fatalf("expected /proc/self/maps allowlist entry, got %d", len(got))
	}
	data = append([]byte("/proc/self/status"), 0)
	if got := scanSection(".rodata", 0, 0x1000, data, 6); len(got) != 0 {
		t.Fatalf("expected non-allowlisted /proc path to be skipped, got %d", len(got))
	}
	data = append([]byte("[%04d] [状态] 开火=%d 开镜=%d scope=%d scopeTrig=%d 模式=%d trigger=%d cnt=%d idx=%d ok=%d fov=%.1f 自身=(%.1f,%.1f,%.1f)"), 0)
	if got := scanSection(".rodata", 0, 0x1000, data, 6); len(got) != 1 {
		t.Fatalf("expected one long utf8 format entry, got %d", len(got))
	}
	data = append([]byte{0x02, 'm', '?', 'M', 'P', 0xfd, '5', 0}, 0)
	if got := scanSection(".rodata", 0, 0x1000, data, 6); len(got) != 0 {
		t.Fatalf("expected invalid utf8 binary run to be skipped, got %d", len(got))
	}
}

func TestRuntimeTableCryptAndSplitKeyRoundTrip(t *testing.T) {
	if stubTableEntSize != 24 {
		t.Fatalf("runtime table entry size got %d want 24", stubTableEntSize)
	}
	entries := []Entry{
		{VAddr: 0x123450, Length: 17, Key: 0x11223344, SaltA: 0x01020304, SaltB: 0x05060708, Variant: 1, Plain: "616263"},
		{VAddr: 0x223344, Length: 9, Key: 0x55667788, SaltA: 0xa1a2a3a4, SaltB: 0xb1b2b3b4, Variant: 2, Plain: "646566"},
	}
	for i := range entries {
		entries[i].SaltB &= 0xffff
		entries[i].ContentTag = runtimeContentTag(entries[i])
	}
	table := buildRuntimeStringTable(entries, 0xaabbccdd, runtimeKeyIndexParam)
	if readTableKeyShard(table, 0) == entries[0].Key || readTableKeyShard(table, 1) == entries[1].Key {
		t.Fatalf("key shard should not equal raw key")
	}
	for i, e := range entries {
		saltB := e.SaltB & 0xffff
		shard := readTableKeyShard(table, i)
		key := shard ^ runtimeKeySplitMask(e.VAddr, uint32(e.Length), uint32(i), 0xaabbccdd, runtimeKeyIndexParam, e.SaltA, saltB, e.Variant)
		if key != e.Key {
			t.Fatalf("split key mismatch at %d: got %#x want %#x", i, key, e.Key)
		}
		packedSaltB := binary.LittleEndian.Uint32(table[i*stubTableEntSize+20:])
		if got := packedSaltB & 0xffff; got != saltB {
			t.Fatalf("saltB low bits mismatch at %d: got %#x want %#x", i, got, saltB)
		}
		if got := uint16(packedSaltB >> 16); got != e.ContentTag {
			t.Fatalf("content tag mismatch at %d: got %#x want %#x", i, got, e.ContentTag)
		}
		packedLen := readTablePackedLen(table, i)
		if got := packedLen & 0xffff; got != uint32(e.Length) {
			t.Fatalf("length mismatch at %d: got %d want %d", i, got, e.Length)
		}
		wantTag := runtimeEntryTag(e.Key, e.VAddr, uint32(e.Length), uint32(i), 0xaabbccdd, runtimeKeyIndexParam, e.SaltA, saltB, e.Variant)
		if got := byte(packedLen >> 16); got != wantTag {
			t.Fatalf("runtime entry tag mismatch at %d: got %#x want %#x", i, got, wantTag)
		}
		if byte(packedLen>>16) == byte(packRuntimeLength(uint32(e.Length), e.Variant, 0)>>16) {
			t.Fatalf("runtime entry tag should not be the legacy zero tag at %d", i)
		}
	}
	if encodeTableSeed(0x12345678)^0xa5c35a7e != 0x12345678 {
		t.Fatalf("table seed encoding mismatch")
	}
	if encodeKeySeed(0x89abcdef)^0x6d9e3b17 != 0x89abcdef {
		t.Fatalf("key seed encoding mismatch")
	}
	plain := append([]byte(nil), table...)
	cryptRuntimeTable(table, 0x13572468, 0x5d, 0x11)
	if bytes.Equal(table, plain) {
		t.Fatalf("table did not change after encryption")
	}
	cryptRuntimeTable(table, 0x13572468, 0x5d, 0x11)
	if !bytes.Equal(table, plain) {
		t.Fatalf("table round-trip mismatch")
	}
}

func TestAtomicWriterReplacesPrivateManifest(t *testing.T) {
	dir := t.TempDir()
	path := dir + "/manifest.json"
	if err := writeFileAtomic(path, []byte("old"), 0o600); err != nil {
		t.Fatalf("initial atomic write failed: %v", err)
	}
	if err := writeFileAtomic(path, []byte("new"), 0o600); err != nil {
		t.Fatalf("replacement atomic write failed: %v", err)
	}
	got, err := os.ReadFile(path)
	if err != nil {
		t.Fatalf("read replacement failed: %v", err)
	}
	if string(got) != "new" {
		t.Fatalf("unexpected replacement content %q", got)
	}
	st, err := os.Stat(path)
	if err != nil {
		t.Fatalf("stat replacement failed: %v", err)
	}
	if st.Mode().Perm() != 0o600 {
		t.Fatalf("unexpected replacement mode %#o", st.Mode().Perm())
	}
}

func TestEncryptFileRejectsZeroProtectedStrings(t *testing.T) {
	dir := t.TempDir()
	inputPath := dir + "/empty.elf"
	raw := make([]byte, 0x300)
	copy(raw, []byte{0x7f, 'E', 'L', 'F', 2, 1, 1})
	raw[0x10] = 2
	raw[0x14] = 1
	binary.LittleEndian.PutUint16(raw[0x12:], 183)
	binary.LittleEndian.PutUint64(raw[0x18:], 0x180)
	binary.LittleEndian.PutUint64(raw[0x20:], 0x40)
	binary.LittleEndian.PutUint16(raw[0x36:], 56)
	binary.LittleEndian.PutUint16(raw[0x38:], 2)
	writePhdr64(raw, 0x40, elf64Phdr{Type: ptLoad, Flags: pfR | pfX, Off: 0, Vaddr: 0, Paddr: 0, Filesz: 0x300, Memsz: 0x300, Align: 0x1000})
	writePhdr64(raw, 0x40+56, elf64Phdr{Type: ptGNUStack, Flags: pfR | pfW, Align: 0x10})
	if err := os.WriteFile(inputPath, raw, 0o755); err != nil {
		t.Fatalf("write input: %v", err)
	}
	_, err := EncryptFile(inputPath, dir+"/out.vmp", dir+"/out.manifest.json", Options{})
	if err == nil || !strings.Contains(err.Error(), "no protected strings found") {
		t.Fatalf("expected zero protected strings error, got %v", err)
	}
}

func TestRuntimeEntriesFilterDoesNotMutateTable(t *testing.T) {
	entries := []Entry{
		{Section: ".rodata", VAddr: 0x1000, Length: 8, Key: 1},
		{Section: ".rodata", VAddr: 0x2000, Length: 9, Key: 2},
		{Section: ".rodata", VAddr: 0x3000, Length: 10, Key: 3},
		{Section: ".rodata", VAddr: 0x4000, Length: 11, Key: 4},
		{Section: ".rodata", VAddr: 0x5000, Length: 12, Key: 5},
		{Section: ".rodata", VAddr: 0x6000, Length: 13, Key: 6},
		{Section: ".rodata", VAddr: 0x7000, Length: 14, Key: 7},
		{Section: ".rodata", VAddr: 0x8000, Length: 15, Key: 8},
	}
	table, decoys, err := prepareRuntimeTableEntries(entries)
	if err != nil {
		t.Fatalf("prepare runtime table failed: %v", err)
	}
	if decoys == 0 || len(table) <= len(entries) {
		t.Fatalf("test setup did not create decoys: decoys=%d table=%d", decoys, len(table))
	}
	before := append([]Entry(nil), table...)
	real := realRuntimeEntries(table)
	if len(real) != len(entries) {
		t.Fatalf("real entries got %d want %d", len(real), len(entries))
	}
	if !equalEntriesForTest(table, before) {
		t.Fatalf("realRuntimeEntries mutated runtime table; this breaks table index based string keys")
	}
	realOrderMatchesInput := true
	realPos := 0
	nonZeroDecoys := 0
	pageVA, pageLen := stringPageWindow(entries)
	pageEnd := pageVA + pageLen
	for i, e := range table {
		if e.RuntimeIndex != i {
			t.Fatalf("runtime index mismatch at table slot %d: got %d", i, e.RuntimeIndex)
		}
		if e.Section == "<decoy>" {
			if e.Length <= 0 {
				t.Fatalf("decoy at table slot %d has empty length", i)
			}
			if pageVA <= e.VAddr && e.VAddr < pageEnd {
				t.Fatalf("decoy at table slot %d points inside real string page window: va=%#x window=%#x-%#x", i, e.VAddr, pageVA, pageEnd)
			}
			nonZeroDecoys++
			continue
		}
		if realPos >= len(entries) || e.VAddr != entries[realPos].VAddr {
			realOrderMatchesInput = false
		}
		realPos++
	}
	if realOrderMatchesInput {
		t.Fatalf("runtime table preserved original real-entry order; expected full-table shuffle")
	}
	if nonZeroDecoys != decoys {
		t.Fatalf("non-zero decoys got %d want %d", nonZeroDecoys, decoys)
	}
}

func TestStringPageWindowIgnoresDecoys(t *testing.T) {
	entries := []Entry{
		{Section: "<decoy>", VAddr: 0x10000000, Length: 64},
		{Section: ".rodata", VAddr: 0x401234, Length: 16},
		{Section: "<decoy>", VAddr: 0x20000000, Length: 32},
	}
	pageVA, pageLen := stringPageWindow(entries)
	if pageVA != 0x401000 || pageLen != 0x1000 {
		t.Fatalf("page window got va=%#x len=%#x want real string page only", pageVA, pageLen)
	}
	if pageVA, pageLen := stringPageWindow([]Entry{{Section: "<decoy>", VAddr: 0x10000000, Length: 64}}); pageVA != 0 || pageLen != 0 {
		t.Fatalf("decoy-only window got va=%#x len=%#x", pageVA, pageLen)
	}
}

func TestRuntimeContentTagsSkipOverlappingEntries(t *testing.T) {
	entries := []Entry{
		{VAddr: 0x1000, Length: 8, Key: 1, SaltA: 2, SaltB: 3, Variant: 1, Plain: "6162636465666768"},
		{VAddr: 0x1004, Length: 4, Key: 4, SaltA: 5, SaltB: 6, Variant: 2, Plain: "65666768"},
		{VAddr: 0x2000, Length: 4, Key: 7, SaltA: 8, SaltB: 9, Variant: 3, Plain: "71727374"},
	}
	enabled := map[uint64]struct{}{0x1000: {}, 0x1004: {}, 0x2000: {}}
	tagged := withRuntimeContentTags(entries, enabled)
	if tagged[0].ContentTag != 0 || tagged[1].ContentTag != 0 {
		t.Fatalf("overlapping entries should skip content tags: %#v", tagged)
	}
	if tagged[2].ContentTag == 0 {
		t.Fatalf("non-overlapping entry should have content tag")
	}
	if entries[2].ContentTag != 0 {
		t.Fatalf("withRuntimeContentTags mutated input")
	}
	tagged = withRuntimeContentTags(entries, map[uint64]struct{}{0x2000: {}})
	if tagged[0].ContentTag != 0 || tagged[1].ContentTag != 0 || tagged[2].ContentTag == 0 {
		t.Fatalf("content tags should only be enabled for selected VAs: %#v", tagged)
	}
}

func equalEntriesForTest(a, b []Entry) bool {
	if len(a) != len(b) {
		return false
	}
	for i := range a {
		if a[i] != b[i] {
			return false
		}
	}
	return true
}

func TestRuntimeEntrypointUsesStubSymbolOffset(t *testing.T) {
	raw := make([]byte, 0x300)
	copy(raw, []byte{0x7f, 'E', 'L', 'F', 2, 1, 1})
	raw[0x10] = 2                                    // ET_EXEC
	raw[0x14] = 1                                    // EV_CURRENT
	binary.LittleEndian.PutUint16(raw[0x12:], 183)   // EM_AARCH64
	binary.LittleEndian.PutUint64(raw[0x18:], 0x780) // original entry
	binary.LittleEndian.PutUint64(raw[0x20:], 0x40)
	binary.LittleEndian.PutUint16(raw[0x36:], 56)
	binary.LittleEndian.PutUint16(raw[0x38:], 2)
	writePhdr64(raw, 0x40, elf64Phdr{Type: ptLoad, Flags: pfR | pfX, Off: 0, Vaddr: 0, Paddr: 0, Filesz: 0x300, Memsz: 0x300, Align: 0x1000})
	writePhdr64(raw, 0x40+56, elf64Phdr{Type: ptGNUStack, Flags: pfR | pfW, Align: 0x10})

	out, err := injectRuntimeDecryptor(raw, []Entry{{Section: ".rodata", Offset: 0x200, VAddr: 0x200, Length: 8, Key: 0x12345678}}, RuntimeMeta{
		TableSeed:        0x11111111,
		KeySeed:          0x22222222,
		ParamTableA:      0x5d,
		ParamTableB:      0x11,
		ParamKeyIndex:    runtimeKeyIndexParam,
		ParamStringPos:   0x9d,
		ParamStringIndex: 0x7b,
		OrigEntryKey:     0x3333333344444444,
	})
	if err != nil {
		t.Fatalf("inject runtime failed: %v", err)
	}
	ehdr := readEhdr64(out)
	var payload elf64Phdr
	found := false
	for i := 0; i < int(ehdr.Phnum); i++ {
		ph := readPhdr64(out, ehdr.Phoff+uint64(i)*uint64(ehdr.Phentsize))
		if ph.Type == ptLoad && ph.Flags == pfR|pfW|pfX {
			payload = ph
			found = true
			break
		}
	}
	if !found {
		t.Fatalf("injected RWE LOAD not found")
	}
	entry := binary.LittleEndian.Uint64(out[0x18:])
	if want := payload.Vaddr + stubEntryOff; entry != want {
		t.Fatalf("entrypoint got %#x want %#x", entry, want)
	}
	payloadRaw := out[payload.Off : payload.Off+payload.Filesz]
	guardSeed := binary.LittleEndian.Uint32(payloadRaw[stubGuardSeedOff:])
	guardHash := binary.LittleEndian.Uint32(payloadRaw[stubGuardHashOff:])
	if guardSeed == 0 || guardHash == 0 {
		t.Fatalf("runtime guard fields not patched: seed=%#x hash=%#x", guardSeed, guardHash)
	}
	if want := computeRuntimeGuardHash(payloadRaw[stubEntryOff:stubAnchorOff], guardSeed); guardHash != want {
		t.Fatalf("runtime guard hash got %#x want %#x", guardHash, want)
	}
}

func readTableKeyShard(table []byte, index int) uint32 {
	off := index*stubTableEntSize + 12
	return uint32(table[off]) | uint32(table[off+1])<<8 | uint32(table[off+2])<<16 | uint32(table[off+3])<<24
}

func readTablePackedLen(table []byte, index int) uint32 {
	off := index*stubTableEntSize + 8
	return uint32(table[off]) | uint32(table[off+1])<<8 | uint32(table[off+2])<<16 | uint32(table[off+3])<<24
}

func TestAArch64InstructionRoundTrip(t *testing.T) {
	pc := uint64(0x220000)
	for _, target := range []uint64{pc + 0x40, pc - 0x40} {
		insn, ok := encodeAArch64BL(pc, target)
		if !ok {
			t.Fatalf("encode BL failed for %#x -> %#x", pc, target)
		}
		got, ok := decodeAArch64BL(insn, pc)
		if !ok || got != target {
			t.Fatalf("BL round-trip got %#x ok=%v want %#x", got, ok, target)
		}
	}

	adrTarget := pc + 0x1234
	adrInsn, ok := encodeAArch64ADR(0, pc, adrTarget)
	if !ok {
		t.Fatalf("encode ADR failed")
	}
	rd, gotADR, ok := decodeAArch64ADR(adrInsn, pc)
	if !ok || rd != 0 || gotADR != adrTarget {
		t.Fatalf("ADR round-trip rd=%d got=%#x ok=%v want %#x", rd, gotADR, ok, adrTarget)
	}

	adrpTarget := uint64(0x345678)
	adrpInsn, ok := encodeAArch64ADRP(0, pc, adrpTarget)
	if !ok {
		t.Fatalf("encode ADRP failed")
	}
	rd, page, ok := decodeAArch64ADRP(adrpInsn, pc)
	if !ok || rd != 0 || page != (adrpTarget&^uint64(0xfff)) {
		t.Fatalf("ADRP round-trip rd=%d page=%#x ok=%v", rd, page, ok)
	}
	addInsn, ok := encodeAArch64ADDImm64(0, 0, adrpTarget&0xfff)
	if !ok {
		t.Fatalf("encode ADD failed")
	}
	addRd, addRn, addImm, ok := decodeAArch64ADDImm64(addInsn)
	if !ok || addRd != 0 || addRn != 0 || addImm != (adrpTarget&0xfff) {
		t.Fatalf("ADD round-trip rd=%d rn=%d imm=%#x ok=%v", addRd, addRn, addImm, ok)
	}
}

func TestDiscoverAArch64CallsitesInText(t *testing.T) {
	textVA := uint64(0x220000)
	textOff := uint64(0x1000)
	stringVA := uint64(0x11c120)
	callVA := textVA + 8
	callTarget := uint64(0x230000)
	adrp, ok := encodeAArch64ADRP(0, textVA, stringVA)
	if !ok {
		t.Fatalf("encode ADRP failed")
	}
	add, ok := encodeAArch64ADDImm64(0, 0, stringVA&0xfff)
	if !ok {
		t.Fatalf("encode ADD failed")
	}
	bl, ok := encodeAArch64BL(callVA, callTarget)
	if !ok {
		t.Fatalf("encode BL failed")
	}
	text := make([]byte, 12)
	binary.LittleEndian.PutUint32(text[0:], adrp)
	binary.LittleEndian.PutUint32(text[4:], add)
	binary.LittleEndian.PutUint32(text[8:], bl)

	entries := []Entry{{VAddr: stringVA, Length: 16}}
	got := discoverAArch64CallsitesInText(text, textOff, textVA, makeEntryRanges(entries))
	if len(got) != 1 {
		t.Fatalf("expected one candidate, got %d", len(got))
	}
	if got[0].TextOffset != textOff+8 || got[0].TextVAddr != callVA || got[0].CallTarget != callTarget || got[0].StringVAddr != stringVA || got[0].Pattern != "adrp-add-x0-bl" {
		t.Fatalf("unexpected candidate: %+v", got[0])
	}
}

func TestSafeScanExcludesDataRelRo(t *testing.T) {
	if !wantedSection(".rodata", false, true) {
		t.Fatalf("safe-scan should include .rodata")
	}
	if wantedSection(".data.rel.ro", false, true) {
		t.Fatalf("safe-scan should exclude .data.rel.ro")
	}
	if wantedSection(".data.rel.ro", false, false) {
		t.Fatalf("normal mode should require -data for .data.rel.ro")
	}
	if !wantedSection(".data.rel.ro", true, false) {
		t.Fatalf("normal -data mode should include .data.rel.ro")
	}
	if wantedSection(".data", false, true) {
		t.Fatalf("safe-scan should exclude .data")
	}
	if !wantedSection(".data", true, false) {
		t.Fatalf("normal mode should include .data when includeData=true")
	}
}

func TestIsSafeStringCandidateFiltersPaths(t *testing.T) {
	// Safe scan should filter out paths and identifiers
	cases := []struct {
		s     string
		safe  bool
		label string
	}{
		{"频道验证成功！欢迎使用牛逼哥！", true, "user text with punctuation"},
		{" /data/local/tmp/弹道追踪.log", false, "file path with /"},
		{"libgui.so", false, ".so library"},
		{"android_app", false, "contains android"},
		{"linker64", false, "contains linker"},
		{"JNI_OnLoad", false, "contains jni"},
		{"getEnv", false, "contains env"},
		{"ImGui_DrawList", false, "contains class-like"},
		{"[%04d] [状态] 开火=%d", true, "format string with brackets"},
		{"帧率 %d fps", true, "format with space"},
		{"Abc", false, "too short (len < 12)"},
	}
	for _, c := range cases {
		got := isSafeStringCandidate([]byte(c.s), safeScanMinLen)
		if got != c.safe {
			t.Errorf("%s (%q) safe-scan got %v want %v", c.label, c.s, got, c.safe)
		}
	}
}

func TestDisableAntiFridaExtraPatches(t *testing.T) {
	// Simulate a payload where maps probe ADR at 0xc8 should become B to 0x270
	// and fd probe ADR at 0x3c8 should become B to 0x584
	payload := make([]byte, 0x600)
	// Put recognizable ADR instructions at the probe offsets
	binary.LittleEndian.PutUint32(payload[0xc8:], 0x10004520)  // dummy ADR
	binary.LittleEndian.PutUint32(payload[0x3c8:], 0x10004520) // dummy ADR

	disableAntiFridaExtra(payload)

	// Verify B instructions were patched
	b0 := binary.LittleEndian.Uint32(payload[0xc8:])
	b1 := binary.LittleEndian.Uint32(payload[0x3c8:])

	// B encoding: 0x14000000 | imm26
	// imm26 for 0xc8 -> 0x270: (0x270 - 0xc8) / 4 = 0x6a
	// imm26 for 0x3c8 -> 0x584: (0x584 - 0x3c8) / 4 = 0x6f
	if b0 != 0x1400006a {
		t.Errorf("maps probe B expected 0x1400006a got 0x%08x", b0)
	}
	if b1 != 0x1400006f {
		t.Errorf("fd probe B expected 0x1400006f got 0x%08x", b1)
	}
}

func TestNoAntiFridaExtraKeepsGuardHash(t *testing.T) {
	// When NoAntiFridaExtra=true, guard hash should still be valid
	// because patch happens before the hash is computed in the full flow
	raw := make([]byte, 0x300)
	copy(raw, []byte{0x7f, 'E', 'L', 'F', 2, 1, 1})
	raw[0x10] = 2
	raw[0x14] = 1
	binary.LittleEndian.PutUint16(raw[0x12:], 183)
	binary.LittleEndian.PutUint64(raw[0x18:], 0x780)
	binary.LittleEndian.PutUint64(raw[0x20:], 0x40)
	binary.LittleEndian.PutUint16(raw[0x36:], 56)
	binary.LittleEndian.PutUint16(raw[0x38:], 2)
	writePhdr64(raw, 0x40, elf64Phdr{Type: ptLoad, Flags: pfR | pfX, Off: 0, Vaddr: 0, Paddr: 0, Filesz: 0x300, Memsz: 0x300, Align: 0x1000})
	writePhdr64(raw, 0x40+56, elf64Phdr{Type: ptGNUStack, Flags: pfR | pfW, Align: 0x10})

	out, err := injectRuntimeDecryptor(raw, []Entry{{Section: ".rodata", Offset: 0x200, VAddr: 0x200, Length: 8, Key: 0x12345678}}, RuntimeMeta{
		TableSeed:        0x11111111,
		KeySeed:          0x22222222,
		ParamTableA:      0x5d,
		ParamTableB:      0x11,
		ParamKeyIndex:    runtimeKeyIndexParam,
		ParamStringPos:   0x9d,
		ParamStringIndex: 0x7b,
		OrigEntryKey:     0x3333333344444444,
		NoAntiFridaExtra: true,
	})
	if err != nil {
		t.Fatalf("inject runtime with NoAntiFridaExtra failed: %v", err)
	}
	ehdr := readEhdr64(out)
	for i := 0; i < int(ehdr.Phnum); i++ {
		ph := readPhdr64(out, ehdr.Phoff+uint64(i)*uint64(ehdr.Phentsize))
		if ph.Type == ptLoad && ph.Flags == pfR|pfW|pfX {
			payload := out[ph.Off : ph.Off+ph.Filesz]
			guardSeed := binary.LittleEndian.Uint32(payload[stubGuardSeedOff:])
			guardHash := binary.LittleEndian.Uint32(payload[stubGuardHashOff:])
			want := computeRuntimeGuardHash(payload[stubEntryOff:stubAnchorOff], guardSeed)
			if guardHash != want {
				t.Fatalf("guard hash mismatch with NoAntiFridaExtra: got %#x want %#x", guardHash, want)
			}
			// Verify probe instructions were patched to B
			bMaps := binary.LittleEndian.Uint32(payload[0xc8:])
			bFd := binary.LittleEndian.Uint32(payload[0x3c8:])
			if bMaps&0xfc000000 != 0x14000000 {
				t.Errorf("maps probe not patched to B: 0x%08x", bMaps)
			}
			if bFd&0xfc000000 != 0x14000000 {
				t.Errorf("fd probe not patched to B: 0x%08x", bFd)
			}
			return
		}
	}
	t.Fatalf("RWE LOAD phdr not found")
}

func TestCallsiteControlFlowLabel(t *testing.T) {
	scanOnly := callsiteControlFlowLabel(callsiteModeAArch64ScanOnly, 2)
	if scanOnly != "opaque-branches-per-entry-loop; aarch64-callsite-candidate-scan; cfg-level-balanced; runtime-state-dispatch" {
		t.Errorf("scan-only label got %q", scanOnly)
	}
	dryRun := callsiteControlFlowLabel(callsiteModeAArch64DryRun, 3)
	if dryRun != "opaque-branches-per-entry-loop; aarch64-callsite-candidate-scan; cfg-level-aggressive; runtime-state-dispatch; honeypot-branch-fanout; aarch64-callsite-lazy-dry-run" {
		t.Errorf("dry-run label got %q", dryRun)
	}
	lazy := callsiteControlFlowLabel(callsiteModeAArch64LazyDecrypt, 3)
	if lazy != "opaque-branches-per-entry-loop; aarch64-callsite-candidate-scan; cfg-level-aggressive; runtime-state-dispatch; honeypot-branch-fanout; aarch64-callsite-lazy-decrypt; lazy-dispatch-randomized" {
		t.Errorf("lazy label got %q", lazy)
	}
}

func TestLimitCallsiteCandidates(t *testing.T) {
	candidates := []CallsiteCandidate{
		{TextOffset: 0x100}, {TextOffset: 0x200}, {TextOffset: 0x300},
		{TextOffset: 0x400}, {TextOffset: 0x500},
	}
	if got := len(limitCallsiteCandidates(candidates, 3)); got != 3 {
		t.Errorf("limit 3 got %d", got)
	}
	if got := len(limitCallsiteCandidates(candidates, 0)); got != 5 {
		t.Errorf("limit 0 got %d", got)
	}
	if got := len(limitCallsiteCandidates(candidates, 10)); got != 5 {
		t.Errorf("limit > len got %d", got)
	}
	if got := len(limitCallsiteCandidates(nil, 5)); got != 0 {
		t.Errorf("nil slice got %d", got)
	}
}

func TestSelectCallsiteProtectionFallsBackWhenLazyPatchHasNoCandidates(t *testing.T) {
	mode, selected, err := selectCallsiteProtection(Options{LazyCallsite: true, LazyCallsiteLimit: 8}, nil)
	if err != nil {
		t.Fatalf("select callsite protection: %v", err)
	}
	if mode != callsiteModeAArch64ScanOnly {
		t.Fatalf("mode got %q want %q", mode, callsiteModeAArch64ScanOnly)
	}
	if len(selected) != 0 {
		t.Fatalf("selected candidates = %+v", selected)
	}
}

func TestSelectCallsiteProtectionKeepsDryRunWithoutCandidates(t *testing.T) {
	mode, selected, err := selectCallsiteProtection(Options{LazyCallsiteDryRun: true, LazyCallsiteLimit: 8}, nil)
	if err != nil {
		t.Fatalf("select callsite protection: %v", err)
	}
	if mode != callsiteModeAArch64DryRun {
		t.Fatalf("mode got %q want %q", mode, callsiteModeAArch64DryRun)
	}
	if len(selected) != 0 {
		t.Fatalf("selected candidates = %+v", selected)
	}
}

func TestIsForcedShortStringCandidate(t *testing.T) {
	// Only 3-5 byte ASCII identifiers with >=3 alpha and >=2 uppercase
	cases := []struct {
		s    string
		want bool
	}{
		{"NBG", true},
		{"DXT", true},
		{"VMP", true},
		{"AID", true},
		{"abc", false},  // no uppercase
		{"Abc", false},  // only 1 uppercase
		{"ABc", true},   // alpha=3 upper=2 => valid short tag
		{"AB", false},   // len=2 < 3
		{"A1B", false},  // alpha=2 < 3
		{"NV1", false},  // alpha=2 < 3
		{"ABCD", true},  // len=4, alpha=4, upper=4
		{"N1BG", true},  // len=4, alpha=3, upper=3
		{"N12G", false}, // alpha=2 < 3
		{"1234", false}, // no alpha
		{"A_B", false},  // '_' not in [A-Za-z0-9]
	}
	for _, c := range cases {
		got := isForcedShortStringCandidate([]byte(c.s))
		if got != c.want {
			t.Errorf("isForcedShortStringCandidate(%q) got %v want %v", c.s, got, c.want)
		}
	}
}

func TestScanWithSyntheticElf(t *testing.T) {
	shstrtab := []byte("\x00.shstrtab\x00.rodata\x00")
	rodataContent := []byte("频道验证成功！\x00AB\x00")
	ehdr := make([]byte, 64)
	ehdr[0] = 0x7f
	ehdr[1], ehdr[2], ehdr[3], ehdr[4], ehdr[5], ehdr[6] = 'E', 'L', 'F', 2, 1, 1
	binary.LittleEndian.PutUint16(ehdr[0x10:], 3)
	binary.LittleEndian.PutUint16(ehdr[0x12:], 183)
	binary.LittleEndian.PutUint32(ehdr[0x14:], 1)
	binary.LittleEndian.PutUint64(ehdr[0x20:], 0x40)
	binary.LittleEndian.PutUint16(ehdr[0x38:], 1)
	binary.LittleEndian.PutUint16(ehdr[0x36:], 56)

	phdr := make([]byte, 56)
	binary.LittleEndian.PutUint32(phdr[0:], ptLoad)
	binary.LittleEndian.PutUint32(phdr[4:], pfR)
	binary.LittleEndian.PutUint64(phdr[32:], 0x200)
	binary.LittleEndian.PutUint64(phdr[40:], 0x200)
	binary.LittleEndian.PutUint64(phdr[48:], 0x1000)

	hdrLen := 64 + 56
	rodataOff := hdrLen                   // 120
	padEnd := hdrLen + len(rodataContent) // 120+25=145
	align8 := (padEnd + 7) &^ 7           // 152
	shstrtabOff := align8
	sectionsOff := shstrtabOff + len(shstrtab) // 152+22=174
	shnum := uint16(3)

	sections := make([]byte, int(shnum)*64)
	// Section 1: .shstrtab (SHT_STRTAB, name at offset 1)
	binary.LittleEndian.PutUint32(sections[64+0:], 1)
	binary.LittleEndian.PutUint32(sections[64+4:], 3)
	binary.LittleEndian.PutUint64(sections[64+24:], uint64(shstrtabOff))
	binary.LittleEndian.PutUint64(sections[64+32:], uint64(len(shstrtab)))
	// Section 2: .rodata (SHT_PROGBITS, name at offset 11 in shstrtab: ".rodata")
	binary.LittleEndian.PutUint32(sections[128+0:], 11)
	binary.LittleEndian.PutUint32(sections[128+4:], 1)
	binary.LittleEndian.PutUint64(sections[128+8:], 2) // SHF_ALLOC
	binary.LittleEndian.PutUint64(sections[128+16:], 0x1000)
	binary.LittleEndian.PutUint64(sections[128+24:], uint64(rodataOff))
	binary.LittleEndian.PutUint64(sections[128+32:], uint64(len(rodataContent)))

	binary.LittleEndian.PutUint64(ehdr[0x28:], uint64(sectionsOff))
	binary.LittleEndian.PutUint16(ehdr[0x3a:], 64)
	binary.LittleEndian.PutUint16(ehdr[0x3c:], shnum)
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

	entries, err := Scan(raw, 6, false)
	if err != nil {
		t.Fatalf("Scan failed: %v", err)
	}
	// Should find at least the Chinese string in .rodata
	if len(entries) == 0 {
		t.Fatalf("expected entries but got none")
	}
	for i, e := range entries {
		t.Logf("  [%d] sec=%s vaddr=%#x len=%d", i, e.Section, e.VAddr, e.Length)
	}
	found := false
	for _, e := range entries {
		if e.Section == ".rodata" && e.Length > 6 {
			found = true
			break
		}
	}
	if !found {
		t.Errorf("did not find expected utf8 string in .rodata")
	}
}

func TestLazyDispatchTableLayoutConstants(t *testing.T) {
	if stubLazyEntSize != 56 {
		t.Fatalf("lazy dispatch entry size got %d want 56", stubLazyEntSize)
	}
	de := LazyDispatchEntry{
		TextVA:     0x1111222233334444,
		StringVA:   0x5555666677778888,
		Length:     0x99aabbcc,
		KeyState:   0xddeeff00,
		PosParam:   0x10203040,
		IdxParam:   0x50607080,
		SaltA:      0x90a0b0c0,
		SaltB:      0xd0e0f001,
		Variant:    0x0e,
		OrigTarget: 0xabcdef0123456789,
	}
	data := make([]byte, stubLazyTableOff+8)
	writePhdr64(data, 0x40, elf64Phdr{})
	// Build a minimal ELF header with one RWX LOAD over the buffer.
	copy(data, []byte{0x7f, 'E', 'L', 'F', 2, 1, 1})
	binary.LittleEndian.PutUint64(data[0x20:], 0x40)
	binary.LittleEndian.PutUint16(data[0x36:], 56)
	binary.LittleEndian.PutUint16(data[0x38:], 1)
	writePhdr64(data, 0x40, elf64Phdr{Type: ptLoad, Flags: pfR | pfW | pfX, Off: 0, Vaddr: 0x100000, Paddr: 0x100000, Filesz: uint64(len(data)), Memsz: uint64(len(data)), Align: 0x1000})

	out := appendLazyDispatchTable(data, []LazyDispatchEntry{de}, 0x100000)
	if got := binary.LittleEndian.Uint32(out[stubLazyCountOff:]); got != 1 {
		t.Fatalf("lazy count got %d want 1", got)
	}
	if got := binary.LittleEndian.Uint64(out[stubPayloadLenOff:]); got != uint64(len(out)) {
		t.Fatalf("payload len got %#x want %#x", got, len(out))
	}
	tableVA := binary.LittleEndian.Uint64(out[stubLazyTableOff:])
	if tableVA < 0x100000 {
		t.Fatalf("lazy table VA got %#x want payload-relative pointer", tableVA)
	}
	base := int(tableVA - 0x100000)
	if base < len(data) {
		t.Fatalf("lazy table was not appended: base=%#x original_len=%#x", base, len(data))
	}
	if got := binary.LittleEndian.Uint64(out[base:]); got != de.TextVA {
		t.Fatalf("TextVA got %#x want %#x", got, de.TextVA)
	}
	if got := binary.LittleEndian.Uint64(out[base+8:]); got != de.StringVA {
		t.Fatalf("StringVA got %#x want %#x", got, de.StringVA)
	}
	if got := binary.LittleEndian.Uint32(out[base+16:]); got != de.Length {
		t.Fatalf("Length got %#x want %#x", got, de.Length)
	}
	if got := out[base+40]; got != de.Variant {
		t.Fatalf("Variant got %#x want %#x", got, de.Variant)
	}
	if got, want := binary.LittleEndian.Uint32(out[base+41:]), lazyDispatchTag(de); got != want {
		t.Fatalf("lazy dispatch tag got %#x want %#x", got, want)
	}
	if pad := out[base+45 : base+48]; !bytes.Equal(pad, make([]byte, 3)) {
		t.Fatalf("lazy dispatch padding not zero: %x", pad)
	}
	if got := binary.LittleEndian.Uint64(out[base+48:]); got != de.OrigTarget {
		t.Fatalf("OrigTarget got %#x want %#x", got, de.OrigTarget)
	}
}

func TestBuildLazyDispatchEntriesMatchesInteriorStringVA(t *testing.T) {
	entries := []Entry{{
		Section:      ".rodata",
		VAddr:        0x5000,
		Length:       16,
		RuntimeIndex: 3,
		Key:          0x12345678,
		SaltA:        0x10,
		SaltB:        0x20,
		Variant:      2,
	}}
	candidates := []CallsiteCandidate{{
		TextVAddr:   0x1000,
		CallTarget:  0x2000,
		StringVAddr: 0x5008,
	}}
	meta := RuntimeMeta{ParamStringPos: 0x9d, ParamStringIndex: 0x7b}
	dispatch := buildLazyDispatchEntries(candidates, entries, meta)
	if len(dispatch) != 1 {
		t.Fatalf("dispatch count got %d want 1", len(dispatch))
	}
	if dispatch[0].StringVA != 0x5000 || dispatch[0].Length != 16 {
		t.Fatalf("dispatch entry = %+v", dispatch[0])
	}
	lazyVAs := lazyDispatchStringEntryVAs(dispatch, entries)
	if _, ok := lazyVAs[0x5000]; !ok || len(lazyVAs) != 1 {
		t.Fatalf("lazy dispatch VA map = %#v", lazyVAs)
	}
}

func TestShuffleLazyDispatchEntriesPreservesEntrySet(t *testing.T) {
	entries := []LazyDispatchEntry{
		{TextVA: 0x1000, StringVA: 0x2000, Length: 4, OrigTarget: 0x3000},
		{TextVA: 0x1010, StringVA: 0x2010, Length: 5, OrigTarget: 0x3010},
		{TextVA: 0x1020, StringVA: 0x2020, Length: 6, OrigTarget: 0x3020},
	}
	before := make(map[uint64]LazyDispatchEntry, len(entries))
	for _, e := range entries {
		before[e.TextVA] = e
	}
	shuffleLazyDispatchEntries(entries)
	if len(entries) != len(before) {
		t.Fatalf("entry count changed to %d", len(entries))
	}
	for _, e := range entries {
		want, ok := before[e.TextVA]
		if !ok || want != e {
			t.Fatalf("shuffle changed entry set: got=%+v want=%+v ok=%v", e, want, ok)
		}
		delete(before, e.TextVA)
	}
	if len(before) != 0 {
		t.Fatalf("shuffle dropped entries: %#v", before)
	}
}

func TestLazyEntryAvoidsCalleeSavedScratchRegisters(t *testing.T) {
	src, err := os.ReadFile("../../stub/arm64/strdec.S")
	if err != nil {
		t.Fatalf("read strdec.S: %v", err)
	}
	start := bytes.Index(src, []byte("strdec_lazy_entry:"))
	if start < 0 {
		t.Fatalf("strdec_lazy_entry not found")
	}
	endRel := bytes.Index(src[start:], []byte("strdec_maps_path_xor:"))
	if endRel < 0 {
		t.Fatalf("strdec_lazy_entry end marker not found")
	}
	body := string(src[start : start+endRel])
	for i, line := range strings.Split(body, "\n") {
		if comment := strings.Index(line, "//"); comment >= 0 {
			line = line[:comment]
		}
		fields := strings.FieldsFunc(line, func(r rune) bool {
			return r == ' ' || r == '\t' || r == ',' || r == '[' || r == ']' || r == '#'
		})
		for _, f := range fields {
			if len(f) == 3 && (f[0] == 'x' || f[0] == 'w') && f[1] == '2' && f[2] >= '1' && f[2] <= '8' {
				t.Fatalf("strdec_lazy_entry uses callee-saved scratch register %q on lazy body line %d: %s", f, i+1, strings.TrimSpace(line))
			}
		}
	}
}

func TestEmbeddedRuntimeStubOffsetsAreInBounds(t *testing.T) {
	if len(assets.StrdecBlob) < stubLazyTableOff+56 {
		t.Fatalf("embedded runtime stub too small: len=%#x lazy_table_end=%#x", len(assets.StrdecBlob), stubLazyTableOff+56)
	}
	for _, tc := range []struct {
		name string
		off  int
		n    int
	}{
		{"entry", stubEntryOff, 4},
		{"lazy_entry", stubLazyEntryOff, 4},
		{"anchor", stubAnchorOff, 8},
		{"static_va", stubStaticVAOff, 8},
		{"orig_entry", stubOrigEntryOff, 8},
		{"payload_len", stubPayloadLenOff, 8},
		{"table", stubTableOff, stubTableEntSize},
		{"lazy_count", stubLazyCountOff, 4},
		{"lazy_table", stubLazyTableOff, stubLazyEntSize},
	} {
		if tc.off < 0 || tc.off+tc.n > len(assets.StrdecBlob) {
			t.Fatalf("%s offset out of embedded stub: off=%#x n=%#x len=%#x", tc.name, tc.off, tc.n, len(assets.StrdecBlob))
		}
	}
	if got := binary.LittleEndian.Uint32(assets.StrdecBlob[stubLazyCountOff:]); got != 0x01234567 {
		t.Fatalf("lazy count placeholder mismatch at %#x: got %#x", stubLazyCountOff, got)
	}
	if got := binary.LittleEndian.Uint64(assets.StrdecBlob[stubLazyTableOff:]); got != 0x123456789abcdef0 {
		t.Fatalf("lazy table placeholder mismatch at %#x: got %#x", stubLazyTableOff, got)
	}
}

func TestFindPayloadSegmentVA(t *testing.T) {
	raw := make([]byte, 0x200)
	copy(raw, []byte{0x7f, 'E', 'L', 'F', 2, 1, 1})
	binary.LittleEndian.PutUint64(raw[0x20:], 0x40)
	binary.LittleEndian.PutUint16(raw[0x36:], 56)
	binary.LittleEndian.PutUint16(raw[0x38:], 3)
	writePhdr64(raw, 0x40, elf64Phdr{Type: ptLoad, Flags: pfR | pfX, Off: 0, Vaddr: 0, Filesz: 0x100, Memsz: 0x100, Align: 0x1000})
	writePhdr64(raw, 0x40+56, elf64Phdr{Type: ptLoad, Flags: pfR | pfW, Off: 0x1000, Vaddr: 0x2000, Filesz: 0x100, Memsz: 0x100, Align: 0x1000})
	writePhdr64(raw, 0x40+112, elf64Phdr{Type: ptLoad, Flags: pfR | pfW | pfX, Off: 0x3000, Vaddr: 0x5000, Filesz: 0x100, Memsz: 0x100, Align: 0x1000})
	if got := findPayloadSegmentVA(raw); got != 0x5000 {
		t.Fatalf("findPayloadSegmentVA got %#x want %#x", got, uint64(0x5000))
	}
	raw[0x40+112+4] = byte(pfR | pfW)
	if got := findPayloadSegmentVA(raw); got != 0 {
		t.Fatalf("findPayloadSegmentVA without RWX got %#x want 0", got)
	}
}

func TestPatchCallsiteBLIfTargetValidatesOriginalTarget(t *testing.T) {
	buf := make([]byte, 4)
	pc := uint64(0x1000)
	orig := uint64(0x2000)
	tramp := uint64(0x3000)
	insn, ok := encodeAArch64BL(pc, orig)
	if !ok {
		t.Fatalf("encode orig BL failed")
	}
	binary.LittleEndian.PutUint32(buf, insn)
	if patchCallsiteBLIfTarget(buf, 0, pc, 0x2222, tramp) {
		t.Fatalf("patch succeeded with wrong expected target")
	}
	if got := binary.LittleEndian.Uint32(buf); got != insn {
		t.Fatalf("instruction changed after failed patch: got %#x want %#x", got, insn)
	}
	if !patchCallsiteBLIfTarget(buf, 0, pc, orig, tramp) {
		t.Fatalf("patch failed with correct expected target")
	}
	gotTarget, ok := decodeAArch64BL(binary.LittleEndian.Uint32(buf), pc)
	if !ok || gotTarget != tramp {
		t.Fatalf("patched target got %#x ok=%v want %#x", gotTarget, ok, tramp)
	}
	binary.LittleEndian.PutUint32(buf, 0xd503201f) // NOP, not BL
	if patchCallsiteBLIfTarget(buf, 0, pc, tramp, orig) {
		t.Fatalf("patch succeeded for non-BL instruction")
	}
}

func TestManifestIncludesOptionsAndRuntimeStubInfo(t *testing.T) {
	m := Manifest{
		Schema: Schema,
		Tool:   "nbg-elf",
		Config: ProtectionConfig{
			Preset:           PresetAggressive,
			ControlFlowLevel: 3,
			FailurePolicy:    "safe-exit",
		},
		Report: ProtectionReport{
			Preset:              PresetAggressive,
			ControlFlowLevel:    3,
			FailurePolicy:       "safe-exit",
			RuntimeTableEntries: 10,
			RuntimeDecoys:       3,
			RuntimeDecoyRatio:   0.3,
			LazyCoveragePercent: 40,
			CallsiteCandidates:  5,
			CallsiteSelected:    2,
			CallsiteSkipped:     3,
			CallsiteLimit:       2,
		},
		Options: ManifestOptions{
			Preset:           PresetAggressive,
			ControlFlowLevel: 3,
			FailurePolicy:    "safe-exit",
			LazyCallsite:     true,
			NoAntiFridaExtra: true,
		},
		RuntimeStub: RuntimeStubInfo{
			SHA256:        "abc123",
			Size:          1234,
			EntryOff:      stubEntryOff,
			LazyEntryOff:  stubLazyEntryOff,
			HoneypotOff:   stubHoneypotEntryOff,
			LazyCountOff:  stubLazyCountOff,
			LazyTableOff:  stubLazyTableOff,
			LazyEntrySize: stubLazyEntSize,
		},
		RuntimePayload: RuntimePayloadInfo{
			SHA256:       "def456",
			Size:         4096,
			DeclaredSize: 4096,
			FileOffset:   0x5000,
			VAddr:        0x7000,
		},
	}
	raw, err := json.Marshal(m)
	if err != nil {
		t.Fatalf("marshal manifest: %v", err)
	}
	var decoded map[string]any
	if err := json.Unmarshal(raw, &decoded); err != nil {
		t.Fatalf("unmarshal manifest map: %v", err)
	}
	if _, ok := decoded["options"]; !ok {
		t.Fatalf("manifest json missing options: %s", raw)
	}
	if _, ok := decoded["runtime_stub"]; !ok {
		t.Fatalf("manifest json missing runtime_stub: %s", raw)
	}
	if _, ok := decoded["runtime_payload"]; !ok {
		t.Fatalf("manifest json missing runtime_payload: %s", raw)
	}
	if _, ok := decoded["config"]; !ok {
		t.Fatalf("manifest json missing config: %s", raw)
	}
	if _, ok := decoded["report"]; !ok {
		t.Fatalf("manifest json missing report: %s", raw)
	}
	m.Entries = []Entry{{SHA256: "abc", Plain: "secret"}}
	raw, err = json.Marshal(m)
	if err != nil {
		t.Fatalf("marshal manifest with entries: %v", err)
	}
	if bytes.Contains(raw, []byte("secret")) || bytes.Contains(raw, []byte("Plain")) || bytes.Contains(raw, []byte("plain")) {
		t.Fatalf("manifest leaked internal plaintext field: %s", raw)
	}
	report := decoded["report"].(map[string]any)
	for _, key := range []string{"runtime_table_entries", "runtime_decoys", "runtime_decoy_ratio", "lazy_coverage_percent"} {
		if _, ok := report[key]; !ok {
			t.Fatalf("manifest report missing %s: %s", key, raw)
		}
	}
}

func TestValidateManifestRuntimeStubCatchesMetadataMismatch(t *testing.T) {
	m := &Manifest{RuntimeStub: runtimeStubInfo()}
	if err := ValidateManifestRuntimeStub(m); err != nil {
		t.Fatalf("validate runtime stub: %v", err)
	}
	m.RuntimeStub.LazyEntryOff++
	if err := ValidateManifestRuntimeStub(m); err == nil {
		t.Fatalf("expected runtime stub metadata mismatch")
	}
}

func TestManifestSelfHashDetectsMetadataTamper(t *testing.T) {
	m := &Manifest{
		Schema:       Schema,
		Tool:         "nbg-elf",
		OutputPath:   "out.vmp",
		OutputSHA256: "abc123",
		EntryCount:   7,
	}
	sum, err := ComputeManifestSHA256(m)
	if err != nil {
		t.Fatalf("compute manifest hash: %v", err)
	}
	m.ManifestSHA256 = sum
	if err := ValidateManifestSelfHash(m); err != nil {
		t.Fatalf("validate manifest self hash: %v", err)
	}
	m.EntryCount++
	if err := ValidateManifestSelfHash(m); err == nil {
		t.Fatalf("expected manifest self hash mismatch after metadata tamper")
	}
}

func TestValidateManifestRuntimeTableProfileCatchesMetadataMismatch(t *testing.T) {
	m := &Manifest{
		EntryCount: 4,
		Report: ProtectionReport{
			RuntimeTableEntries: 6,
			RuntimeDecoys:       2,
			RuntimeDecoyRatio:   runtimeDecoyRatio(2, 6),
			LazyCoveragePercent: 50,
		},
		Protection: ProtectionProfile{
			RuntimeTableEntries:    6,
			DecoyCount:             2,
			DecoyRatio:             runtimeDecoyRatio(2, 6),
			CallsiteLazyCandidates: 4,
			CallsiteLazySelected:   2,
			CallsiteLazyCoverage:   50,
		},
	}
	if err := ValidateManifestRuntimeTableProfile(m); err != nil {
		t.Fatalf("validate runtime table profile: %v", err)
	}
	m.Protection.RuntimeTableEntries++
	if err := ValidateManifestRuntimeTableProfile(m); err == nil {
		t.Fatalf("expected runtime table entry count mismatch")
	}
	m.Protection.RuntimeTableEntries = 6
	m.Report.LazyCoveragePercent = 75
	if err := ValidateManifestRuntimeTableProfile(m); err == nil {
		t.Fatalf("expected lazy coverage mismatch")
	}
}

func TestStubSymbolOffsetsMatchRuntimeConstants(t *testing.T) {
	stubPath := buildCurrentStubELFForTest(t)
	f, err := elf.Open(stubPath)
	if err != nil {
		t.Fatalf("open generated stub ELF: %v", err)
	}
	defer f.Close()
	syms, err := f.Symbols()
	if err != nil {
		t.Fatalf("read stub symbols: %v", err)
	}
	values := make(map[string]uint64)
	for _, s := range syms {
		values[s.Name] = s.Value
	}
	for _, tc := range []struct {
		name string
		want uint64
	}{
		{"strdec_entry", stubEntryOff},
		{"strdec_lazy_entry", stubLazyEntryOff},
		{"strdec_honeypot_entry", stubHoneypotEntryOff},
		{"strdec_anchor", stubAnchorOff},
		{"strdec_static_anchor_va", stubStaticVAOff},
		{"strdec_orig_entry_va", stubOrigEntryOff},
		{"strdec_page_va", stubPageVAOff},
		{"strdec_page_len", stubPageLenOff},
		{"strdec_payload_len", stubPayloadLenOff},
		{"strdec_entry_count", stubEntryCountOff},
		{"strdec_guard_seed", stubGuardSeedOff},
		{"strdec_table_seed", stubTableSeedOff},
		{"strdec_key_seed", stubKeySeedOff},
		{"strdec_param_table_a", stubParamTableAOff},
		{"strdec_param_table_b", stubParamTableBOff},
		{"strdec_param_key_index", stubParamKeyIndexOff},
		{"strdec_param_string_pos", stubParamStringPosOff},
		{"strdec_param_string_index", stubParamStringIndexOff},
		{"strdec_guard_hash", stubGuardHashOff},
		{"strdec_orig_entry_key", stubOrigEntryKeyOff},
		{"strdec_table", stubTableOff},
		{"strdec_lazy_count", stubLazyCountOff},
		{"strdec_lazy_table", stubLazyTableOff},
	} {
		got, ok := values[tc.name]
		if !ok {
			t.Fatalf("stub symbol %s not found", tc.name)
		}
		if got != tc.want {
			t.Fatalf("stub symbol %s offset got %#x want %#x", tc.name, got, tc.want)
		}
	}
}

func buildCurrentStubELFForTest(t *testing.T) string {
	t.Helper()
	if _, err := exec.LookPath("aarch64-linux-gnu-as"); err != nil {
		t.Skipf("aarch64 assembler not available: %v", err)
	}
	if _, err := exec.LookPath("aarch64-linux-gnu-ld"); err != nil {
		t.Skipf("aarch64 linker not available: %v", err)
	}
	dir := t.TempDir()
	objPath := filepath.Join(dir, "strdec.o")
	elfPath := filepath.Join(dir, "strdec.elf")
	srcPath := filepath.Join("..", "..", "stub", "arm64", "strdec.S")
	ldsPath := filepath.Join("..", "..", "stub", "arm64", "strdec.lds")
	if out, err := exec.Command("aarch64-linux-gnu-as", "-o", objPath, srcPath).CombinedOutput(); err != nil {
		t.Fatalf("assemble stub: %v\n%s", err, out)
	}
	if out, err := exec.Command("aarch64-linux-gnu-ld", "-T", ldsPath, "-o", elfPath, objPath).CombinedOutput(); err != nil {
		t.Fatalf("link stub: %v\n%s", err, out)
	}
	return elfPath
}

func TestValidateInjectedOutputCatchesCorruption(t *testing.T) {
	raw := make([]byte, 0x300)
	copy(raw, []byte{0x7f, 'E', 'L', 'F', 2, 1, 1})
	raw[0x10] = 2
	raw[0x14] = 1
	binary.LittleEndian.PutUint16(raw[0x12:], 183)
	binary.LittleEndian.PutUint64(raw[0x18:], 0x780)
	binary.LittleEndian.PutUint64(raw[0x20:], 0x40)
	binary.LittleEndian.PutUint16(raw[0x36:], 56)
	binary.LittleEndian.PutUint16(raw[0x38:], 2)
	writePhdr64(raw, 0x40, elf64Phdr{Type: ptLoad, Flags: pfR | pfX, Off: 0, Vaddr: 0, Paddr: 0, Filesz: 0x300, Memsz: 0x300, Align: 0x1000})
	writePhdr64(raw, 0x40+56, elf64Phdr{Type: ptGNUStack, Flags: pfR | pfW, Align: 0x10})

	out, err := injectRuntimeDecryptor(raw, []Entry{{Section: ".rodata", Offset: 0x200, VAddr: 0x200, Length: 8, Key: 0x12345678}}, RuntimeMeta{
		TableSeed:        0x11111111,
		KeySeed:          0x22222222,
		ParamTableA:      0x5d,
		ParamTableB:      0x11,
		ParamKeyIndex:    runtimeKeyIndexParam,
		ParamStringPos:   0x9d,
		ParamStringIndex: 0x7b,
		OrigEntryKey:     0x3333333344444444,
	})
	if err != nil {
		t.Fatalf("inject runtime failed: %v", err)
	}
	stripSectionHeaders(out)
	if err := validateInjectedOutput(out, false); err != nil {
		t.Fatalf("validate injected output failed: %v", err)
	}
	corrupt := append([]byte(nil), out...)
	binary.LittleEndian.PutUint64(corrupt[0x18:], 0x1234)
	if err := validateInjectedOutput(corrupt, false); err == nil {
		t.Fatalf("validate injected output accepted corrupt entrypoint")
	}
	expectedEntries := 1
	if err := validateInjectedOutputRuntimeTable(out, expectedEntries); err != nil {
		t.Fatalf("validate runtime table failed: %v", err)
	}
	payloadInfo, err := runtimePayloadInfoFromBytes(out)
	if err != nil {
		t.Fatalf("runtime payload info: %v", err)
	}
	m := &Manifest{RuntimePayload: payloadInfo}
	if err := ValidateManifestRuntimePayloadBytes(m, out); err != nil {
		t.Fatalf("validate runtime payload failed: %v", err)
	}
	corruptPayload := append([]byte(nil), out...)
	_, payloadRaw, _, err := findRuntimePayload(corruptPayload)
	if err != nil {
		t.Fatalf("find runtime payload for corrupt copy: %v", err)
	}
	payloadRaw[stubEntryOff] ^= 0xff
	if err := ValidateManifestRuntimePayloadBytes(m, corruptPayload); err == nil {
		t.Fatalf("validate runtime payload accepted corrupt payload")
	}
	corruptTable := append([]byte(nil), out...)
	_, payloadRaw, _, err = findRuntimePayload(corruptTable)
	if err != nil {
		t.Fatalf("find runtime payload: %v", err)
	}
	binary.LittleEndian.PutUint32(payloadRaw[stubEntryCountOff:], 2)
	if err := validateInjectedOutputRuntimeTable(corruptTable, expectedEntries); err == nil {
		t.Fatalf("validate runtime table accepted corrupt entry count")
	}
}

func TestRuntimeTableADROffsetTargetsStubTable(t *testing.T) {
	if int(stubRuntimeTableADROff)+4 > len(assets.StrdecBlob) {
		t.Fatalf("runtime table ADR offset outside stub")
	}
	rd, target, ok := decodeAArch64ADR(binary.LittleEndian.Uint32(assets.StrdecBlob[stubRuntimeTableADROff:]), stubRuntimeTableADROff)
	if !ok || rd != 25 {
		t.Fatalf("runtime table ADR decode ok=%v rd=%d", ok, rd)
	}
	if target != stubTableOff {
		t.Fatalf("runtime table ADR target got %#x want %#x", target, stubTableOff)
	}
}

func TestValidateLazyDispatchMetadataCatchesCorruption(t *testing.T) {
	data := make([]byte, stubLazyTableOff+8)
	copy(data, []byte{0x7f, 'E', 'L', 'F', 2, 1, 1})
	binary.LittleEndian.PutUint64(data[0x20:], 0x40)
	binary.LittleEndian.PutUint16(data[0x36:], 56)
	binary.LittleEndian.PutUint16(data[0x38:], 1)
	writePhdr64(data, 0x40, elf64Phdr{Type: ptLoad, Flags: pfR | pfW | pfX, Off: 0, Vaddr: 0x100000, Paddr: 0x100000, Filesz: uint64(len(data)), Memsz: uint64(len(data)), Align: 0x1000})
	bl, ok := encodeAArch64BL(0x100100, 0x100000+stubLazyEntryOff)
	if !ok {
		t.Fatalf("encode lazy BL failed")
	}
	binary.LittleEndian.PutUint32(data[0x100:], bl)
	de := LazyDispatchEntry{
		TextVA:     0x100100,
		StringVA:   0x200200,
		Length:     12,
		KeyState:   0x11111111,
		PosParam:   0x22,
		IdxParam:   0x33,
		SaltA:      0x44,
		SaltB:      0x55,
		Variant:    1,
		OrigTarget: 0x300300,
	}
	out := appendLazyDispatchTable(data, []LazyDispatchEntry{de}, 0x100000)
	payloadLen := uint64(len(out))
	binary.LittleEndian.PutUint64(out[stubPayloadLenOff:], payloadLen)
	if err := validateInjectedOutputLazyDispatch(out, 1); err != nil {
		t.Fatalf("validate lazy dispatch failed: %v", err)
	}
	if err := validateInjectedOutputLazyDispatch(out, 2); err == nil {
		t.Fatalf("accepted lazy dispatch count mismatch")
	}

	corruptPtr := append([]byte(nil), out...)
	binary.LittleEndian.PutUint64(corruptPtr[stubLazyTableOff:], 0x999)
	if err := validateInjectedOutputLazyDispatch(corruptPtr, 1); err == nil {
		t.Fatalf("accepted lazy dispatch table before payload")
	}

	corruptLen := append([]byte(nil), out...)
	tableVA := binary.LittleEndian.Uint64(corruptLen[stubLazyTableOff:])
	base := int(tableVA - 0x100000)
	binary.LittleEndian.PutUint32(corruptLen[base+16:], 0)
	if err := validateInjectedOutputLazyDispatch(corruptLen, 1); err == nil {
		t.Fatalf("accepted lazy dispatch entry with zero length")
	}

	corruptTag := append([]byte(nil), out...)
	corruptTag[base+41] ^= 0xff
	if err := validateInjectedOutputLazyDispatch(corruptTag, 1); err == nil {
		t.Fatalf("accepted lazy dispatch entry with corrupt tag")
	}

	corruptPad := append([]byte(nil), out...)
	corruptPad[base+45] = 0xff
	if err := validateInjectedOutputLazyDispatch(corruptPad, 1); err == nil {
		t.Fatalf("accepted lazy dispatch entry with non-zero padding")
	}

	corruptCallsite := append([]byte(nil), out...)
	binary.LittleEndian.PutUint32(corruptCallsite[0x100:], 0xd503201f)
	if err := validateInjectedOutputLazyDispatch(corruptCallsite, 1); err == nil {
		t.Fatalf("accepted lazy dispatch entry with unpatched callsite")
	}
}

func TestPlaintextResidueAuditCatchesMissedString(t *testing.T) {
	raw := []byte("prefix protected-secret-string\x00 suffix")
	entries := []Entry{{
		Section: ".rodata",
		Offset:  7,
		VAddr:   0x4007,
		Length:  len("protected-secret-string"),
		SHA256:  "test",
	}}
	if err := validateNoPlaintextResidue(raw, append([]byte(nil), raw...), entries); err == nil {
		t.Fatalf("plaintext residue audit accepted unchanged output")
	}
	out := append([]byte(nil), raw...)
	copy(out[7:7+entries[0].Length], bytes.Repeat([]byte{0xa5}, entries[0].Length))
	if err := validateNoPlaintextResidue(raw, out, entries); err != nil {
		t.Fatalf("plaintext residue audit rejected encrypted output: %v", err)
	}
}
