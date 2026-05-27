package elfstr

import (
	"encoding/binary"
	"testing"
)

func TestAArch64EncodeDecodeBL(t *testing.T) {
	for _, tc := range []struct {
		pc     uint64
		target uint64
	}{
		{pc: 0x1000, target: 0x1800},
		{pc: 0x2000, target: 0x1000},
	} {
		insn, ok := encodeAArch64BL(tc.pc, tc.target)
		if !ok {
			t.Fatalf("encode BL pc=%#x target=%#x failed", tc.pc, tc.target)
		}
		got, ok := decodeAArch64BL(insn, tc.pc)
		if !ok || got != tc.target {
			t.Fatalf("decode BL got (%#x,%v), want (%#x,true)", got, ok, tc.target)
		}
	}
	if _, ok := encodeAArch64BL(0x1000, 0x1002); ok {
		t.Fatalf("unaligned BL target should not encode")
	}
	if _, ok := decodeAArch64BL(0x14000000, 0x1000); ok {
		t.Fatalf("B must not decode as BL")
	}
}

func TestAArch64EncodeDecodeAddressConstructors(t *testing.T) {
	adrPC := uint64(0x10000)
	adrTarget := uint64(0x0ff80)
	adr, ok := encodeAArch64ADR(0, adrPC, adrTarget)
	if !ok {
		t.Fatalf("encode ADR failed")
	}
	rd, gotADR, ok := decodeAArch64ADR(adr, adrPC)
	if !ok || rd != 0 || gotADR != adrTarget {
		t.Fatalf("decode ADR got rd=%d target=%#x ok=%v", rd, gotADR, ok)
	}
	if _, _, ok := decodeAArch64ADR(adr|1, adrPC); !ok {
		t.Fatalf("ADR with another rd should still decode")
	}

	adrpPC := uint64(0x123456)
	adrpTarget := uint64(0x342abc)
	adrp, ok := encodeAArch64ADRP(0, adrpPC, adrpTarget)
	if !ok {
		t.Fatalf("encode ADRP failed")
	}
	rd, gotPage, ok := decodeAArch64ADRP(adrp, adrpPC)
	if !ok || rd != 0 || gotPage != adrpTarget&^0xfff {
		t.Fatalf("decode ADRP got rd=%d page=%#x ok=%v", rd, gotPage, ok)
	}

	add, ok := encodeAArch64ADDImm64(0, 0, 0xabc)
	if !ok {
		t.Fatalf("encode ADD immediate failed")
	}
	rd, rn, imm, ok := decodeAArch64ADDImm64(add)
	if !ok || rd != 0 || rn != 0 || imm != 0xabc {
		t.Fatalf("decode ADD got rd=%d rn=%d imm=%#x ok=%v", rd, rn, imm, ok)
	}
	add, ok = encodeAArch64ADDImm64(0, 0, 0x3000)
	if !ok {
		t.Fatalf("encode shifted ADD immediate failed")
	}
	_, _, imm, ok = decodeAArch64ADDImm64(add)
	if !ok || imm != 0x3000 {
		t.Fatalf("decode shifted ADD got imm=%#x ok=%v", imm, ok)
	}
}

func TestDiscoverAArch64CallsitesInTextADRAndFilters(t *testing.T) {
	textVA := uint64(0x10000)
	textOff := uint64(0x400)
	adrpString := uint64(0x23048)
	adrString := uint64(0x10102)
	entries := []Entry{
		{VAddr: adrpString, Length: 8},
		{VAddr: adrString - 2, Length: 8},
	}
	ranges := makeEntryRanges(entries)
	text := make([]byte, 28)

	adrp, ok := encodeAArch64ADRP(0, textVA, adrpString)
	if !ok {
		t.Fatalf("encode ADRP failed")
	}
	add, ok := encodeAArch64ADDImm64(0, 0, adrpString&0xfff)
	if !ok {
		t.Fatalf("encode ADD failed")
	}
	bl, ok := encodeAArch64BL(textVA+8, 0x18000)
	if !ok {
		t.Fatalf("encode BL failed")
	}
	binary.LittleEndian.PutUint32(text[0:], adrp)
	binary.LittleEndian.PutUint32(text[4:], add)
	binary.LittleEndian.PutUint32(text[8:], bl)

	adr, ok := encodeAArch64ADR(0, textVA+12, adrString)
	if !ok {
		t.Fatalf("encode ADR failed")
	}
	bl, ok = encodeAArch64BL(textVA+16, 0x19000)
	if !ok {
		t.Fatalf("encode BL failed")
	}
	binary.LittleEndian.PutUint32(text[12:], adr)
	binary.LittleEndian.PutUint32(text[16:], bl)

	adrWrongReg, ok := encodeAArch64ADR(1, textVA+20, adrString)
	if !ok {
		t.Fatalf("encode ADR x1 failed")
	}
	bl, ok = encodeAArch64BL(textVA+24, 0x1a000)
	if !ok {
		t.Fatalf("encode BL failed")
	}
	binary.LittleEndian.PutUint32(text[20:], adrWrongReg)
	binary.LittleEndian.PutUint32(text[24:], bl)

	got := discoverAArch64CallsitesInText(text, textOff, textVA, ranges)
	if len(got) != 2 {
		t.Fatalf("candidates got %d want 2: %#v", len(got), got)
	}
	if got[0].Pattern != "adrp-add-x0-bl" || got[0].TextOffset != textOff+8 || got[0].StringVAddr != adrpString || got[0].EntryIndex != 0 {
		t.Fatalf("unexpected ADRP candidate: %#v", got[0])
	}
	if got[1].Pattern != "adr-x0-bl" || got[1].TextOffset != textOff+16 || got[1].StringVAddr != adrString || got[1].EntryIndex != 1 {
		t.Fatalf("unexpected ADR candidate: %#v", got[1])
	}
}
