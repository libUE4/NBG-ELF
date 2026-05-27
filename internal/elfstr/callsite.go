package elfstr

import (
	"bytes"
	"debug/elf"
	"encoding/binary"
	"sort"
)

const (
	callsiteModeAArch64ScanOnly    = "aarch64-lazy-scan-only-no-patch"
	callsiteModeAArch64DryRun      = "aarch64-lazy-dry-run-no-patch"
	callsiteModeAArch64LazyDecrypt = "aarch64-lazy-decrypt-patch"
)

type CallsiteCandidate struct {
	TextOffset  uint64
	TextVAddr   uint64
	CallTarget  uint64
	StringVAddr uint64
	EntryIndex  int
	Pattern     string
}

func discoverAArch64Callsites(raw []byte, entries []Entry) ([]CallsiteCandidate, error) {
	if len(entries) == 0 {
		return nil, nil
	}
	f, err := elf.NewFile(bytes.NewReader(raw))
	if err != nil {
		return nil, err
	}
	defer f.Close()
	if f.Class != elf.ELFCLASS64 || f.Machine != elf.EM_AARCH64 {
		return nil, nil
	}

	ranges := makeEntryRanges(entries)
	if len(ranges) == 0 {
		return nil, nil
	}

	var out []CallsiteCandidate
	for _, sec := range f.Sections {
		if sec.Name != ".text" || sec.Size < 8 || sec.Offset+sec.Size > uint64(len(raw)) {
			continue
		}
		text := raw[sec.Offset : sec.Offset+sec.Size]
		out = append(out, discoverAArch64CallsitesInText(text, sec.Offset, sec.Addr, ranges)...)
	}
	return out, nil
}

func discoverAArch64CallsitesInText(text []byte, textOff, textVA uint64, ranges []entryRange) []CallsiteCandidate {
	if len(text) < 8 || len(ranges) == 0 {
		return nil
	}
	limit := len(text) &^ 3
	var out []CallsiteCandidate
	for off := 0; off < limit; off += 4 {
		callInsn := binary.LittleEndian.Uint32(text[off:])
		callVA := textVA + uint64(off)
		callTarget, ok := decodeAArch64BL(callInsn, callVA)
		if !ok {
			continue
		}

		if off >= 4 {
			adrInsn := binary.LittleEndian.Uint32(text[off-4:])
			if rd, stringVA, ok := decodeAArch64ADR(adrInsn, callVA-4); ok && rd == 0 {
				if entryIdx, ok := findEntryRange(ranges, stringVA); ok {
					out = append(out, CallsiteCandidate{
						TextOffset:  textOff + uint64(off),
						TextVAddr:   callVA,
						CallTarget:  callTarget,
						StringVAddr: stringVA,
						EntryIndex:  entryIdx,
						Pattern:     "adr-x0-bl",
					})
				}
			}
		}

		if off >= 8 {
			adrpInsn := binary.LittleEndian.Uint32(text[off-8:])
			addInsn := binary.LittleEndian.Uint32(text[off-4:])
			rd, pageVA, ok := decodeAArch64ADRP(adrpInsn, callVA-8)
			addRd, addRn, addImm, addOK := decodeAArch64ADDImm64(addInsn)
			if ok && addOK && rd == 0 && addRd == 0 && addRn == 0 {
				stringVA := pageVA + addImm
				if entryIdx, ok := findEntryRange(ranges, stringVA); ok {
					out = append(out, CallsiteCandidate{
						TextOffset:  textOff + uint64(off),
						TextVAddr:   callVA,
						CallTarget:  callTarget,
						StringVAddr: stringVA,
						EntryIndex:  entryIdx,
						Pattern:     "adrp-add-x0-bl",
					})
				}
			}
		}
	}
	return out
}

type entryRange struct {
	start uint64
	end   uint64
	index int
}

func makeEntryRanges(entries []Entry) []entryRange {
	ranges := make([]entryRange, 0, len(entries))
	for i, e := range entries {
		if e.Length <= 0 {
			continue
		}
		end := e.VAddr + uint64(e.Length)
		if end <= e.VAddr {
			continue
		}
		ranges = append(ranges, entryRange{start: e.VAddr, end: end, index: i})
	}
	sort.Slice(ranges, func(i, j int) bool {
		if ranges[i].start == ranges[j].start {
			return ranges[i].end < ranges[j].end
		}
		return ranges[i].start < ranges[j].start
	})
	return ranges
}

func findEntryRange(ranges []entryRange, va uint64) (int, bool) {
	i := sort.Search(len(ranges), func(i int) bool { return ranges[i].start > va }) - 1
	if i < 0 || va >= ranges[i].end {
		return 0, false
	}
	return ranges[i].index, true
}

func limitCallsiteCandidates(candidates []CallsiteCandidate, limit int) []CallsiteCandidate {
	if limit <= 0 || limit >= len(candidates) {
		return candidates
	}
	return candidates[:limit]
}

func patchCallsiteBL(data []byte, textOff uint64, textVA uint64, trampolineVA uint64) bool {
	return patchCallsiteBLIfTarget(data, textOff, textVA, 0, trampolineVA)
}

func patchCallsiteBLIfTarget(data []byte, textOff uint64, textVA uint64, expectedTarget uint64, trampolineVA uint64) bool {
	if textOff+4 > uint64(len(data)) {
		return false
	}
	cur := binary.LittleEndian.Uint32(data[textOff:])
	origTarget, ok := decodeAArch64BL(cur, textVA)
	if !ok {
		return false
	}
	if expectedTarget != 0 && origTarget != expectedTarget {
		return false
	}
	bl, ok := encodeAArch64BL(textVA, trampolineVA)
	if !ok {
		return false
	}
	binary.LittleEndian.PutUint32(data[textOff:], bl)
	return true
}
