package elfstr

const aarch64PageSize = uint64(4096)

func decodeAArch64BL(insn uint32, pc uint64) (uint64, bool) {
	if insn&0xfc000000 != 0x94000000 {
		return 0, false
	}
	imm := signExtendAArch64(uint64(insn&0x03ffffff), 26) << 2
	return uint64(int64(pc) + imm), true
}

func encodeAArch64BL(pc, target uint64) (uint32, bool) {
	off := int64(target) - int64(pc)
	if off%4 != 0 {
		return 0, false
	}
	imm := off >> 2
	if imm < -(1<<25) || imm > (1<<25)-1 {
		return 0, false
	}
	return 0x94000000 | (uint32(imm) & 0x03ffffff), true
}

func decodeAArch64ADR(insn uint32, pc uint64) (uint32, uint64, bool) {
	if insn&0x9f000000 != 0x10000000 {
		return 0, 0, false
	}
	rd := insn & 0x1f
	immlo := (insn >> 29) & 0x3
	immhi := (insn >> 5) & 0x7ffff
	imm := signExtendAArch64(uint64(immhi<<2|immlo), 21)
	return rd, uint64(int64(pc) + imm), true
}

func encodeAArch64ADR(rd uint32, pc, target uint64) (uint32, bool) {
	if rd > 31 {
		return 0, false
	}
	off := int64(target) - int64(pc)
	if off < -(1<<20) || off > (1<<20)-1 {
		return 0, false
	}
	imm := uint32(off) & 0x1fffff
	immlo := (imm & 0x3) << 29
	immhi := ((imm >> 2) & 0x7ffff) << 5
	return 0x10000000 | immlo | immhi | rd, true
}

func decodeAArch64ADRP(insn uint32, pc uint64) (uint32, uint64, bool) {
	if insn&0x9f000000 != 0x90000000 {
		return 0, 0, false
	}
	rd := insn & 0x1f
	immlo := (insn >> 29) & 0x3
	immhi := (insn >> 5) & 0x7ffff
	pages := signExtendAArch64(uint64(immhi<<2|immlo), 21)
	base := pc &^ (aarch64PageSize - 1)
	return rd, uint64(int64(base) + (pages << 12)), true
}

func encodeAArch64ADRP(rd uint32, pc, target uint64) (uint32, bool) {
	if rd > 31 {
		return 0, false
	}
	pcPage := pc &^ (aarch64PageSize - 1)
	targetPage := target &^ (aarch64PageSize - 1)
	pages := int64(targetPage/aarch64PageSize) - int64(pcPage/aarch64PageSize)
	if pages < -(1<<20) || pages > (1<<20)-1 {
		return 0, false
	}
	imm := uint32(pages) & 0x1fffff
	immlo := (imm & 0x3) << 29
	immhi := ((imm >> 2) & 0x7ffff) << 5
	return 0x90000000 | immlo | immhi | rd, true
}

func decodeAArch64ADDImm64(insn uint32) (uint32, uint32, uint64, bool) {
	if insn&0xff800000 != 0x91000000 {
		return 0, 0, 0, false
	}
	rd := insn & 0x1f
	rn := (insn >> 5) & 0x1f
	imm := uint64((insn >> 10) & 0xfff)
	if insn&(1<<22) != 0 {
		imm <<= 12
	}
	return rd, rn, imm, true
}

func encodeAArch64ADDImm64(rd, rn uint32, imm uint64) (uint32, bool) {
	if rd > 31 || rn > 31 {
		return 0, false
	}
	shift := uint32(0)
	encodedImm := imm
	if encodedImm > 0xfff {
		if encodedImm%aarch64PageSize != 0 || encodedImm/aarch64PageSize > 0xfff {
			return 0, false
		}
		shift = 1
		encodedImm /= aarch64PageSize
	}
	return 0x91000000 | (shift << 22) | (uint32(encodedImm) << 10) | (rn << 5) | rd, true
}

func signExtendAArch64(v uint64, bits uint) int64 {
	shift := 64 - bits
	return int64(v<<shift) >> shift
}
