package elfstr

import "encoding/binary"

type elf64Ehdr struct {
	Phoff     uint64
	Shoff     uint64
	Phentsize uint16
	Phnum     uint16
	Shentsize uint16
	Shnum     uint16
	Shstrndx  uint16
}

type elf64Phdr struct {
	Type   uint32
	Flags  uint32
	Off    uint64
	Vaddr  uint64
	Paddr  uint64
	Filesz uint64
	Memsz  uint64
	Align  uint64
}

func readEhdr64(data []byte) elf64Ehdr {
	return elf64Ehdr{
		Phoff:     binary.LittleEndian.Uint64(data[0x20:]),
		Shoff:     binary.LittleEndian.Uint64(data[0x28:]),
		Phentsize: binary.LittleEndian.Uint16(data[0x36:]),
		Phnum:     binary.LittleEndian.Uint16(data[0x38:]),
		Shentsize: binary.LittleEndian.Uint16(data[0x3a:]),
		Shnum:     binary.LittleEndian.Uint16(data[0x3c:]),
		Shstrndx:  binary.LittleEndian.Uint16(data[0x3e:]),
	}
}

func readPhdr64(data []byte, off uint64) elf64Phdr {
	return elf64Phdr{
		Type:   binary.LittleEndian.Uint32(data[off:]),
		Flags:  binary.LittleEndian.Uint32(data[off+4:]),
		Off:    binary.LittleEndian.Uint64(data[off+8:]),
		Vaddr:  binary.LittleEndian.Uint64(data[off+16:]),
		Paddr:  binary.LittleEndian.Uint64(data[off+24:]),
		Filesz: binary.LittleEndian.Uint64(data[off+32:]),
		Memsz:  binary.LittleEndian.Uint64(data[off+40:]),
		Align:  binary.LittleEndian.Uint64(data[off+48:]),
	}
}

func writePhdr64(data []byte, off uint64, ph elf64Phdr) {
	binary.LittleEndian.PutUint32(data[off:], ph.Type)
	binary.LittleEndian.PutUint32(data[off+4:], ph.Flags)
	binary.LittleEndian.PutUint64(data[off+8:], ph.Off)
	binary.LittleEndian.PutUint64(data[off+16:], ph.Vaddr)
	binary.LittleEndian.PutUint64(data[off+24:], ph.Paddr)
	binary.LittleEndian.PutUint64(data[off+32:], ph.Filesz)
	binary.LittleEndian.PutUint64(data[off+40:], ph.Memsz)
	binary.LittleEndian.PutUint64(data[off+48:], ph.Align)
}

func alignUp(v, align uint64) uint64 {
	if align == 0 {
		return v
	}
	return (v + align - 1) &^ (align - 1)
}

func stripSectionHeaders(data []byte) {
	if len(data) < 0x40 || data[0] != 0x7f || data[1] != 'E' || data[2] != 'L' || data[3] != 'F' {
		return
	}
	// Section headers are not needed by the dynamic loader but give static
	// tooling named ranges (.rodata/.data.rel.ro) which make automated string
	// recovery easier. Clearing the ELF section-header table mirrors a stripped
	// runtime-only view while preserving program headers used for loading.
	binary.LittleEndian.PutUint64(data[0x28:], 0) // e_shoff
	binary.LittleEndian.PutUint16(data[0x3a:], 0) // e_shentsize
	binary.LittleEndian.PutUint16(data[0x3c:], 0) // e_shnum
	binary.LittleEndian.PutUint16(data[0x3e:], 0) // e_shstrndx
}
