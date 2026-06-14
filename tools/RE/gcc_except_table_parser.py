#!/usr/bin/env python3
"""Parse GCC/Itanium C++ exception tables from ELF binaries.

This is a Python port/rework of the small C parser at
https://github.com/nest-leonlee/gcc_except_table. It resolves a throwing PC to
the LSDA call-site row and landing pad, and can also dump all parsed call-site
tables:

    python tools/gcc_except_table_parser.py ./tmp/nothing 0x404be8
    python tools/gcc_except_table_parser.py ./tmp/nothing --dump --limit 5

For PIE/shared-library addresses from a debugger or IDA-rebased database, pass
the loaded image base with --base.
"""

from __future__ import annotations

import argparse
import bisect
import json
import struct
import sys
from dataclasses import dataclass
from pathlib import Path
from typing import Any


DW_EH_PE_ABSPTR = 0x00
DW_EH_PE_ULEB128 = 0x01
DW_EH_PE_UDATA2 = 0x02
DW_EH_PE_UDATA4 = 0x03
DW_EH_PE_UDATA8 = 0x04
DW_EH_PE_SLEB128 = 0x09
DW_EH_PE_SDATA2 = 0x0A
DW_EH_PE_SDATA4 = 0x0B
DW_EH_PE_SDATA8 = 0x0C

DW_EH_PE_PCREL = 0x10
DW_EH_PE_TEXTREL = 0x20
DW_EH_PE_DATAREL = 0x30
DW_EH_PE_FUNCREL = 0x40
DW_EH_PE_ALIGNED = 0x50
DW_EH_PE_INDIRECT = 0x80
DW_EH_PE_OMIT = 0xFF

DW_EH_PE_FORMAT_MASK = 0x0F
DW_EH_PE_APPL_MASK = 0x70

ET_DYN = 3
PT_LOAD = 1
SHF_EXECINSTR = 0x4


class ParseError(Exception):
    pass


@dataclass(frozen=True)
class Section:
    index: int
    name: str
    sh_type: int
    flags: int
    addr: int
    offset: int
    size: int
    link: int
    info: int
    addralign: int
    entsize: int

    @property
    def end_offset(self) -> int:
        return self.offset + self.size

    @property
    def end_addr(self) -> int:
        return self.addr + self.size


@dataclass(frozen=True)
class Segment:
    p_type: int
    flags: int
    offset: int
    vaddr: int
    paddr: int
    filesz: int
    memsz: int
    align: int


@dataclass(frozen=True)
class EntryHeader:
    offset: int
    address: int
    length: int
    length_size: int
    id_size: int
    id_offset: int
    payload_offset: int
    end_offset: int
    entry_id: int


@dataclass
class CIE:
    offset: int
    address: int
    length: int
    version: int
    augmentation: str
    code_alignment_factor: int
    data_alignment_factor: int
    return_address_register: int
    personality_encoding: int = DW_EH_PE_OMIT
    personality_routine: int | None = None
    fde_encoding: int = DW_EH_PE_ABSPTR
    lsda_encoding: int = DW_EH_PE_OMIT

    @property
    def has_z_augmentation(self) -> bool:
        return self.augmentation.startswith("z")


@dataclass
class FDE:
    offset: int
    address: int
    length: int
    cie: CIE
    function_start: int
    range_length: int
    lsda_address: int | None
    lsda_offset: int | None

    @property
    def function_end(self) -> int:
        return self.function_start + self.range_length


@dataclass
class EHFrameHdrEntry:
    initial_location: int
    fde_address: int
    fde_offset: int


@dataclass
class ActionRecord:
    offset: int
    type_filter: int
    next_offset: int


@dataclass
class CallSite:
    start: int
    length: int
    landing_pad: int
    action: int
    start_address: int
    end_address: int
    landing_pad_address: int | None
    actions: list[ActionRecord]


@dataclass
class LSDA:
    offset: int
    address: int
    lpstart_encoding: int
    lpstart: int
    ttype_encoding: int
    type_table_offset: int | None
    type_table_address: int | None
    call_site_encoding: int
    call_sites: list[CallSite]


@dataclass(frozen=True)
class CallReference:
    call_address: int
    target_address: int
    section_name: str


@dataclass
class ExceptionTableMatch:
    fde: FDE
    lsda: LSDA | None
    call_site: CallSite | None
    roles: list[str]
    landing_pad_span: tuple[int, int] | None = None
    call_chain: tuple[CallReference, ...] = ()


class ELFFile:
    def __init__(self, path: Path) -> None:
        self.path = path
        self.data = path.read_bytes()
        if len(self.data) < 16 or self.data[:4] != b"\x7fELF":
            raise ParseError(f"{path} is not an ELF file")

        elf_class = self.data[4]
        elf_data = self.data[5]
        if elf_class not in (1, 2):
            raise ParseError(f"unsupported ELF class {elf_class}")
        if elf_data not in (1, 2):
            raise ParseError(f"unsupported ELF byte order {elf_data}")

        self.is_64 = elf_class == 2
        self.ptr_size = 8 if self.is_64 else 4
        self.endian = "<" if elf_data == 1 else ">"
        self.e_type = 0
        self.e_machine = 0
        self.e_entry = 0
        self.program_headers: list[Segment] = []
        self.sections: list[Section] = []
        self.sections_by_name: dict[str, Section] = {}
        self._direct_calls_by_target: dict[int, list[CallReference]] | None = None
        self._parse_headers()

    def unpack_from(self, fmt: str, offset: int) -> tuple[Any, ...]:
        size = struct.calcsize(fmt)
        if offset < 0 or offset + size > len(self.data):
            raise ParseError(f"read outside file at offset 0x{offset:x}")
        return struct.unpack_from(fmt, self.data, offset)

    def read_uint(self, offset: int, size: int, signed: bool = False) -> int:
        if size not in (1, 2, 4, 8):
            raise ParseError(f"unsupported integer size {size}")
        fmt_map = {
            (1, False): "B",
            (1, True): "b",
            (2, False): "H",
            (2, True): "h",
            (4, False): "I",
            (4, True): "i",
            (8, False): "Q",
            (8, True): "q",
        }
        return self.unpack_from(self.endian + fmt_map[(size, signed)], offset)[0]

    def _parse_headers(self) -> None:
        if self.is_64:
            header = self.unpack_from(self.endian + "HHIQQQIHHHHHH", 16)
            (
                self.e_type,
                self.e_machine,
                _e_version,
                self.e_entry,
                e_phoff,
                e_shoff,
                _e_flags,
                _e_ehsize,
                e_phentsize,
                e_phnum,
                e_shentsize,
                e_shnum,
                e_shstrndx,
            ) = header
            ph_fmt = self.endian + "IIQQQQQQ"
            sh_fmt = self.endian + "IIQQQQIIQQ"
        else:
            header = self.unpack_from(self.endian + "HHIIIIIHHHHHH", 16)
            (
                self.e_type,
                self.e_machine,
                _e_version,
                self.e_entry,
                e_phoff,
                e_shoff,
                _e_flags,
                _e_ehsize,
                e_phentsize,
                e_phnum,
                e_shentsize,
                e_shnum,
                e_shstrndx,
            ) = header
            ph_fmt = self.endian + "IIIIIIII"
            sh_fmt = self.endian + "IIIIIIIIII"

        if e_phentsize < struct.calcsize(ph_fmt):
            raise ParseError("program header entry size is smaller than expected")
        if e_shentsize < struct.calcsize(sh_fmt):
            raise ParseError("section header entry size is smaller than expected")

        for i in range(e_phnum):
            offset = e_phoff + i * e_phentsize
            fields = self.unpack_from(ph_fmt, offset)
            if self.is_64:
                p_type, p_flags, p_offset, p_vaddr, p_paddr, p_filesz, p_memsz, p_align = fields
            else:
                p_type, p_offset, p_vaddr, p_paddr, p_filesz, p_memsz, p_flags, p_align = fields
            self.program_headers.append(
                Segment(p_type, p_flags, p_offset, p_vaddr, p_paddr, p_filesz, p_memsz, p_align)
            )

        raw_sections: list[tuple[int, tuple[Any, ...]]] = []
        for i in range(e_shnum):
            offset = e_shoff + i * e_shentsize
            raw_sections.append((i, self.unpack_from(sh_fmt, offset)))

        if e_shstrndx >= len(raw_sections):
            raise ParseError("invalid section-name string table index")

        shstr = raw_sections[e_shstrndx][1]
        shstr_offset = shstr[4] if self.is_64 else shstr[4]
        shstr_size = shstr[5] if self.is_64 else shstr[5]
        shstr_data = self.data[shstr_offset : shstr_offset + shstr_size]

        for index, fields in raw_sections:
            if self.is_64:
                name_off, sh_type, flags, addr, offset, size, link, info, addralign, entsize = fields
            else:
                name_off, sh_type, flags, addr, offset, size, link, info, addralign, entsize = fields
            name = read_c_string(shstr_data, name_off)
            section = Section(index, name, sh_type, flags, addr, offset, size, link, info, addralign, entsize)
            self.sections.append(section)
            self.sections_by_name[name] = section

    def section(self, name: str) -> Section:
        try:
            return self.sections_by_name[name]
        except KeyError as exc:
            raise ParseError(f"missing required section {name}") from exc

    def executable_base(self) -> int:
        candidates = [
            segment.vaddr
            for segment in self.program_headers
            if segment.p_type == PT_LOAD and segment.flags & 0x1
        ]
        if candidates:
            return min(candidates)
        candidates = [section.addr for section in self.sections if section.flags & SHF_EXECINSTR]
        return min(candidates) if candidates else 0

    def data_base(self) -> int:
        candidates = [
            segment.vaddr
            for segment in self.program_headers
            if segment.p_type == PT_LOAD and not (segment.flags & 0x1)
        ]
        return min(candidates) if candidates else 0

    def executable_sections(self) -> list[Section]:
        return [section for section in self.sections if section.flags & SHF_EXECINSTR and section.size > 0]

    def direct_calls_by_target(self) -> dict[int, list[CallReference]]:
        if self._direct_calls_by_target is not None:
            return self._direct_calls_by_target

        calls: dict[int, list[CallReference]] = {}
        if self.e_machine not in (3, 62) or self.endian != "<":
            self._direct_calls_by_target = calls
            return calls

        for section in self.executable_sections():
            section_data = self.data[section.offset : section.offset + section.size]
            index = 0
            while True:
                index = section_data.find(b"\xe8", index)
                if index < 0:
                    break
                if index + 5 > len(section_data):
                    break
                rel32 = struct.unpack_from("<i", section_data, index + 1)[0]
                call_address = section.addr + index
                target_address = call_address + 5 + rel32
                calls.setdefault(target_address, []).append(
                    CallReference(call_address, target_address, section.name)
                )
                index += 1

        self._direct_calls_by_target = calls
        return calls

    def direct_calls_to(self, target_address: int) -> list[CallReference]:
        return self.direct_calls_by_target().get(target_address, [])

    def offset_to_va(self, offset: int) -> int:
        for segment in self.program_headers:
            if segment.p_type != PT_LOAD:
                continue
            if segment.offset <= offset < segment.offset + segment.filesz:
                return segment.vaddr + (offset - segment.offset)
        for section in self.sections:
            if section.offset <= offset < section.offset + section.size:
                return section.addr + (offset - section.offset)
        return offset

    def va_to_offset(self, address: int) -> int:
        for segment in self.program_headers:
            if segment.p_type != PT_LOAD:
                continue
            if segment.vaddr <= address < segment.vaddr + segment.filesz:
                return segment.offset + (address - segment.vaddr)
        for section in self.sections:
            if section.addr <= address < section.addr + section.size:
                return section.offset + (address - section.addr)
        raise ParseError(f"cannot map virtual address 0x{address:x} to a file offset")


def read_c_string(data: bytes, offset: int) -> str:
    if offset < 0 or offset >= len(data):
        return ""
    end = data.find(b"\x00", offset)
    if end == -1:
        end = len(data)
    return data[offset:end].decode("utf-8", errors="replace")


def read_uleb128(data: bytes, offset: int, end: int | None = None) -> tuple[int, int]:
    limit = len(data) if end is None else min(end, len(data))
    result = 0
    shift = 0
    start = offset
    while True:
        if offset >= limit:
            raise ParseError(f"malformed ULEB128 at offset 0x{start:x}")
        byte = data[offset]
        offset += 1
        result |= (byte & 0x7F) << shift
        if byte < 0x80:
            return result, offset
        shift += 7
        if shift >= 64:
            raise ParseError(f"ULEB128 too large at offset 0x{start:x}")


def read_sleb128(data: bytes, offset: int, end: int | None = None) -> tuple[int, int]:
    limit = len(data) if end is None else min(end, len(data))
    result = 0
    shift = 0
    start = offset
    while True:
        if offset >= limit:
            raise ParseError(f"malformed SLEB128 at offset 0x{start:x}")
        byte = data[offset]
        offset += 1
        result |= (byte & 0x7F) << shift
        shift += 7
        if byte < 0x80:
            if byte & 0x40:
                result |= -1 << shift
            return result, offset
        if shift >= 64:
            raise ParseError(f"SLEB128 too large at offset 0x{start:x}")


def align_up(value: int, alignment: int) -> int:
    return (value + alignment - 1) & ~(alignment - 1)


def pointer_format_size(encoding: int, ptr_size: int) -> int | None:
    form = encoding & DW_EH_PE_FORMAT_MASK
    if form == DW_EH_PE_ABSPTR:
        return ptr_size
    if form in (DW_EH_PE_UDATA2, DW_EH_PE_SDATA2):
        return 2
    if form in (DW_EH_PE_UDATA4, DW_EH_PE_SDATA4):
        return 4
    if form in (DW_EH_PE_UDATA8, DW_EH_PE_SDATA8):
        return 8
    if form in (DW_EH_PE_ULEB128, DW_EH_PE_SLEB128):
        return None
    raise ParseError(f"unsupported DW_EH pointer format 0x{form:x}")


def read_encoded_scalar(elf: ELFFile, offset: int, encoding: int, end: int | None = None) -> tuple[int, int]:
    if encoding == DW_EH_PE_OMIT:
        raise ParseError("attempted to read omitted DW_EH pointer")

    form = encoding & DW_EH_PE_FORMAT_MASK
    if form == DW_EH_PE_ULEB128:
        return read_uleb128(elf.data, offset, end)
    if form == DW_EH_PE_SLEB128:
        return read_sleb128(elf.data, offset, end)
    if form == DW_EH_PE_ABSPTR:
        size = elf.ptr_size
        return elf.read_uint(offset, size), offset + size
    if form == DW_EH_PE_UDATA2:
        return elf.read_uint(offset, 2), offset + 2
    if form == DW_EH_PE_UDATA4:
        return elf.read_uint(offset, 4), offset + 4
    if form == DW_EH_PE_UDATA8:
        return elf.read_uint(offset, 8), offset + 8
    if form == DW_EH_PE_SDATA2:
        return elf.read_uint(offset, 2, signed=True), offset + 2
    if form == DW_EH_PE_SDATA4:
        return elf.read_uint(offset, 4, signed=True), offset + 4
    if form == DW_EH_PE_SDATA8:
        return elf.read_uint(offset, 8, signed=True), offset + 8
    raise ParseError(f"unsupported DW_EH pointer encoding 0x{encoding:x}")


def read_encoded_pointer(
    elf: ELFFile,
    offset: int,
    encoding: int,
    *,
    pcrel_base: int | None = None,
    textrel_base: int | None = None,
    datarel_base: int | None = None,
    funcrel_base: int | None = None,
    end: int | None = None,
) -> tuple[int, int]:
    if encoding == DW_EH_PE_OMIT:
        raise ParseError("attempted to read omitted DW_EH pointer")

    raw_offset = offset
    application = encoding & DW_EH_PE_APPL_MASK
    if application == DW_EH_PE_ALIGNED:
        offset = align_up(offset, elf.ptr_size)
        raw_offset = offset

    raw_value, new_offset = read_encoded_scalar(elf, offset, encoding, end)
    field_address = elf.offset_to_va(raw_offset)
    value = raw_value

    if application == 0:
        pass
    elif application == DW_EH_PE_PCREL:
        value = (field_address if pcrel_base is None else pcrel_base) + raw_value
    elif application == DW_EH_PE_TEXTREL:
        value = (elf.executable_base() if textrel_base is None else textrel_base) + raw_value
    elif application == DW_EH_PE_DATAREL:
        if datarel_base is None:
            datarel_base = elf.data_base()
        value = datarel_base + raw_value
    elif application == DW_EH_PE_FUNCREL:
        if funcrel_base is None:
            raise ParseError("DW_EH_PE_funcrel pointer has no function-relative base")
        value = funcrel_base + raw_value
    elif application == DW_EH_PE_ALIGNED:
        value = raw_value
    else:
        raise ParseError(f"unsupported DW_EH pointer application 0x{application:x}")

    if encoding & DW_EH_PE_INDIRECT:
        deref_offset = elf.va_to_offset(value)
        value = elf.read_uint(deref_offset, elf.ptr_size)

    return value, new_offset


def encoding_name(encoding: int) -> str:
    if encoding == DW_EH_PE_OMIT:
        return "omit"
    formats = {
        DW_EH_PE_ABSPTR: "absptr",
        DW_EH_PE_ULEB128: "uleb128",
        DW_EH_PE_UDATA2: "udata2",
        DW_EH_PE_UDATA4: "udata4",
        DW_EH_PE_UDATA8: "udata8",
        DW_EH_PE_SLEB128: "sleb128",
        DW_EH_PE_SDATA2: "sdata2",
        DW_EH_PE_SDATA4: "sdata4",
        DW_EH_PE_SDATA8: "sdata8",
    }
    applications = {
        0: "",
        DW_EH_PE_PCREL: "pcrel|",
        DW_EH_PE_TEXTREL: "textrel|",
        DW_EH_PE_DATAREL: "datarel|",
        DW_EH_PE_FUNCREL: "funcrel|",
        DW_EH_PE_ALIGNED: "aligned|",
    }
    form = formats.get(encoding & DW_EH_PE_FORMAT_MASK, f"form_0x{encoding & DW_EH_PE_FORMAT_MASK:x}")
    application = applications.get(encoding & DW_EH_PE_APPL_MASK, f"appl_0x{encoding & DW_EH_PE_APPL_MASK:x}|")
    indirect = "indirect|" if encoding & DW_EH_PE_INDIRECT else ""
    return f"{indirect}{application}{form}"


class GCCExceptTableParser:
    def __init__(self, elf: ELFFile) -> None:
        self.elf = elf
        self.cie_cache: dict[int, CIE] = {}
        self.fde_cache: dict[int, FDE] = {}
        self._all_fdes_cache: list[FDE] | None = None
        self.lsda_cache: dict[int, LSDA] = {}
        self.eh_frame = elf.section(".eh_frame")
        self.eh_frame_hdr = elf.sections_by_name.get(".eh_frame_hdr")
        self.gcc_except_table = elf.sections_by_name.get(".gcc_except_table")

    def entry_header_at(self, offset: int) -> EntryHeader | None:
        if offset + 4 > len(self.elf.data):
            raise ParseError(f"entry header outside file at 0x{offset:x}")
        length32 = self.elf.read_uint(offset, 4)
        if length32 == 0:
            return None
        if length32 == 0xFFFFFFFF:
            length = self.elf.read_uint(offset + 4, 8)
            length_size = 12
            id_size = 8
        else:
            length = length32
            length_size = 4
            id_size = 4
        id_offset = offset + length_size
        payload_offset = id_offset + id_size
        end_offset = offset + length_size + length
        if end_offset > len(self.elf.data):
            raise ParseError(f".eh_frame entry at 0x{offset:x} extends past the file")
        entry_id = self.elf.read_uint(id_offset, id_size)
        return EntryHeader(
            offset=offset,
            address=self.elf.offset_to_va(offset),
            length=length,
            length_size=length_size,
            id_size=id_size,
            id_offset=id_offset,
            payload_offset=payload_offset,
            end_offset=end_offset,
            entry_id=entry_id,
        )

    def iter_eh_frame_entry_offsets(self) -> list[int]:
        offsets: list[int] = []
        offset = self.eh_frame.offset
        end = self.eh_frame.end_offset
        while offset < end:
            header = self.entry_header_at(offset)
            if header is None:
                break
            offsets.append(offset)
            offset = header.end_offset
        return offsets

    def parse_cie(self, offset: int) -> CIE:
        if offset in self.cie_cache:
            return self.cie_cache[offset]

        header = self.entry_header_at(offset)
        if header is None or header.entry_id != 0:
            raise ParseError(f"0x{offset:x} is not a CIE")

        pos = header.payload_offset
        version = self.elf.read_uint(pos, 1)
        pos += 1
        aug_end = self.elf.data.find(b"\x00", pos, header.end_offset)
        if aug_end == -1:
            raise ParseError(f"unterminated CIE augmentation string at 0x{pos:x}")
        augmentation = self.elf.data[pos:aug_end].decode("ascii", errors="replace")
        pos = aug_end + 1

        if augmentation.startswith("eh"):
            pos += self.elf.ptr_size

        code_alignment_factor, pos = read_uleb128(self.elf.data, pos, header.end_offset)
        data_alignment_factor, pos = read_sleb128(self.elf.data, pos, header.end_offset)
        if version == 1:
            return_address_register = self.elf.read_uint(pos, 1)
            pos += 1
        else:
            return_address_register, pos = read_uleb128(self.elf.data, pos, header.end_offset)

        cie = CIE(
            offset=offset,
            address=header.address,
            length=header.length,
            version=version,
            augmentation=augmentation,
            code_alignment_factor=code_alignment_factor,
            data_alignment_factor=data_alignment_factor,
            return_address_register=return_address_register,
        )

        if augmentation.startswith("z"):
            augmentation_length, pos = read_uleb128(self.elf.data, pos, header.end_offset)
            augmentation_end = pos + augmentation_length
            if augmentation_end > header.end_offset:
                raise ParseError(f"CIE augmentation at 0x{offset:x} extends past the CIE")

            for char in augmentation[1:]:
                if char == "P":
                    cie.personality_encoding = self.elf.read_uint(pos, 1)
                    pos += 1
                    cie.personality_routine, pos = read_encoded_pointer(
                        self.elf,
                        pos,
                        cie.personality_encoding,
                        datarel_base=self.eh_frame.addr,
                        end=augmentation_end,
                    )
                elif char == "L":
                    cie.lsda_encoding = self.elf.read_uint(pos, 1)
                    pos += 1
                elif char == "R":
                    cie.fde_encoding = self.elf.read_uint(pos, 1)
                    pos += 1
                elif char in ("S", "B", "G"):
                    continue
                else:
                    # Unknown augmentation letters are not parseable without
                    # ABI-specific size rules, so leave the rest opaque.
                    break

        self.cie_cache[offset] = cie
        return cie

    def parse_fde(self, offset: int) -> FDE:
        if offset in self.fde_cache:
            return self.fde_cache[offset]

        header = self.entry_header_at(offset)
        if header is None or header.entry_id == 0:
            raise ParseError(f"0x{offset:x} is not an FDE")

        cie_address = self.elf.offset_to_va(header.id_offset) - header.entry_id
        cie_offset = self.elf.va_to_offset(cie_address)
        cie = self.parse_cie(cie_offset)

        pos = header.payload_offset
        function_start, pos = read_encoded_pointer(
            self.elf,
            pos,
            cie.fde_encoding,
            datarel_base=self.eh_frame.addr,
            end=header.end_offset,
        )
        range_length, pos = read_encoded_scalar(self.elf, pos, cie.fde_encoding, header.end_offset)

        lsda_address: int | None = None
        lsda_offset: int | None = None
        if cie.has_z_augmentation:
            augmentation_length, pos = read_uleb128(self.elf.data, pos, header.end_offset)
            augmentation_end = pos + augmentation_length
            if augmentation_end > header.end_offset:
                raise ParseError(f"FDE augmentation at 0x{offset:x} extends past the FDE")
            if cie.lsda_encoding != DW_EH_PE_OMIT and pos < augmentation_end:
                lsda_address, pos = read_encoded_pointer(
                    self.elf,
                    pos,
                    cie.lsda_encoding,
                    datarel_base=self.eh_frame.addr,
                    funcrel_base=function_start,
                    end=augmentation_end,
                )
                if lsda_address != 0:
                    try:
                        lsda_offset = self.elf.va_to_offset(lsda_address)
                    except ParseError:
                        lsda_offset = None

        fde = FDE(
            offset=offset,
            address=header.address,
            length=header.length,
            cie=cie,
            function_start=function_start,
            range_length=range_length,
            lsda_address=lsda_address,
            lsda_offset=lsda_offset,
        )
        self.fde_cache[offset] = fde
        return fde

    def parse_eh_frame_hdr_entries(self) -> list[EHFrameHdrEntry]:
        if self.eh_frame_hdr is None:
            return []

        pos = self.eh_frame_hdr.offset
        end = self.eh_frame_hdr.end_offset
        version = self.elf.read_uint(pos, 1)
        pos += 1
        if version != 1:
            raise ParseError(f"unsupported .eh_frame_hdr version {version}")

        eh_frame_ptr_enc = self.elf.read_uint(pos, 1)
        pos += 1
        fde_count_enc = self.elf.read_uint(pos, 1)
        pos += 1
        table_enc = self.elf.read_uint(pos, 1)
        pos += 1

        if eh_frame_ptr_enc != DW_EH_PE_OMIT:
            _eh_frame_ptr, pos = read_encoded_pointer(
                self.elf,
                pos,
                eh_frame_ptr_enc,
                datarel_base=self.eh_frame_hdr.addr,
                end=end,
            )

        if fde_count_enc == DW_EH_PE_OMIT:
            return []
        fde_count, pos = read_encoded_scalar(self.elf, pos, fde_count_enc, end)

        entries: list[EHFrameHdrEntry] = []
        for _ in range(fde_count):
            initial_location, pos = read_encoded_pointer(
                self.elf,
                pos,
                table_enc,
                datarel_base=self.eh_frame_hdr.addr,
                end=end,
            )
            fde_address, pos = read_encoded_pointer(
                self.elf,
                pos,
                table_enc,
                datarel_base=self.eh_frame_hdr.addr,
                end=end,
            )
            try:
                fde_offset = self.elf.va_to_offset(fde_address)
            except ParseError:
                continue
            entries.append(EHFrameHdrEntry(initial_location, fde_address, fde_offset))
        return entries

    def iter_fdes(self) -> list[FDE]:
        if self._all_fdes_cache is not None:
            return self._all_fdes_cache

        fdes: list[FDE] = []
        for offset in self.iter_eh_frame_entry_offsets():
            header = self.entry_header_at(offset)
            if header is None or header.entry_id == 0:
                continue
            try:
                fdes.append(self.parse_fde(offset))
            except ParseError:
                continue
        self._all_fdes_cache = sorted(fdes, key=lambda item: (item.function_start, item.offset))
        return self._all_fdes_cache

    def find_fde(self, pc: int) -> FDE:
        hdr_entries = self.parse_eh_frame_hdr_entries()
        if hdr_entries:
            starts = [entry.initial_location for entry in hdr_entries]
            index = bisect.bisect_right(starts, pc) - 1
            nearby = range(max(0, index - 2), min(len(hdr_entries), index + 3))
            for i in reversed(list(nearby)):
                fde = self.parse_fde(hdr_entries[i].fde_offset)
                if fde.function_start <= pc < fde.function_end:
                    return fde

        for fde in self.iter_fdes():
            if fde.function_start <= pc < fde.function_end:
                return fde

        raise ParseError(f"no FDE covers PC 0x{pc:x}")

    def parse_action_chain(self, action: int, action_table_start: int, limit: int) -> list[ActionRecord]:
        if action == 0:
            return []

        records: list[ActionRecord] = []
        seen: set[int] = set()
        record_offset = action_table_start + action - 1
        for _ in range(64):
            if record_offset in seen or record_offset < action_table_start or record_offset >= limit:
                break
            seen.add(record_offset)
            pos = record_offset
            type_filter, pos = read_sleb128(self.elf.data, pos, limit)
            next_offset_field = pos
            next_offset, pos = read_sleb128(self.elf.data, pos, limit)
            records.append(ActionRecord(record_offset, type_filter, next_offset))
            if next_offset == 0:
                break
            record_offset = next_offset_field + next_offset
        return records

    def parse_lsda(self, fde: FDE) -> LSDA:
        if fde.offset in self.lsda_cache:
            return self.lsda_cache[fde.offset]

        if fde.lsda_offset is None or fde.lsda_address is None:
            raise ParseError("FDE has no LSDA")
        if self.gcc_except_table is not None:
            table_end = self.gcc_except_table.end_offset
        else:
            table_end = len(self.elf.data)

        pos = fde.lsda_offset
        address = self.elf.offset_to_va(pos)

        lpstart_encoding = self.elf.read_uint(pos, 1)
        pos += 1
        if lpstart_encoding == DW_EH_PE_OMIT:
            lpstart = fde.function_start
        else:
            lpstart, pos = read_encoded_pointer(
                self.elf,
                pos,
                lpstart_encoding,
                datarel_base=self.eh_frame.addr,
                funcrel_base=fde.function_start,
                end=table_end,
            )

        ttype_encoding = self.elf.read_uint(pos, 1)
        pos += 1
        type_table_offset: int | None = None
        type_table_address: int | None = None
        if ttype_encoding != DW_EH_PE_OMIT:
            type_table_offset, pos = read_uleb128(self.elf.data, pos, table_end)
            try:
                type_table_address = self.elf.offset_to_va(pos + type_table_offset)
            except ParseError:
                type_table_address = None

        call_site_encoding = self.elf.read_uint(pos, 1)
        pos += 1
        call_site_table_length, pos = read_uleb128(self.elf.data, pos, table_end)
        call_site_table_start = pos
        call_site_table_end = pos + call_site_table_length
        if call_site_table_end > table_end:
            raise ParseError(f"LSDA at 0x{fde.lsda_offset:x} has an oversized call-site table")

        call_sites: list[CallSite] = []
        while pos < call_site_table_end:
            start, pos = read_encoded_scalar(self.elf, pos, call_site_encoding, call_site_table_end)
            length, pos = read_encoded_scalar(self.elf, pos, call_site_encoding, call_site_table_end)
            landing_pad, pos = read_encoded_scalar(self.elf, pos, call_site_encoding, call_site_table_end)
            action, pos = read_uleb128(self.elf.data, pos, call_site_table_end)
            landing_pad_address = None if landing_pad == 0 else lpstart + landing_pad
            call_sites.append(
                CallSite(
                    start=start,
                    length=length,
                    landing_pad=landing_pad,
                    action=action,
                    start_address=lpstart + start,
                    end_address=lpstart + start + length,
                    landing_pad_address=landing_pad_address,
                    actions=[],
                )
            )

        action_table_start = call_site_table_end
        action_limit = self.elf.va_to_offset(type_table_address) if type_table_address is not None else table_end
        for call_site in call_sites:
            call_site.actions = self.parse_action_chain(call_site.action, action_table_start, action_limit)

        lsda = LSDA(
            offset=fde.lsda_offset,
            address=address,
            lpstart_encoding=lpstart_encoding,
            lpstart=lpstart,
            ttype_encoding=ttype_encoding,
            type_table_offset=type_table_offset,
            type_table_address=type_table_address,
            call_site_encoding=call_site_encoding,
            call_sites=call_sites,
        )
        self.lsda_cache[fde.offset] = lsda
        return lsda

    def landing_pad_for_pc(self, pc: int) -> tuple[FDE, LSDA, CallSite | None]:
        fde = self.find_fde(pc)
        lsda = self.parse_lsda(fde)
        for call_site in lsda.call_sites:
            if call_site.start_address <= pc < call_site.end_address:
                return fde, lsda, call_site
        return fde, lsda, None

    @staticmethod
    def landing_pad_span(fde: FDE, lsda: LSDA, call_site: CallSite) -> tuple[int, int] | None:
        if call_site.landing_pad_address is None:
            return None

        boundaries = {fde.function_start, fde.function_end}
        for entry in lsda.call_sites:
            boundaries.add(entry.start_address)
            boundaries.add(entry.end_address)
            if entry.landing_pad_address is not None:
                boundaries.add(entry.landing_pad_address)

        next_boundaries = sorted(boundary for boundary in boundaries if boundary > call_site.landing_pad_address)
        end = next_boundaries[0] if next_boundaries else fde.function_end
        if end <= call_site.landing_pad_address:
            end = fde.function_end
        return call_site.landing_pad_address, end

    def fdes_containing(self, address: int) -> list[FDE]:
        return [fde for fde in self.iter_fdes() if fde.function_start <= address < fde.function_end]

    def _find_exception_entries_at_address(
        self,
        address: int,
        *,
        include_fde_only: bool,
    ) -> list[ExceptionTableMatch]:
        matches: list[ExceptionTableMatch] = []

        for fde in self.fdes_containing(address):
            if fde.lsda_offset is None or fde.lsda_address is None:
                if include_fde_only:
                    matches.append(ExceptionTableMatch(fde, None, None, ["fde_range_no_lsda"]))
                continue

            try:
                lsda = self.parse_lsda(fde)
            except ParseError:
                if include_fde_only:
                    matches.append(ExceptionTableMatch(fde, None, None, ["fde_range_lsda_parse_failed"]))
                continue

            matched_this_fde = False
            for call_site in lsda.call_sites:
                roles: list[str] = []
                landing_pad_span = self.landing_pad_span(fde, lsda, call_site)

                if call_site.start_address <= address < call_site.end_address:
                    roles.append("protected_range")

                if landing_pad_span is not None and landing_pad_span[0] <= address < landing_pad_span[1]:
                    if address == landing_pad_span[0]:
                        roles.append("landing_pad_start")
                    else:
                        roles.append("landing_pad_range")

                if roles:
                    matches.append(ExceptionTableMatch(fde, lsda, call_site, roles, landing_pad_span))
                    matched_this_fde = True

            if include_fde_only and not matched_this_fde:
                matches.append(ExceptionTableMatch(fde, lsda, None, ["function_range"]))

        return matches

    @staticmethod
    def caller_roles(roles: list[str], depth: int) -> list[str]:
        prefix = "callee_called_from" if depth == 1 else "callee_reaches"
        rewritten: list[str] = []
        for role in roles:
            if role == "protected_range":
                rewritten.append(f"{prefix}_protected_range")
            elif role in ("landing_pad_start", "landing_pad_range"):
                rewritten.append(f"{prefix}_landing_pad")
            elif role == "function_range":
                rewritten.append(f"{prefix}_function_range")
            elif role == "fde_range_no_lsda":
                rewritten.append(f"{prefix}_fde_range_no_lsda")
            elif role == "fde_range_lsda_parse_failed":
                rewritten.append(f"{prefix}_fde_range_lsda_parse_failed")
            else:
                rewritten.append(f"{prefix}_{role}")
        return rewritten

    @staticmethod
    def match_key(match: ExceptionTableMatch) -> tuple[Any, ...]:
        call_site_key = None
        if match.call_site is not None:
            call_site_key = (
                match.call_site.start_address,
                match.call_site.end_address,
                match.call_site.landing_pad_address,
                match.call_site.action,
            )
        call_chain_key = tuple((call.call_address, call.target_address) for call in match.call_chain)
        return (match.fde.offset, call_site_key, tuple(match.roles), call_chain_key)

    def find_caller_exception_entries(self, address: int, max_depth: int) -> list[ExceptionTableMatch]:
        if max_depth <= 0:
            return []

        matches: list[ExceptionTableMatch] = []
        seen_matches: set[tuple[Any, ...]] = set()
        seen_targets: set[tuple[int, int]] = {(address, 0)}
        queue: list[tuple[int, tuple[CallReference, ...], int]] = [(address, (), 0)]

        while queue:
            target_address, inner_chain, depth = queue.pop(0)
            if depth >= max_depth:
                continue

            for call_ref in self.elf.direct_calls_to(target_address):
                call_chain = (call_ref,) + inner_chain
                caller_matches = self._find_exception_entries_at_address(
                    call_ref.call_address,
                    include_fde_only=False,
                )
                for caller_match in caller_matches:
                    match = ExceptionTableMatch(
                        caller_match.fde,
                        caller_match.lsda,
                        caller_match.call_site,
                        self.caller_roles(caller_match.roles, len(call_chain)),
                        caller_match.landing_pad_span,
                        call_chain,
                    )
                    key = self.match_key(match)
                    if key not in seen_matches:
                        seen_matches.add(key)
                        matches.append(match)

                for caller_fde in self.fdes_containing(call_ref.call_address):
                    next_target = caller_fde.function_start
                    next_state = (next_target, depth + 1)
                    if next_state in seen_targets:
                        continue
                    seen_targets.add(next_state)
                    queue.append((next_target, call_chain, depth + 1))

        return matches

    def find_exception_entries(self, address: int, caller_depth: int = 2) -> list[ExceptionTableMatch]:
        matches = self._find_exception_entries_at_address(address, include_fde_only=True)
        seen = {self.match_key(match) for match in matches}
        for caller_match in self.find_caller_exception_entries(address, caller_depth):
            key = self.match_key(caller_match)
            if key not in seen:
                seen.add(key)
                matches.append(caller_match)
        return matches


def parse_int(value: str) -> int:
    return int(value, 0)


def hex_or_none(value: int | None, base: int = 0) -> str:
    if value is None:
        return "none"
    return f"0x{value + base:x}"


def action_to_dict(action: ActionRecord) -> dict[str, int]:
    return {
        "offset": action.offset,
        "type_filter": action.type_filter,
        "next_offset": action.next_offset,
    }


def call_reference_to_dict(call: CallReference, base: int) -> dict[str, Any]:
    return {
        "call_address": call.call_address + base,
        "target_address": call.target_address + base,
        "section_name": call.section_name,
    }


def call_site_to_dict(call_site: CallSite, base: int) -> dict[str, Any]:
    return {
        "start": call_site.start,
        "length": call_site.length,
        "landing_pad": call_site.landing_pad,
        "action": call_site.action,
        "start_address": call_site.start_address + base,
        "end_address": call_site.end_address + base,
        "landing_pad_address": None
        if call_site.landing_pad_address is None
        else call_site.landing_pad_address + base,
        "actions": [action_to_dict(action) for action in call_site.actions],
    }


def fde_to_dict(fde: FDE, base: int) -> dict[str, Any]:
    return {
        "fde_address": fde.address + base,
        "fde_offset": fde.offset,
        "function_start": fde.function_start + base,
        "function_end": fde.function_end + base,
        "range_length": fde.range_length,
        "cie_address": fde.cie.address + base,
        "cie_augmentation": fde.cie.augmentation,
        "fde_encoding": encoding_name(fde.cie.fde_encoding),
        "lsda_encoding": encoding_name(fde.cie.lsda_encoding),
        "lsda_address": None if fde.lsda_address is None else fde.lsda_address + base,
        "lsda_offset": fde.lsda_offset,
    }


def lsda_to_dict(lsda: LSDA, base: int, include_call_sites: bool = True) -> dict[str, Any]:
    result: dict[str, Any] = {
        "lsda_address": lsda.address + base,
        "lsda_offset": lsda.offset,
        "lpstart": lsda.lpstart + base,
        "lpstart_encoding": encoding_name(lsda.lpstart_encoding),
        "ttype_encoding": encoding_name(lsda.ttype_encoding),
        "type_table_address": None if lsda.type_table_address is None else lsda.type_table_address + base,
        "call_site_encoding": encoding_name(lsda.call_site_encoding),
    }
    if include_call_sites:
        result["call_sites"] = [call_site_to_dict(call_site, base) for call_site in lsda.call_sites]
    return result


def match_to_dict(match: ExceptionTableMatch, base: int) -> dict[str, Any]:
    result: dict[str, Any] = {
        "roles": match.roles,
        "fde": fde_to_dict(match.fde, base),
        "lsda": None if match.lsda is None else lsda_to_dict(match.lsda, base, include_call_sites=False),
        "call_site": None if match.call_site is None else call_site_to_dict(match.call_site, base),
        "call_chain": [call_reference_to_dict(call, base) for call in match.call_chain],
    }
    if match.landing_pad_span is not None:
        result["landing_pad_span"] = {
            "start": match.landing_pad_span[0] + base,
            "end": match.landing_pad_span[1] + base,
            "note": "inferred from neighboring call-site and landing-pad boundaries",
        }
    return result


def print_pc_result(
    elf: ELFFile,
    raw_pc: int,
    rebased_pc: int,
    base: int,
    fde: FDE,
    lsda: LSDA,
    call_site: CallSite | None,
) -> None:
    print(f"ELF: {elf.path}")
    if base:
        print(f"Image base: 0x{base:x}")
        print(f"PC: 0x{raw_pc:x} -> file VA 0x{rebased_pc:x}")
    else:
        print(f"PC: 0x{raw_pc:x}")
    print(
        "Function: "
        f"{hex_or_none(fde.function_start, base)}..{hex_or_none(fde.function_end, base)} "
        f"(FDE {hex_or_none(fde.address, base)}, file offset 0x{fde.offset:x})"
    )
    print(
        "CIE: "
        f"{hex_or_none(fde.cie.address, base)} aug={fde.cie.augmentation!r} "
        f"fde_enc={encoding_name(fde.cie.fde_encoding)} "
        f"lsda_enc={encoding_name(fde.cie.lsda_encoding)}"
    )
    print(
        "LSDA: "
        f"{hex_or_none(lsda.address, base)} file offset 0x{lsda.offset:x} "
        f"call_site_enc={encoding_name(lsda.call_site_encoding)}"
    )

    if call_site is None:
        print(f"No call-site row covers 0x{raw_pc:x}.")
        return

    landing = hex_or_none(call_site.landing_pad_address, base)
    print(
        "Call site: "
        f"{hex_or_none(call_site.start_address, base)}..{hex_or_none(call_site.end_address, base)} "
        f"-> landing_pad={landing} action={call_site.action}"
    )
    if call_site.landing_pad_address is None:
        print(f"There is no landing pad when a C++ exception is raised at 0x{raw_pc:x}.")
    else:
        print(
            "The landing pad is "
            f"{hex_or_none(call_site.landing_pad_address, base)} "
            f"<+0x{call_site.landing_pad:x}> when a C++ exception is raised at 0x{raw_pc:x}."
        )


def print_address_matches(
    elf: ELFFile,
    raw_address: int,
    rebased_address: int,
    base: int,
    matches: list[ExceptionTableMatch],
) -> None:
    print(f"ELF: {elf.path}")
    if base:
        print(f"Image base: 0x{base:x}")
        print(f"Address: 0x{raw_address:x} -> file VA 0x{rebased_address:x}")
    else:
        print(f"Address: 0x{raw_address:x}")

    if not matches:
        print("No FDE/LSDA/call-site entry matched this address.")
        return

    print(f"Matched exception entries: {len(matches)}")
    for index, match in enumerate(matches, 1):
        print("")
        print(f"[{index}] roles={', '.join(match.roles)}")
        if match.call_chain:
            print("    Via calls:")
            for call in match.call_chain:
                print(
                    "      "
                    f"{hex_or_none(call.call_address, base)} -> "
                    f"{hex_or_none(call.target_address, base)}"
                )
        print(
            "    Function: "
            f"{hex_or_none(match.fde.function_start, base)}..{hex_or_none(match.fde.function_end, base)} "
            f"(FDE {hex_or_none(match.fde.address, base)}, file offset 0x{match.fde.offset:x})"
        )

        if match.lsda is None:
            print("    LSDA: none or failed to parse")
        else:
            print(
                "    LSDA: "
                f"{hex_or_none(match.lsda.address, base)} file offset 0x{match.lsda.offset:x} "
                f"call_site_enc={encoding_name(match.lsda.call_site_encoding)}"
            )

        if match.call_site is None:
            continue

        print(
            "    Entry: "
            f"{hex_or_none(match.call_site.start_address, base)}.."
            f"{hex_or_none(match.call_site.end_address, base)} "
            f"-> landing_pad={hex_or_none(match.call_site.landing_pad_address, base)} "
            f"action={match.call_site.action}"
        )
        if match.landing_pad_span is not None:
            print(
                "    Landing-pad span: "
                f"{hex_or_none(match.landing_pad_span[0], base)}.."
                f"{hex_or_none(match.landing_pad_span[1], base)} "
                "(inferred)"
            )


def print_dump(parser: GCCExceptTableParser, base: int, limit: int) -> None:
    count = 0
    for fde in parser.iter_fdes():
        if fde.lsda_offset is None:
            continue
        try:
            lsda = parser.parse_lsda(fde)
        except ParseError:
            continue
        print(
            f"{hex_or_none(fde.function_start, base)}..{hex_or_none(fde.function_end, base)} "
            f"FDE={hex_or_none(fde.address, base)} LSDA={hex_or_none(lsda.address, base)}"
        )
        for call_site in lsda.call_sites:
            print(
                "  "
                f"{hex_or_none(call_site.start_address, base)}..{hex_or_none(call_site.end_address, base)} "
                f"-> {hex_or_none(call_site.landing_pad_address, base)} "
                f"action={call_site.action}"
            )
        count += 1
        if limit and count >= limit:
            break


def build_arg_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(
        description=(
            "Parse GCC/Itanium C++ exception metadata from ELF .eh_frame and "
            ".gcc_except_table sections, then map addresses to all matching FDE, "
            "LSDA, call-site, and landing-pad entries."
        )
    )
    parser.add_argument("elf", type=Path, help="ELF executable, shared object, or object file")
    parser.add_argument("pc", nargs="?", type=parse_int, help="address to resolve")
    parser.add_argument("--base", type=parse_int, default=0, help="loaded image base to subtract from PC and add to output")
    parser.add_argument("--dump", action="store_true", help="dump call-site tables for FDEs that have LSDAs")
    parser.add_argument("--limit", type=int, default=0, help="limit --dump to this many functions")
    parser.add_argument(
        "--caller-depth",
        type=int,
        default=2,
        help="follow direct reverse-call edges this many levels when resolving function-entry addresses",
    )
    parser.add_argument("--json", action="store_true", help="emit JSON")
    parser.add_argument("--quiet", action="store_true", help="with an address, print matching landing-pad addresses or none")
    return parser


def main(argv: list[str] | None = None) -> int:
    args = build_arg_parser().parse_args(argv)
    if args.pc is None and not args.dump:
        raise SystemExit("provide a PC/address, or use --dump")

    try:
        elf = ELFFile(args.elf)
        parser = GCCExceptTableParser(elf)
        base = args.base
        pc = None if args.pc is None else args.pc - base

        if args.dump:
            if args.json:
                items: list[dict[str, Any]] = []
                for fde in parser.iter_fdes():
                    if fde.lsda_offset is None:
                        continue
                    try:
                        lsda = parser.parse_lsda(fde)
                    except ParseError:
                        continue
                    items.append({"fde": fde_to_dict(fde, base), "lsda": lsda_to_dict(lsda, base)})
                    if args.limit and len(items) >= args.limit:
                        break
                print(json.dumps(items, indent=2, sort_keys=True))
            else:
                print_dump(parser, base, args.limit)

        if pc is not None:
            matches = parser.find_exception_entries(pc, caller_depth=args.caller_depth)
            if args.json:
                payload = {
                    "address": args.pc,
                    "file_va": pc,
                    "base": base,
                    "match_count": len(matches),
                    "matches": [match_to_dict(match, base) for match in matches],
                }
                print(json.dumps(payload, indent=2, sort_keys=True))
            elif args.quiet:
                landing_pads = sorted(
                    {
                        match.call_site.landing_pad_address + base
                        for match in matches
                        if match.call_site is not None and match.call_site.landing_pad_address is not None
                    }
                )
                if not landing_pads:
                    print("none")
                else:
                    for landing_pad in landing_pads:
                        print(hex(landing_pad))
            else:
                print_address_matches(elf, args.pc, pc, base, matches)

        return 0
    except (OSError, ParseError, struct.error) as exc:
        print(f"error: {exc}", file=sys.stderr)
        return 1


if __name__ == "__main__":
    raise SystemExit(main())
