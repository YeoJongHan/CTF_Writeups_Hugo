#!/usr/bin/env python3
import argparse
import struct
import sys
from dataclasses import dataclass

DW_OP_NAMES = {
    0x03: "DW_OP_addr",
    0x06: "DW_OP_deref",
    0x08: "DW_OP_const1u",
    0x09: "DW_OP_const1s",
    0x0A: "DW_OP_const2u",
    0x0B: "DW_OP_const2s",
    0x0C: "DW_OP_const4u",
    0x0D: "DW_OP_const4s",
    0x0E: "DW_OP_const8u",
    0x0F: "DW_OP_const8s",
    0x10: "DW_OP_constu",
    0x11: "DW_OP_consts",
    0x12: "DW_OP_dup",
    0x13: "DW_OP_drop",
    0x14: "DW_OP_over",
    0x15: "DW_OP_pick",
    0x16: "DW_OP_swap",
    0x17: "DW_OP_rot",
    0x18: "DW_OP_xderef",
    0x19: "DW_OP_abs",
    0x1A: "DW_OP_and",
    0x1B: "DW_OP_div",
    0x1C: "DW_OP_minus",
    0x1D: "DW_OP_mod",
    0x1E: "DW_OP_mul",
    0x1F: "DW_OP_neg",
    0x20: "DW_OP_not",
    0x21: "DW_OP_or",
    0x22: "DW_OP_plus",
    0x23: "DW_OP_plus_uconst",
    0x24: "DW_OP_shl",
    0x25: "DW_OP_shr",
    0x26: "DW_OP_shra",
    0x27: "DW_OP_xor",
    0x28: "DW_OP_bra",
    0x29: "DW_OP_eq",
    0x2A: "DW_OP_ge",
    0x2B: "DW_OP_gt",
    0x2C: "DW_OP_le",
    0x2D: "DW_OP_lt",
    0x2E: "DW_OP_ne",
    0x2F: "DW_OP_skip",
    0x90: "DW_OP_regx",
    0x91: "DW_OP_fbreg",
    0x92: "DW_OP_bregx",
    0x93: "DW_OP_piece",
    0x94: "DW_OP_deref_size",
    0x95: "DW_OP_xderef_size",
    0x96: "DW_OP_nop",
    0x97: "DW_OP_push_object_address",
    0x9C: "DW_OP_call_frame_cfa",
    0x9F: "DW_OP_stack_value",
}


@dataclass
class Section:
    name: str
    addr: int
    offset: int
    size: int


@dataclass
class CIE:
    off: int
    augmentation: str
    fde_encoding: int
    has_z_augmentation: bool


def parse_int(s):
    return int(s, 0)


def uleb(data, pos):
    value = 0
    shift = 0
    start = pos
    while True:
        if pos >= len(data):
            raise ValueError("truncated ULEB128")
        byte = data[pos]
        pos += 1
        value |= (byte & 0x7F) << shift
        if byte < 0x80:
            return value, pos, pos - start
        shift += 7


def sleb(data, pos):
    value = 0
    shift = 0
    start = pos
    while True:
        if pos >= len(data):
            raise ValueError("truncated SLEB128")
        byte = data[pos]
        pos += 1
        value |= (byte & 0x7F) << shift
        shift += 7
        if byte < 0x80:
            break
    if byte & 0x40:
        value |= -(1 << shift)
    return value, pos, pos - start


def c_string(data, pos):
    end = data.index(0, pos)
    return data[pos:end].decode("ascii", errors="replace"), end + 1


def parse_elf_sections(blob):
    if blob[:4] != b"\x7fELF":
        raise ValueError("not an ELF file")
    if blob[4] != 2:
        raise ValueError("only ELF64 is supported")
    if blob[5] != 1:
        raise ValueError("only little-endian ELF is supported")

    e_shoff = struct.unpack_from("<Q", blob, 0x28)[0]
    e_shentsize = struct.unpack_from("<H", blob, 0x3A)[0]
    e_shnum = struct.unpack_from("<H", blob, 0x3C)[0]
    e_shstrndx = struct.unpack_from("<H", blob, 0x3E)[0]

    raw_sections = []
    for i in range(e_shnum):
        off = e_shoff + i * e_shentsize
        sh_name, _, _, sh_addr, sh_offset, sh_size = struct.unpack_from(
            "<IIQQQQ", blob, off
        )
        raw_sections.append((sh_name, sh_addr, sh_offset, sh_size))

    shstr_name, _, shstr_off, shstr_size = raw_sections[e_shstrndx]
    shstr = blob[shstr_off : shstr_off + shstr_size]

    sections = {}
    for sh_name, sh_addr, sh_offset, sh_size in raw_sections:
        name_end = shstr.find(b"\x00", sh_name)
        name = shstr[sh_name:name_end].decode("ascii", errors="replace")
        sections[name] = Section(name, sh_addr, sh_offset, sh_size)
    return sections


def eh_data_size(fmt, addr_size=8):
    if fmt in (0x01, 0x09):
        return None
    return {
        0x00: addr_size,
        0x02: 2,
        0x03: 4,
        0x04: 8,
        0x0A: 2,
        0x0B: 4,
        0x0C: 8,
    }.get(fmt)


def decode_eh_value(data, pos, field_addr, enc, addr_size=8, apply_relative=True):
    if enc == 0xFF:
        return None, pos

    fmt = enc & 0x0F
    app = enc & 0x70

    if fmt == 0x01:
        value, pos, _ = uleb(data, pos)
    elif fmt == 0x09:
        value, pos, _ = sleb(data, pos)
    else:
        size = eh_data_size(fmt, addr_size)
        if size is None:
            raise ValueError(f"unsupported DW_EH_PE format 0x{fmt:x}")
        signed = fmt in (0x0A, 0x0B, 0x0C)
        value = int.from_bytes(data[pos : pos + size], "little", signed=signed)
        pos += size

    if apply_relative:
        if app == 0x10:  # DW_EH_PE_pcrel
            value += field_addr
        elif app not in (0x00,):
            # Enough for this challenge. Still return the raw value for unsupported bases.
            pass

    return value, pos


def parse_cie(sec_data, cie_off):
    pos = cie_off
    length = struct.unpack_from("<I", sec_data, pos)[0]
    if length == 0xFFFFFFFF:
        raise ValueError("64-bit .eh_frame lengths are not supported")
    content = pos + 4
    end = content + length
    cie_id = struct.unpack_from("<I", sec_data, content)[0]
    if cie_id != 0:
        raise ValueError(f"entry at 0x{cie_off:x} is not a CIE")

    pos = content + 4
    version = sec_data[pos]
    pos += 1
    augmentation, pos = c_string(sec_data, pos)
    _, pos, _ = uleb(sec_data, pos)  # code alignment
    _, pos, _ = sleb(sec_data, pos)  # data alignment
    _, pos, _ = uleb(sec_data, pos)  # return address column, version 1 here

    fde_encoding = 0x00
    has_z = augmentation.startswith("z")
    if has_z:
        aug_len, pos, _ = uleb(sec_data, pos)
        aug_end = pos + aug_len
        for ch in augmentation[1:]:
            if ch == "P":
                personality_enc = sec_data[pos]
                pos += 1
                _, pos = decode_eh_value(
                    sec_data, pos, 0, personality_enc, apply_relative=False
                )
            elif ch == "L":
                pos += 1
            elif ch == "R":
                fde_encoding = sec_data[pos]
                pos += 1
            else:
                raise ValueError(f"unsupported CIE augmentation char {ch!r}")
        pos = aug_end

    if pos > end:
        raise ValueError("CIE augmentation overran entry")
    return CIE(cie_off, augmentation, fde_encoding, has_z)


def skip_cfi_instruction(data, pos):
    op = data[pos]
    pos += 1
    top = op >> 6
    if top == 1:
        return pos
    if top == 2:
        _, pos, _ = uleb(data, pos)
        return pos
    if top == 3:
        return pos

    if op in (0x00, 0x0A, 0x0B):
        return pos
    if op == 0x01:
        return pos + 8
    if op == 0x02:
        return pos + 1
    if op == 0x03:
        return pos + 2
    if op == 0x04:
        return pos + 4
    if op in (0x05, 0x09, 0x0C, 0x11, 0x12, 0x14, 0x15):
        _, pos, _ = uleb(data, pos)
        if op in (0x11, 0x12, 0x15):
            _, pos, _ = sleb(data, pos)
        else:
            _, pos, _ = uleb(data, pos)
        return pos
    if op in (0x06, 0x07, 0x08, 0x0D, 0x0E):
        _, pos, _ = uleb(data, pos)
        return pos
    if op in (0x0F,):
        length, pos, _ = uleb(data, pos)
        return pos + length
    if op in (0x10, 0x16):
        _, pos, _ = uleb(data, pos)
        length, pos, _ = uleb(data, pos)
        return pos + length
    if op == 0x13:
        _, pos, _ = sleb(data, pos)
        return pos
    raise ValueError(f"unsupported DW_CFA opcode 0x{op:02x} at CFI offset 0x{pos-1:x}")


def find_val_expression(sec_data, cfi_start, cfi_end, reg):
    pos = cfi_start
    while pos < cfi_end:
        op_pos = pos
        op = sec_data[pos]
        pos += 1
        top = op >> 6
        if top:
            pos = skip_cfi_instruction(sec_data, op_pos)
            continue

        if op == 0x16:  # DW_CFA_val_expression
            got_reg, pos, _ = uleb(sec_data, pos)
            length, pos, _ = uleb(sec_data, pos)
            expr_start = pos
            expr_end = pos + length
            if got_reg == reg:
                return op_pos, expr_start, expr_end
            pos = expr_end
        else:
            pos = skip_cfi_instruction(sec_data, op_pos)
    return None


def find_expression_in_eh_frame(blob, pc, reg):
    sections = parse_elf_sections(blob)
    if ".eh_frame" not in sections:
        raise ValueError("ELF has no .eh_frame section")
    sec = sections[".eh_frame"]
    sec_data = blob[sec.offset : sec.offset + sec.size]

    cies = {}
    pos = 0
    while pos < len(sec_data):
        entry_off = pos
        if pos + 4 > len(sec_data):
            break
        length = struct.unpack_from("<I", sec_data, pos)[0]
        if length == 0:
            break
        if length == 0xFFFFFFFF:
            raise ValueError("64-bit .eh_frame lengths are not supported")
        content = pos + 4
        end = content + length
        entry_id = struct.unpack_from("<I", sec_data, content)[0]

        if entry_id == 0:
            cie = parse_cie(sec_data, entry_off)
            cies[entry_off] = cie
            pos = end
            continue

        cie_ptr_field = content
        cie_off = cie_ptr_field - entry_id
        cie = cies.get(cie_off)
        if cie is None:
            pos = end
            continue

        cursor = content + 4
        initial_field_addr = sec.addr + cursor
        initial, cursor = decode_eh_value(
            sec_data, cursor, initial_field_addr, cie.fde_encoding
        )

        # The range uses the same representation size, but not the pcrel base.
        range_enc = cie.fde_encoding & 0x0F
        address_range, cursor = decode_eh_value(
            sec_data, cursor, 0, range_enc, apply_relative=False
        )

        if cie.has_z_augmentation:
            aug_len, cursor, _ = uleb(sec_data, cursor)
            cursor += aug_len

        if initial <= pc < initial + address_range:
            found = find_val_expression(sec_data, cursor, end, reg)
            if not found:
                raise ValueError(
                    f"FDE 0x{entry_off:x} covers pc 0x{pc:x}, "
                    f"but has no DW_CFA_val_expression for reg {reg}"
                )
            cfa_off, expr_start, expr_end = found
            return {
                "section": sec,
                "fde_off": entry_off,
                "fde_file_off": sec.offset + entry_off,
                "fde_end_off": end,
                "initial": initial,
                "address_range": address_range,
                "cfa_off": cfa_off,
                "expr_sec_off": expr_start,
                "expr_file_off": sec.offset + expr_start,
                "expr_va": sec.addr + expr_start,
                "expr": sec_data[expr_start:expr_end],
            }

        pos = end

    raise ValueError(f"no FDE found covering pc 0x{pc:x}")


def format_bytes(bs):
    return " ".join(f"{b:02x}" for b in bs)


def disassemble_expr(data, base=0, limit=None, show_bytes=False):
    pos = 0
    count = 0
    while pos < len(data):
        if limit is not None and count >= limit:
            print(f"... stopped after {limit} instructions at +0x{pos:x}")
            return

        start = pos
        op = data[pos]
        pos += 1
        operands = ""
        target = None

        if 0x30 <= op <= 0x4F:
            name = f"DW_OP_lit{op - 0x30}"
        elif 0x50 <= op <= 0x6F:
            name = f"DW_OP_reg{op - 0x50}"
        elif 0x70 <= op <= 0x8F:
            name = f"DW_OP_breg{op - 0x70}"
            value, pos, _ = sleb(data, pos)
            operands = str(value)
        else:
            name = DW_OP_NAMES.get(op, f"UNKNOWN_0x{op:02x}")
            if op in (0x08, 0x09, 0x15, 0x94, 0x95):
                value = data[pos]
                pos += 1
                operands = str(value)
            elif op in (0x0A, 0x0B):
                signed = op == 0x0B
                value = int.from_bytes(data[pos : pos + 2], "little", signed=signed)
                pos += 2
                operands = str(value)
            elif op in (0x0C, 0x0D):
                signed = op == 0x0D
                value = int.from_bytes(data[pos : pos + 4], "little", signed=signed)
                pos += 4
                operands = f"0x{value & 0xffffffff:08x}" if not signed else str(value)
            elif op in (0x0E, 0x0F):
                signed = op == 0x0F
                value = int.from_bytes(data[pos : pos + 8], "little", signed=signed)
                pos += 8
                operands = (
                    f"0x{value & 0xffffffffffffffff:016x}" if not signed else str(value)
                )
            elif op in (0x10, 0x23, 0x90, 0x93):
                value, pos, _ = uleb(data, pos)
                operands = str(value)
            elif op in (0x11, 0x91):
                value, pos, _ = sleb(data, pos)
                operands = str(value)
            elif op == 0x92:
                reg, pos, _ = uleb(data, pos)
                off, pos, _ = sleb(data, pos)
                operands = f"{reg} {off}"
            elif op in (0x28, 0x2F):
                rel = int.from_bytes(data[pos : pos + 2], "little", signed=True)
                pos += 2
                target = pos + rel
                operands = f"{rel:+d} -> 0x{base + target:04x}"
            elif op == 0x03:
                value = int.from_bytes(data[pos : pos + 8], "little")
                pos += 8
                operands = f"0x{value:016x}"

        raw = ""
        if show_bytes:
            raw = f"  {format_bytes(data[start:pos]):<32}"
        print(f"0x{base + start:04x}:{raw} {name} {operands}".rstrip())
        count += 1


def main():
    parser = argparse.ArgumentParser(
        description="Extract and disassemble DWARF DW_OP expressions from .eh_frame."
    )
    parser.add_argument("path", help="ELF file, or raw expression bytes with --raw")
    parser.add_argument(
        "--raw", action="store_true", help="treat input as raw DW_OP bytes"
    )
    parser.add_argument(
        "--pc", type=parse_int, default=0x404990, help="PC to find in .eh_frame"
    )
    parser.add_argument(
        "--reg", type=parse_int, default=3, help="DWARF register number"
    )
    parser.add_argument(
        "--offset", type=parse_int, help="file offset of raw expression in path"
    )
    parser.add_argument("--length", type=parse_int, help="length of raw expression")
    parser.add_argument("--limit", type=int, help="maximum instruction count to print")
    parser.add_argument(
        "--bytes", action="store_true", help="show raw bytes per instruction"
    )
    parser.add_argument("--dump", help="write extracted expression bytes to this file")
    args = parser.parse_args()

    blob = open(args.path, "rb").read()

    if args.raw:
        expr = blob
        info = None
    elif args.offset is not None:
        if args.length is None:
            parser.error("--offset requires --length")
        expr = blob[args.offset : args.offset + args.length]
        info = {
            "expr_file_off": args.offset,
            "expr_va": None,
            "expr": expr,
        }
    else:
        info = find_expression_in_eh_frame(blob, args.pc, args.reg)
        expr = info["expr"]

    if args.dump:
        with open(args.dump, "wb") as f:
            f.write(expr)

    if info:
        print(f"expression length: 0x{len(expr):x} ({len(expr)})")
        print(f"expression file offset: 0x{info['expr_file_off']:x}")
        if info.get("expr_va") is not None:
            print(f"expression VA: 0x{info['expr_va']:x}")
            print(f"FDE file offset: 0x{info['fde_file_off']:x}")
            print(
                f"FDE pc range: 0x{info['initial']:x}.."
                f"0x{info['initial'] + info['address_range']:x}"
            )
        print()

    disassemble_expr(expr, limit=args.limit, show_bytes=args.bytes)


if __name__ == "__main__":
    try:
        main()
    except Exception as exc:
        print(f"error: {exc}", file=sys.stderr)
        sys.exit(1)
