#!/usr/bin/env python3
"""Deterministic fixture generator for the TypeMorph test-suite.

Generates two kinds of committed fixtures:

1. ``sample_v1.bin`` / ``sample_v2.bin`` / ``sample_v3.bin``
   Three instances of a synthetic, little-endian file format.  The layout is
   deliberately shaped so the differential inference engine can recover it:
   an invariant magic, a per-version header, a monotonically increasing
   timestamp, a record count and a fixed-stride record array, followed by a
   UTF-8 string table whose byte length differs between the samples.

2. ``rust_sample.elf``
   A minimal but fully valid ELF64 (x86-64, ET_EXEC, little-endian) image with
   real program headers, section headers, a section-name string table and
   symbols.  ``.text`` contains three plausible function prologues,
   ``.rodata`` contains UTF-8 string literals and ``.data`` contains three Rust
   ``(ptr, len)`` fat-pointer pairs plus a trait-object vtable with the layout
   ``[drop_in_place, size, align, method_0, method_1]``.  The fixture is what
   the SliceScanner / VTableAnalyzer integration tests consume.

The generator is byte-for-byte deterministic: it uses only fixed constants (no
clock, no randomness, no environment dependent values).  Run with ``--verify``
to assert that the committed files still match this script.

Usage:
    python tests/fixtures/generate_fixtures.py            # regenerate in place
    python tests/fixtures/generate_fixtures.py --verify   # CI determinism check
"""

from __future__ import annotations

import argparse
import struct
import sys
from dataclasses import dataclass
from pathlib import Path
from typing import Sequence

# ---------------------------------------------------------------------------
# Synthetic differential-inference samples
# ---------------------------------------------------------------------------

#: Invariant four-byte magic shared by every sample version.
SAMPLE_MAGIC = b"TMSX"
#: Fixed per-record stride; total file size must change by exactly
#: ``record_count * RECORD_STRIDE`` plus the string-table delta.
RECORD_STRIDE = 12
#: Invariant per-record tag value (constant-value evidence for the inferrer).
RECORD_TAG = 0xABCD
#: Size of the fixed header which precedes the record array.
SAMPLE_HEADER_SIZE = 20


@dataclass(frozen=True)
class SampleSpec:
    filename: str
    version: int
    flags: int
    timestamp: int
    record_count: int
    labels: tuple[str, ...]


SAMPLE_SPECS: tuple[SampleSpec, ...] = (
    SampleSpec(
        filename="sample_v1.bin",
        version=1,
        flags=0x0001,
        timestamp=1_700_000_000,
        record_count=3,
        labels=("alpha", "beta"),
    ),
    SampleSpec(
        filename="sample_v2.bin",
        version=2,
        flags=0x0003,
        timestamp=1_700_003_600,
        record_count=7,
        labels=("alpha", "beta", "gamma"),
    ),
    SampleSpec(
        filename="sample_v3.bin",
        version=3,
        flags=0x0007,
        timestamp=1_700_007_200,
        record_count=12,
        labels=("alpha", "beta", "gamma", "delta", "caf\u00e9"),
    ),
)


def build_sample(spec: SampleSpec) -> bytes:
    """Serialises one synthetic sample.

    Layout (little-endian)::

        offset  size  field
        0       4     magic           = b"TMSX" (invariant)
        4       2     version         u16   (1, 2, 3)
        6       2     flags           u16   (0x0001, 0x0003, 0x0007)
        8       8     timestamp       u64   (strictly increasing)
        16      4     record_count    u32   (3, 7, 12)
        20      12*n  records         n x {u32 id, u16 kind, u16 tag=0xABCD, u32 value}
        20+12*n  ...   string table    u32 string_count, then per string:
                                       u16 byte_length + byte_length UTF-8 bytes
    """
    out = bytearray()
    out += SAMPLE_MAGIC
    out += struct.pack(
        "<HHQI", spec.version, spec.flags, spec.timestamp, spec.record_count
    )
    for index in range(spec.record_count):
        record_id = index + 1
        kind = (index * 3 + spec.version) % 4
        value = 0x1000 + index * 0x111 + spec.version * 0x40
        out += struct.pack("<IHHI", record_id, kind, RECORD_TAG, value)

    out += struct.pack("<I", len(spec.labels))
    for label in spec.labels:
        encoded = label.encode("utf-8")
        out += struct.pack("<H", len(encoded))
        out += encoded
    return bytes(out)


def sample_string_table_size(spec: SampleSpec) -> int:
    """Byte length of the string-table region for a spec (documentation helper)."""
    size = 4  # u32 string_count
    for label in spec.labels:
        size += 2 + len(label.encode("utf-8"))  # u16 length prefix
    return size


# ---------------------------------------------------------------------------
# rust_sample.elf
# ---------------------------------------------------------------------------

ELF64_HEADER_SIZE = 64
ELF64_PROGRAM_HEADER_SIZE = 56
ELF64_SECTION_HEADER_SIZE = 64
ELF64_SYMBOL_SIZE = 24

# Virtual address / file offset plan.  The file is laid out like a conventional
# linkable executable: ELF header + program headers first, then the RX segment
# (.text, .rodata) and finally the RW segment (.data).
IMAGE_BASE = 0x400000
TEXT_VADDR = 0x401000
RODATA_VADDR = 0x402000
DATA_VADDR = 0x403000
TEXT_OFF = 0x1000
RODATA_OFF = 0x2000
DATA_OFF = 0x3000

TEXT_FUNCTION_SIZE = 32
RODATA_STRING_ALIGNMENT = 32
RODATA_SIZE = 0x80
VTABLE_DATA_OFFSET = 0x40  # Offset of the vtable inside .data.
VTABLE_SIZE = 5 * 8

#: (symbol name, x86-64 machine code prefix).  Every function begins with
#: endbr64 + a standard frame prologue so function-start heuristics fire.
RUST_FUNCTIONS: tuple[tuple[str, int], ...] = (
    ("rust_sample_drop_in_place", 0x00),
    ("rust_sample_method_0", 0x20),
    ("rust_sample_method_1", 0x40),
)

#: UTF-8 byte strings placed in .rodata (multi-byte text included on purpose).
RUST_STRINGS: tuple[str, ...] = (
    "hello from rust_sample.elf",
    "TypeMorph Rust fat-pointer demo",
    "gr\u00fc\u00dfe, \u4e16\u754c",
)


def _align_up(value: int, alignment: int) -> int:
    if alignment <= 1:
        return value
    return (value + alignment - 1) // alignment * alignment


def _function_bytes(index: int) -> bytes:
    """32 bytes of plausible x86-64 function code at a 16-byte boundary."""
    code = bytearray(
        [
            0xF3,
            0x0F,
            0x1E,
            0xFA,  # endbr64
            0x55,  # push rbp
            0x48,
            0x89,
            0xE5,  # mov rbp, rsp
            0x48,
            0x83,
            0xEC,
            0x20,  # sub rsp, 0x20
            0x89,
            0xF8,  # mov eax, edi
            0x83,
            0xC0,
            index & 0xFF,  # add eax, imm8
            0x48,
            0x83,
            0xC4,
            0x20,  # add rsp, 0x20
            0x5D,  # pop rbp
            0xC3,  # ret
        ]
    )
    if len(code) > TEXT_FUNCTION_SIZE:
        raise AssertionError("function template exceeds the fixed stride")
    code.extend(b"\x90" * (TEXT_FUNCTION_SIZE - len(code)))  # NOP padding
    return bytes(code)


def _build_rodata() -> tuple[bytes, dict[str, tuple[int, int]]]:
    """Returns the .rodata bytes and {string: (section offset, byte length)}."""
    buffer = bytearray(RODATA_SIZE)
    layout: dict[str, tuple[int, int]] = {}
    cursor = 0
    for text in RUST_STRINGS:
        encoded = text.encode("utf-8")
        if cursor + len(encoded) + 1 > len(buffer):
            raise AssertionError(".rodata overflow")
        layout[text] = (cursor, len(encoded))
        buffer[cursor : cursor + len(encoded)] = encoded
        buffer[cursor + len(encoded)] = 0
        cursor = _align_up(cursor + len(encoded) + 1, RODATA_STRING_ALIGNMENT)
    return bytes(buffer), layout


def _build_text() -> tuple[bytes, dict[str, int]]:
    """Returns the .text bytes and {symbol: section offset}."""
    buffer = bytearray()
    layout: dict[str, int] = {}
    for index, (name, offset) in enumerate(RUST_FUNCTIONS):
        if offset != len(buffer):
            raise AssertionError("function offsets must be contiguous")
        layout[name] = offset
        buffer += _function_bytes(index)
    return bytes(buffer), layout


def _build_data(
    string_layout: dict[str, tuple[int, int]],
) -> tuple[bytes, int]:
    """Returns the .data bytes and the section offset of the vtable."""
    buffer = bytearray(VTABLE_DATA_OFFSET + VTABLE_SIZE)

    # Rust fat pointers: (data pointer, byte length) pairs.  The lengths are the
    # exact UTF-8 byte lengths of the strings in .rodata.
    pair_offset = 0
    for text in RUST_STRINGS:
        string_offset, string_length = string_layout[text]
        pointer = RODATA_VADDR + string_offset
        struct.pack_into("<QQ", buffer, pair_offset, pointer, string_length)
        pair_offset += 16

    # Trait-object vtable: [drop_in_place, size, align, method_0, method_1].
    method_addresses = [
        TEXT_VADDR + offset for _name, offset in RUST_FUNCTIONS
    ]
    struct.pack_into(
        "<QQQQQ",
        buffer,
        VTABLE_DATA_OFFSET,
        method_addresses[0],  # drop_in_place
        0x18,  # object size (24)
        0x08,  # object alignment (power of two)
        method_addresses[1],  # method_0
        method_addresses[2],  # method_1
    )
    return bytes(buffer), VTABLE_DATA_OFFSET


def build_rust_sample_elf() -> bytes:
    text, function_offsets = _build_text()
    rodata, string_layout = _build_rodata()
    data, vtable_offset = _build_data(string_layout)

    # --- symbol string table and symbols -----------------------------------
    symbol_names = [
        "rust_sample.elf",  # STT_FILE, SHN_ABS
        *[name for name, _offset in RUST_FUNCTIONS],
        *[f"rust_sample_str{index}" for index in range(len(RUST_STRINGS))],
        "rust_sample_vtable",
    ]
    strtab = bytearray(b"\x00")
    name_offsets: dict[str, int] = {}
    for name in symbol_names:
        name_offsets[name] = len(strtab)
        strtab += name.encode("utf-8") + b"\x00"

    symbols = bytearray(ELF64_SYMBOL_SIZE)  # Null symbol.
    symbol_defs: list[tuple[str, int, int, int, int, int]] = []

    def add_symbol(
        name: str,
        info: int,
        section_index: int,
        value: int,
        size: int,
    ) -> None:
        symbol_defs.append((name, info, section_index, value, size, name_offsets[name]))

    # Local file symbol first (ELF requires SHN_ABS for STT_FILE).
    add_symbol("rust_sample.elf", (0 << 4) | 4, 0xFFF1, 0, 0)
    for name, offset in RUST_FUNCTIONS:
        add_symbol(name, (1 << 4) | 2, 1, TEXT_VADDR + offset, TEXT_FUNCTION_SIZE)
    for index, literal in enumerate(RUST_STRINGS):
        string_offset, string_length = string_layout[literal]
        add_symbol(
            f"rust_sample_str{index}",
            (1 << 4) | 1,
            2,
            RODATA_VADDR + string_offset,
            string_length + 1,
        )
    add_symbol("rust_sample_vtable", (1 << 4) | 1, 3, DATA_VADDR + vtable_offset, VTABLE_SIZE)

    for _name, info, section_index, value, size, name_offset in symbol_defs:
        symbols += struct.pack(
            "<IBBHQQ", name_offset, info, 0, section_index, value, size
        )

    # --- section-name string table -----------------------------------------
    section_names = [
        ".text",
        ".rodata",
        ".data",
        ".symtab",
        ".strtab",
        ".shstrtab",
    ]
    shstrtab = bytearray(b"\x00")
    section_name_offsets: dict[str, int] = {}
    for name in section_names:
        section_name_offsets[name] = len(shstrtab)
        shstrtab += name.encode("ascii") + b"\x00"

    # --- fixed file layout --------------------------------------------------
    program_headers = bytearray()
    program_headers += struct.pack(
        "<IIQQQQQQ",
        1,  # PT_LOAD
        5,  # PF_R | PF_X
        0,  # p_offset
        IMAGE_BASE,  # p_vaddr
        IMAGE_BASE,  # p_paddr
        RODATA_OFF + len(rodata),  # p_filesz (headers + .text + .rodata)
        RODATA_OFF + len(rodata),  # p_memsz
        0x1000,  # p_align
    )
    program_headers += struct.pack(
        "<IIQQQQQQ",
        1,  # PT_LOAD
        6,  # PF_R | PF_W
        DATA_OFF,  # p_offset
        DATA_VADDR,  # p_vaddr
        DATA_VADDR,  # p_paddr
        len(data),  # p_filesz
        len(data),  # p_memsz
        0x1000,  # p_align
    )
    if len(program_headers) != 2 * ELF64_PROGRAM_HEADER_SIZE:
        raise AssertionError("unexpected program header size")

    offset = ELF64_HEADER_SIZE + len(program_headers)
    offset = _align_up(offset, TEXT_OFF)
    text_offset = offset
    offset += len(text)
    offset = _align_up(offset, RODATA_OFF)
    rodata_offset = offset
    offset += len(rodata)
    offset = _align_up(offset, DATA_OFF)
    data_offset = offset
    offset += len(data)
    offset = _align_up(offset, 8)
    symtab_offset = offset
    offset += len(symbols)
    strtab_offset = offset
    offset += len(strtab)
    shstrtab_offset = offset
    offset += len(shstrtab)
    offset = _align_up(offset, 8)
    section_header_offset = offset
    total_size = section_header_offset + 7 * ELF64_SECTION_HEADER_SIZE

    # Sanity checks so the fixture stays honest if someone edits the layout.
    if text_offset != TEXT_OFF or rodata_offset != RODATA_OFF or data_offset != DATA_OFF:
        raise AssertionError("fixture layout constants are inconsistent")
    if section_header_offset % 8 != 0:
        raise AssertionError("section header table must be 8-byte aligned")

    image = bytearray(total_size)

    # ELF header.
    ident = b"\x7fELF" + bytes([2, 1, 1, 0]) + b"\x00" * 8  # 64-bit, LSB, v1
    struct.pack_into(
        "<16sHHIQQQIHHHHHH",
        image,
        0,
        ident,
        2,  # e_type = ET_EXEC
        62,  # e_machine = EM_X86_64
        1,  # e_version
        TEXT_VADDR,  # e_entry
        ELF64_HEADER_SIZE,  # e_phoff
        section_header_offset,  # e_shoff
        0,  # e_flags
        ELF64_HEADER_SIZE,  # e_ehsize
        ELF64_PROGRAM_HEADER_SIZE,  # e_phentsize
        2,  # e_phnum
        ELF64_SECTION_HEADER_SIZE,  # e_shentsize
        7,  # e_shnum (NULL + 3 data + symtab + strtab + shstrtab)
        6,  # e_shstrndx
    )
    image[ELF64_HEADER_SIZE : ELF64_HEADER_SIZE + len(program_headers)] = program_headers
    image[text_offset : text_offset + len(text)] = text
    image[rodata_offset : rodata_offset + len(rodata)] = rodata
    image[data_offset : data_offset + len(data)] = data
    image[symtab_offset : symtab_offset + len(symbols)] = symbols
    image[strtab_offset : strtab_offset + len(strtab)] = strtab
    image[shstrtab_offset : shstrtab_offset + len(shstrtab)] = shstrtab

    # --- section headers ----------------------------------------------------
    def write_section_header(
        index: int,
        name: str,
        section_type: int,
        flags: int,
        address: int,
        file_offset: int,
        size: int,
        link: int,
        info: int,
        alignment: int,
        entry_size: int,
    ) -> None:
        base = section_header_offset + index * ELF64_SECTION_HEADER_SIZE
        name_offset = 0 if name == "" else section_name_offsets[name]
        struct.pack_into(
            "<IIQQQQIIQQ",
            image,
            base,
            name_offset,
            section_type,
            flags,
            address,
            file_offset,
            size,
            link,
            info,
            alignment,
            entry_size,
        )

    write_section_header(0, "", 0, 0, 0, 0, 0, 0, 0, 0, 0)
    write_section_header(
        1, ".text", 1, 0x6, TEXT_VADDR, text_offset, len(text), 0, 0, 16, 0
    )
    write_section_header(
        2, ".rodata", 1, 0x2, RODATA_VADDR, rodata_offset, len(rodata), 0, 0, 16, 0
    )
    write_section_header(
        3, ".data", 1, 0x3, DATA_VADDR, data_offset, len(data), 0, 0, 8, 0
    )
    write_section_header(
        4,
        ".symtab",
        2,
        0,
        0,
        symtab_offset,
        len(symbols),
        5,  # sh_link -> .strtab
        2,  # sh_info -> index of first global symbol
        8,
        ELF64_SYMBOL_SIZE,
    )
    write_section_header(5, ".strtab", 3, 0, 0, strtab_offset, len(strtab), 0, 0, 1, 0)
    write_section_header(6, ".shstrtab", 3, 0, 0, shstrtab_offset, len(shstrtab), 0, 0, 1, 0)

    return bytes(image)


# ---------------------------------------------------------------------------
# CLI
# ---------------------------------------------------------------------------


def build_all() -> dict[str, bytes]:
    outputs: dict[str, bytes] = {}
    for spec in SAMPLE_SPECS:
        outputs[spec.filename] = build_sample(spec)
    outputs["rust_sample.elf"] = build_rust_sample_elf()
    return outputs


def manifest() -> str:
    lines: list[str] = []
    for spec in SAMPLE_SPECS:
        payload = build_sample(spec)
        strings_size = sample_string_table_size(spec)
        lines.append(
            f"{spec.filename}: size={len(payload)} version={spec.version} "
            f"flags=0x{spec.flags:04x} timestamp={spec.timestamp} "
            f"records={spec.record_count} stride={RECORD_STRIDE} "
            f"records_offset={SAMPLE_HEADER_SIZE} "
            f"records_bytes={spec.record_count * RECORD_STRIDE} "
            f"string_table_offset={SAMPLE_HEADER_SIZE + spec.record_count * RECORD_STRIDE} "
            f"string_table_bytes={strings_size}"
        )
    elf = build_rust_sample_elf()
    lines.append(
        f"rust_sample.elf: size={len(elf)} entry=0x{TEXT_VADDR:x} "
        f"image_base=0x{IMAGE_BASE:x} sections=7 symbols=8"
    )
    return "\n".join(lines)


def main(argv: Sequence[str] | None = None) -> int:
    parser = argparse.ArgumentParser(
        description="Generate deterministic TypeMorph test fixtures."
    )
    parser.add_argument(
        "--out-dir",
        type=Path,
        default=Path(__file__).resolve().parent,
        help="directory receiving the fixtures (default: script directory)",
    )
    parser.add_argument(
        "--verify",
        action="store_true",
        help="do not write; fail if committed fixtures differ from generator output",
    )
    args = parser.parse_args(argv)

    outputs = build_all()
    exit_code = 0
    if args.verify:
        for name, payload in outputs.items():
            target = args.out_dir / name
            if not target.is_file():
                print(f"MISSING: {target}", file=sys.stderr)
                exit_code = 1
                continue
            existing = target.read_bytes()
            if existing != payload:
                mismatch = next(
                    (
                        index
                        for index, (left, right) in enumerate(zip(existing, payload))
                        if left != right
                    ),
                    min(len(existing), len(payload)),
                )
                print(
                    f"MISMATCH: {target} (size {len(existing)} != {len(payload)}, "
                    f"first difference at offset {mismatch})",
                    file=sys.stderr,
                )
                exit_code = 1
            else:
                print(f"OK: {target}")
    else:
        args.out_dir.mkdir(parents=True, exist_ok=True)
        for name, payload in outputs.items():
            target = args.out_dir / name
            target.write_bytes(payload)
            print(f"wrote {target} ({len(payload)} bytes)")

    print(manifest(), file=sys.stderr)
    return exit_code


if __name__ == "__main__":
    raise SystemExit(main())
