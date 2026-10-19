#!/usr/bin/env python3
"""
TypeMorph Ghidra Sync - Semantic Binary Integration for Ghidra
Compatible with Ghidra 10.x/11.x (Python 3 / Ghidrathon / PyGhidra) and headless CLI.

Features:
- Rust Semantic Recovery:
  * Renames mangled Rust symbols to demangled paths
  * Annotates string fat-pointer slices (.rodata references)
  * Defines TraitObject vtable structs and labels method pointers
- String Revealer:
  * Locates and annotates stack strings, XOR-obfuscated strings, and UTF-16 wide strings
  * Creates Ghidra bookmarks for decoded secrets and critical payloads
- Devirtualizer:
  * Annotates VM interpreter dispatchers
  * Labels VM bytecode handlers (vm_handler_op_0xXX) and registers jump tables
"""

import os
import sys
import json
import shutil
import subprocess
from typing import Dict, Any, List, Optional

# Attempt to import Ghidra flat API if running inside Ghidra environment
IN_GHIDRA = False
try:
    from ghidra.program.model.symbol import SourceType
    from ghidra.program.model.data import (
        StructureDataType, PointerDataType, VoidDataType,
        UnsignedIntegerDataType, ByteDataType, DataTypeConflictHandler
    )
    IN_GHIDRA = True
except ImportError:
    pass


def find_typemorph_binary() -> str:
    """Finds the TypeMorph executable on PATH or in standard build locations."""
    env_bin = os.environ.get("TYPEMORPH_BIN")
    if env_bin and os.path.exists(env_bin):
        return env_bin

    which = shutil.which("typemorph")
    if which:
        return which

    # Check relative build directories
    script_dir = os.path.dirname(os.path.abspath(__file__))
    candidates = [
        os.path.join(script_dir, "..", "..", "build", "Debug", "typemorph.exe"),
        os.path.join(script_dir, "..", "..", "build", "Release", "typemorph.exe"),
        os.path.join(script_dir, "..", "..", "build-final", "Debug", "typemorph.exe"),
        os.path.join(script_dir, "..", "..", "build-final", "Release", "typemorph.exe"),
        os.path.join(script_dir, "..", "..", "build", "typemorph"),
    ]
    for candidate in candidates:
        if os.path.exists(candidate):
            return os.path.abspath(candidate)

    return "typemorph"


def run_typemorph_command(typemorph_bin: str, subcommand: str, target_file: str, extra_args: Optional[List[str]] = None) -> Optional[Any]:
    """Executes a TypeMorph CLI command with --json and parses output."""
    cmd = [typemorph_bin, subcommand, target_file, "--json"]
    if extra_args:
        cmd.extend(extra_args)

    try:
        proc = subprocess.run(cmd, stdout=subprocess.PIPE, stderr=subprocess.PIPE, text=True, check=True)
        return json.loads(proc.stdout)
    except Exception as exc:
        print(f"[TypeMorph Ghidra] Error executing {cmd}: {exc}")
        return None


class GhidraSync:
    def __init__(self, target_path: str, typemorph_bin: Optional[str] = None):
        self.target_path = target_path
        self.typemorph_bin = typemorph_bin or find_typemorph_binary()

    def sync_rust(self) -> None:
        """Runs TypeMorph Rust recovery and applies labels, strings, and vtables in Ghidra."""
        print(f"[TypeMorph Ghidra] Analyzing Rust semantics for: {self.target_path}")
        data = run_typemorph_command(self.typemorph_bin, "rust", self.target_path)
        if not data:
            return

        # 1. Demangle and rename symbols
        symbols = data.get("rust_symbols", [])
        print(f"[TypeMorph Ghidra] Found {len(symbols)} Rust symbol(s)")
        if IN_GHIDRA:
            symbol_table = currentProgram.getSymbolTable()
            for sym in symbols:
                mangled = sym.get("mangled")
                demangled = sym.get("demangled")
                if mangled and demangled and mangled != demangled:
                    for ghidra_sym in symbol_table.getSymbols(mangled):
                        addr = ghidra_sym.getAddress()
                        try:
                            ghidra_sym.setName(demangled, SourceType.ANALYSIS)
                            setPlateComment(addr, f"[TypeMorph Rust Demangled]\n{demangled}\nCrate: {sym.get('crate', 'unknown')}")
                        except Exception as e:
                            print(f"[TypeMorph Ghidra] Failed to rename {mangled} -> {demangled}: {e}")

        # 2. Annotate string slices
        strings = data.get("strings", [])
        print(f"[TypeMorph Ghidra] Recovered {len(strings)} Rust string slice(s)")
        if IN_GHIDRA:
            listing = currentProgram.getListing()
            for s in strings:
                val = s.get("value", "")
                data_va = s.get("data_address", 0)
                pair_va = s.get("pair_address", 0)
                if data_va:
                    addr = toAddr(data_va)
                    cmt = f'[TypeMorph Rust &str] "{val}" (len={s.get("length", 0)})'
                    setPlateComment(addr, cmt)
                if pair_va:
                    pair_addr = toAddr(pair_va)
                    setEOLComment(pair_addr, f'[TypeMorph FatPointer -> "{val}"]')

        # 3. Trait vtables
        vtables = data.get("vtables", [])
        print(f"[TypeMorph Ghidra] Discovered {len(vtables)} Rust trait vtable(s)")
        if IN_GHIDRA:
            dtm = currentProgram.getDataTypeManager()
            for idx, vt in enumerate(vtables):
                vtable_va = vt.get("address", 0)
                if not vtable_va:
                    continue
                vtable_addr = toAddr(vtable_va)
                createLabel(vtable_addr, f"rust_vtable_{idx}_va_{hex(vtable_va)}", True)
                setPlateComment(
                    vtable_addr,
                    f"[TypeMorph Rust VTable #{idx}]\n"
                    f"drop_in_place: {hex(vt.get('drop_in_place', 0))}\n"
                    f"object_size: {vt.get('object_size', 0)} bytes\n"
                    f"object_align: {vt.get('object_align', 0)} bytes\n"
                    f"confidence: {vt.get('confidence', 0):.2f}\n"
                    f"rationale: {vt.get('rationale', '')}"
                )

                entries = vt.get("entries", [])
                for entry in entries:
                    method_va = entry.get("address", 0)
                    method_idx = entry.get("index", 0)
                    if method_va and entry.get("points_to_code", False):
                        method_addr = toAddr(method_va)
                        createLabel(method_addr, f"rust_trait_method_{idx}_{method_idx}", False)

    def sync_strings(self) -> None:
        """Extracts and annotates hidden strings (stack strings, XOR, wide strings)."""
        print(f"[TypeMorph Ghidra] Extracting hidden strings for: {self.target_path}")
        data = run_typemorph_command(self.typemorph_bin, "strings", self.target_path)
        if not data:
            return

        strings = data if isinstance(data, list) else data.get("strings", [])
        print(f"[TypeMorph Ghidra] Extracted {len(strings)} candidate string(s)")
        if IN_GHIDRA:
            bm = currentProgram.getBookmarkManager()
            for s in strings:
                val = s.get("value", "")
                offset = s.get("offset", 0)
                cat = s.get("category", "ascii")
                note = s.get("note", "")
                addr = toAddr(offset)

                comment = f"[TypeMorph String:{cat}] \"{val}\""
                if note:
                    comment += f" ({note})"
                setEOLComment(addr, comment)

                if cat in ("stack", "xor"):
                    bm.setBookmark(addr, "TypeMorph", cat.upper() + "_STRING", val)

    def sync_devirt(self) -> None:
        """Analyzes VM interpreters and labels handlers."""
        print(f"[TypeMorph Ghidra] Analyzing virtual machine interpreters for: {self.target_path}")
        data = run_typemorph_command(self.typemorph_bin, "devirt", self.target_path)
        if not data:
            return

        instances = data.get("instances", [])
        print(f"[TypeMorph Ghidra] Found {len(instances)} VM interpreter instance(s)")
        if IN_GHIDRA:
            for vm_idx, inst in enumerate(instances):
                tbl_va = inst.get("table_va", 0)
                disp_va = inst.get("dispatcher_va", 0)
                conf = inst.get("confidence", 0.0)
                handlers = inst.get("handlers", [])

                if disp_va:
                    disp_addr = toAddr(disp_va)
                    createLabel(disp_addr, f"vm_dispatcher_{vm_idx}", True)
                    setPlateComment(disp_addr, f"[TypeMorph VM Dispatcher #{vm_idx}]\nConfidence: {conf:.2f}\nHandlers: {len(handlers)}")

                if tbl_va:
                    tbl_addr = toAddr(tbl_va)
                    createLabel(tbl_addr, f"vm_jumptable_{vm_idx}", True)

                for h in handlers:
                    opcode = h.get("opcode", 0)
                    h_va = h.get("handler_va", 0)
                    mnemonic = h.get("mnemonic", "")
                    if h_va:
                        h_addr = toAddr(h_va)
                        name = f"vm_handler_{vm_idx}_op_{hex(opcode)}"
                        createLabel(h_addr, name, True)
    def sync_crypto(self) -> None:
        """Runs TypeMorph Crypto scanner and annotates cryptographic constants."""
        print(f"[TypeMorph Ghidra] Scanning for crypto constants in: {self.target_path}")
        data = run_typemorph_command(self.typemorph_bin, "crypto", self.target_path)
        if not data:
            return
        matches = data.get("matches", [])
        print(f"[TypeMorph Ghidra] Found {len(matches)} crypto constant(s)")
        if IN_GHIDRA:
            for m in matches:
                offset = m.get("offset", 0)
                algo = m.get("algorithm", "")
                role = m.get("role", "")
                desc = m.get("description", "")
                addr = toAddr(offset)
                createBookmark(addr, "TypeMorph-Crypto", f"{algo} - {role}")
                setPlateComment(addr, f"[TypeMorph Crypto]\nAlgorithm: {algo} ({role})\nDescription: {desc}")

    def sync_cff(self) -> None:
        """Deobfuscates Control Flow Flattening (CFF) and labels reconstructed blocks."""
        print(f"[TypeMorph Ghidra] Analyzing Control Flow Flattening in: {self.target_path}")
        data = run_typemorph_command(self.typemorph_bin, "cff", self.target_path)
        if not data:
            return
        fns = data.get("functions", [])
        print(f"[TypeMorph Ghidra] Found {len(fns)} flattened function(s)")
        if IN_GHIDRA:
            for idx, fn in enumerate(fns):
                disp_va = fn.get("dispatcher_va", 0)
                state_var = fn.get("state_variable", "")
                blocks = fn.get("blocks", [])
                transitions = fn.get("transitions", [])
                if disp_va:
                    disp_addr = toAddr(disp_va)
                    createLabel(disp_addr, f"cff_dispatcher_{idx}", True)
                    createBookmark(disp_addr, "TypeMorph-CFF", f"CFF Dispatcher #{idx}")
                    comment = f"[TypeMorph CFF Dispatcher #{idx}]\nState Variable: {state_var}\nBlocks: {len(blocks)}\nTransitions:\n"
                    for t in transitions[:12]:
                        comment += f"  State 0x{t.get('from', 0):X} -> State 0x{t.get('to', 0):X}\n"
                    setPlateComment(disp_addr, comment)

                for blk in blocks:
                    st_id = blk.get("state_id", 0)
                    va = blk.get("va", 0)
                    if va:
                        blk_addr = toAddr(va)
                        tag = "entry" if blk.get("is_entry") else ("exit" if blk.get("is_exit") else "case")
                        createLabel(blk_addr, f"cff_block_{idx}_st_0x{st_id:X}_{tag}", True)
                        setEOLComment(blk_addr, f"[TypeMorph CFF State 0x{st_id:X} ({tag})]")

    def sync_apihash(self) -> None:
        """Detects API hashes and annotates resolved Windows/POSIX imports."""
        print(f"[TypeMorph Ghidra] Scanning API hashes in: {self.target_path}")
        data = run_typemorph_command(self.typemorph_bin, "apihash", self.target_path)
        if not data:
            return
        matches = data.get("matches", [])
        print(f"[TypeMorph Ghidra] Found {len(matches)} API hash match(es)")
        if IN_GHIDRA:
            for m in matches:
                off = m.get("offset", 0)
                api = m.get("api", "")
                mod = m.get("module", "")
                algo = m.get("algorithm", "")
                hash_val = m.get("hash", 0)
                addr = currentProgram.getImageBase().add(off)
                setEOLComment(addr, f"[TypeMorph API Hash] 0x{hash_val:08X} -> {mod}!{api} ({algo})")

    def sync_opaque(self) -> None:
        """Detects opaque predicates and dead branches in Ghidra."""
        print(f"[TypeMorph Ghidra] Scanning opaque predicates in: {self.target_path}")
        data = run_typemorph_command(self.typemorph_bin, "opaque", self.target_path)
        if not data:
            return
        preds = data.get("predicates", [])
        print(f"[TypeMorph Ghidra] Found {len(preds)} opaque predicate(s)")
        if IN_GHIDRA:
            for p in preds:
                off = p.get("offset", 0)
                disasm = p.get("disassembly", "")
                outcome = p.get("outcome", "")
                rationale = p.get("rationale", "")
                addr = currentProgram.getImageBase().add(off)
                tag = "ALWAYS TAKEN" if outcome == "always_true" else "NEVER TAKEN (DEAD)"
                setPreComment(addr, f"[TypeMorph Opaque Predicate] {disasm} => {tag}\n{rationale}")

    def run_all(self) -> None:
        self.sync_rust()
        self.sync_strings()
        self.sync_devirt()
        self.sync_crypto()
        self.sync_cff()
        self.sync_apihash()
        self.sync_opaque()
        print("[TypeMorph Ghidra] Synchronization complete!")


def main():
    target = None
    if IN_GHIDRA:
        target = currentProgram.getExecutablePath()
    elif len(sys.argv) > 1:
        target = sys.argv[1]

    if not target or not os.path.exists(target):
        print(f"[TypeMorph Ghidra] Usage: python typemorph_sync.py <binary_path>")
        return

    sync = GhidraSync(target)
    sync.run_all()


if __name__ == "__main__":
    main()
