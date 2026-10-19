#!/usr/bin/env python3
"""
TypeMorph Binary Ninja Integration - Semantic Recovery & Deobfuscation Plugin
Compatible with Binary Ninja API v3/v4.

Features:
- Rust Semantic Recovery:
  * Renames mangled Rust symbols to demangled full path names
  * Annotates string fat-pointer slices (.rodata references)
  * Defines TraitObject vtable structures and labels method pointers
- String Revealer:
  * Detects and comments stack strings and XOR-encoded strings
  * Creates Binary Ninja tags for decoded strings
- Devirtualizer:
  * Labels VM bytecode handlers (vm_handler_op_0xXX)
  * Annotates dispatcher functions and registers jump tables
"""

import os
import sys
import json
import shutil
import subprocess
from typing import Dict, Any, List, Optional

# Attempt to import Binary Ninja API
IN_BINJA = False
try:
    import binaryninja
    from binaryninja import (
        PluginCommand, Symbol, SymbolType, StructureBuilder,
        Type, TagType, Tag
    )
    IN_BINJA = True
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
    cmd = [typemorph_bin, subcommand, target_file, "--json"]
    if extra_args:
        cmd.extend(extra_args)

    try:
        proc = subprocess.run(cmd, stdout=subprocess.PIPE, stderr=subprocess.PIPE, text=True, check=True)
        return json.loads(proc.stdout)
    except Exception as exc:
        print(f"[TypeMorph Binja] Error executing {cmd}: {exc}")
        return None


class BinaryNinjaSync:
    def __init__(self, target_path: str, bv: Optional[Any] = None, typemorph_bin: Optional[str] = None):
        self.target_path = target_path
        self.bv = bv
        self.typemorph_bin = typemorph_bin or find_typemorph_binary()

    def sync_rust(self) -> None:
        print(f"[TypeMorph Binja] Analyzing Rust semantics for: {self.target_path}")
        data = run_typemorph_command(self.typemorph_bin, "rust", self.target_path)
        if not data:
            return

        symbols = data.get("rust_symbols", [])
        print(f"[TypeMorph Binja] Renaming {len(symbols)} Rust symbol(s)...")
        if self.bv:
            for sym in symbols:
                mangled = sym.get("mangled")
                demangled = sym.get("demangled")
                if mangled and demangled and mangled != demangled:
                    binja_syms = self.bv.get_symbols_by_name(mangled)
                    for s in binja_syms:
                        new_sym = Symbol(s.type, s.address, demangled, demangled, s.raw_name)
                        self.bv.define_auto_symbol(new_sym)
                        self.bv.set_comment_at(s.address, f"[TypeMorph Rust] Crate: {sym.get('crate')}")

        strings = data.get("strings", [])
        print(f"[TypeMorph Binja] Annotating {len(strings)} Rust string literal(s)...")
        if self.bv:
            for s in strings:
                val = s.get("value", "")
                data_va = s.get("data_address", 0)
                pair_va = s.get("pair_address", 0)
                if data_va:
                    self.bv.set_comment_at(data_va, f'[TypeMorph Rust &str] "{val}"')
                if pair_va:
                    self.bv.set_comment_at(pair_va, f'[TypeMorph FatPointer -> "{val}"]')

        vtables = data.get("vtables", [])
        print(f"[TypeMorph Binja] Found {len(vtables)} Rust trait vtable(s)...")
        if self.bv:
            for idx, vt in enumerate(vtables):
                vtable_va = vt.get("address", 0)
                if not vtable_va:
                    continue
                vtable_sym = Symbol(SymbolType.DataSymbol, vtable_va, f"rust_vtable_{idx}_{hex(vtable_va)}")
                self.bv.define_auto_symbol(vtable_sym)
                cmt = (
                    f"[TypeMorph Rust VTable #{idx}]\n"
                    f"drop: {hex(vt.get('drop_in_place', 0))}, size: {vt.get('object_size', 0)} B, "
                    f"align: {vt.get('object_align', 0)} B"
                )
                self.bv.set_comment_at(vtable_va, cmt)

                for entry in vt.get("entries", []):
                    method_va = entry.get("address", 0)
                    method_idx = entry.get("index", 0)
                    if method_va and entry.get("points_to_code", False):
                        m_sym = Symbol(SymbolType.FunctionSymbol, method_va, f"rust_trait_{idx}_method_{method_idx}")
                        self.bv.define_auto_symbol(m_sym)

    def sync_strings(self) -> None:
        print(f"[TypeMorph Binja] Revealing strings for: {self.target_path}")
        data = run_typemorph_command(self.typemorph_bin, "strings", self.target_path)
        if not data:
            return

        strings = data if isinstance(data, list) else data.get("strings", [])
        print(f"[TypeMorph Binja] Discovered {len(strings)} candidate string(s)...")
        if self.bv:
            for s in strings:
                val = s.get("value", "")
                offset = s.get("offset", 0)
                cat = s.get("category", "ascii")
                note = s.get("note", "")
                cmt = f'[TypeMorph String:{cat}] "{val}"'
                if note:
                    cmt += f" ({note})"
                self.bv.set_comment_at(offset, cmt)

    def sync_devirt(self) -> None:
        print(f"[TypeMorph Binja] Analyzing VM interpreters for: {self.target_path}")
        data = run_typemorph_command(self.typemorph_bin, "devirt", self.target_path)
        if not data:
            return

        instances = data.get("instances", [])
        print(f"[TypeMorph Binja] Found {len(instances)} VM interpreter instance(s)...")
        if self.bv:
            for vm_idx, inst in enumerate(instances):
                disp_va = inst.get("dispatcher_va", 0)
                tbl_va = inst.get("table_va", 0)
                conf = inst.get("confidence", 0.0)
                handlers = inst.get("handlers", [])

                if disp_va:
                    disp_sym = Symbol(SymbolType.FunctionSymbol, disp_va, f"vm_dispatcher_{vm_idx}")
                    self.bv.define_auto_symbol(disp_sym)
                    self.bv.set_comment_at(disp_va, f"[TypeMorph VM Dispatcher #{vm_idx}] Confidence: {conf:.2f}")

                if tbl_va:
                    tbl_sym = Symbol(SymbolType.DataSymbol, tbl_va, f"vm_jumptable_{vm_idx}")
                    self.bv.define_auto_symbol(tbl_sym)

                for h in handlers:
                    opcode = h.get("opcode", 0)
                    h_va = h.get("handler_va", 0)
                    mnemonic = h.get("mnemonic", "")
                    if h_va:
                        h_sym = Symbol(SymbolType.FunctionSymbol, h_va, f"vm_handler_{vm_idx}_op_{hex(opcode)}")
                        self.bv.define_auto_symbol(h_sym)
    def sync_crypto(self) -> None:
        """Runs TypeMorph Crypto scanner and annotates cryptographic constants."""
        print(f"[TypeMorph Binja] Scanning for crypto constants in: {self.target_path}")
        data = run_typemorph_command(self.typemorph_bin, "crypto", self.target_path)
        if not data:
            return
        matches = data.get("matches", [])
        print(f"[TypeMorph Binja] Found {len(matches)} crypto constant(s)")
        if self.bv:
            for m in matches:
                offset = m.get("offset", 0)
                algo = m.get("algorithm", "")
                role = m.get("role", "")
                desc = m.get("description", "")
                addr = self.bv.start + offset
                self.bv.set_comment_at(addr, f"[TypeMorph Crypto] {algo} - {role} ({desc})")

    def sync_cff(self) -> None:
        """Deobfuscates Control Flow Flattening (CFF) and labels reconstructed blocks."""
        print(f"[TypeMorph Binja] Analyzing Control Flow Flattening in: {self.target_path}")
        data = run_typemorph_command(self.typemorph_bin, "cff", self.target_path)
        if not data:
            return
        fns = data.get("functions", [])
        print(f"[TypeMorph Binja] Found {len(fns)} flattened function(s)")
        if self.bv:
            for idx, fn in enumerate(fns):
                disp_va = fn.get("dispatcher_va", 0)
                state_var = fn.get("state_variable", "")
                blocks = fn.get("blocks", [])
                transitions = fn.get("transitions", [])
                if disp_va:
                    disp_sym = Symbol(SymbolType.FunctionSymbol, disp_va, f"cff_dispatcher_{idx}")
                    self.bv.define_auto_symbol(disp_sym)
                    cmt = f"[TypeMorph CFF Dispatcher #{idx}] StateVar: {state_var}\n"
                    for t in transitions[:8]:
                        cmt += f"State 0x{t.get('from', 0):X} -> State 0x{t.get('to', 0):X}\n"
                    self.bv.set_comment_at(disp_va, cmt)

                for blk in blocks:
                    st_id = blk.get("state_id", 0)
                    va = blk.get("va", 0)
                    if va:
                        tag = "entry" if blk.get("is_entry") else ("exit" if blk.get("is_exit") else "case")
                        sym = Symbol(SymbolType.FunctionSymbol, va, f"cff_st_0x{st_id:X}_{tag}")
                        self.bv.define_auto_symbol(sym)
                        self.bv.set_comment_at(va, f"[TypeMorph CFF State 0x{st_id:X} ({tag})]")

    def run_all(self) -> None:
        self.sync_rust()
        self.sync_strings()
        self.sync_devirt()
        self.sync_crypto()
        self.sync_cff()
        print("[TypeMorph Binja] Synchronization complete!")


def binja_sync_all(bv):
    sync = BinaryNinjaSync(bv.file.filename, bv)
    sync.run_all()


if IN_BINJA:
    PluginCommand.register("TypeMorph\\Sync All (Rust, Strings, Devirt, Crypto, CFF)", "Run full TypeMorph analysis", binja_sync_all)


def main():
    if len(sys.argv) < 2:
        print("Usage: python typemorph_binja.py <binary_path>")
        return

    target = sys.argv[1]
    if not os.path.exists(target):
        print(f"Error: file not found: {target}")
        return

    bv = None
    if IN_BINJA:
        bv = binaryninja.load(target)

    sync = BinaryNinjaSync(target, bv)
    sync.run_all()


if __name__ == "__main__":
    main()
