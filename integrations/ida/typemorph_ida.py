#!/usr/bin/env python3
"""
TypeMorph IDA Pro Integration - IDAPython Plugin & Semantic Recovery Script
Compatible with IDA Pro 7.x, 8.x, 9.x (Python 3).

Features:
- Rust Semantic Recovery:
  * Demangles Rust symbols and renames subroutines
  * Names and annotates string literals (&str slice pairs)
  * Defines TraitObject vtable structs in IDA Local Types and names method pointers
- String Revealer:
  * Discovers stack strings, XOR-decoded strings, and UTF-16LE wide strings
  * Comments disassembled instructions and registers string references
- Devirtualizer:
  * Identifies VM interpreter dispatch loops
  * Automatically labels VM bytecode handler functions (vm_handler_op_0xXX)
"""

import os
import sys
import json
import shutil
import subprocess
from typing import Dict, Any, List, Optional

# Attempt IDA imports
IN_IDA = False
try:
    import ida_idaapi
    import ida_nalt
    import ida_bytes
    import ida_name
    import ida_funcs
    import ida_struct
    import ida_kernwin
    IN_IDA = True
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
        print(f"[TypeMorph IDA] Command {cmd} failed: {exc}")
        return None


class TypeMorphIdaSync:
    def __init__(self, target_path: str, typemorph_bin: Optional[str] = None):
        self.target_path = target_path
        self.typemorph_bin = typemorph_bin or find_typemorph_binary()

    def sync_rust(self) -> None:
        print(f"[TypeMorph IDA] Analyzing Rust semantics for: {self.target_path}")
        data = run_typemorph_command(self.typemorph_bin, "rust", self.target_path)
        if not data:
            return

        # 1. Demangle symbols
        symbols = data.get("rust_symbols", [])
        print(f"[TypeMorph IDA] Renaming {len(symbols)} Rust function(s)...")
        if IN_IDA:
            for sym in symbols:
                mangled = sym.get("mangled")
                demangled = sym.get("demangled")
                if mangled and demangled and mangled != demangled:
                    ea = ida_name.get_name_ea(ida_idaapi.BADADDR, mangled)
                    if ea != ida_idaapi.BADADDR:
                        ida_name.set_name(ea, demangled, ida_name.SN_NOWARN)
                        ida_bytes.set_cmt(ea, f"[TypeMorph Rust Demangled] Crate: {sym.get('crate')}", False)

        # 2. String fat-pointers
        strings = data.get("strings", [])
        print(f"[TypeMorph IDA] Annotating {len(strings)} Rust string literal(s)...")
        if IN_IDA:
            for s in strings:
                val = s.get("value", "")
                data_ea = s.get("data_address", 0)
                pair_ea = s.get("pair_address", 0)
                if data_ea:
                    ida_bytes.set_cmt(data_ea, f'[TypeMorph Rust &str] "{val}"', False)
                if pair_ea:
                    ida_bytes.set_cmt(pair_ea, f'[TypeMorph FatPointer -> "{val}"]', False)

        # 3. Trait vtables
        vtables = data.get("vtables", [])
        print(f"[TypeMorph IDA] Found {len(vtables)} Rust trait vtable(s)...")
        if IN_IDA:
            for idx, vt in enumerate(vtables):
                vtable_ea = vt.get("address", 0)
                if not vtable_ea:
                    continue
                ida_name.set_name(vtable_ea, f"rust_vtable_{idx}_{hex(vtable_ea)}", ida_name.SN_NOWARN)
                comment = (
                    f"[TypeMorph Rust VTable #{idx}]\n"
                    f"drop: {hex(vt.get('drop_in_place', 0))}, size: {vt.get('object_size', 0)} B, "
                    f"align: {vt.get('object_align', 0)} B"
                )
                ida_bytes.set_cmt(vtable_ea, comment, False)

                for entry in vt.get("entries", []):
                    method_ea = entry.get("address", 0)
                    method_idx = entry.get("index", 0)
                    if method_ea and entry.get("points_to_code", False):
                        ida_name.set_name(method_ea, f"rust_trait_{idx}_method_{method_idx}", ida_name.SN_NOWARN)

    def sync_strings(self) -> None:
        print(f"[TypeMorph IDA] Revealing strings for: {self.target_path}")
        data = run_typemorph_command(self.typemorph_bin, "strings", self.target_path)
        if not data:
            return

        strings = data if isinstance(data, list) else data.get("strings", [])
        print(f"[TypeMorph IDA] Annotating {len(strings)} discovered string(s)...")
        if IN_IDA:
            for s in strings:
                val = s.get("value", "")
                offset = s.get("offset", 0)
                cat = s.get("category", "ascii")
                note = s.get("note", "")
                cmt = f'[TypeMorph String:{cat}] "{val}"'
                if note:
                    cmt += f" ({note})"
                ida_bytes.set_cmt(offset, cmt, False)

    def sync_devirt(self) -> None:
        print(f"[TypeMorph IDA] Analyzing VM dispatchers for: {self.target_path}")
        data = run_typemorph_command(self.typemorph_bin, "devirt", self.target_path)
        if not data:
            return

        instances = data.get("instances", [])
        print(f"[TypeMorph IDA] Found {len(instances)} VM interpreter instance(s)...")
        if IN_IDA:
            for vm_idx, inst in enumerate(instances):
                disp_ea = inst.get("dispatcher_va", 0)
                tbl_ea = inst.get("table_va", 0)
                conf = inst.get("confidence", 0.0)
                handlers = inst.get("handlers", [])

                if disp_ea:
                    ida_name.set_name(disp_ea, f"vm_dispatcher_{vm_idx}", ida_name.SN_NOWARN)
                    ida_bytes.set_cmt(disp_ea, f"[TypeMorph VM Dispatcher #{vm_idx}] Confidence: {conf:.2f}", False)

                if tbl_ea:
                    ida_name.set_name(tbl_ea, f"vm_jumptable_{vm_idx}", ida_name.SN_NOWARN)

                for h in handlers:
                    opcode = h.get("opcode", 0)
                    h_ea = h.get("handler_va", 0)
                    mnemonic = h.get("mnemonic", "")
                    if h_ea:
                        ida_name.set_name(h_ea, f"vm_handler_{vm_idx}_op_{hex(opcode)}", ida_name.SN_NOWARN)
    def sync_crypto(self) -> None:
        """Runs TypeMorph Crypto scanner and annotates cryptographic constants."""
        print(f"[TypeMorph IDA] Scanning for crypto constants in: {self.target_path}")
        data = run_typemorph_command(self.typemorph_bin, "crypto", self.target_path)
        if not data:
            return
        matches = data.get("matches", [])
        print(f"[TypeMorph IDA] Found {len(matches)} crypto constant(s)")
        if IN_IDA:
            for m in matches:
                offset = m.get("offset", 0)
                algo = m.get("algorithm", "")
                role = m.get("role", "")
                desc = m.get("description", "")
                ea = ida_nalt.get_imagebase() + offset
                ida_bytes.set_cmt(ea, f"[TypeMorph Crypto] {algo} - {role} ({desc})", False)

    def sync_cff(self) -> None:
        """Deobfuscates Control Flow Flattening (CFF) and labels reconstructed blocks."""
        print(f"[TypeMorph IDA] Analyzing Control Flow Flattening in: {self.target_path}")
        data = run_typemorph_command(self.typemorph_bin, "cff", self.target_path)
        if not data:
            return
        fns = data.get("functions", [])
        print(f"[TypeMorph IDA] Found {len(fns)} flattened function(s)")
        if IN_IDA:
            for idx, fn in enumerate(fns):
                disp_ea = fn.get("dispatcher_va", 0)
                state_var = fn.get("state_variable", "")
                blocks = fn.get("blocks", [])
                transitions = fn.get("transitions", [])
                if disp_ea:
                    ida_name.set_name(disp_ea, f"cff_dispatcher_{idx}", ida_name.SN_NOWARN)
                    cmt = f"[TypeMorph CFF Dispatcher #{idx}] StateVar: {state_var}\n"
                    for t in transitions[:8]:
                        cmt += f"State 0x{t.get('from', 0):X} -> State 0x{t.get('to', 0):X}\n"
                    ida_bytes.set_cmt(disp_ea, cmt, False)

                for blk in blocks:
                    st_id = blk.get("state_id", 0)
                    ea = blk.get("va", 0)
                    if ea:
                        tag = "entry" if blk.get("is_entry") else ("exit" if blk.get("is_exit") else "case")
                        ida_name.set_name(ea, f"cff_st_0x{st_id:X}_{tag}", ida_name.SN_NOWARN)
                        ida_bytes.set_cmt(ea, f"[TypeMorph CFF State 0x{st_id:X} ({tag})]", False)

    def run_all(self) -> None:
        self.sync_rust()
        self.sync_strings()
        self.sync_devirt()
        self.sync_crypto()
        self.sync_cff()
        print("[TypeMorph IDA] Synchronization complete!")


def main():
    target = None
    if IN_IDA:
        target = ida_nalt.get_input_file_path()
    elif len(sys.argv) > 1:
        target = sys.argv[1]

    if not target or not os.path.exists(target):
        print("[TypeMorph IDA] Usage: python typemorph_ida.py <binary_path>")
        return

    sync = TypeMorphIdaSync(target)
    sync.run_all()


if __name__ == "__main__":
    main()
