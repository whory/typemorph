#!/usr/bin/env python3
"""
TypeMorph Radare2 / Cutter Integration - r2pipe Semantic Sync Script
Compatible with Radare2, Cutter, and iaito.

Features:
- Rust Semantic Recovery:
  * Renames functions using 'afn <demangled> <addr>'
  * Comments string literal references using 'CC <comment> @ <addr>'
  * Adds flags for trait vtables ('f vtable_... = <addr>')
- String Revealer:
  * Annotates stack strings and XOR decoded strings ('CC [TypeMorph String] @ <addr>')
- Devirtualizer:
  * Defines flags for VM dispatchers and handlers ('f vm_handler_... = <addr>')
"""

import os
import sys
import json
import shutil
import subprocess
from typing import Dict, Any, List, Optional

# Attempt r2pipe import
IN_R2PIPE = False
try:
    import r2pipe
    IN_R2PIPE = True
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
        print(f"[TypeMorph R2] Error executing {cmd}: {exc}")
        return None


class R2Sync:
    def __init__(self, target_path: str, r2: Optional[Any] = None, typemorph_bin: Optional[str] = None):
        self.target_path = target_path
        self.r2 = r2
        self.typemorph_bin = typemorph_bin or find_typemorph_binary()

    def cmd(self, command: str) -> None:
        if self.r2:
            self.r2.cmd(command)

    def sync_rust(self) -> None:
        print(f"[TypeMorph R2] Analyzing Rust semantics for: {self.target_path}")
        data = run_typemorph_command(self.typemorph_bin, "rust", self.target_path)
        if not data:
            return

        symbols = data.get("rust_symbols", [])
        print(f"[TypeMorph R2] Renaming {len(symbols)} Rust symbol(s)...")
        for sym in symbols:
            mangled = sym.get("mangled")
            demangled = sym.get("demangled")
            if mangled and demangled and mangled != demangled:
                clean_name = demangled.replace(" ", "_").replace("::", ".")
                self.cmd(f"afn {clean_name} @ sym.{mangled}")

        strings = data.get("strings", [])
        print(f"[TypeMorph R2] Annotating {len(strings)} Rust string literal(s)...")
        for s in strings:
            val = s.get("value", "").replace('"', '\\"')
            data_va = s.get("data_address", 0)
            pair_va = s.get("pair_address", 0)
            if data_va:
                self.cmd(f'CC [TypeMorph Rust &str] "{val}" @ {data_va}')
            if pair_va:
                self.cmd(f'CC [TypeMorph FatPointer -> "{val}"] @ {pair_va}')

        vtables = data.get("vtables", [])
        print(f"[TypeMorph R2] Found {len(vtables)} Rust trait vtable(s)...")
        for idx, vt in enumerate(vtables):
            vtable_va = vt.get("address", 0)
            if not vtable_va:
                continue
            self.cmd(f"f vtable.rust.{idx} = {vtable_va}")
            self.cmd(f'CC [TypeMorph Rust VTable #{idx}] size={vt.get("object_size")} align={vt.get("object_align")} @ {vtable_va}')
            for entry in vt.get("entries", []):
                method_va = entry.get("address", 0)
                method_idx = entry.get("index", 0)
                if method_va and entry.get("points_to_code", False):
                    self.cmd(f"f vtable.rust.{idx}.method.{method_idx} = {method_va}")

    def sync_strings(self) -> None:
        print(f"[TypeMorph R2] Revealing strings for: {self.target_path}")
        data = run_typemorph_command(self.typemorph_bin, "strings", self.target_path)
        if not data:
            return

        strings = data if isinstance(data, list) else data.get("strings", [])
        print(f"[TypeMorph R2] Discovered {len(strings)} candidate string(s)...")
        for s in strings:
            val = s.get("value", "").replace('"', '\\"')
            offset = s.get("offset", 0)
            cat = s.get("category", "ascii")
            self.cmd(f'CC [TypeMorph String:{cat}] "{val}" @ {offset}')

    def sync_devirt(self) -> None:
        print(f"[TypeMorph R2] Analyzing VM interpreters for: {self.target_path}")
        data = run_typemorph_command(self.typemorph_bin, "devirt", self.target_path)
        if not data:
            return

        instances = data.get("instances", [])
        print(f"[TypeMorph R2] Found {len(instances)} VM interpreter instance(s)...")
        for vm_idx, inst in enumerate(instances):
            disp_va = inst.get("dispatcher_va", 0)
            tbl_va = inst.get("table_va", 0)
            conf = inst.get("confidence", 0.0)
            handlers = inst.get("handlers", [])

            if disp_va:
                self.cmd(f"f vm.dispatcher.{vm_idx} = {disp_va}")
                self.cmd(f"CC [TypeMorph VM Dispatcher #{vm_idx}] Confidence: {conf:.2f} @ {disp_va}")

            if tbl_va:
                self.cmd(f"f vm.jumptable.{vm_idx} = {tbl_va}")

            for h in handlers:
                opcode = h.get("opcode", 0)
                h_va = h.get("handler_va", 0)
                if h_va:
                    self.cmd(f"f vm.handler.{vm_idx}.op_{hex(opcode)} = {h_va}")
                    self.cmd(f"CC [TypeMorph VM Opcode {hex(opcode)}] {h.get('mnemonic')} @ {h_va}")

    def run_all(self) -> None:
        self.sync_rust()
        self.sync_strings()
        self.sync_devirt()
        print("[TypeMorph R2] Synchronization complete!")


def main():
    if len(sys.argv) < 2:
        print("Usage: python typemorph_r2.py <binary_path>")
        return

    target = sys.argv[1]
    if not os.path.exists(target):
        print(f"Error: file not found: {target}")
        return

    r2 = None
    if IN_R2PIPE:
        r2 = r2pipe.open(target)

    sync = R2Sync(target, r2)
    sync.run_all()


if __name__ == "__main__":
    main()
