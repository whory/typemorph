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
    def sync_crypto(self) -> None:
        print(f"[TypeMorph R2] Scanning for crypto constants in: {self.target_path}")
        data = run_typemorph_command(self.typemorph_bin, "crypto", self.target_path)
        if not data:
            return
        matches = data.get("matches", [])
        print(f"[TypeMorph R2] Found {len(matches)} crypto constant(s)...")
        for m in matches:
            offset = m.get("offset", 0)
            algo = m.get("algorithm", "")
            role = m.get("role", "")
            desc = m.get("description", "")
            self.cmd(f"f crypto.{algo}.{role} = {offset}")
            self.cmd(f'CC [TypeMorph Crypto] "{algo}: {role} ({desc})" @ {offset}')

    def sync_cff(self) -> None:
        print(f"[TypeMorph R2] Analyzing Control Flow Flattening in: {self.target_path}")
        data = run_typemorph_command(self.typemorph_bin, "cff", self.target_path)
        if not data:
            return
        fns = data.get("functions", [])
        print(f"[TypeMorph R2] Found {len(fns)} flattened function(s)...")
        for idx, fn in enumerate(fns):
            disp_va = fn.get("dispatcher_va", 0)
            state_var = fn.get("state_variable", "")
            blocks = fn.get("blocks", [])
            transitions = fn.get("transitions", [])
            if disp_va:
                self.cmd(f"f cff.dispatcher.{idx} = {disp_va}")
                cmt = f"[TypeMorph CFF Dispatcher #{idx}] StateVar: {state_var}"
                self.cmd(f'CC "{cmt}" @ {disp_va}')

            for blk in blocks:
                st_id = blk.get("state_id", 0)
                va = blk.get("va", 0)
                if va:
                    tag = "entry" if blk.get("is_entry") else ("exit" if blk.get("is_exit") else "case")
                    self.cmd(f"f cff.block.{idx}.st_{hex(st_id)}.{tag} = {va}")
                    self.cmd(f'CC "[TypeMorph CFF State {hex(st_id)} ({tag})]" @ {va}')

    def sync_apihash(self) -> None:
        print(f"[TypeMorph R2] Scanning for API hashes in: {self.target_path}")
        data = run_typemorph_command(self.typemorph_bin, "apihash", self.target_path)
        if not data:
            return
        matches = data.get("matches", [])
        print(f"[TypeMorph R2] Found {len(matches)} API hash match(es)...")
        for m in matches:
            offset = m.get("offset", 0)
            api = m.get("api", "")
            mod = m.get("module", "")
            algo = m.get("algorithm", "")
            hash_val = m.get("hash", 0)
            self.cmd(f"f apihash.{mod}.{api} = {offset}")
            self.cmd(f'CC "[TypeMorph API Hash] 0x{hash_val:08X} -> {mod}!{api} ({algo})" @ {offset}')

    def sync_opaque(self) -> None:
        print(f"[TypeMorph R2] Scanning for opaque predicates in: {self.target_path}")
        data = run_typemorph_command(self.typemorph_bin, "opaque", self.target_path)
        if not data:
            return
        preds = data.get("predicates", [])
        print(f"[TypeMorph R2] Found {len(preds)} opaque predicate(s)...")
        for p in preds:
            offset = p.get("offset", 0)
            disasm = p.get("disassembly", "")
            outcome = p.get("outcome", "")
            tag = "ALWAYS TAKEN" if outcome == "always_true" else "DEAD (NEVER TAKEN)"
            self.cmd(f'CC "[TypeMorph Opaque Predicate] {disasm} => {tag}" @ {offset}')

    def sync_rtti(self) -> None:
        print(f"[TypeMorph R2] Reconstructing C++ RTTI in: {self.target_path}")
        data = run_typemorph_command(self.typemorph_bin, "rtti", self.target_path)
        if not data:
            return
        classes = data.get("classes", [])
        print(f"[TypeMorph R2] Found {len(classes)} polymorphic C++ class(es)...")
        for cls in classes:
            name = cls.get("name", "UnknownClass").replace("::", "__")
            vf_va = cls.get("vftable_va", 0)
            loc_va = cls.get("locator_va", 0)
            bases = cls.get("base_classes", [])
            methods = cls.get("methods", [])

            if vf_va:
                self.cmd(f"f vftable.{name} = {vf_va}")
                base_str = ", ".join(f"{b.get('name')} (+{b.get('offset', 0)})" for b in bases)
                cmt = f"[TypeMorph RTTI] class {name}"
                if base_str:
                    cmt += f" : {base_str}"
                self.cmd(f'CC "{cmt}" @ {vf_va}')

            if loc_va:
                self.cmd(f"f rtti.locator.{name} = {loc_va}")

            for m in methods:
                m_va = m.get("virtual_address", 0)
                slot = m.get("slot", 0)
                if m_va:
                    self.cmd(f"f {name}.slot_{slot} = {m_va}")
                    self.cmd(f'CC "[TypeMorph RTTI] {name}::slot_{slot}" @ {m_va}')

    def sync_checksec(self) -> None:
        print(f"[TypeMorph R2] Inspecting security mitigations (checksec) in: {self.target_path}")
        data = run_typemorph_command(self.typemorph_bin, "checksec", self.target_path)
        if not data:
            return
        mits = data.get("mitigations", {})
        packers = data.get("packers", [])
        anomalies = data.get("section_anomalies", [])
        anti = data.get("anti_analysis_indicators", [])
        print(f"[TypeMorph R2] Hardening: ASLR={mits.get('aslr')}, DEP={mits.get('dep_nx')}, CFG={mits.get('cfg')}")
        ep = data.get("entry_point", 0)
        if ep:
            cmt = f"[TypeMorph checksec] ASLR={mits.get('aslr')}, DEP={mits.get('dep_nx')}, CFG={mits.get('cfg')}, SafeSEH={mits.get('safe_seh')}"
            if packers:
                cmt += f" | Packers: {', '.join(p.get('name') for p in packers)}"
            self.cmd(f'CC "{cmt}" @ {ep}')

    def sync_go(self) -> None:
        print(f"[TypeMorph R2] Reconstructing Golang metadata in: {self.target_path}")
        data = run_typemorph_command(self.typemorph_bin, "go", self.target_path)
        if not data or not data.get("detected"):
            return
        fns = data.get("functions", [])
        print(f"[TypeMorph R2] Found {len(fns)} Go function(s) ({data.get('version')})...")
        for fn in fns:
            name = fn.get("name", "")
            va = fn.get("entry_va", 0)
            if va and name:
                sanitized = name.replace(" ", "_").replace("·", "_").replace(".", "__")
                self.cmd(f"f go.{sanitized} = {va}")
                self.cmd(f'CC "[TypeMorph Go] {name}" @ {va}')

    def sync_rich(self) -> None:
        print(f"[TypeMorph R2] Decoding MSVC Rich Header in: {self.target_path}")
        data = run_typemorph_command(self.typemorph_bin, "rich", self.target_path)
        if not data or not data.get("present"):
            return
        recs = data.get("records", [])
        hash_val = data.get("hash", "")
        vs_versions = data.get("compiler_versions", [])
        print(f"[TypeMorph R2] Rich Header: Hash {hash_val}, Toolsets: {', '.join(vs_versions)}...")
        off = data.get("offset", 0x80)
        cmt = f"[TypeMorph Rich Header] Hash: {hash_val} | Toolsets: {', '.join(vs_versions)}"
        self.cmd(f'CC "{cmt}" @ {off}')

    def sync_abi(self) -> None:
        print(f"[TypeMorph R2] Classifying calling conventions in: {self.target_path}")
        data = run_typemorph_command(self.typemorph_bin, "abi", self.target_path)
        if not data:
            return
        sigs = data.get("signatures", [])
        dist = data.get("conventions", {})
        print(f"[TypeMorph R2] Analyzed {len(sigs)} function(s). Conventions: {dist}...")
        for s in sigs:
            va = s.get("entry_va", 0)
            proto = s.get("prototype", "")
            conv = s.get("convention", "")
            rat = s.get("rationale", "")
            if va:
                safe_proto = proto.replace('"', '\\"')
                self.cmd(f'CC "[TypeMorph ABI] {safe_proto} ({conv})" @ {va}')

    def sync_decompile(self) -> None:
        print(f"[TypeMorph R2] Decompiling functions & inferring structs in: {self.target_path}")
        data = run_typemorph_command(self.typemorph_bin, "decompile", self.target_path)
        if not data:
            return
        fns = data.get("functions", [])
        structs = data.get("structs", [])
        print(f"[TypeMorph R2] Decompiled {len(fns)} function(s), {len(structs)} struct layout(s)...")
        for fn in fns:
            va = fn.get("entry_va", 0)
            pseudo = fn.get("pseudocode", "")
            if va and pseudo:
                first_line = pseudo.split("\n")[0].replace('"', '\\"')
                self.cmd(f'CC "[TypeMorph Decompile] {first_line}" @ {va}')

    def sync_csharp(self) -> None:
        print(f"[TypeMorph R2] Extracting .NET metadata in: {self.target_path}")
        data = run_typemorph_command(self.typemorph_bin, "csharp", self.target_path)
        if not data or not data.get("is_dotnet"):
            return
        types = data.get("types", [])
        print(f"[TypeMorph R2] Recovered {len(types)} .NET type(s)...")
        for t in types:
            for m in t.get("methods", []):
                rva = m.get("rva", 0)
                if rva:
                    self.cmd(f"f dotnet.{t.get('name')}.{m.get('name')} = {rva}")

    def sync_detect(self) -> None:
        """Deep compiler, packer and protection identification (DIE Engine)."""
        print(f"[TypeMorph R2] Detecting compiler & packers (DIE Engine): {self.target_path}")
        data = run_typemorph_command(self.typemorph_bin, "detect", self.target_path)
        if not data:
            return
        compiler = data.get("primary_compiler", "Unknown")
        packer = data.get("primary_packer", "None")
        protector = data.get("primary_protector", "None")
        print(f"[TypeMorph R2] Compiler: {compiler} | Packer: {packer} | Protector: {protector}")
        ep = data.get("entry_point", 0)
        if ep:
            self.cmd(f'CC "[TypeMorph Detect] {compiler} / {packer} / {protector}" @ {ep}')

    def run_all(self) -> None:
        self.sync_detect()
        self.sync_rust()
        self.sync_strings()
        self.sync_devirt()
        self.sync_crypto()
        self.sync_cff()
        self.sync_apihash()
        self.sync_opaque()
        self.sync_rtti()
        self.sync_checksec()
        self.sync_go()
        self.sync_rich()
        self.sync_abi()
        self.sync_decompile()
        self.sync_csharp()
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
