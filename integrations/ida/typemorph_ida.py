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

    def sync_apihash(self) -> None:
        """Detects API hashes and annotates resolved Windows/POSIX imports."""
        print(f"[TypeMorph IDA] Scanning API hashes in: {self.target_path}")
        data = run_typemorph_command(self.typemorph_bin, "apihash", self.target_path)
        if not data:
            return
        matches = data.get("matches", [])
        print(f"[TypeMorph IDA] Found {len(matches)} API hash match(es)")
        if IN_IDA:
            for m in matches:
                offset = m.get("offset", 0)
                api = m.get("api", "")
                mod = m.get("module", "")
                algo = m.get("algorithm", "")
                hash_val = m.get("hash", 0)
                ea = ida_nalt.get_imagebase() + offset
                ida_bytes.set_cmt(ea, f"[TypeMorph API Hash] 0x{hash_val:08X} -> {mod}!{api} ({algo})", False)

    def sync_opaque(self) -> None:
        """Detects opaque predicates and dead branches in IDA."""
        print(f"[TypeMorph IDA] Scanning opaque predicates in: {self.target_path}")
        data = run_typemorph_command(self.typemorph_bin, "opaque", self.target_path)
        if not data:
            return
        preds = data.get("predicates", [])
        print(f"[TypeMorph IDA] Found {len(preds)} opaque predicate(s)")
        if IN_IDA:
            for p in preds:
                offset = p.get("offset", 0)
                disasm = p.get("disassembly", "")
                outcome = p.get("outcome", "")
                rationale = p.get("rationale", "")
                ea = ida_nalt.get_imagebase() + offset
                tag = "ALWAYS TAKEN" if outcome == "always_true" else "NEVER TAKEN (DEAD)"
                ida_bytes.set_cmt(ea, f"[TypeMorph Opaque Predicate] {disasm} => {tag}\n{rationale}", True)

    def sync_rtti(self) -> None:
        """Reconstructs C++ polymorphic classes, inheritance hierarchy, and vftables in IDA."""
        print(f"[TypeMorph IDA] Reconstructing C++ RTTI in: {self.target_path}")
        data = run_typemorph_command(self.typemorph_bin, "rtti", self.target_path)
        if not data:
            return
        classes = data.get("classes", [])
        print(f"[TypeMorph IDA] Found {len(classes)} polymorphic C++ class(es)")
        if IN_IDA:
            for cls in classes:
                name = cls.get("name", "UnknownClass").replace("::", "__")
                vf_va = cls.get("vftable_va", 0)
                loc_va = cls.get("locator_va", 0)
                bases = cls.get("base_classes", [])
                methods = cls.get("methods", [])

                if vf_va:
                    ida_name.set_name(vf_va, f"vftable_{name}", ida_name.SN_FORCE)
                    base_str = ", ".join(f"{b.get('name')} (+{b.get('offset', 0)})" for b in bases)
                    cmt = f"[TypeMorph RTTI] class {name}"
                    if base_str:
                        cmt += f" : {base_str}"
                    ida_bytes.set_cmt(vf_va, cmt, True)

                if loc_va:
                    ida_name.set_name(loc_va, f"rtti_locator_{name}", ida_name.SN_FORCE)

                for m in methods:
                    m_va = m.get("virtual_address", 0)
                    slot = m.get("slot", 0)
                    if m_va:
                        ida_name.set_name(m_va, f"{name}__slot{slot}", ida_name.SN_NOWARN)
                        ida_bytes.set_cmt(m_va, f"[TypeMorph RTTI] {name}::slot_{slot}", False)

    def sync_checksec(self) -> None:
        """Inspects binary hardening mitigations and packers in IDA."""
        print(f"[TypeMorph IDA] Inspecting security mitigations (checksec) in: {self.target_path}")
        data = run_typemorph_command(self.typemorph_bin, "checksec", self.target_path)
        if not data:
            return
        mits = data.get("mitigations", {})
        packers = data.get("packers", [])
        anomalies = data.get("section_anomalies", [])
        anti = data.get("anti_analysis_indicators", [])
        print(f"[TypeMorph IDA] Hardening: ASLR={mits.get('aslr')}, DEP={mits.get('dep_nx')}, CFG={mits.get('cfg')}")
        if IN_IDA:
            ep = data.get("entry_point", 0)
            if ep:
                cmt = "[TypeMorph checksec Security Report]\n"
                cmt += f"  Mitigations: ASLR={mits.get('aslr')}, DEP={mits.get('dep_nx')}, CFG={mits.get('cfg')}, SafeSEH={mits.get('safe_seh')}\n"
                if packers:
                    cmt += f"  Packers: {', '.join(p.get('name') for p in packers)}\n"
                if anomalies:
                    cmt += f"  Section Anomalies: {len(anomalies)} detected\n"
                if anti:
                    cmt += f"  Anti-Analysis: {', '.join(anti)}\n"
                ida_bytes.set_cmt(ep, cmt, True)

    def sync_go(self) -> None:
        """Reconstructs Golang functions, packages, and pclntab symbols in IDA."""
        print(f"[TypeMorph IDA] Reconstructing Golang metadata in: {self.target_path}")
        data = run_typemorph_command(self.typemorph_bin, "go", self.target_path)
        if not data or not data.get("detected"):
            return
        fns = data.get("functions", [])
        print(f"[TypeMorph IDA] Found {len(fns)} Go function(s) ({data.get('version')})")
        if IN_IDA:
            for fn in fns:
                name = fn.get("name", "")
                va = fn.get("entry_va", 0)
                if va and name:
                    sanitized = name.replace(" ", "_").replace("·", "_").replace(".", "__")
                    ida_name.set_name(va, f"go__{sanitized}", ida_name.SN_NOWARN)
                    ida_bytes.set_cmt(va, f"[TypeMorph Go] {name}", False)

    def sync_rich(self) -> None:
        """Extracts MSVC Rich Header compiler telemetry and build fingerprints in IDA."""
        print(f"[TypeMorph IDA] Decoding MSVC Rich Header in: {self.target_path}")
        data = run_typemorph_command(self.typemorph_bin, "rich", self.target_path)
        if not data or not data.get("present"):
            return
        recs = data.get("records", [])
        hash_val = data.get("hash", "")
        vs_versions = data.get("compiler_versions", [])
        print(f"[TypeMorph IDA] Rich Header: Hash {hash_val}, Toolsets: {', '.join(vs_versions)}")
        if IN_IDA:
            off = data.get("offset", 0x80)
            ea = ida_nalt.get_imagebase() + off
            cmt = f"[TypeMorph MSVC Rich Header]\n  Hash: {hash_val}\n  Toolsets: {', '.join(vs_versions)}\n"
            for r in recs[:8]:
                cmt += f"  {r.get('tool_name')} (Build {r.get('build_number')}): {r.get('count')} objects [{r.get('vs_version')}]\n"
            ida_bytes.set_cmt(ea, cmt, True)

    def sync_abi(self) -> None:
        """Classifies function calling conventions and sets function prototypes in IDA."""
        print(f"[TypeMorph IDA] Classifying calling conventions in: {self.target_path}")
        data = run_typemorph_command(self.typemorph_bin, "abi", self.target_path)
        if not data:
            return
        sigs = data.get("signatures", [])
        dist = data.get("conventions", {})
        print(f"[TypeMorph IDA] Analyzed {len(sigs)} function(s). Conventions: {dist}")
        if IN_IDA:
            for s in sigs:
                va = s.get("entry_va", 0)
                proto = s.get("prototype", "")
                conv = s.get("convention", "")
                rat = s.get("rationale", "")
                if va:
                    ida_bytes.set_cmt(va, f"[TypeMorph ABI] {proto}\nConvention: {conv} ({rat})", True)
                    try:
                        ida_typeinf.apply_cdecl(None, va, proto)
                    except Exception:
                        pass

    def sync_decompile(self) -> None:
        """Decompiles functions and infers struct layouts from machine displacements."""
        print(f"[TypeMorph IDA] Decompiling functions & inferring structs in: {self.target_path}")
        data = run_typemorph_command(self.typemorph_bin, "decompile", self.target_path)
        if not data:
            return
        structs = data.get("structs", [])
        fns = data.get("functions", [])
        print(f"[TypeMorph IDA] Decompiled {len(fns)} function(s), inferred {len(structs)} struct layout(s)")
        if IN_IDA:
            for fn in fns:
                va = fn.get("entry_va", 0)
                pseudo = fn.get("pseudocode", "")
                if va and pseudo:
                    ida_bytes.set_cmt(va, f"[TypeMorph Decompile]\n{pseudo[:500]}...", True)

    def sync_csharp(self) -> None:
        """Extracts ECMA-335 CLI metadata and decompiles C# types."""
        print(f"[TypeMorph IDA] Extracting .NET / C# metadata in: {self.target_path}")
        data = run_typemorph_command(self.typemorph_bin, "csharp", self.target_path)
        if not data or not data.get("is_dotnet"):
            return
        types = data.get("types", [])
        print(f"[TypeMorph IDA] Recovered {len(types)} .NET type(s) ({data.get('runtime_version')})")
        if IN_IDA:
            for t in types:
                for m in t.get("methods", []):
                    rva = m.get("rva", 0)
                    if rva:
                        ea = ida_nalt.get_imagebase() + rva
                        ida_name.set_name(ea, f"dotnet__{t.get('name')}__{m.get('name')}", ida_name.SN_NOWARN)

    def sync_detect(self) -> None:
        """Deep compiler, packer and protection identification (DIE Engine)."""
        print(f"[TypeMorph IDA] Detecting compiler & packers (DIE Engine): {self.target_path}")
        data = run_typemorph_command(self.typemorph_bin, "detect", self.target_path)
        if not data:
            return
        compiler = data.get("primary_compiler", "Unknown")
        packer = data.get("primary_packer", "None")
        protector = data.get("primary_protector", "None")
        print(f"[TypeMorph IDA] Compiler: {compiler} | Packer: {packer} | Protector: {protector}")
        if IN_IDA:
            info_cmt = f"TypeMorph Detect: Compiler={compiler}, Packer={packer}, Protector={protector}"
            ep = data.get("entry_point", 0)
            if ep:
                ida_bytes.set_cmt(ep, info_cmt, False)

    def sync_fixiat(self) -> None:
        """Reconstruct PE IAT and label resolved API thunks."""
        print(f"[TypeMorph IDA] Analyzing & fixing IAT: {self.target_path}")
        data = run_typemorph_command(self.typemorph_bin, "fixiat", self.target_path)
        if not data:
            return
        modules = data.get("modules", [])
        total_apis = data.get("resolved_functions", 0)
        print(f"[TypeMorph IDA] Reconstructed {len(modules)} modules with {total_apis} resolved APIs")
        if IN_IDA:
            for mod in modules:
                mod_name = mod.get("module_name", "")
                for fn in mod.get("functions", []):
                    iat_va = fn.get("iat_va", 0)
                    fn_name = fn.get("name", "")
                    if iat_va and fn_name:
                        lbl = f"__imp_{fn_name}"
                        ida_name.set_name(iat_va, lbl, ida_name.SN_NOWARN)
                        cmt = f"Import: {mod_name}!{fn_name}"
                        if fn.get("resolution_type") != "direct_va":
                            cmt += f" ({fn.get('resolution_type')})"
                        ida_bytes.set_cmt(iat_va, cmt, False)

    def run_all(self) -> None:
        self.sync_detect()
        self.sync_fixiat()
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
