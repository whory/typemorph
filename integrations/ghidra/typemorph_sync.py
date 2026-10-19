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

    def sync_rtti(self) -> None:
        """Reconstructs C++ polymorphic classes, inheritance hierarchy, and vftables in Ghidra."""
        print(f"[TypeMorph Ghidra] Reconstructing C++ RTTI in: {self.target_path}")
        data = run_typemorph_command(self.typemorph_bin, "rtti", self.target_path)
        if not data:
            return
        classes = data.get("classes", [])
        print(f"[TypeMorph Ghidra] Found {len(classes)} polymorphic C++ class(es)")
        if IN_GHIDRA:
            for cls in classes:
                name = cls.get("name", "UnknownClass").replace("::", "__")
                vf_va = cls.get("vftable_va", 0)
                loc_va = cls.get("locator_va", 0)
                bases = cls.get("base_classes", [])
                methods = cls.get("methods", [])

                if vf_va:
                    vf_addr = toAddr(vf_va)
                    createLabel(vf_addr, f"vftable_{name}", True, SourceType.USER_DEFINED)
                    base_str = ", ".join(f"{b.get('name')} (+{b.get('offset', 0)})" for b in bases)
                    cmt = f"[TypeMorph RTTI] class {name}"
                    if base_str:
                        cmt += f" : {base_str}"
                    setPlateComment(vf_addr, cmt)

                if loc_va:
                    loc_addr = toAddr(loc_va)
                    createLabel(loc_addr, f"rtti_locator_{name}", True, SourceType.USER_DEFINED)

                for m in methods:
                    m_va = m.get("virtual_address", 0)
                    slot = m.get("slot", 0)
                    if m_va:
                        m_addr = toAddr(m_va)
                        createLabel(m_addr, f"{name}__slot{slot}", False, SourceType.USER_DEFINED)
                        setPreComment(m_addr, f"[TypeMorph RTTI] {name}::slot_{slot}")

    def sync_checksec(self) -> None:
        """Inspects binary hardening mitigations and packers, adding comments in Ghidra."""
        print(f"[TypeMorph Ghidra] Inspecting security mitigations (checksec) in: {self.target_path}")
        data = run_typemorph_command(self.typemorph_bin, "checksec", self.target_path)
        if not data:
            return
        mits = data.get("mitigations", {})
        packers = data.get("packers", [])
        anomalies = data.get("section_anomalies", [])
        anti = data.get("anti_analysis_indicators", [])
        print(f"[TypeMorph Ghidra] Hardening: ASLR={mits.get('aslr')}, DEP={mits.get('dep_nx')}, CFG={mits.get('cfg')}")
        if IN_GHIDRA:
            ep = data.get("entry_point", 0)
            if ep:
                ep_addr = toAddr(ep)
                cmt = "[TypeMorph checksec Security Report]\n"
                cmt += f"  Mitigations: ASLR={mits.get('aslr')}, DEP={mits.get('dep_nx')}, CFG={mits.get('cfg')}, SafeSEH={mits.get('safe_seh')}\n"
                if packers:
                    cmt += f"  Packers: {', '.join(p.get('name') for p in packers)}\n"
                if anomalies:
                    cmt += f"  Section Anomalies: {len(anomalies)} detected\n"
                if anti:
                    cmt += f"  Anti-Analysis: {', '.join(anti)}\n"
                setPlateComment(ep_addr, cmt)

    def sync_go(self) -> None:
        """Reconstructs Golang functions, packages, and pclntab symbols in Ghidra."""
        print(f"[TypeMorph Ghidra] Reconstructing Golang metadata in: {self.target_path}")
        data = run_typemorph_command(self.typemorph_bin, "go", self.target_path)
        if not data or not data.get("detected"):
            return
        fns = data.get("functions", [])
        print(f"[TypeMorph Ghidra] Found {len(fns)} Go function(s) ({data.get('version')})")
        if IN_GHIDRA:
            for fn in fns:
                name = fn.get("name", "")
                va = fn.get("entry_va", 0)
                if va and name:
                    addr = toAddr(va)
                    sanitized = name.replace(" ", "_").replace("·", "_").replace(".", "__")
                    createLabel(addr, f"go__{sanitized}", False, SourceType.USER_DEFINED)
                    setPreComment(addr, f"[TypeMorph Go] {name}")

    def sync_rich(self) -> None:
        """Extracts MSVC Rich Header compiler telemetry and build fingerprints in Ghidra."""
        print(f"[TypeMorph Ghidra] Decoding MSVC Rich Header in: {self.target_path}")
        data = run_typemorph_command(self.typemorph_bin, "rich", self.target_path)
        if not data or not data.get("present"):
            return
        recs = data.get("records", [])
        hash_val = data.get("hash", "")
        vs_versions = data.get("compiler_versions", [])
        print(f"[TypeMorph Ghidra] Rich Header: Hash {hash_val}, Toolsets: {', '.join(vs_versions)}")
        if IN_GHIDRA:
            off = data.get("offset", 0x80)
            addr = toAddr(currentProgram.getImageBase().getOffset() + off)
            cmt = f"[TypeMorph MSVC Rich Header]\n  Hash: {hash_val}\n  Toolsets: {', '.join(vs_versions)}\n"
            for r in recs[:8]:
                cmt += f"  {r.get('tool_name')} (Build {r.get('build_number')}): {r.get('count')} objects [{r.get('vs_version')}]\n"
            setPlateComment(addr, cmt)

    def sync_abi(self) -> None:
        """Classifies function calling conventions and sets function prototypes in Ghidra."""
        print(f"[TypeMorph Ghidra] Classifying calling conventions in: {self.target_path}")
        data = run_typemorph_command(self.typemorph_bin, "abi", self.target_path)
        if not data:
            return
        sigs = data.get("signatures", [])
        dist = data.get("conventions", {})
        print(f"[TypeMorph Ghidra] Analyzed {len(sigs)} function(s). Conventions: {dist}")
        if IN_GHIDRA:
            listing = currentProgram.getListing()
            for s in sigs:
                va = s.get("entry_va", 0)
                proto = s.get("prototype", "")
                conv = s.get("convention", "")
                rat = s.get("rationale", "")
                if va:
                    addr = toAddr(va)
                    fn = listing.getFunctionAt(addr)
                    if fn:
                        setPlateComment(addr, f"[TypeMorph ABI]\nPrototype: {proto}\nConvention: {conv}\nRationale: {rat}")
                        try:
                            if conv in ("__stdcall", "__cdecl", "__fastcall", "__thiscall"):
                                fn.setCallingConvention(conv.replace("__", ""))
                        except Exception:
                            pass
                    else:
                        setPreComment(addr, f"[TypeMorph ABI] {proto} ({conv})")

    def sync_decompile(self) -> None:
        """Decompiles functions and infers struct layouts in Ghidra."""
        print(f"[TypeMorph Ghidra] Decompiling functions & inferring structs in: {self.target_path}")
        data = run_typemorph_command(self.typemorph_bin, "decompile", self.target_path)
        if not data:
            return
        structs = data.get("structs", [])
        fns = data.get("functions", [])
        print(f"[TypeMorph Ghidra] Decompiled {len(fns)} function(s), inferred {len(structs)} struct layout(s)")
        if IN_GHIDRA:
            for fn in fns:
                va = fn.get("entry_va", 0)
                pseudo = fn.get("pseudocode", "")
                if va and pseudo:
                    addr = toAddr(va)
                    setPlateComment(addr, f"[TypeMorph Decompile]\n{pseudo[:500]}...")

    def sync_csharp(self) -> None:
        """Extracts ECMA-335 CLI metadata and decompiles C# types in Ghidra."""
        print(f"[TypeMorph Ghidra] Extracting .NET / C# metadata in: {self.target_path}")
        data = run_typemorph_command(self.typemorph_bin, "csharp", self.target_path)
        if not data or not data.get("is_dotnet"):
            return
        types = data.get("types", [])
        print(f"[TypeMorph Ghidra] Recovered {len(types)} .NET type(s) ({data.get('runtime_version')})")
        if IN_GHIDRA:
            for t in types:
                for m in t.get("methods", []):
                    rva = m.get("rva", 0)
                    if rva:
                        addr = toAddr(currentProgram.getImageBase().getOffset() + rva)
                        createLabel(addr, f"dotnet__{t.get('name')}__{m.get('name')}", True)

    def sync_detect(self) -> None:
        """Deep compiler, packer and protection identification (DIE Engine)."""
        print(f"[TypeMorph Ghidra] Detecting compiler & packers (DIE Engine): {self.target_path}")
        data = run_typemorph_command(self.typemorph_bin, "detect", self.target_path)
        if not data:
            return
        compiler = data.get("primary_compiler", "Unknown")
        packer = data.get("primary_packer", "None")
        protector = data.get("primary_protector", "None")
        print(f"[TypeMorph Ghidra] Compiler: {compiler} | Packer: {packer} | Protector: {protector}")
        if IN_GHIDRA:
            ep = data.get("entry_point", 0)
            if ep:
                addr = toAddr(ep)
                setPlateComment(addr, f"[TypeMorph Detect]\nCompiler: {compiler}\nPacker: {packer}\nProtector: {protector}")

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
