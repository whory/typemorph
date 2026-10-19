# TypeMorph Architecture

TypeMorph is split into a headless, zero-copy core and thin frontends. Every
engine depends only on `typemorph::core`; the CLI, TUI, and JSON-RPC layer share
the same inference and DeRust results.

## Layering

```
                    ┌──────────────┐  ┌──────────────┐
                    │  TUI (ANSI)  │  │ JSON-RPC/CLI │
                    └──────┬───────┘  └──────┬───────┘
                           └──────────┬──────┘
                    ┌─────────────────▼─────────────────┐
                    │  infer / derust / emitter engines │
                    └─────────────────┬─────────────────┘
                    ┌─────────────────▼─────────────────┐
                    │ core: BinaryView · TypeAST ·      │
                    │       Result · entropy · image     │
                    └───────────────────────────────────┘
```

- `core::BinaryView` owns a read-only mmap (or an in-memory buffer) through
  shared storage. Copies are cheap; no analysis code owns raw file data.
- `core::Result<T>` is the error channel. No engine throws for malformed input.
- `core::TypeNode` is the interchange AST. All emitters and the TUI consume it;
  nothing downstream re-parses the binary to generate output.
- `core::ExecutableImage` normalizes ELF/PE/Mach-O into sections, symbols, and
  VA↔file-offset translation. DeRust never assumes a particular container.

## Differential inference pipeline

1. **Load** `1..N` samples (`infer::Sample`). One sample is accepted but
   confidence is capped.
2. **Invariant scan** — for each byte offset, check equality across all samples;
   build constant runs and magic candidates. High-entropy invariant runs are
   preferred over zero runs.
3. **Field candidates** — aligned widths 1/2/4/8 at each offset. `AlignmentOracle`
   scores candidates using natural alignment, zero-padding priors, and byte-plane
   entropy.
4. **Size correlation** — `ArrayDetector` regresses count changes against file
   size changes. A stride is accepted only if all deltas divide exactly and the
   implied length fits every sample. The count field becomes an `ArrayNode`
   length with `element_stride`.
4. **Bitfield & Flag Detector (`typemorph::infer::BitfieldDetector`)**:
   - Analyzes integer fields across multi-sample columns for power-of-two values, independent toggle bitmasks, and bit gaps.
   - Converts confirmed bitmask sets into `core::BitfieldNode` with structured `BitfieldMember` offsets and widths.
5. **Sequence detection** — monotonic values across sample order produce
   timestamp/ID evidence.
6. **Merge** — greedy non-overlapping field selection with confidence threshold;
   gaps become `Unknown`/`Padding`. Nested record structs are inferred by
   scanning the repeated element region.
7. **Emit** — `KaitaiEmitter`, `ImHexEmitter`, `CppEmitter`, `RustEmitter` walk the AST. Count
   links become `repeat-expr`, C++ `std::vector`/`std::span`, and ImHex arrays. Bitfields become native `b1`/`bN` fields in Kaitai, bitfield structs in C++, `#[repr(transparent)]` structs with const bitmasks in Rust, and `bitfield` blocks in ImHex.

Confidence is a product of independent evidence; the CLI's
`--confidence-threshold` filters low-evidence fields from emitted output.

## DeRust pipeline

1. Parse the container into `ExecutableImage`.
2. `SliceScanner` walks aligned pointer pairs in data sections, translates each
   pointer VA to a file offset, validates UTF-8 and length, and collapses
   duplicates. Results are `RustString` records.
3. `VTableAnalyzer` finds candidate arrays whose first word is executable,
   followed by small size and power-of-two align values, then executable method
   pointers. Function-start preambles (`endbr64`, `push rbp`, etc.) increase
   confidence; symbols are correlated by address.
4. `EnumReconstructor` scans for repeated small tags at fixed stride and
   pointer-sized niche patterns. It is explicitly heuristic and emits confidence
   plus rationale.
5. `demangle()` handles legacy and v0 Rust symbol grammars.

## Deobfuscation pipeline

1. **API Hash Resolver (`typemorph::deobf::ApiHashResolver`)**:
   - Resolves obfuscated Windows and POSIX API calls against precomputed database of critical syscalls and library functions.
   - Supports ROR13 (Metasploit, Cobalt Strike), DJB2, SDBM, FNV-1a (32-bit), and IEEE 802.3 CRC32 hash algorithms.
   - Scans binary immediate values and read-only data tables to reveal hidden import tables and API resolution stubs (`typemorph apihash`).
2. **Opaque Predicate & Dead Code Detector (`typemorph::deobf::OpaquePredicateDetector`)**:
   - Identifies invariant control-flow constructs: self-register clearing (`xor r, r`, `sub r, r`, `cmp r, r`), static flag setting (`clc`, `stc`), and unconditional conditional branch sequences.
   - Classifies branches into `always_true` and `always_false`, discovering dead code blocks and simplifying control flow analysis (`typemorph opaque`).
3. **Control Flow Flattening (CFF) Reconstructor (`typemorph::deobf::CffReconstructor`)**:
   - Identifies dispatcher compare ladders (`cmp [state], imm32` / `je [target]`).
   - Maps state variable IDs to basic block handlers and resolves dispatcher loops.
   - Follows block executions to discover state update mutations (`mov [state], next_id`) and back-edges.
   - Unflattens obscured control flow graphs and exports to Graphviz DOT, Mermaid diagrams, and JSON AST.
4. **UnXORer (`typemorph::deobf::Unxorer`)**:
   - Single-byte XOR brute force: evaluates all 256 keys using English character frequency (Chi-squared metric against natural language priors) and printable byte ratio.
   - Multi-byte repeating XOR: derives candidate key lengths via Index of Coincidence (IC), solves each key column via frequency analysis, and reduces periodic duplicate keys (`reduce_key`).
   - Rolling XOR: decrypts streams where byte `i` is XORed with `(k + i)`.
   - Null-run exploitation: inspects contiguous zero-padding regions in file containers to directly read multi-byte repeating keys.
5. **String Revealer (`typemorph::deobf::StringRevealer`)**:
   - Multi-mode scanning: printable ASCII, UTF-8, and UTF-16LE wide strings.
   - Stack string reconstruction: scans machine code for x86/x64 immediate stack moves (`mov [rbp-disp], imm8/imm32`) and reassembles contiguous string literals.
   - XOR-encoded strings: identifies small localized XOR-encrypted blocks with high printable yields.
   - Base64 payload decoding: isolates Base64 runs, filters non-payload ASCII false positives, and validates decoded printable payload buffers.
   - ROT13 deobfuscation: scans tokenized buffers, applies Caesar cipher shifts, and matches recovered system commands/keywords.
6. **Devirtualizer (`typemorph::deobf::Devirtualizer`)**:
   - Jump table scanner: detects dense arrays of valid code pointers within read-only image sections.
   - Function prologue validation: verifies code pointers against known x86/x64 prologs (`push rbp`, `mov rbp, rsp`, `sub rsp`, `endbr64`).
   - VM dispatcher identification: maps opcode indices to routine entry points and traces candidate bytecode streams.

7. **Entropy Analysis Engine (`typemorph::core::shannon_entropy`)**:
   - Calculates exact Shannon entropy in bits per byte over sliding windows or uniform blocks.
   - Categorizes regions into `zero`/`sparse` (<1.0), `structured`/`code` (1.0-6.0), `compressed`/`text` (6.0-7.2), and `encrypted`/`packed` (>7.2).
   - Renders ASCII bar visualizations in CLI and density heat maps in TUI.
8. **YARA Signature Generation Engine**:
   - Synthesizes robust detection rules matching invariant format magics, high-confidence recovered strings, and jump table entry points.
   - Outputs ready-to-deploy `.yar` rule files with structural conditions.
9. **Crypto & Hash Constant Detector (`typemorph::crypto::CryptoScanner`)**:
   - Matches cryptographic constants: AES forward/inverse S-boxes, Rijndael Rcon, SHA-256 / SHA-1 states & round constants, MD5 sine tables, ChaCha20/Salsa20 sigma/tau strings, CRC32 tables, TEA deltas, Blowfish P-array, DES initial permutation tables, SM4 S-box/FK constants, Curve25519 field prime modulus, and Keccak-f[1600] constants.
   - Reports file offsets, algorithm family, roles, categories, and endianness.
10. **Structural Binary Diff Engine (`typemorph::diff::BinaryDiffEngine`)**:
   - Aligns and compares two binary files at the byte level with similarity scoring.
   - Cross-analyzes sections and symbols when comparing two ELF, PE, or Mach-O executable images.
11. **C++ RTTI & Class Hierarchy Reconstructor (`typemorph::rtti::RttiAnalyzer`)**:
   - Parses MSVC `RTTICompleteObjectLocator` (32-bit direct VAs, 64-bit RVAs relative to image base), `TypeDescriptor` (`.?AV...@@`), `ClassHierarchyDescriptor`, and `BaseClassArray` (with inheritance offsets `mdisp`).
   - Demangles MSVC type names into idiomatic C++ namespaces (`.?AVDog@Zoo@@` -> `Zoo::Dog`).
   - Reconstructs virtual function tables (`vftable_va`), locator VAs, and slot-indexed method tables.
   - Supports Itanium ABI `_ZTV` / `_ZTI` symbol demangling and method extraction.
   - Emits compilable C++ class definitions with virtual destructors and method signatures via `to_cpp_header()`.
12. **Binary Hardening & Security Inspector (`typemorph::security::SecurityAnalyzer`)**:
   - Hardening mitigation checks: ASLR, HighEntropyVA, DEP/NX, Control Flow Guard, CET Shadow Stack, SafeSEH, Authenticode digital signatures, PIE, RELRO, Stack Canary.
   - Section anomaly detection: $W \oplus X$ violations (writable & executable sections), memory expansion ratios ($\text{virtual\_size} / \text{raw\_size} \ge 3.0$), and unmapped raw executable sections.
   - Packer & protector signatures: UPX, ASPack, PECompact, VMProtect, Themida, Enigma, PyInstaller.
   - Overlay inspection: detects trailing bytes beyond the last physical section, calculates size, offset, and Shannon entropy.
   - Anti-analysis heuristics: PEB `BeingDebugged` checks (`fs:[0x30]`, `gs:[0x60]`), timing checks (`RDTSC`/`RDTSCP`), and TLS callbacks.
13. **Golang pclntab & Metadata Reconstructor (`typemorph::golang::GoAnalyzer`)**:
   - Scans `.gopclntab` and executable sections for Go magic (`0xFFFFFFFB` [Go 1.2-1.15], `0xFFFFFFFA` [Go 1.16-1.17], `0xFFFFFFF0`/`0xFFFFFFF1` [Go 1.18-1.23+]).
   - Reconstructs function names, entry points, frame sizes, and separates user packages from runtime packages (`typemorph go`).
14. **MSVC Rich Header & Compiler Fingerprinting (`typemorph::pe::RichHeaderParser`)**:
   - Decodes XOR-encrypted `@comp.id` telemetry records from the PE DOS stub.
   - Resolves Tool IDs (Utc1900_C, Utc1900_CPP, Linker, Cvtres, Masm) and build numbers to Visual Studio versions (VS 2003 through VS 2026).
   - Computes RichPE telemetry hash and verifies XOR checksum (`typemorph rich`).
15. **Calling Convention & Function Signature Classifier (`typemorph::abi::AbiClassifier`)**:
   - Disassembles function prologues and epilogues across x86 and x64 architectures.
   - Analyzes register read-before-write access and stack purge bytes (`ret N` vs `ret`) to classify calling conventions (`__cdecl`, `__stdcall`, `__fastcall`, `__thiscall`, `__win64`, `__sysv`).
   - Detects stack frame allocations and return kinds (integer, pointer, boolean, float, double), synthesizing complete C/C++ prototypes (`typemorph abi`).
16. **C / C++ Struct Memory Layout Inferrer & Structured Decompiler (`typemorph::decompile::CDecompiler`)**:
   - Disassembles function basic blocks and traces base register memory access operands (`[reg + disp]`, 8-bit/32-bit displacements, float/double SSE accesses).
   - Recovers struct field offsets, sizes, alignments, and padding to emit valid C `typedef struct { ... }`.
   - Synthesizes structured C pseudocode (`if`, conditional jumps, calls, arithmetic, returns) (`typemorph decompile`).
17. **C# (.NET / CLR) Metadata Engine & Code Decompiler (`typemorph::dotnet::DotNetAnalyzer`)**:
   - Locates CLI header (`IMAGE_COR20_HEADER`) via PE COM descriptor directory.
   - Decodes `BSJB` metadata root and stream headers (`#~`, `#Strings`, `#Blob`).
   - Parses ECMA-335 metadata tables (`TypeDef`, `MethodDef`, `Field`, `TypeRef`) with 1-based index mapping.
   - Emits clean, compilable C# source code files with namespaces, classes, interfaces, enums, structs, fields, and method stubs (`typemorph csharp`).
18. **Rust High-Level Source Code Reconstructor (`typemorph::derust::RustSourceReconstructor`)**:
   - Synthesizes recovered trait-object vtables, niche-encoded enums, tagged unions, and demangled symbols.
   - Emits idiomatic, compilable Rust source code files (`.rs`) (`typemorph decompile --lang=rust`).
19. **Golang Runtime Type Descriptor & Interface Table Reconstructor (`typemorph::golang::GoAnalyzer`)**:
   - Recovers Go struct types, field offsets, types, and tags from runtime memory descriptors.
   - Recovers interface tables (`itabs`) mapping interface methods to concrete function pointers.
   - Emits complete, compilable Go source code with interfaces, structs, method sets, and implementations (`typemorph go --source`).
20. **Deep Compiler, Packer & Protection Identifier (`typemorph::detect::DetectorEngine`)**:
   - Implements DIE-style (Detect It Easy) heuristic and signature pattern matching against binary entry point opcodes.
   - Identifies major compilers (MSVC, GCC, Clang, Delphi, FreePascal, Rust, Go), packers (UPX, ASPack, PECompact, Spoon Studio), protectors (VMProtect, Themida, Enigma, Armadillo, ConfuserEx, SmartAssembly, .NET Reactor), and installers (Inno Setup, NSIS, PyInstaller).
   - Correlates PE Rich headers, .NET CLI metadata headers, and section markers to provide a high-confidence forensic verdict (`typemorph detect`).
21. **PE IAT Reconstruction & Import Table Fixer (`typemorph::pe::IatReconstructor`)**:
   - Implements Scylla and VMPImportFixer inspired import reconstruction for memory dumps and packed binaries.
   - Discovers candidate IAT thunk tables across memory sections by scanning for consecutive pointer runs.
   - Traces obfuscated import redirection stubs (`jmp [rel32/abs64]`, `jmp imm`, `push imm; ret`, `mov rax/eax, imm; jmp/push-ret`).
   - Resolves target addresses against internal Windows API database (`KERNEL32`, `ntdll`, `USER32`, `ADVAPI32`, `WS2_32`).
   - Injects a fresh section (`.typem`), builds valid `IMAGE_IMPORT_DESCRIPTOR` arrays, OriginalFirstThunk (INT), FirstThunk (IAT), and hint/name strings, updating PE data directories and headers (`typemorph fixiat`).
22. **ClassInformer C++ RTTI & Polymorphic Hierarchy Explorer (`typemorph classinformer`)**:
   - ClassInformer-style discovery of MSVC and Itanium C++ polymorphic class structures.
   - Parses RTTICompleteObjectLocator, TypeDescriptor, ClassHierarchyDescriptor, and BaseClassArray tables.
   - Emits class hierarchy trees, virtual method table slots, and exportable C++ header structures (`--format=cpp`, `--format=csv`).
23. **Signature Maker Engine (`typemorph sigmake` / `sigmaker`)**:
   - Generates resilient opcode patterns for subroutines and entry points.
   - Automatically masks relocation offsets (call/jmp rel32) and RIP-relative memory displacement operands into `??` wildcards.
   - Formats outputs in IDA Pro pattern format (`55 8B EC ?? ??`), YARA hex rules, C byte arrays (`\x55\x8B\xEC`), and string masks (`xxx??`).
24. **ApplyCalleeType Call Site & Prototype Propagator (`typemorph applycalletype`)**:
   - Analyzes subroutine call sites, matches argument registers and stack footprints, and classifies callee prototypes.
   - Propagates recovered C function signatures, calling conventions, and parameter types into disassemblers.
25. **Subroutine Dumper (`typemorph dumpsubs`)**:
   - Disassembles and classifies all binary subroutines into structured CSV or JSON inventories.
   - Captures entry VAs, sizes, names, calling conventions, stack purge counts, and full C prototypes.



## Emitters

- **Kaitai Struct (`typemorph::emit::KaitaiEmitter`)**: Emits specification YAML adhering to Kaitai Struct 0.10.
- **ImHex (`typemorph::emit::ImHexEmitter`)**: Emits ImHex `.hexpat` pattern definitions.
- **C++20 (`typemorph::emit::CppEmitter`)**: Emits self-contained, zero-dependency C++20 deserialization headers.
- **Rust (`typemorph::emit::RustEmitter`)**: Emits idiomatic `#[repr(C)]` Rust struct definitions and enums with derives.

## RE Suite Integrations

- **Ghidra**: `integrations/ghidra/typemorph_sync.py` (Python 3 / Ghidrathon / PyGhidra)
- **IDA Pro**: `integrations/ida/typemorph_ida.py` (IDAPython for IDA 7.x/8.x/9.x)
- **Binary Ninja**: `integrations/binaryninja/typemorph_binja.py` (Binary Ninja API v3/v4 plugin)
- **Radare2 / Cutter**: `integrations/r2/typemorph_r2.py` (r2pipe semantic sync script)
- Connects either standalone or through `typemorph serve --stdio` JSON-RPC.
- Automatically renames subroutines from demangled Rust symbols, populates structure definitions for Rust trait vtables, adds comments for string slice pairs and stack strings, labels VM dispatcher handlers, marks cryptographic constants, maps CFF state dispatchers, annotates resolved API hashes and opaque predicates, labels C++ RTTI vftables and methods, posts security hardening reports, sets Go function labels, and applies classified calling conventions.

## CLI / JSON-RPC

`cli::Application` parses Git-style subcommands (`infer`, `inspect`, `rust`, `hybrid`, `unxor`, `strings`, `devirt`, `cff`, `apihash`, `opaque`, `rtti`, `checksec`, `go`, `rich`, `abi`, `entropy`, `sig`, `crypto`, `diff`, `serve`), builds engine options, and
delegates to `KaitaiEmitter`/`RustEmitter`/etc. `serve --stdio` performs line-delimited
JSON-RPC 2.0 using the same helpers, so protocol and CLI behavior cannot drift.
JSON is produced by the built-in `JsonValue` writer (or nlohmann/json when
compiled in) with deterministic object ordering.

## TUI

`hex_component`, `ast_component`, and `emitter_component` are pure state models
with deterministic render helpers. `Dashboard` adds the terminal backend
(Windows console VT mode or POSIX termios) and key routing. Rendering only walks
visible rows/lines, so multi-hundred-megabyte files do not allocate per frame.

## Testing strategy

- Unit tests target invariants: entropy values, bounds behavior, AST sizes,
  parser offsets, JSON escapes, demangler grammar.
- Integration tests use committed fixtures: the synthetic `TMSX` samples for
  diff inference and gold-master-ish emitter checks; `rust_sample.elf` for fat
  pointers and vtables.
- The test harness is self-contained and returns a non-zero exit on failure;
  CTest drives it in CI.
