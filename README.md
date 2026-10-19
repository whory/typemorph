# TypeMorph

**Binary structure inference and Rust semantic recovery, in modern C++20.**

TypeMorph turns opaque binary blobs into reviewable specifications. Give it one
or more samples of an unknown format and it produces a Kaitai Struct (`.ksy`),
an ImHex pattern (`.hexpat`), or a C++20 deserialization header. Point it at a
stripped Rust executable and it reconstructs fat pointers (`&str`, slices),
trait-object vtables, niche-encoded enums, and demangled symbols. The same core
powers an interactive terminal dashboard and a JSON-RPC daemon for
Ghidra/IDA/editor integration.

```
                      ┌──────────────────────────────┐
  samples ──────────► │  Multi-sample diff inference  │ ──► .ksy / .hexpat / .hpp
                      │  invariants · size deltas     │
                      │  timestamps · alignment       │
                      └──────────────────────────────┘
  Rust PE/ELF/Mach-O ► DeRust engine ──► strings · vtables · enums · symbols
                      └──────────────────────────────┘
                                  │
                    ┌─────────────┴─────────────┐
                    ▼                           ▼
             FTXUI-style TUI             JSON-RPC daemon
        hex + AST + live emitter       (Ghidra / IDA / VSCode)
```

## Highlights

- **Diff-Infer** — inferring a format from one file is guessing; inferring from
  several is arithmetic. TypeMorph correlates changing integer fields with file
  size deltas (`Δsize / Δcount` = element stride), finds invariant magic with
  bitwise masking, tags monotonic sequences as timestamps/IDs, and infers **bitfield flag sets**
  via power-of-two and bit-gap analysis.
- **Deep Compiler, Packer & Protection Identifier (`typemorph detect` / DIE Engine)** — deep identification of compilers (MSVC, GCC/MinGW, Clang, Delphi, FreePascal, Rust, Go), packers & protectors (UPX, ASPack, PECompact, VMProtect, Themida/WinLicense, Enigma, Armadillo, ConfuserEx, SmartAssembly, .NET Reactor, Spoon Studio), installers (Inno Setup, NSIS, PyInstaller), and runtime engines (AutoIt, .NET CLR) via entry point pattern matching and header metadata.
- **C / C++ Struct Memory Layout Inferrer & Structured Decompiler (`typemorph decompile`)** — infers struct fields, offsets, alignments, and padding from memory displacement operands (`[reg + disp]`, 8-bit/32-bit displacements, float/double SSE accesses) and decompiles basic blocks into structured C pseudocode (`if`, conditional branches, calls, arithmetic, returns).
- **C# (.NET / CLR) Metadata Engine & Code Decompiler (`typemorph csharp`)** — pure C++20 PE COM descriptor and ECMA-335 CLI metadata parser. Decodes `BSJB` metadata root, `#Strings`, `#Blob`, and `#~` tables (`TypeDef`, `MethodDef`, `Field`, `TypeRef`), reconstructing formatted and compilable C# source code.
- **Rust High-Level Source Code Reconstructor (`typemorph decompile --lang=rust`)** — synthesizes recovered trait-object vtables, niche-encoded enums, tagged unions, and demangled symbols into idiomatic, compilable Rust module source files (`.rs`).
- **Golang Runtime Type Descriptor & Interface Table Reconstructor (`typemorph go --source`)** — reconstructs Go structs, field tags, interfaces, method sets, and interface implementation tables (`itabs`), emitting complete Go source code (`package main`, `type ... struct`, `type ... interface`).
- **C++ RTTI & Class Hierarchy Reconstructor** — reconstructs polymorphic C++ class names, CompleteObjectLocator tables, virtual method slot lists, and inheritance hierarchies from MSVC and Itanium ABI binaries, with direct export to compilable C++ headers (`typemorph rtti --format=cpp`).
- **Binary Hardening & Security Inspector (`checksec`)** — audits binary protections (ASLR, HighEntropyVA, DEP/NX, Control Flow Guard, CET Shadow Stack, SafeSEH, Authenticode signatures, PIE, RELRO, Stack Canary), detects common packers (UPX, ASPack, PECompact, VMProtect, Themida, Enigma, PyInstaller), flags section anomalies ($W \oplus X$ violations, high expansion ratios), overlay data, and anti-analysis evasion tactics (`typemorph checksec`).
- **Golang pclntab & Metadata Reconstructor** — extracts stripped Go functions, entry VAs, frame sizes, and package hierarchies from Go 1.2 through Go 1.23+ runtime formats (`typemorph go`).
- **MSVC Rich Header & Compiler Fingerprinting** — decodes XOR-encrypted `@comp.id` records, resolves Visual C++ compiler/linker tool IDs and build numbers, infers Visual Studio release version, and calculates RichPE telemetry hashes (`typemorph rich`).
- **Calling Convention & Function Signature Classifier** — detects function prologues, frame sizes, register arguments, and stack purges to classify calling conventions (`__cdecl`, `__stdcall`, `__fastcall`, `__thiscall`, `__win64`, `__sysv`), argument counts, and emits complete C/C++ prototypes (`typemorph abi`).
- **DeRust** — validates Rust fat pointers `(ptr, len)` against `.rodata`,
  reconstructs `[drop_in_place, size, align, methods...]` trait vtables, and
  demangles both legacy `_ZN...E` and modern `_Rv0` symbols.
- **Deobfuscation Engine** — includes:
  * **API Hash Resolver**: resolves obfuscated Windows & POSIX API calls against precomputed hash tables (ROR13, DJB2, SDBM, FNV-1a, CRC32) or scans binaries for hidden import hashes (`typemorph apihash`).
  * **Opaque Predicate & Dead Code Detector**: detects invariant conditions (self-xor, self-cmp, CLC/STC flags) and marks dead branches (`typemorph opaque`).
  * **Control Flow Flattening (CFF) Reconstructor**: detects dispatcher compare ladders, maps state variable IDs to basic blocks, tracks state transitions, and emits unflattened CFG graphs in Graphviz DOT, Mermaid, and JSON (`typemorph cff`).
  * **UnXORer**: automated single-byte, multi-byte, and rolling XOR cracking using IC and null-run heuristics.
  * **String Revealer**: extracts ASCII, UTF-16, x86/x64 stack strings (`mov [rbp-X], byte/imm32`), XOR payloads, Base64 strings, and ROT13 obfuscated commands.
  * **Devirtualizer**: detects VM bytecode interpreters, maps jump tables, and extracts opcode -> handler routines.
- **Four complete emitters** — Kaitai Struct 0.10 YAML (`.ksy`), ImHex pattern language (`.hexpat`),
  compilable C++20 deserialization headers (`.hpp`), and idiomatic Rust structs (`.rs`), generated from the same recovered AST, with native bitfield support (`type: b1` in Kaitai, bitfield structs in C++, repr transparent + const masks in Rust, `bitfield` in ImHex).
- **Crypto & Hash Constant Scanner** — recognizes AES forward/inverse S-boxes, Rijndael Rcon, SHA-256 / SHA-1 initial states and round constants, MD5 constants, ChaCha20/Salsa20 sigma/tau strings, CRC32 tables, TEA deltas, Blowfish P-array, DES IP tables, SM4 S-box/FK constants, Curve25519 field prime, and Keccak-f[1600] constants.
- **Structural Binary Diffing** — byte-level delta mapping, similarity scoring, and section/symbol comparison for executables.
- **Full RE Suite Integrations** — out-of-the-box scripts and plugins in `integrations/`:
  * **Ghidra**: `integrations/ghidra/typemorph_sync.py` (Python 3 / Ghidrathon / PyGhidra)
  * **IDA Pro**: `integrations/ida/typemorph_ida.py` (IDAPython for IDA 7.x/8.x/9.x)
  * **Binary Ninja**: `integrations/binaryninja/typemorph_binja.py` (Binja API v3/v4 plugin)
  * **Radare2 / Cutter**: `integrations/r2/typemorph_r2.py` (r2pipe semantic sync script)
- **Two UX modes** — a UNIX-style CLI (`inspect`, `infer`, `rust`, `hybrid`, `unxor`, `strings`, `devirt`, `cff`, `apihash`, `opaque`, `rtti`, `checksec`, `entropy`, `sig`, `crypto`, `diff`,
  `serve`) and an ANSI terminal dashboard with hex/entropy heat map, collapsible AST, and live preview (`e` Kaitai, `K` C++, `R` Rust, `s`/`w` save).
- **Zero required third-party dependencies** — the analysis core, executable
  parser, JSON-RPC, TUI, and test harness are self-contained, so air-gapped RE
  labs and CI can build with nothing but a C++20 compiler. CMake also discovers
  FTXUI/LIEF/nlohmann-json when installed for downstream integrations; the
  portable built-in implementations are the reference path used by this build.

## Quick start

### Windows (Visual Studio 2026 / MSVC)


```bat
cmake --preset windows-vs2026
cmake --build --preset windows-vs2026-debug
ctest --preset windows-vs2026-debug
build\vs2026\Debug\typemorph.exe --help
```

If CMake is not on PATH, use the copy shipped with Visual Studio:

```bat
"C:\Program Files\Microsoft Visual Studio\18\Community\Common7\IDE\CommonExtensions\Microsoft\CMake\CMake\bin\cmake.exe" --preset windows-vs2026
```

### Linux / macOS


```bash
cmake -S . -B build -G Ninja -DCMAKE_BUILD_TYPE=Release
cmake --build build
ctest --test-dir build --output-on-failure
```

### Optional dependencies

`TYPEMORPH_FETCH_DEPS=ON` acquires FTXUI v5, LIEF 0.15, nlohmann/json, CLI11,
yaml-cpp, and Catch2 through `FetchContent`; discovered system packages are used
otherwise. The shipped build deliberately works without them:

| Library | Role | Offline fallback |
|---|---|---|
| LIEF | ELF/PE/Mach-O parsing | built-in bounds-checked parsers |
| FTXUI | rich TUI | built-in ANSI terminal renderer |
| CLI11 | argument parsing | built-in command parser |
| yaml-cpp | YAML emission | built-in `KaitaiEmitter` |
| nlohmann_json | JSON | built-in `cli::JsonValue` |
| Catch2 | tests | built-in `tmtest` harness |

## CLI

```bash
# Interactive inspector: hex/entropy + AST + live Kaitai/C++/Rust preview
typemorph inspect sample_v1.bin

# Headless render (CI-friendly, no terminal needed)
typemorph inspect sample_v1.bin --render-once --width=140 --height=40

# Multi-sample differential inference (generates Kaitai, ImHex, C++, or Rust)
typemorph infer sample_v1.bin sample_v2.bin sample_v3.bin \
    --format=rust --out=types.rs \
    --min-array-elements=3 --confidence-threshold=0.85

# Rust semantic recovery
typemorph rust target.elf \
    --demangle \
    --extract-strings=rust_strings.txt \
    --dump-vtables=vtables.json \
    --emit-types=reconstructed_types.hpp

# Infer a format embedded in an executable section
typemorph hybrid rust_sample.exe --section=.rodata --format=imhex --out=rodata.hexpat

# XOR key discovery and deobfuscation
typemorph unxor encrypted.bin --out=decrypted.bin
typemorph unxor encrypted.bin --key=5A --out=decrypted.bin

# Reveal printable, UTF-16, and stack strings
typemorph strings sample.bin --min-len=4

# Devirtualize bytecode interpreter & extract handler jump tables
typemorph devirt target.exe

# Control flow unflattening (CFF) & CFG reconstruction
typemorph cff target.exe --format=dot --out=unflattened.dot
typemorph cff target.exe --function=0x140001000 --format=mermaid

# Resolve single API hash or scan binary for hidden import hashes
typemorph apihash 0x0726774C
typemorph apihash malware.bin

# Detect invariant opaque predicates and dead branches
typemorph opaque obfuscated.exe

# Reconstruct C++ RTTI class hierarchy, vftables, and emit C++ header
typemorph rtti target.exe
typemorph rtti target.exe --format=cpp

# Deep compiler, packer, and protection detection (DIE Engine)
typemorph detect target.exe
typemorph detect target.exe --json

# Inspect binary hardening mitigations (ASLR, DEP, CFG, CET, SafeSEH, RELRO), packers & anomalies
typemorph checksec target.exe

# Reconstruct Golang pclntab, packages, and functions from stripped Go binary
typemorph go target.elf

# Decode MSVC Rich Header, build numbers, and compiler fingerprints
typemorph rich target.exe

# Classify calling conventions, argument registers, and generate C prototypes
typemorph abi target.exe
typemorph abi target.exe --function=0x140001000

# Terminal ASCII Shannon entropy visualizer & packed section detector
typemorph entropy sample.bin --block-size=64

# Automated YARA signature rule generator
typemorph sig sample.bin --name=malware_family --out=rule.yar

# Cryptographic and hashing constant scanner (AES, SHA, MD5, ChaCha, CRC)
typemorph crypto target.exe

# Structural and binary diff comparator
typemorph diff sample_v1.bin sample_v2.bin

# JSON-RPC 2.0 daemon (one request per line, for Ghidra/IDA/editor plugins)
typemorph serve --stdio
```

Every subcommand supports `--json` for machine-readable output.

### RE Suite Integrations (Ghidra, IDA Pro, Binary Ninja, Radare2)

Run the sync scripts directly in your disassembler / decompiler environment:

```bash
# Ghidra sync
python integrations/ghidra/typemorph_sync.py path/to/binary

# IDA Pro sync
python integrations/ida/typemorph_ida.py path/to/binary

# Binary Ninja sync
python integrations/binaryninja/typemorph_binja.py path/to/binary

# Radare2 / Cutter sync
python integrations/r2/typemorph_r2.py path/to/binary
```

### JSON-RPC example

```json
{"jsonrpc":"2.0","id":1,"method":"typemorph.infer","params":{
  "files":["sample_v1.bin","sample_v2.bin","sample_v3.bin"],
  "format":"rust","confidence_threshold":0.85
}}
```

Implemented methods: `ping`, `version`, `infer`, `hybrid`, `rust`, `inspect`, `unxor`, `strings`, `devirt`, `cff`, `bitfield`, `apihash`, `opaque`, `rtti`, `checksec`, `go`, `rich`, `abi`, `entropy`, `sig`, `crypto`, `diff`
(also namespaced as `typemorph.*`). Notifications (requests without `id`) are
executed without a reply, per JSON-RPC 2.0.

## Recovered fixture format

The committed samples under `tests/fixtures/` are a deterministic synthetic
format used by the end-to-end tests:

| Offset | Size | Field |
|---:|---:|---|
| 0 | 4 | magic `TMSX` (invariant) |
| 4 | 2 | version `u16` |
| 6 | 2 | flags `u16` |
| 8 | 8 | timestamp `u64`, strictly increasing |
| 16 | 4 | record count `u32` |
| 20 | `12*n` | records: `{u32 id, u16 kind, u16 tag=0xABCD, u32 value}` |
| `20+12*n` | var | string table: `u32 count`, then `{u16 len, UTF-8}` |

File sizes differ by exactly `Δcount * 12 + Δstring_table`, which is the signal
the diff engine uses to find the array length and element stride. Regenerate or
verify the fixture bytes with:

```bash
python tests/fixtures/generate_fixtures.py
python tests/fixtures/generate_fixtures.py --verify
```

`rust_sample.elf` is a valid ELF64 image with `.text`, `.rodata`, `.data`,
fat-pointer pairs, and a Rust-style vtable for DeRust integration tests.

## How the inference works

1. **Normalize** all samples and establish a common prefix. Sizes that differ
   are evidence, not noise.
2. **Invariant mask**: bytes equal across every sample become constants or
   padding; runs of high-entropy invariant bytes become magic candidates.
3. **Size correlation**: for each candidate integer field, regress per-sample
   value deltas against file-size deltas. If `Δsize % Δfield == 0` and the
   implied stride is a plausible power-of-two-aligned element size, the field
   becomes an `ArrayLength`.
4. **Sequence detection**: monotonic fields ordered by sample order are tagged
   as timestamps/sequence IDs with confidence based on strictness and magnitude.
5. **Alignment and entropy priors** resolve overlapping primitive candidates;
   deterministic greedy merging produces non-overlapping fields.
6. **AST construction**: higher-confidence fields win; gaps become `Unknown`
   or `Padding`; array regions can be expanded into nested record structs.
7. **Emit**: Kaitai/ImHex/C++ generators walk the AST, sanitize identifiers,
   link count expressions, and honor endianness and file size.

## DeRust pipeline

- **Executable parsing** — native ELF32/64, PE32/32+, and Mach-O 32/64
  parsers produce section/VA/symbol maps. BSS and zero-fill ranges are rejected
  for byte access.
- **Fat-pointer scan** — aligned `(uintptr_t ptr, uintptr_t len)` pairs whose
  pointer lands in a read-only section are validated as UTF-8 with the claimed
  length; overlapping/duplicate pairs are collapsed.
- **VTable scan** — candidate arrays must start with an executable
  `drop_in_place`, followed by a small object size and a power-of-two alignment,
  then a run of executable method pointers. Confidence rises with symbol and
  preamble corroboration.
- **Niche/enum reconstruction** — repeated small discriminant tags at fixed
  stride and pointer-sized niche words (null pointers, non-zero integers,
  alignment holes) are reported with rationale and confidence.
- **Demangling** — legacy length-prefixed paths with Rust escape sequences and
  v0 paths with backreferences/generic arguments.

## Architecture

```text
include/typemorph/
├── core/         BinaryView, Result, TypeAST, entropy, executable image model
├── infer/        alignment oracle, pointer graph, array detector, diff engine
├── derust/       demangler, slice scanner, vtable analyzer, enum reconstructor
├── deobf/        unxorer (single/multi/rolling), string revealer, devirtualizer
├── emitter/      Kaitai, ImHex and C++20 generators
├── tui/          hex, AST, preview components and dashboard
└── cli/          JSON value, CLI application and JSON-RPC dispatcher
integrations/
├── ghidra/       Ghidra Python sync script (symbols, vtables, strings, VM handlers)
└── ida/          IDAPython sync script (IDA 7.x/8.x/9.x)
src/              implementations grouped by the same modules
tests/            self-contained harness, unit/integration tests, fixtures
```

## Testing

The default build uses a small self-contained test harness (no Catch2 needed):

```bash
cmake --build build --target typemorph_tests
build\vs2026\Debug\typemorph_tests.exe            # Windows
build/typemorph_tests                              # Unix
build\vs2026\Debug\typemorph_tests.exe --filter=entropy   # filter by substring
```

Covered areas: entropy math, bounds-checked views, AST sizing, executable
parsing, JSON round-trips, differential inference, array stride detection,
emitters, Rust demangling, fat pointers, vtables, and TUI state/rendering.

## Design constraints

- **Hostile inputs are normal inputs.** Every read is bounds-checked; lengths
  are validated before allocation; malformed ELF/PE/Mach-O images return
  `Result` errors instead of crashing.
- **Zero-copy at the core.** File-backed `BinaryView` is an mmap'd read-only
  view; copies share storage. Parsers read in place and only allocate metadata.
- **Deterministic output.** Emitters and inference sort/normalize their work so
  the same inputs produce byte-identical specifications.
- **RAII everywhere.** Mappings, handles, file descriptors, and terminal state
  are owned by scoped objects; no raw owning pointers.

## Current limitations

- Rust v0 demangling covers the common path/generic/backref grammar, not every
  obscure vendor extension.
- Enum reconstruction is heuristic: it surfaces candidates and confidence, not
  a proof of the original Rust type.
- Inference assumes samples share a format and mostly stable layout; heavily
  compressed or encrypted payloads are reported as opaque high-entropy regions.
- The offline ANSI dashboard is the reference UI; FTXUI integration is optional
  and enabled only when the package is available.

## License

MIT. See [LICENSE](LICENSE).
