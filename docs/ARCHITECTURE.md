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
- Automatically renames subroutines from demangled Rust symbols, populates structure definitions for Rust trait vtables, adds comments for string slice pairs and stack strings, labels VM dispatcher handlers, marks cryptographic constants, maps CFF state dispatchers, and annotates resolved API hashes and opaque predicates.

## CLI / JSON-RPC

`cli::Application` parses Git-style subcommands (`infer`, `inspect`, `rust`, `hybrid`, `unxor`, `strings`, `devirt`, `cff`, `apihash`, `opaque`, `entropy`, `sig`, `crypto`, `diff`, `serve`), builds engine options, and
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
