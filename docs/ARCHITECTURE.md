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
5. **Sequence detection** — monotonic values across sample order produce
   timestamp/ID evidence.
6. **Merge** — greedy non-overlapping field selection with confidence threshold;
   gaps become `Unknown`/`Padding`. Nested record structs are inferred by
   scanning the repeated element region.
7. **Emit** — `KaitaiEmitter`, `ImHexEmitter`, `CppEmitter` walk the AST. Count
   links become `repeat-expr`, C++ `std::vector`/`std::span`, and ImHex arrays.

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

1. **UnXORer (`typemorph::deobf::Unxorer`)**:
   - Single-byte XOR brute force: evaluates all 256 keys using English character frequency (Chi-squared metric against natural language priors) and printable byte ratio.
   - Multi-byte repeating XOR: derives candidate key lengths via Index of Coincidence (IC), solves each key column via frequency analysis, and reduces periodic duplicate keys (`reduce_key`).
   - Rolling XOR: decrypts streams where byte `i` is XORed with `(k + i)`.
   - Null-run exploitation: inspects contiguous zero-padding regions in file containers to directly read multi-byte repeating keys.
2. **String Revealer (`typemorph::deobf::StringRevealer`)**:
   - Multi-mode scanning: printable ASCII, UTF-8, and UTF-16LE wide strings.
   - Stack string reconstruction: scans machine code for x86/x64 immediate stack moves (`mov [rbp-disp], imm8/imm32`) and reassembles contiguous string literals.
   - XOR-encoded strings: identifies small localized XOR-encrypted blocks with high printable yields.
3. **Devirtualizer (`typemorph::deobf::Devirtualizer`)**:
   - Jump table scanner: detects dense arrays of valid code pointers within read-only image sections.
   - Function prologue validation: verifies code pointers against known x86/x64 prologs (`push rbp`, `mov rbp, rsp`, `sub rsp`, `endbr64`).
   - VM dispatcher identification: maps opcode indices to routine entry points and traces candidate bytecode streams.

## Ghidra & IDA Pro Integrations

- Located in `integrations/ghidra/typemorph_sync.py` and `integrations/ida/typemorph_ida.py`.
- Connects either standalone or through `typemorph serve --stdio` JSON-RPC.
- Automatically renames subroutines from demangled Rust symbols, populates structure definitions for Rust trait vtables, adds comments for string slice pairs and stack strings, and labels VM dispatcher handlers.

## CLI / JSON-RPC

`cli::Application` parses Git-style subcommands (`infer`, `inspect`, `rust`, `hybrid`, `unxor`, `strings`, `devirt`, `serve`), builds engine options, and
delegates to `KaitaiEmitter`/etc. `serve --stdio` performs line-delimited
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
