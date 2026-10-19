#include "typemorph/cli/app.hpp"

#include "typemorph/cli/json.hpp"
#include "typemorph/core/binary_view.hpp"
#include "typemorph/core/entropy.hpp"
#include "typemorph/core/executable.hpp"
#include "typemorph/core/result.hpp"
#include "typemorph/crypto/crypto_scanner.hpp"
#include "typemorph/deobf/devirtualizer.hpp"
#include "typemorph/deobf/strings.hpp"
#include "typemorph/deobf/unxorer.hpp"
#include "typemorph/derust/demangle.hpp"
#include "typemorph/derust/enum_reconstruct.hpp"
#include "typemorph/derust/slice_scanner.hpp"
#include "typemorph/derust/vtable_analyzer.hpp"
#include "typemorph/diff/binary_diff.hpp"
#include "typemorph/emitter/cpp_emitter.hpp"
#include "typemorph/emitter/imhex_emitter.hpp"
#include "typemorph/emitter/kaitai_emitter.hpp"
#include "typemorph/emitter/rust_emitter.hpp"
#include "typemorph/infer/diff_engine.hpp"
#include "typemorph/tui/dashboard.hpp"

#include <algorithm>
#include <charconv>
#include <chrono>
#include <cmath>
#include <cstdint>
#include <cstdlib>
#include <filesystem>
#include <fstream>
#include <iomanip>
#include <iostream>
#include <map>
#include <optional>
#include <set>
#include <sstream>
#include <string>
#include <string_view>
#include <vector>

#ifdef _WIN32
#include <io.h>
#else
#include <unistd.h>
#endif

namespace typemorph::cli {
namespace {

using core::BinaryView;
using core::Error;
using core::ErrorCode;
using core::Result;
using core::make_error;

constexpr std::string_view kVersion = TYPEMORPH_VERSION;

std::string version_line() {
    return std::string("TypeMorph ") + std::string(kVersion);
}

bool stdout_is_tty() {
#ifdef _WIN32
    return _isatty(_fileno(stdout)) != 0;
#else
    return ::isatty(STDOUT_FILENO) != 0;
#endif
}

std::string format_error(const Error& error) { return error.to_string(); }

struct Arguments {
    std::vector<std::string> positional;
    std::map<std::string, std::string> values;
    std::set<std::string> flags;

    [[nodiscard]] bool has(std::string_view name) const {
        return flags.contains(std::string(name)) || values.contains(std::string(name));
    }
    [[nodiscard]] std::optional<std::string> get(std::string_view name) const {
        const auto it = values.find(std::string(name));
        if (it == values.end()) return std::nullopt;
        return it->second;
    }
    [[nodiscard]] std::string get_or(std::string_view name, std::string fallback) const {
        const auto it = values.find(std::string(name));
        return it == values.end() ? std::move(fallback) : it->second;
    }
};

Result<Arguments> parse_arguments(std::span<const std::string_view> args,
                                  std::initializer_list<std::string_view> value_options,
                                  std::initializer_list<std::string_view> switch_options,
                                  std::size_t min_positional, std::size_t max_positional) {
    std::set<std::string> valued;
    for (const auto option : value_options) valued.emplace(option);
    std::set<std::string> switches = {"help", "json"};
    for (const auto option : switch_options) switches.emplace(option);

    Arguments parsed;
    bool positional_only = false;
    for (std::size_t index = 0; index < args.size(); ++index) {
        std::string_view argument = args[index];
        if (!positional_only && argument == "--") {
            positional_only = true;
            continue;
        }
        if (!positional_only && argument.size() > 2 && argument.rfind("--", 0) == 0) {
            std::string_view name = argument.substr(2);
            std::optional<std::string_view> inline_value;
            const auto equals = name.find('=');
            if (equals != std::string_view::npos) {
                inline_value = name.substr(equals + 1);
                name = name.substr(0, equals);
            }
            const std::string key(name);
            if (valued.contains(key)) {
                if (inline_value) {
                    parsed.values[key] = std::string(*inline_value);
                } else {
                    if (index + 1 >= args.size()) {
                        return make_error(ErrorCode::invalid_argument,
                                          "option --" + key + " requires a value");
                    }
                    parsed.values[key] = std::string(args[++index]);
                }
            } else if (switches.contains(key)) {
                if (inline_value) {
                    return make_error(ErrorCode::invalid_argument,
                                      "option --" + key + " does not take a value");
                }
                parsed.flags.insert(key);
            } else {
                return make_error(ErrorCode::invalid_argument, "unknown option --" + key);
            }
            continue;
        }
        if (!positional_only && argument == "-h") {
            parsed.flags.insert("help");
            continue;
        }
        if (!positional_only && argument.size() > 1 && argument[0] == '-') {
            return make_error(ErrorCode::invalid_argument,
                              "unknown option " + std::string(argument));
        }
        parsed.positional.emplace_back(argument);
    }

    if (parsed.positional.size() < min_positional) {
        return make_error(ErrorCode::invalid_argument, "missing required argument");
    }
    if (parsed.positional.size() > max_positional) {
        return make_error(ErrorCode::invalid_argument, "too many positional arguments");
    }
    return parsed;
}

Result<std::uint64_t> parse_u64(std::string_view text, std::string_view option) {
    std::uint64_t value = 0;
    const auto* begin = text.data();
    const auto* end = text.data() + text.size();
    const auto result = std::from_chars(begin, end, value);
    if (result.ec != std::errc{} || result.ptr != end) {
        return make_error(ErrorCode::invalid_argument,
                          "invalid integer for --" + std::string(option) + ": " + std::string(text));
    }
    return value;
}

Result<double> parse_double(std::string_view text, std::string_view option) {
    std::string owned(text);
    char* end = nullptr;
    const double value = std::strtod(owned.c_str(), &end);
    if (end == owned.c_str() || *end != '\0' || !std::isfinite(value)) {
        return make_error(ErrorCode::invalid_argument,
                          "invalid number for --" + std::string(option) + ": " + owned);
    }
    return value;
}

core::ByteOrder parse_endian(std::string_view text) {
    return text == "big" || text == "be" ? core::ByteOrder::big : core::ByteOrder::little;
}

enum class OutputFormat { kaitai, imhex, cpp, rust, json };

Result<OutputFormat> parse_format(std::string_view text) {
    if (text == "kaitai" || text == "ksy") return OutputFormat::kaitai;
    if (text == "imhex" || text == "hexpat") return OutputFormat::imhex;
    if (text == "cpp" || text == "hpp" || text == "header") return OutputFormat::cpp;
    if (text == "rust" || text == "rs") return OutputFormat::rust;
    if (text == "json") return OutputFormat::json;
    return make_error(ErrorCode::invalid_argument,
                      "unknown output format: " + std::string(text) +
                          " (expected kaitai, imhex, cpp, rust or json)");
}

std::string format_label(OutputFormat format) {
    switch (format) {
    case OutputFormat::kaitai: return "kaitai";
    case OutputFormat::imhex: return "imhex";
    case OutputFormat::cpp: return "cpp";
    case OutputFormat::rust: return "rust";
    case OutputFormat::json: return "json";
    }
    return "kaitai";
}

Result<void> write_file(const std::filesystem::path& path, std::string_view text) {
    std::ofstream stream(path, std::ios::binary | std::ios::trunc);
    if (!stream) {
        return make_error(ErrorCode::io, "cannot open output file", path.string());
    }
    stream.write(text.data(), static_cast<std::streamsize>(text.size()));
    if (!stream) {
        return make_error(ErrorCode::io, "failed while writing output file", path.string());
    }
    return {};
}

Result<void> write_binary_file(const std::filesystem::path& path, std::span<const std::uint8_t> bytes) {
    std::ofstream stream(path, std::ios::binary | std::ios::trunc);
    if (!stream) {
        return make_error(ErrorCode::io, "cannot open output file", path.string());
    }
    stream.write(reinterpret_cast<const char*>(bytes.data()), static_cast<std::streamsize>(bytes.size()));
    if (!stream) {
        return make_error(ErrorCode::io, "failed while writing output file", path.string());
    }
    return {};
}

Result<std::vector<std::uint8_t>> parse_hex_string(std::string_view hex) {
    if (hex.starts_with("0x") || hex.starts_with("0X")) {
        hex.remove_prefix(2);
    }
    std::string clean;
    for (char c : hex) {
        if (std::isspace(static_cast<unsigned char>(c)) || c == ':' || c == '-') continue;
        clean.push_back(c);
    }
    if (clean.empty() || clean.size() % 2 != 0) {
        return make_error(ErrorCode::invalid_argument, "invalid hex string: " + std::string(hex));
    }
    auto hex_val = [](char c) -> int {
        if (c >= '0' && c <= '9') return c - '0';
        if (c >= 'a' && c <= 'f') return c - 'a' + 10;
        if (c >= 'A' && c <= 'F') return c - 'A' + 10;
        return -1;
    };
    std::vector<std::uint8_t> bytes;
    bytes.reserve(clean.size() / 2);
    for (std::size_t i = 0; i < clean.size(); i += 2) {
        int high = hex_val(clean[i]);
        int low = hex_val(clean[i + 1]);
        if (high < 0 || low < 0) {
            return make_error(ErrorCode::invalid_argument, "invalid hex character in: " + std::string(hex));
        }
        bytes.push_back(static_cast<std::uint8_t>((high << 4) | low));
    }
    return bytes;
}

std::string to_hex_string(std::span<const std::uint8_t> bytes) {
    std::string out;
    out.reserve(bytes.size() * 2);
    static constexpr char kDigits[] = "0123456789abcdef";
    for (std::uint8_t b : bytes) {
        out.push_back(kDigits[(b >> 4) & 0xF]);
        out.push_back(kDigits[b & 0xF]);
    }
    return out;
}

constexpr const char* xor_mode_name(deobf::XorMode mode) noexcept {
    switch (mode) {
    case deobf::XorMode::single_byte: return "single_byte";
    case deobf::XorMode::multi_byte: return "multi_byte";
    case deobf::XorMode::rolling: return "rolling";
    }
    return "unknown";
}

JsonValue xor_candidates_to_json(const std::vector<deobf::XorCandidate>& candidates) {
    JsonValue array = JsonValue::array();
    for (const auto& cand : candidates) {
        JsonValue item = JsonValue::object();
        item["key"] = JsonValue(to_hex_string(cand.key));
        item["mode"] = JsonValue(xor_mode_name(cand.mode));
        item["confidence"] = JsonValue(cand.confidence);
        item["entropy"] = JsonValue(cand.entropy);
        item["printable_ratio"] = JsonValue(cand.printable_ratio);
        item["preview"] = JsonValue(cand.preview);
        item["rationale"] = JsonValue(cand.rationale);
        array.push(std::move(item));
    }
    return array;
}

JsonValue extracted_strings_to_json(const std::vector<deobf::ExtractedString>& strings) {
    JsonValue array = JsonValue::array();
    for (const auto& s : strings) {
        JsonValue item = JsonValue::object();
        item["value"] = JsonValue(s.value);
        item["offset"] = JsonValue(s.offset);
        item["raw_length"] = JsonValue(static_cast<std::uint64_t>(s.raw_length));
        item["category"] = JsonValue(std::string(deobf::to_string(s.category)));
        item["confidence"] = JsonValue(s.confidence);
        if (!s.note.empty()) {
            item["note"] = JsonValue(s.note);
        }
        array.push(std::move(item));
    }
    return array;
}

JsonValue devirt_instances_to_json(const std::vector<deobf::VmInstance>& instances) {
    JsonValue array = JsonValue::array();
    for (const auto& inst : instances) {
        JsonValue item = JsonValue::object();
        item["dispatcher_va"] = JsonValue(inst.dispatcher_va);
        item["table_va"] = JsonValue(inst.table_va);
        item["table_file_offset"] = JsonValue(inst.table_file_offset);
        item["opcode_count"] = JsonValue(static_cast<std::uint64_t>(inst.opcode_count));
        item["confidence"] = JsonValue(inst.confidence);
        item["dispatch_type"] = JsonValue(inst.dispatch_type);
        item["rationale"] = JsonValue(inst.rationale);
        JsonValue handlers = JsonValue::array();
        for (const auto& h : inst.handlers) {
            JsonValue hend = JsonValue::object();
            hend["opcode"] = JsonValue(static_cast<std::uint64_t>(h.opcode));
            hend["handler_va"] = JsonValue(h.handler_va);
            hend["handler_file_offset"] = JsonValue(h.handler_file_offset);
            hend["mnemonic"] = JsonValue(h.mnemonic);
            hend["estimated_size"] = JsonValue(static_cast<std::uint64_t>(h.estimated_size));
            handlers.push(std::move(hend));
        }
        item["handlers"] = std::move(handlers);
        array.push(std::move(item));
    }
    return array;
}


Result<std::vector<infer::Sample>> load_samples(const std::vector<std::string>& paths) {
    std::vector<infer::Sample> samples;
    samples.reserve(paths.size());
    for (const auto& path : paths) {
        auto view = BinaryView::open(path);
        if (!view) return view.error();
        samples.push_back(infer::Sample{std::move(view).value(), path, std::nullopt});
    }
    return samples;
}

emit::EmitOptions make_emit_options(const infer::InferenceResult& result) {
    emit::EmitOptions options;
    options.format_name = result.format_name.empty() ? "recovered" : result.format_name;
    options.root_type_name = "RecoveredFile";
    options.file_size = result.max_size;
    options.endian = result.endian;
    options.emit_comments = true;
    options.emit_instances = true;
    return options;
}

Result<std::string> generate_output(const infer::InferenceResult& result, OutputFormat format) {
    const auto options = make_emit_options(result);
    switch (format) {
    case OutputFormat::kaitai: return emit::KaitaiEmitter{}.generate(*result.root, options);
    case OutputFormat::imhex: return emit::ImHexEmitter{}.generate(*result.root, options);
    case OutputFormat::cpp: return emit::CppEmitter{}.generate(*result.root, options);
    case OutputFormat::rust: return emit::RustEmitter{}.generate(*result.root, options);
    case OutputFormat::json: {
        // Handled by the caller; reaching this branch is an internal contract
        // violation rather than a user error.
        return make_error(ErrorCode::invalid_argument, "JSON output is assembled separately");
    }
    }
    return make_error(ErrorCode::invalid_argument, "unknown output format");
}

JsonValue inference_to_json(const infer::InferenceResult& result) {
    JsonValue root = JsonValue::object();
    root["format"] = JsonValue(result.format_name);
    root["confidence"] = JsonValue(result.confidence);
    root["endian"] = JsonValue(result.endian == core::ByteOrder::big ? "big" : "little");
    root["sample_count"] = JsonValue(static_cast<std::uint64_t>(result.sample_count));
    root["min_size"] = JsonValue(result.min_size);
    root["max_size"] = JsonValue(result.max_size);

    JsonValue fields = JsonValue::array();
    for (const auto& field : result.fields) {
        JsonValue entry = JsonValue::object();
        entry["name"] = JsonValue(field.name);
        entry["offset"] = JsonValue(field.offset);
        entry["width"] = JsonValue(static_cast<std::uint64_t>(field.width));
        entry["type"] = JsonValue(std::string(core::to_string(field.kind)));
        entry["confidence"] = JsonValue(field.confidence);
        entry["invariant"] = JsonValue(field.invariant);
        if (field.array_element_size) {
            entry["array_element_size"] = JsonValue(*field.array_element_size);
        }
        if (field.count_field_offset) {
            entry["count_field_offset"] = JsonValue(*field.count_field_offset);
        }
        if (field.element_count) entry["element_count"] = JsonValue(*field.element_count);
        entry["rationale"] = JsonValue(field.rationale);
        fields.push(std::move(entry));
    }
    root["fields"] = std::move(fields);

    JsonValue evidence = JsonValue::array();
    for (const auto& item : result.evidence) {
        JsonValue entry = JsonValue::object();
        entry["kind"] = JsonValue(std::string(infer::to_string(item.kind)));
        entry["offset"] = JsonValue(item.offset);
        entry["confidence"] = JsonValue(item.confidence);
        entry["description"] = JsonValue(item.description);
        evidence.push(std::move(entry));
    }
    root["evidence"] = std::move(evidence);
    return root;
}

struct RustAnalysis {
    core::BinaryView view;
    core::ExecutableImage image;
    std::vector<derust::RustString> strings;
    std::vector<derust::VTableCandidate> vtables;
    std::vector<derust::DemangledSymbol> symbols;
    std::vector<derust::TaggedUnionCandidate> tagged_unions;
    std::vector<derust::NicheCandidate> niches;
};

Result<RustAnalysis> analyze_rust(const std::string& path, bool demangle_symbols,
                                  bool include_strings, bool include_vtables, bool include_enums) {
    auto view_result = BinaryView::open(path);
    if (!view_result) return view_result.error();
    RustAnalysis analysis;
    analysis.view = std::move(view_result).value();
    auto image_result = core::ExecutableImage::parse(analysis.view);
    if (!image_result) return image_result.error();
    analysis.image = std::move(image_result).value();

    if (demangle_symbols) {
        for (const auto& symbol : analysis.image.symbols()) {
            if (!derust::looks_like_rust_symbol(symbol.name)) continue;
            auto demangled = derust::demangle(symbol.name);
            if (demangled) {
                analysis.symbols.push_back(std::move(demangled).value());
            } else {
                derust::DemangledSymbol fallback;
                fallback.mangled = symbol.name;
                fallback.demangled = symbol.name;
                analysis.symbols.push_back(std::move(fallback));
            }
        }
    }

    if (include_strings) {
        auto strings = derust::SliceScanner{}.scan(analysis.image);
        if (!strings) return strings.error();
        analysis.strings = std::move(strings).value();
    }
    if (include_vtables) {
        auto vtables = derust::VTableAnalyzer{}.analyze(analysis.image);
        if (!vtables) return vtables.error();
        analysis.vtables = std::move(vtables).value();
    }
    if (include_enums) {
        analysis.tagged_unions =
            derust::EnumReconstructor{}.scan_tagged_unions(analysis.view, &analysis.image);
        analysis.niches = derust::EnumReconstructor{}.scan_niches(analysis.view, &analysis.image);
    }
    return analysis;
}

JsonValue strings_to_json(const std::vector<derust::RustString>& strings) {
    JsonValue array = JsonValue::array();
    for (const auto& string : strings) {
        JsonValue entry = JsonValue::object();
        entry["value"] = JsonValue(string.value);
        entry["length"] = JsonValue(string.length);
        entry["data_address"] = JsonValue(string.data_address);
        entry["data_file_offset"] = JsonValue(string.data_file_offset);
        entry["pair_address"] = JsonValue(string.pair_address);
        entry["pair_file_offset"] = JsonValue(string.pair_file_offset);
        entry["confidence"] = JsonValue(string.confidence);
        array.push(std::move(entry));
    }
    return array;
}

JsonValue vtables_to_json(const std::vector<derust::VTableCandidate>& vtables) {
    JsonValue array = JsonValue::array();
    for (const auto& vtable : vtables) {
        JsonValue entry = JsonValue::object();
        entry["address"] = JsonValue(vtable.address);
        entry["file_offset"] = JsonValue(vtable.file_offset);
        entry["drop_in_place"] = JsonValue(vtable.drop_in_place);
        entry["object_size"] = JsonValue(vtable.object_size);
        entry["object_align"] = JsonValue(vtable.object_align);
        entry["confidence"] = JsonValue(vtable.confidence);
        entry["rationale"] = JsonValue(vtable.rationale);
        JsonValue methods = JsonValue::array();
        for (const auto& method : vtable.entries) {
            JsonValue method_entry = JsonValue::object();
            method_entry["index"] = JsonValue(static_cast<std::uint64_t>(method.index));
            method_entry["address"] = JsonValue(method.address);
            method_entry["file_offset"] = JsonValue(method.file_offset);
            method_entry["symbol"] = JsonValue(method.symbol);
            method_entry["points_to_code"] = JsonValue(method.points_to_code);
            methods.push(std::move(method_entry));
        }
        entry["entries"] = std::move(methods);
        array.push(std::move(entry));
    }
    return array;
}

std::string rust_type_header(const RustAnalysis& analysis) {
    std::ostringstream out;
    out << "// Recovered by TypeMorph DeRust.\n";
    out << "// Generated from " << analysis.image.format_name() << " image.\n";
    out << "#pragma once\n\n";
    out << "#include <cstddef>\n#include <cstdint>\n\n";
    out << "namespace typemorph::recovered {\n\n";
    out << "// Rust fat pointer / slice header.\n";
    out << "struct FatPointer {\n";
    out << "    const std::uint8_t* data = nullptr;\n";
    out << "    std::size_t length = 0;\n";
    out << "};\n\n";
    out << "// Rust trait-object vtable header: [drop_in_place, size, align, methods...]\n";
    out << "struct TraitVTableHeader {\n";
    out << "    void (*drop_in_place)(void*) = nullptr;\n";
    out << "    std::size_t object_size = 0;\n";
    out << "    std::size_t object_align = 0;\n";
    out << "};\n\n";
    if (!analysis.vtables.empty()) {
        for (std::size_t index = 0; index < analysis.vtables.size(); ++index) {
            const auto& vtable = analysis.vtables[index];
            out << "// vtable VA=0x" << std::hex << vtable.address << std::dec
                << " confidence=" << std::fixed << std::setprecision(2) << vtable.confidence
                << "\n";
            out << "struct TraitVTable_" << index << " {\n";
            out << "    TraitVTableHeader header;\n";
            // The first three words are the header: drop_in_place, size, align.
            const std::size_t header_entries = std::min<std::size_t>(vtable.entries.size(), 3);
            for (std::size_t method_index = header_entries; method_index < vtable.entries.size();
                 ++method_index) {
                const auto& method = vtable.entries[method_index];
                out << "    void* method_" << (method_index - header_entries)
                    << " = nullptr;  // 0x" << std::hex << method.address << std::dec << "\n";
            }
            out << "};\n\n";
        }
    }
    if (!analysis.strings.empty()) {
        out << "// String literals recovered from fat-pointer pairs.\n";
        out << "inline constexpr const char* kRecoveredStringLiterals[] = {\n";
        for (std::size_t index = 0; index < analysis.strings.size(); ++index) {
            out << "    \"" << json_escape(analysis.strings[index].value) << "\",\n";
            if (index == 255) {
                out << "    // ... " << (analysis.strings.size() - index - 1) << " more strings\n";
                break;
            }
        }
        out << "};\n";
    }
    out << "\n}  // namespace typemorph::recovered\n";
    return out.str();
}

std::string command_help(std::string_view command) {
    if (command == "inspect") {
        return "Usage: typemorph inspect <file> [--render-once] [--no-tui] [--width=N] "
               "[--height=N] [--json]\n"
               "Interactive hex/entropy, AST and live emitter dashboard.\n";
    }
    if (command == "infer") {
        return "Usage: typemorph infer <sample>... [--format=kaitai|imhex|cpp|rust|json] [--out=FILE]\n"
               "       [--min-array-elements=N] [--confidence-threshold=F] [--endian=little|big]\n"
               "Infer a format from one or more instances; stdout is the generator output.\n";
    }
    if (command == "rust") {
        return "Usage: typemorph rust <binary> [--demangle] [--extract-strings=FILE]\n"
               "       [--dump-vtables=FILE] [--emit-types=FILE] [--enums] [--json]\n"
               "Recover Rust fat pointers, vtables, demangled symbols and tagged-union evidence.\n";
    }
    if (command == "hybrid") {
        return "Usage: typemorph hybrid <binary> [--section=.rodata] [--format=kaitai|imhex|cpp|rust|json]\n"
               "       [--out=FILE]\n"
               "Run the format inferrer against an embedded executable section.\n";
    }
    if (command == "unxor") {
        return "Usage: typemorph unxor <file> [--key=HEX] [--out=FILE] [--json]\n"
               "       [--min-key-length=N] [--max-key-length=N]\n"
               "Crack single/multi-byte/rolling XOR encryption or decrypt with a known key.\n";
    }
    if (command == "strings") {
        return "Usage: typemorph strings <file> [--min-len=N] [--json]\n"
               "       [--no-stack] [--no-xor] [--no-utf16]\n"
               "Extract printable ASCII, UTF-16, x86 stack strings, and XOR-encoded strings.\n";
    }
    if (command == "devirt") {
        return "Usage: typemorph devirt <binary> [--min-handlers=N] [--json]\n"
               "Analyze VM bytecode interpreter dispatch loops and handler jump tables.\n";
    }
    if (command == "entropy") {
        return "Usage: typemorph entropy <file> [--block-size=N] [--json]\n"
               "Calculate Shannon entropy distribution and highlight packed/encrypted zones.\n";
    }
    if (command == "sig") {
        return "Usage: typemorph sig <binary> [--name=RULE_NAME] [--out=FILE] [--json]\n"
               "Generate a high-fidelity YARA signature rule matching invariants and strings.\n";
    }
    if (command == "crypto") {
        return "Usage: typemorph crypto <file> [--json]\n"
               "Detect cryptographic constants (AES S-boxes, SHA, MD5, ChaCha, CRC, TEA).\n";
    }
    if (command == "diff") {
        return "Usage: typemorph diff <file_a> <file_b> [--json]\n"
               "Structural and binary diffing: byte changes, section & symbol deltas, entropy shifts.\n";
    }
    if (command == "serve") {
        return "Usage: typemorph serve --stdio\n"
               "Line-delimited JSON-RPC 2.0 daemon for Ghidra/IDA/editor integration.\n";
    }
    return "TypeMorph - binary structure inference, Rust recovery & deobfuscation.\n\n"
           "Commands:\n"
           "  inspect <file>       Interactive TUI dashboard\n"
           "  infer <samples...>   Differential format inference\n"
           "  rust <binary>        Rust semantic recovery\n"
           "  hybrid <binary>      Infer an embedded executable section\n"
           "  unxor <file>         XOR key discovery and deobfuscation\n"
           "  strings <file>       String revealer (ASCII, UTF-16, stack, XOR)\n"
           "  devirt <binary>      Devirtualizer (VM dispatchers & handlers)\n"
           "  entropy <file>       Shannon entropy graph & high-density zones\n"
           "  sig <binary>         Generate YARA rule from invariants & strings\n"
           "  crypto <file>        Detect cryptographic & hashing constants\n"
           "  diff <a.bin> <b.bin> Structural & binary diff comparator\n"
           "  serve --stdio        JSON-RPC daemon on stdio\n"
           "  version              Print version\n"
           "  help [command]       Show help\n";
}

std::string usage_error(const std::string& message) {
    return "TypeMorph: " + message + "\nTry 'typemorph help' for usage.";
}

// ---------------------------------------------------------------------------
// CLI command implementations
// ---------------------------------------------------------------------------

int command_infer(const Arguments& args, std::ostream& out, std::ostream& err) {
    if (args.positional.empty()) {
        err << usage_error("infer requires at least one sample") << '\n';
        return 2;
    }
    if (args.has("help")) {
        out << command_help("infer");
        return 0;
    }

    infer::DiffOptions options;
    options.endian = parse_endian(args.get_or("endian", "little"));
    if (auto value = args.get("min-array-elements")) {
        auto parsed = parse_u64(*value, "min-array-elements");
        if (!parsed) {
            err << usage_error(parsed.error().message) << '\n';
            return 2;
        }
        options.min_array_elements = parsed.value();
    }
    if (auto value = args.get("confidence-threshold")) {
        auto parsed = parse_double(*value, "confidence-threshold");
        if (!parsed) {
            err << usage_error(parsed.error().message) << '\n';
            return 2;
        }
        options.confidence_threshold = parsed.value();
    }
    if (auto value = args.get("max-fields")) {
        auto parsed = parse_u64(*value, "max-fields");
        if (!parsed) {
            err << usage_error(parsed.error().message) << '\n';
            return 2;
        }
        options.max_fields = parsed.value();
    }

    auto format = parse_format(args.get_or("format", "kaitai"));
    if (!format) {
        err << usage_error(format.error().message) << '\n';
        return 2;
    }

    auto samples = load_samples(args.positional);
    if (!samples) {
        err << "TypeMorph: " << format_error(samples.error()) << '\n';
        return 1;
    }

    infer::DiffEngine engine(options);
    auto result = engine.infer(samples.value());
    if (!result) {
        err << "TypeMorph: " << format_error(result.error()) << '\n';
        return 1;
    }

    std::string payload;
    if (format.value() == OutputFormat::json || args.has("json")) {
        payload = inference_to_json(result.value()).dump(2);
        payload.push_back('\n');
    } else {
        auto generated = generate_output(result.value(), format.value());
        if (!generated) {
            err << "TypeMorph: " << format_error(generated.error()) << '\n';
            return 1;
        }
        payload = std::move(generated).value();
    }

    if (auto target = args.get("out")) {
        auto written = write_file(*target, payload);
        if (!written) {
            err << "TypeMorph: " << format_error(written.error()) << '\n';
            return 1;
        }
        err << "TypeMorph: wrote " << format_label(format.value()) << " to " << *target << " ("
            << result.value().fields.size() << " fields, confidence "
            << std::fixed << std::setprecision(3) << result.value().confidence << ")\n";
    } else {
        out << payload;
    }
    return 0;
}

int command_inspect(const Arguments& args, std::ostream& out, std::ostream& err) {
    if (args.has("help")) {
        out << command_help("inspect");
        return 0;
    }
    if (args.positional.empty()) {
        err << usage_error("inspect requires a file") << '\n';
        return 2;
    }

    auto view_result = BinaryView::open(args.positional.front());
    if (!view_result) {
        err << "TypeMorph: " << format_error(view_result.error()) << '\n';
        return 1;
    }
    auto view = std::move(view_result).value();

    infer::DiffOptions options;
    options.confidence_threshold = 0.50;  // single sample; show useful structure
    infer::DiffEngine engine(options);
    auto sample = infer::Sample{view, args.positional.front(), std::nullopt};
    auto result = engine.infer(std::span<const infer::Sample>(&sample, 1));
    if (!result) {
        err << "TypeMorph: " << format_error(result.error()) << '\n';
        return 1;
    }

    auto options_emit = make_emit_options(result.value());
    auto kaitai = emit::KaitaiEmitter{}.generate(*result.value().root, options_emit);
    if (!kaitai) {
        err << "TypeMorph: " << format_error(kaitai.error()) << '\n';
        return 1;
    }
    auto cpp = emit::CppEmitter{}.generate(*result.value().root, options_emit);
    if (!cpp) {
        err << "TypeMorph: " << format_error(cpp.error()) << '\n';
        return 1;
    }
    auto rust = emit::RustEmitter{}.generate(*result.value().root, options_emit);
    if (!rust) {
        err << "TypeMorph: " << format_error(rust.error()) << '\n';
        return 1;
    }

    if (args.has("json")) {
        JsonValue document = inference_to_json(result.value());
        document["kaitai"] = JsonValue(std::move(kaitai).value());
        document["cpp"] = JsonValue(std::move(cpp).value());
        document["rust"] = JsonValue(std::move(rust).value());
        out << document.dump(2) << '\n';
        return 0;
    }

    tui::DashboardModel model;
    model.view = view;
    model.root = result.value().root;
    model.kaitai_preview = std::move(kaitai).value();
    model.cpp_preview = std::move(cpp).value();
    model.rust_preview = std::move(rust).value();
    model.source_name = args.positional.front();
    model.format_name = result.value().format_name;

    std::size_t width = 120;
    std::size_t height = 35;
    if (auto value = args.get("width")) {
        auto parsed = parse_u64(*value, "width");
        if (!parsed || parsed.value() < 40) {
            err << usage_error("width must be an integer >= 40") << '\n';
            return 2;
        }
        width = static_cast<std::size_t>(parsed.value());
    }
    if (auto value = args.get("height")) {
        auto parsed = parse_u64(*value, "height");
        if (!parsed || parsed.value() < 12) {
            err << usage_error("height must be an integer >= 12") << '\n';
            return 2;
        }
        height = static_cast<std::size_t>(parsed.value());
    }

    tui::Dashboard dashboard(std::move(model));
    if (args.has("render-once") || args.has("no-tui") || !stdout_is_tty()) {
        out << dashboard.render_frame(width, height, 0);
        if (out) out.put('\n');
        return 0;
    }
    return dashboard.run();
}

int command_rust(const Arguments& args, std::ostream& out, std::ostream& err) {
    if (args.has("help")) {
        out << command_help("rust");
        return 0;
    }
    if (args.positional.empty()) {
        err << usage_error("rust requires an executable") << '\n';
        return 2;
    }

    const bool include_all = args.has("demangle") || args.has("enums");
    auto analysis = analyze_rust(args.positional.front(), args.has("demangle"), true, true,
                                 include_all || args.has("enums"));
    if (!analysis) {
        err << "TypeMorph: " << format_error(analysis.error()) << '\n';
        return 1;
    }
    auto& rust = analysis.value();

    if (auto path = args.get("extract-strings")) {
        std::ostringstream lines;
        for (const auto& string : rust.strings) {
            lines << string.value << '\n';
        }
        auto written = write_file(*path, lines.str());
        if (!written) {
            err << "TypeMorph: " << format_error(written.error()) << '\n';
            return 1;
        }
        err << "TypeMorph: wrote " << rust.strings.size() << " Rust strings to " << *path << '\n';
    }
    if (auto path = args.get("dump-vtables")) {
        auto written = write_file(*path, vtables_to_json(rust.vtables).dump(2) + "\n");
        if (!written) {
            err << "TypeMorph: " << format_error(written.error()) << '\n';
            return 1;
        }
        err << "TypeMorph: wrote " << rust.vtables.size() << " vtables to " << *path << '\n';
    }
    if (auto path = args.get("emit-types")) {
        auto written = write_file(*path, rust_type_header(rust));
        if (!written) {
            err << "TypeMorph: " << format_error(written.error()) << '\n';
            return 1;
        }
        err << "TypeMorph: wrote reconstructed C++ types to " << *path << '\n';
    }

    if (args.has("json")) {
        JsonValue document = JsonValue::object();
        document["format"] = JsonValue(rust.image.format_name());
        document["bits"] = JsonValue(static_cast<std::uint64_t>(rust.image.bits()));
        document["sections"] = JsonValue(static_cast<std::uint64_t>(rust.image.sections().size()));
        document["symbols"] = JsonValue(static_cast<std::uint64_t>(rust.image.symbols().size()));
        JsonValue demangled = JsonValue::array();
        for (const auto& symbol : rust.symbols) {
            JsonValue entry = JsonValue::object();
            entry["mangled"] = JsonValue(symbol.mangled);
            entry["demangled"] = JsonValue(symbol.demangled);
            entry["crate"] = JsonValue(symbol.crate);
            entry["path"] = JsonValue(symbol.path);
            entry["v0"] = JsonValue(symbol.is_v0);
            demangled.push(std::move(entry));
        }
        document["rust_symbols"] = std::move(demangled);
        document["strings"] = strings_to_json(rust.strings);
        document["vtables"] = vtables_to_json(rust.vtables);
        JsonValue enums = JsonValue::array();
        for (const auto& candidate : rust.tagged_unions) {
            JsonValue entry = JsonValue::object();
            entry["offset"] = JsonValue(candidate.offset);
            entry["tag_width"] = JsonValue(static_cast<std::uint64_t>(candidate.tag_width));
            entry["confidence"] = JsonValue(candidate.confidence);
            entry["rationale"] = JsonValue(candidate.rationale);
            entry["variants"] = JsonValue(static_cast<std::uint64_t>(candidate.variants.size()));
            enums.push(std::move(entry));
        }
        document["tagged_unions"] = std::move(enums);
        out << document.dump(2) << '\n';
        return 0;
    }

    out << "TypeMorph DeRust: " << rust.image.format_name() << ' ' << rust.image.bits()
        << "-bit image\n";
    out << "  sections: " << rust.image.sections().size()
        << "  symbols: " << rust.image.symbols().size() << '\n';
    out << "  rust symbols: " << rust.symbols.size() << '\n';
    if (args.has("demangle")) {
        for (const auto& symbol : rust.symbols) {
            out << "  " << symbol.mangled << "\n        -> " << symbol.demangled << '\n';
        }
    }
    out << "  UTF-8 strings: " << rust.strings.size() << '\n';
    out << "  vtables: " << rust.vtables.size() << '\n';
    if (!rust.strings.empty()) {
        out << "  first string: \"" << rust.strings.front().value << "\" (length "
            << rust.strings.front().length << ")\n";
    }
    if (args.has("enums")) {
        out << "  tagged unions: " << rust.tagged_unions.size()
            << "  niche candidates: " << rust.niches.size() << '\n';
    }
    return 0;
}

int command_hybrid(const Arguments& args, std::ostream& out, std::ostream& err) {
    if (args.has("help")) {
        out << command_help("hybrid");
        return 0;
    }
    if (args.positional.empty()) {
        err << usage_error("hybrid requires an executable") << '\n';
        return 2;
    }

    auto view_result = BinaryView::open(args.positional.front());
    if (!view_result) {
        err << "TypeMorph: " << format_error(view_result.error()) << '\n';
        return 1;
    }
    auto view = std::move(view_result).value();
    auto image_result = core::ExecutableImage::parse(view);
    if (!image_result) {
        err << "TypeMorph: " << format_error(image_result.error()) << '\n';
        return 1;
    }
    auto image = std::move(image_result).value();

    const std::string section_name = args.get_or("section", ".rodata");
    const auto* section = image.find_section(section_name);
    if (section == nullptr) {
        err << "TypeMorph: section not found: " << section_name << '\n';
        return 1;
    }
    auto bytes = image.section_bytes(*section);
    if (!bytes) {
        err << "TypeMorph: " << format_error(bytes.error()) << '\n';
        return 1;
    }
    if (bytes.value().empty()) {
        err << "TypeMorph: section is empty: " << section_name << '\n';
        return 1;
    }

    auto section_view = BinaryView::from_external(bytes.value(), section_name);
    infer::DiffOptions infer_options;
    infer_options.confidence_threshold = 0.50;
    infer::DiffEngine engine(infer_options);
    auto sample = infer::Sample{section_view, section_name, std::nullopt};
    auto result = engine.infer(std::span<const infer::Sample>(&sample, 1));
    if (!result) {
        err << "TypeMorph: " << format_error(result.error()) << '\n';
        return 1;
    }

    auto format = parse_format(args.get_or("format", "kaitai"));
    if (!format) {
        err << usage_error(format.error().message) << '\n';
        return 2;
    }

    std::string payload;
    if (format.value() == OutputFormat::json) {
        JsonValue document = inference_to_json(result.value());
        document["source"] = JsonValue(args.positional.front());
        document["section"] = JsonValue(section_name);
        document["section_offset"] = JsonValue(section->file_offset);
        document["section_address"] = JsonValue(section->virtual_address);
        payload = document.dump(2) + "\n";
    } else {
        auto generated = generate_output(result.value(), format.value());
        if (!generated) {
            err << "TypeMorph: " << format_error(generated.error()) << '\n';
            return 1;
        }
        payload = std::move(generated).value();
    }

    if (auto target = args.get("out")) {
        auto written = write_file(*target, payload);
        if (!written) {
            err << "TypeMorph: " << format_error(written.error()) << '\n';
            return 1;
        }
        err << "TypeMorph: wrote hybrid layout for " << section_name << " to " << *target << '\n';
    } else {
        out << payload;
    }
    return 0;
}

int command_unxor(const Arguments& args, std::ostream& out, std::ostream& err) {
    if (args.has("help")) {
        out << command_help("unxor");
        return 0;
    }
    if (args.positional.empty()) {
        err << usage_error("unxor requires a target file") << '\n';
        return 2;
    }
    const std::string& path = args.positional.front();
    auto view_result = BinaryView::open(path);
    if (!view_result) {
        err << "TypeMorph: " << format_error(view_result.error()) << '\n';
        return 1;
    }
    const auto& view = view_result.value();

    std::vector<deobf::XorCandidate> candidates;

    if (auto key_opt = args.get("key")) {
        auto key_bytes = parse_hex_string(*key_opt);
        if (!key_bytes) {
            err << usage_error(key_bytes.error().message) << '\n';
            return 2;
        }
        deobf::Unxorer unxorer;
        auto mode = key_bytes.value().size() == 1 ? deobf::XorMode::single_byte : deobf::XorMode::multi_byte;
        auto decrypted = unxorer.decrypt(view, key_bytes.value(), mode);
        deobf::XorCandidate cand;
        cand.key = std::move(key_bytes).value();
        cand.mode = mode;
        cand.confidence = 1.0;
        cand.entropy = core::shannon_entropy(decrypted.bytes());
        cand.printable_ratio = 1.0;
        std::string preview_text;
        for (std::size_t i = 0; i < std::min<std::size_t>(decrypted.size(), 64); ++i) {
            uint8_t c = decrypted.bytes()[i];
            preview_text.push_back((c >= 0x20 && c <= 0x7E) ? static_cast<char>(c) : '.');
        }
        cand.preview = std::move(preview_text);
        cand.rationale = "User-specified key";
        cand.decrypted = std::move(decrypted);
        candidates.push_back(std::move(cand));
    } else {
        deobf::UnxorOptions options;
        if (auto val = args.get("min-key-length")) {
            auto parsed = parse_u64(*val, "min-key-length");
            if (!parsed) {
                err << usage_error(parsed.error().message) << '\n';
                return 2;
            }
            options.min_key_length = static_cast<std::size_t>(parsed.value());
        }
        if (auto val = args.get("max-key-length")) {
            auto parsed = parse_u64(*val, "max-key-length");
            if (!parsed) {
                err << usage_error(parsed.error().message) << '\n';
                return 2;
            }
            options.max_key_length = static_cast<std::size_t>(parsed.value());
        }
        deobf::Unxorer unxorer(options);
        candidates = unxorer.crack(view);
    }

    if (auto out_path = args.get("out")) {
        if (!candidates.empty()) {
            auto written = write_binary_file(*out_path, candidates.front().decrypted.bytes());
            if (!written) {
                err << "TypeMorph: " << format_error(written.error()) << '\n';
                return 1;
            }
            err << "TypeMorph: decrypted " << candidates.front().decrypted.size()
                << " bytes written to " << *out_path << '\n';
        } else {
            err << "TypeMorph: no XOR key found to decrypt output\n";
            return 1;
        }
    }

    if (args.has("json")) {
        out << xor_candidates_to_json(candidates).dump(2) << '\n';
        return 0;
    }

    if (candidates.empty()) {
        out << "TypeMorph UnXORer: no viable XOR keys discovered for " << path << '\n';
        return 0;
    }

    out << "TypeMorph UnXORer: " << candidates.size() << " candidate key(s) for " << path << ":\n";
    for (std::size_t i = 0; i < candidates.size(); ++i) {
        const auto& c = candidates[i];
        out << "  #" << (i + 1) << " [" << xor_mode_name(c.mode) << "] Key: 0x"
            << to_hex_string(c.key) << " (conf: " << std::fixed << std::setprecision(2)
            << c.confidence << ", printable: " << std::setprecision(1) << (c.printable_ratio * 100.0)
            << "%, entropy: " << std::setprecision(2) << c.entropy << ")\n"
            << "     Preview: \"" << c.preview << "\"\n"
            << "     Note: " << c.rationale << "\n";
    }
    return 0;
}

int command_strings(const Arguments& args, std::ostream& out, std::ostream& err) {
    if (args.has("help")) {
        out << command_help("strings");
        return 0;
    }
    if (args.positional.empty()) {
        err << usage_error("strings requires a target file") << '\n';
        return 2;
    }
    const std::string& path = args.positional.front();
    auto view_result = BinaryView::open(path);
    if (!view_result) {
        err << "TypeMorph: " << format_error(view_result.error()) << '\n';
        return 1;
    }
    const auto& view = view_result.value();

    deobf::StringScanOptions options;
    if (auto val = args.get("min-len")) {
        auto parsed = parse_u64(*val, "min-len");
        if (!parsed) {
            err << usage_error(parsed.error().message) << '\n';
            return 2;
        }
        options.min_length = static_cast<std::size_t>(parsed.value());
    }
    if (args.has("no-stack")) options.scan_stack_strings = false;
    if (args.has("no-xor")) options.scan_xor_strings = false;
    if (args.has("no-utf16")) options.scan_utf16le = false;

    deobf::StringRevealer revealer(options);
    auto strings = revealer.extract(view);

    if (args.has("json")) {
        out << extracted_strings_to_json(strings).dump(2) << '\n';
        return 0;
    }

    for (const auto& s : strings) {
        char buf[32];
        std::snprintf(buf, sizeof(buf), "0x%08llx", static_cast<unsigned long long>(s.offset));
        out << buf << " [" << std::left << std::setw(7) << deobf::to_string(s.category)
            << std::right << "] " << s.value;
        if (!s.note.empty()) {
            out << " (" << s.note << ")";
        }
        out << '\n';
    }
    return 0;
}

int command_devirt(const Arguments& args, std::ostream& out, std::ostream& err) {
    if (args.has("help")) {
        out << command_help("devirt");
        return 0;
    }
    if (args.positional.empty()) {
        err << usage_error("devirt requires an executable binary") << '\n';
        return 2;
    }
    const std::string& path = args.positional.front();
    auto view_result = BinaryView::open(path);
    if (!view_result) {
        err << "TypeMorph: " << format_error(view_result.error()) << '\n';
        return 1;
    }
    auto image_result = core::ExecutableImage::parse(view_result.value());
    if (!image_result) {
        err << "TypeMorph: " << format_error(image_result.error()) << '\n';
        return 1;
    }
    const auto& image = image_result.value();

    deobf::DevirtOptions options;
    if (auto val = args.get("min-handlers")) {
        auto parsed = parse_u64(*val, "min-handlers");
        if (!parsed) {
            err << usage_error(parsed.error().message) << '\n';
            return 2;
        }
        options.min_handlers = static_cast<std::size_t>(parsed.value());
    }

    deobf::Devirtualizer devirt(options);
    auto instances = devirt.analyze(image);

    if (args.has("json")) {
        JsonValue doc = JsonValue::object();
        doc["source"] = JsonValue(path);
        doc["instances"] = devirt_instances_to_json(instances);
        out << doc.dump(2) << '\n';
        return 0;
    }

    if (instances.empty()) {
        out << "TypeMorph Devirtualizer: no virtual machine interpreters detected in " << path << '\n';
        return 0;
    }

    out << "TypeMorph Devirtualizer: detected " << instances.size() << " VM instance(s) in " << path << ":\n";
    for (std::size_t i = 0; i < instances.size(); ++i) {
        const auto& inst = instances[i];
        out << "\n[VM #" << (i + 1) << "] Jump Table VA: 0x" << std::hex << inst.table_va
            << " (file offset: 0x" << inst.table_file_offset << ")\n"
            << "  Dispatch Type: " << inst.dispatch_type << " | Handlers: " << std::dec
            << inst.opcode_count << " (conf: " << std::fixed << std::setprecision(2)
            << inst.confidence << ")\n"
            << "  Note: " << inst.rationale << "\n"
            << "  Opcode  Handler VA  File Offset  Size\n";
        for (const auto& h : inst.handlers) {
            char op_buf[16];
            std::snprintf(op_buf, sizeof(op_buf), "  0x%02X  ", h.opcode);
            char va_buf[32];
            std::snprintf(va_buf, sizeof(va_buf), "0x%08llx  ", static_cast<unsigned long long>(h.handler_va));
            char fo_buf[32];
            std::snprintf(fo_buf, sizeof(fo_buf), "0x%08llx   ", static_cast<unsigned long long>(h.handler_file_offset));
            out << op_buf << va_buf << fo_buf << h.estimated_size << " B (" << h.mnemonic << ")\n";
        }
    }
    return 0;
}

int command_entropy(const Arguments& args, std::ostream& out, std::ostream& err) {
    if (args.has("help")) {
        out << command_help("entropy");
        return 0;
    }
    if (args.positional.empty()) {
        err << usage_error("entropy requires a target file") << '\n';
        return 2;
    }
    const std::string& path = args.positional.front();
    auto view_result = BinaryView::open(path);
    if (!view_result) {
        err << "TypeMorph: " << format_error(view_result.error()) << '\n';
        return 1;
    }
    const auto& view = view_result.value();
    if (view.empty()) {
        err << "TypeMorph: file is empty: " << path << '\n';
        return 1;
    }

    std::size_t block_size = 512;
    if (auto val = args.get("block-size")) {
        auto parsed = parse_u64(*val, "block-size");
        if (!parsed) {
            err << usage_error(parsed.error().message) << '\n';
            return 2;
        }
        block_size = static_cast<std::size_t>(parsed.value());
        if (block_size == 0) block_size = 512;
    } else {
        if (view.size() > 48 * 512) {
            block_size = (view.size() + 31) / 32;
            block_size = ((block_size + 63) / 64) * 64;
        } else if (view.size() < 16 * 512) {
            block_size = std::max<std::size_t>(16, view.size() / 16);
        }
    }

    auto blocks_res = core::block_entropy(view.bytes(), block_size);
    if (!blocks_res) {
        err << "TypeMorph: " << format_error(blocks_res.error()) << '\n';
        return 1;
    }
    const auto& blocks = blocks_res.value();
    const double total_entropy = core::shannon_entropy(view.bytes());

    double min_ent = 8.0;
    double max_ent = 0.0;
    double sum_ent = 0.0;
    for (double ent : blocks) {
        if (ent < min_ent) min_ent = ent;
        if (ent > max_ent) max_ent = ent;
        sum_ent += ent;
    }
    const double mean_ent = blocks.empty() ? 0.0 : sum_ent / static_cast<double>(blocks.size());

    struct Range {
        std::uint64_t start = 0;
        std::uint64_t end = 0;
        double sum = 0.0;
        std::size_t count = 0;
    };
    std::vector<Range> high_ranges;
    Range current_high;
    bool in_high = false;
    for (std::size_t i = 0; i < blocks.size(); ++i) {
        const std::uint64_t offset = static_cast<std::uint64_t>(i) * block_size;
        const std::uint64_t end = std::min<std::uint64_t>(offset + block_size, view.size());
        if (blocks[i] >= 7.20) {
            if (!in_high) {
                in_high = true;
                current_high.start = offset;
                current_high.end = end;
                current_high.sum = blocks[i];
                current_high.count = 1;
            } else {
                current_high.end = end;
                current_high.sum += blocks[i];
                current_high.count += 1;
            }
        } else {
            if (in_high) {
                high_ranges.push_back(current_high);
                in_high = false;
            }
        }
    }
    if (in_high) {
        high_ranges.push_back(current_high);
    }

    if (args.has("json")) {
        JsonValue doc = JsonValue::object();
        doc["file"] = JsonValue(path);
        doc["size"] = JsonValue(view.size());
        doc["total_entropy"] = JsonValue(total_entropy);
        doc["min_entropy"] = JsonValue(min_ent);
        doc["max_entropy"] = JsonValue(max_ent);
        doc["mean_entropy"] = JsonValue(mean_ent);
        doc["block_size"] = JsonValue(static_cast<std::uint64_t>(block_size));

        JsonValue json_blocks = JsonValue::array();
        for (std::size_t i = 0; i < blocks.size(); ++i) {
            JsonValue b = JsonValue::object();
            const std::uint64_t offset = static_cast<std::uint64_t>(i) * block_size;
            const std::uint64_t end = std::min<std::uint64_t>(offset + block_size, view.size());
            b["offset"] = JsonValue(offset);
            b["size"] = JsonValue(end - offset);
            b["entropy"] = JsonValue(blocks[i]);
            b["classification"] = JsonValue(std::string(core::entropy_label(blocks[i])));
            json_blocks.push(std::move(b));
        }
        doc["blocks"] = std::move(json_blocks);

        JsonValue json_high = JsonValue::array();
        for (const auto& r : high_ranges) {
            JsonValue hr = JsonValue::object();
            hr["offset"] = JsonValue(r.start);
            hr["size"] = JsonValue(r.end - r.start);
            hr["mean_entropy"] = JsonValue(r.count == 0 ? 0.0 : r.sum / static_cast<double>(r.count));
            json_high.push(std::move(hr));
        }
        doc["high_entropy_ranges"] = std::move(json_high);
        out << doc.dump(2) << '\n';
        return 0;
    }

    out << "TypeMorph Entropy Analysis: " << path << " (" << view.size() << " bytes)\n"
        << "Total Entropy: " << std::fixed << std::setprecision(2) << total_entropy
        << " / 8.00 bits/byte | Block size: " << block_size << " bytes\n"
        << "Range: [" << min_ent << " .. " << max_ent << "], Mean: " << mean_ent << " bits/byte\n"
        << "--------------------------------------------------------------------------------\n"
        << "Offset Range               Entropy Bar                  Bits/B  Class\n"
        << "--------------------------------------------------------------------------------\n";

    for (std::size_t i = 0; i < blocks.size(); ++i) {
        const std::uint64_t offset = static_cast<std::uint64_t>(i) * block_size;
        const std::uint64_t end = std::min<std::uint64_t>(offset + block_size, view.size());
        const double ent = blocks[i];
        const int filled = std::clamp(static_cast<int>(std::round((ent / 8.0) * 24.0)), 0, 24);
        std::string bar(filled, '#');
        bar.append(24 - filled, '.');

        char range_buf[64];
        std::snprintf(range_buf, sizeof(range_buf), "0x%08llx - 0x%08llx",
                      static_cast<unsigned long long>(offset),
                      static_cast<unsigned long long>(end > 0 ? end - 1 : 0));

        out << range_buf << "  [" << bar << "]  " << std::fixed << std::setprecision(2) << ent << "   "
            << core::entropy_label(ent);
        if (ent >= 7.20) {
            out << " [HIGH]";
        }
        out << '\n';
    }
    out << "--------------------------------------------------------------------------------\n";
    if (!high_ranges.empty()) {
        out << "Detected " << high_ranges.size() << " High-Entropy Zone(s) (>= 7.20 bits/byte):\n";
        for (const auto& r : high_ranges) {
            const double avg = r.count == 0 ? 0.0 : r.sum / static_cast<double>(r.count);
            char r_buf[64];
            std::snprintf(r_buf, sizeof(r_buf), "  * 0x%08llx - 0x%08llx",
                          static_cast<unsigned long long>(r.start),
                          static_cast<unsigned long long>(r.end > 0 ? r.end - 1 : 0));
            out << r_buf << " (" << (r.end - r.start) << " B, avg " << std::fixed
                << std::setprecision(2) << avg << " bits/byte) -> Packed, compressed, or encrypted\n";
        }
    } else {
        out << "No packed or encrypted high-entropy zones detected (all blocks < 7.20 bits/byte).\n";
    }
    return 0;
}

int command_sig(const Arguments& args, std::ostream& out, std::ostream& err) {
    if (args.has("help")) {
        out << command_help("sig");
        return 0;
    }
    if (args.positional.empty()) {
        err << usage_error("sig requires a target binary") << '\n';
        return 2;
    }
    const std::string& path = args.positional.front();
    auto view_result = BinaryView::open(path);
    if (!view_result) {
        err << "TypeMorph: " << format_error(view_result.error()) << '\n';
        return 1;
    }
    const auto& view = view_result.value();
    if (view.empty()) {
        err << "TypeMorph: file is empty: " << path << '\n';
        return 1;
    }

    std::string rule_name = args.get_or("name", "");
    if (rule_name.empty()) {
        std::filesystem::path p(path);
        std::string stem = p.stem().string();
        for (char c : stem) {
            if (std::isalnum(static_cast<unsigned char>(c)) || c == '_') {
                rule_name.push_back(c);
            } else {
                rule_name.push_back('_');
            }
        }
        if (rule_name.empty() || std::isdigit(static_cast<unsigned char>(rule_name.front()))) {
            rule_name = "typemorph_" + rule_name;
        }
    }

    std::string magic_hex;
    if (view.size() >= 4) {
        auto slice = view.slice_unchecked(0, 4);
        magic_hex = to_hex_string(slice);
    }

    deobf::StringScanOptions str_opts;
    str_opts.min_length = 5;
    deobf::StringRevealer revealer(str_opts);
    auto extracted = revealer.extract(view);

    std::vector<std::string> rule_strings;
    for (const auto& s : extracted) {
        if (s.value.size() >= 6 && s.confidence >= 0.85) {
            rule_strings.push_back(s.value);
            if (rule_strings.size() >= 6) break;
        }
    }

    std::ostringstream yara;
    yara << "rule " << rule_name << " {\n"
         << "    meta:\n"
         << "        description = \"Generated by TypeMorph Binary Signature Engine\"\n"
         << "        generator = \"TypeMorph " << kVersion << "\"\n"
         << "        target_file = \"" << json_escape(path) << "\"\n"
         << "        target_size = " << view.size() << "\n"
         << "    strings:\n";

    if (!magic_hex.empty()) {
        yara << "        $magic = { ";
        for (std::size_t i = 0; i < magic_hex.size(); i += 2) {
            yara << magic_hex[i] << magic_hex[i + 1] << " ";
        }
        yara << "} // offset 0x0\n";
    }

    int str_idx = 0;
    for (const auto& str_val : rule_strings) {
        yara << "        $s" << str_idx++ << " = \"" << json_escape(str_val) << "\" ascii\n";
    }

    yara << "    condition:\n";
    if (!magic_hex.empty()) {
        yara << "        $magic at 0";
        if (!rule_strings.empty()) {
            yara << " and " << (rule_strings.size() > 2 ? "2 of ($s*)" : "all of ($s*)");
        }
    } else if (!rule_strings.empty()) {
        yara << "        " << (rule_strings.size() > 2 ? "2 of ($s*)" : "all of ($s*)");
    } else {
        yara << "        filesize == " << view.size();
    }
    yara << "\n}\n";

    const std::string rule_text = yara.str();

    if (auto out_path = args.get("out")) {
        auto written = write_file(*out_path, rule_text);
        if (!written) {
            err << "TypeMorph: " << format_error(written.error()) << '\n';
            return 1;
        }
        err << "TypeMorph: wrote YARA signature to " << *out_path << '\n';
    }

    if (args.has("json")) {
        JsonValue doc = JsonValue::object();
        doc["rule_name"] = JsonValue(rule_name);
        doc["target_file"] = JsonValue(path);
        doc["target_size"] = JsonValue(view.size());
        doc["yara_rule"] = JsonValue(rule_text);
        out << doc.dump(2) << '\n';
        return 0;
    }

    out << rule_text;
    return 0;
}

int command_crypto(const Arguments& args, std::ostream& out, std::ostream& err) {
    if (args.has("help")) {
        out << command_help("crypto");
        return 0;
    }
    if (args.positional.empty()) {
        err << usage_error("crypto requires a target file") << '\n';
        return 2;
    }
    const std::string& path = args.positional.front();
    auto view_result = BinaryView::open(path);
    if (!view_result) {
        err << "TypeMorph: " << format_error(view_result.error()) << '\n';
        return 1;
    }
    const auto& view = view_result.value();
    crypto::CryptoScanOptions opts;
    crypto::CryptoScanner scanner(opts);
    auto matches = scanner.scan(view);

    if (args.has("json")) {
        JsonValue doc = JsonValue::object();
        doc["file"] = JsonValue(path);
        doc["size"] = JsonValue(view.size());
        doc["match_count"] = JsonValue(static_cast<std::uint64_t>(matches.size()));
        JsonValue array = JsonValue::array();
        for (const auto& m : matches) {
            JsonValue entry = JsonValue::object();
            entry["offset"] = JsonValue(m.offset);
            entry["size"] = JsonValue(static_cast<std::uint64_t>(m.size));
            entry["algorithm"] = JsonValue(m.algorithm);
            entry["role"] = JsonValue(m.role);
            entry["category"] = JsonValue(std::string(crypto::to_string(m.category)));
            entry["endianness"] = JsonValue(m.endianness);
            entry["confidence"] = JsonValue(m.confidence);
            entry["description"] = JsonValue(m.description);
            array.push(std::move(entry));
        }
        doc["matches"] = std::move(array);
        out << doc.dump(2) << '\n';
        return 0;
    }

    out << "TypeMorph Cryptographic & Hashing Constant Scanner: " << path << " (" << view.size() << " bytes)\n";
    if (matches.empty()) {
        out << "No known cryptographic constants detected.\n";
        return 0;
    }
    out << "Found " << matches.size() << " cryptographic constant(s):\n";
    out << "--------------------------------------------------------------------------------\n";
    out << "Offset      Algorithm           Role                      Category   Endian\n";
    out << "--------------------------------------------------------------------------------\n";
    for (const auto& m : matches) {
        char buf[32];
        std::snprintf(buf, sizeof(buf), "0x%08llx", static_cast<unsigned long long>(m.offset));
        out << buf << "  "
            << std::left << std::setw(18) << m.algorithm.substr(0, 18) << "  "
            << std::setw(24) << m.role.substr(0, 24) << "  "
            << std::setw(10) << std::string(crypto::to_string(m.category)) << " "
            << m.endianness << "\n";
        out << "            -> " << m.description << "\n";
    }
    out << "--------------------------------------------------------------------------------\n";
    return 0;
}

int command_diff(const Arguments& args, std::ostream& out, std::ostream& err) {
    if (args.has("help")) {
        out << command_help("diff");
        return 0;
    }
    if (args.positional.size() < 2) {
        err << usage_error("diff requires two files (file_a and file_b)") << '\n';
        return 2;
    }
    const std::string& path_a = args.positional[0];
    const std::string& path_b = args.positional[1];
    auto view_a = BinaryView::open(path_a);
    if (!view_a) {
        err << "TypeMorph: " << format_error(view_a.error()) << '\n';
        return 1;
    }
    auto view_b = BinaryView::open(path_b);
    if (!view_b) {
        err << "TypeMorph: " << format_error(view_b.error()) << '\n';
        return 1;
    }

    diff::BinaryDiffEngine engine;
    auto res = engine.compare(view_a.value(), view_b.value(), path_a, path_b);

    if (args.has("json")) {
        JsonValue doc = JsonValue::object();
        doc["file_a"] = JsonValue(res.file_a);
        doc["file_b"] = JsonValue(res.file_b);
        doc["size_a"] = JsonValue(res.size_a);
        doc["size_b"] = JsonValue(res.size_b);
        doc["size_delta"] = JsonValue(res.size_delta);
        doc["entropy_a"] = JsonValue(res.entropy_a);
        doc["entropy_b"] = JsonValue(res.entropy_b);
        doc["similarity"] = JsonValue(res.similarity);
        doc["both_executables"] = JsonValue(res.both_executables);
        if (res.both_executables) {
            doc["format_a"] = JsonValue(res.format_a);
            doc["format_b"] = JsonValue(res.format_b);
            JsonValue secs = JsonValue::array();
            for (const auto& s : res.section_diffs) {
                JsonValue entry = JsonValue::object();
                entry["name"] = JsonValue(s.name);
                entry["status"] = JsonValue(s.status);
                entry["size_a"] = JsonValue(s.size_a);
                entry["size_b"] = JsonValue(s.size_b);
                entry["entropy_a"] = JsonValue(s.entropy_a);
                entry["entropy_b"] = JsonValue(s.entropy_b);
                secs.push(std::move(entry));
            }
            doc["sections"] = std::move(secs);

            JsonValue syms = JsonValue::array();
            for (const auto& s : res.symbol_diffs) {
                JsonValue entry = JsonValue::object();
                entry["name"] = JsonValue(s.name);
                entry["status"] = JsonValue(s.status);
                entry["addr_a"] = JsonValue(s.addr_a);
                entry["addr_b"] = JsonValue(s.addr_b);
                syms.push(std::move(entry));
            }
            doc["symbols"] = std::move(syms);
        }

        JsonValue ranges = JsonValue::array();
        for (const auto& r : res.ranges) {
            JsonValue entry = JsonValue::object();
            entry["offset_a"] = JsonValue(r.offset_a);
            entry["size_a"] = JsonValue(r.size_a);
            entry["offset_b"] = JsonValue(r.offset_b);
            entry["size_b"] = JsonValue(r.size_b);
            entry["kind"] = JsonValue(r.kind);
            ranges.push(std::move(entry));
        }
        doc["ranges"] = std::move(ranges);
        out << doc.dump(2) << '\n';
        return 0;
    }

    out << "TypeMorph Binary & Structural Diff\n"
        << "  File A: " << res.file_a << " (" << res.size_a << " bytes, entropy "
        << std::fixed << std::setprecision(2) << res.entropy_a << ")\n"
        << "  File B: " << res.file_b << " (" << res.size_b << " bytes, entropy "
        << std::fixed << std::setprecision(2) << res.entropy_b << ")\n"
        << "  Size Delta: " << (res.size_delta >= 0 ? "+" : "") << res.size_delta << " bytes\n"
        << "  Similarity: " << std::fixed << std::setprecision(1) << (res.similarity * 100.0) << "%\n";

    if (res.both_executables) {
        out << "\n[Structural Executable Analysis: " << res.format_a << " vs " << res.format_b << "]\n";
        out << "Sections:\n";
        for (const auto& s : res.section_diffs) {
            out << "  " << std::left << std::setw(10) << s.status << " " << std::setw(16) << s.name
                << " size: " << s.size_a << " -> " << s.size_b
                << " (entropy " << std::setprecision(2) << s.entropy_a << " -> " << s.entropy_b << ")\n";
        }
        if (!res.symbol_diffs.empty()) {
            std::size_t shown = 0;
            out << "Symbols (" << res.symbol_diffs.size() << " changed):\n";
            for (const auto& s : res.symbol_diffs) {
                if (s.status == "matched") continue;
                out << "  " << std::left << std::setw(16) << s.status << " " << s.name;
                if (s.status == "address_changed") {
                    char a_buf[64];
                    std::snprintf(a_buf, sizeof(a_buf), " (0x%llx -> 0x%llx)",
                                  static_cast<unsigned long long>(s.addr_a),
                                  static_cast<unsigned long long>(s.addr_b));
                    out << a_buf;
                }
                out << "\n";
                if (++shown >= 20) {
                    out << "  ... (" << (res.symbol_diffs.size() - shown) << " more symbols omitted)\n";
                    break;
                }
            }
        }
    }

    out << "\n[Byte-level Differences: " << res.ranges.size() << " segment(s)]\n";
    std::size_t shown_ranges = 0;
    for (const auto& r : res.ranges) {
        if (r.kind == "match") continue;
        char r_buf[128];
        std::snprintf(r_buf, sizeof(r_buf), "  %-10s A: 0x%06llx (+%lluB) -> B: 0x%06llx (+%lluB)",
                      r.kind.c_str(),
                      static_cast<unsigned long long>(r.offset_a),
                      static_cast<unsigned long long>(r.size_a),
                      static_cast<unsigned long long>(r.offset_b),
                      static_cast<unsigned long long>(r.size_b));
        out << r_buf << "\n";
        if (++shown_ranges >= 25) {
            out << "  ... (" << (res.ranges.size() - shown_ranges) << " more ranges omitted)\n";
            break;
        }
    }
    if (shown_ranges == 0) {
        out << "  Files are byte-identical.\n";
    }
    return 0;
}

// ---------------------------------------------------------------------------
// JSON-RPC
// ---------------------------------------------------------------------------

JsonValue rpc_error(const JsonValue& id, int code, const std::string& message) {
    JsonValue response = JsonValue::object();
    response["jsonrpc"] = JsonValue("2.0");
    response["id"] = id;
    JsonValue error = JsonValue::object();
    error["code"] = JsonValue(static_cast<std::int64_t>(code));
    error["message"] = JsonValue(message);
    response["error"] = std::move(error);
    return response;
}

JsonValue rpc_result(const JsonValue& id, JsonValue result) {
    JsonValue response = JsonValue::object();
    response["jsonrpc"] = JsonValue("2.0");
    response["id"] = id;
    response["result"] = std::move(result);
    return response;
}

Result<std::string> json_string_field(const JsonValue& object, std::string_view key,
                                      bool required = true) {
    const auto* value = object.find(key);
    if (value == nullptr) {
        if (!required) return std::string{};
        return make_error(ErrorCode::invalid_argument, "missing parameter: " + std::string(key));
    }
    const auto* text = value->as_string();
    if (text == nullptr) {
        return make_error(ErrorCode::invalid_argument,
                          "parameter must be a string: " + std::string(key));
    }
    return *text;
}

Result<std::vector<std::string>> json_string_array(const JsonValue& object, std::string_view key) {
    const auto* value = object.find(key);
    if (value == nullptr) {
        return make_error(ErrorCode::invalid_argument, "missing parameter: " + std::string(key));
    }
    const auto* array = value->as_array();
    if (array == nullptr) {
        return make_error(ErrorCode::invalid_argument,
                          "parameter must be an array: " + std::string(key));
    }
    std::vector<std::string> result;
    result.reserve(array->size());
    for (const auto& item : *array) {
        const auto* text = item.as_string();
        if (text == nullptr) {
            return make_error(ErrorCode::invalid_argument,
                              "array elements must be strings: " + std::string(key));
        }
        result.push_back(*text);
    }
    return result;
}

Result<JsonValue> rpc_dispatch(const std::string& method, const JsonValue& params,
                               std::ostream& err) {
    if (method == "ping" || method == "typemorph.ping") {
        JsonValue result = JsonValue::object();
        result["pong"] = JsonValue(true);
        return result;
    }
    if (method == "version" || method == "typemorph.version") {
        JsonValue result = JsonValue::object();
        result["name"] = JsonValue("TypeMorph");
        result["version"] = JsonValue(std::string(kVersion));
        JsonValue capabilities = JsonValue::array();
        capabilities.push(JsonValue("infer"));
        capabilities.push(JsonValue("rust"));
        capabilities.push(JsonValue("hybrid"));
        capabilities.push(JsonValue("inspect"));
        capabilities.push(JsonValue("unxor"));
        capabilities.push(JsonValue("strings"));
        capabilities.push(JsonValue("devirt"));
        capabilities.push(JsonValue("entropy"));
        capabilities.push(JsonValue("sig"));
        capabilities.push(JsonValue("crypto"));
        capabilities.push(JsonValue("diff"));
        result["capabilities"] = std::move(capabilities);
        return result;
    }
    if (method == "infer" || method == "typemorph.infer") {
        auto files = json_string_array(params, "files");
        if (!files) return files.error();
        infer::DiffOptions options;
        if (const auto* threshold = params.find("confidence_threshold")) {
            if (const auto number = threshold->as_double()) options.confidence_threshold = *number;
        }
        if (const auto* min_array = params.find("min_array_elements")) {
            if (const auto number = min_array->as_int())
                options.min_array_elements = static_cast<std::uint64_t>(*number);
        }
        auto samples = load_samples(files.value());
        if (!samples) return samples.error();
        infer::DiffEngine engine(options);
        auto inference = engine.infer(samples.value());
        if (!inference) return inference.error();
        JsonValue result = inference_to_json(inference.value());
        auto format = parse_format(json_string_field(params, "format", false).value_or("kaitai"));
        if (!format) return format.error();
        if (format.value() != OutputFormat::json) {
            auto generated = generate_output(inference.value(), format.value());
            if (!generated) return generated.error();
            if (auto out_path = json_string_field(params, "out", false);
                out_path && !out_path.value().empty()) {
                auto written = write_file(out_path.value(), generated.value());
                if (!written) return written.error();
                result["out"] = JsonValue(out_path.value());
            } else {
                result["output"] = JsonValue(std::move(generated).value());
            }
        }
        return result;
    }
    if (method == "hybrid" || method == "typemorph.hybrid") {
        auto file = json_string_field(params, "file");
        if (!file) return file.error();
        auto view_result = BinaryView::open(file.value());
        if (!view_result) return view_result.error();
        auto view = std::move(view_result).value();
        auto image_result = core::ExecutableImage::parse(view);
        if (!image_result) return image_result.error();
        auto image = std::move(image_result).value();
        auto section_name = json_string_field(params, "section", false);
        const std::string name = section_name && !section_name.value().empty() ? section_name.value()
                                                                              : ".rodata";
        const auto* section = image.find_section(name);
        if (section == nullptr) {
            return make_error(ErrorCode::not_found, "section not found: " + name);
        }
        auto bytes = image.section_bytes(*section);
        if (!bytes) return bytes.error();
        auto section_view = BinaryView::from_external(bytes.value(), name);
        infer::DiffEngine engine;
        auto sample = infer::Sample{section_view, name, std::nullopt};
        auto inference = engine.infer(std::span<const infer::Sample>(&sample, 1));
        if (!inference) return inference.error();
        JsonValue result = inference_to_json(inference.value());
        result["section"] = JsonValue(name);
        result["section_offset"] = JsonValue(section->file_offset);
        result["section_address"] = JsonValue(section->virtual_address);
        auto format = parse_format(json_string_field(params, "format", false).value_or("kaitai"));
        if (!format) return format.error();
        if (format.value() != OutputFormat::json) {
            auto generated = generate_output(inference.value(), format.value());
            if (!generated) return generated.error();
            if (auto out_path = json_string_field(params, "out", false);
                out_path && !out_path.value().empty()) {
                auto written = write_file(out_path.value(), generated.value());
                if (!written) return written.error();
                result["out"] = JsonValue(out_path.value());
            } else {
                result["output"] = JsonValue(std::move(generated).value());
            }
        }
        return result;
    }
    if (method == "rust" || method == "typemorph.rust") {
        auto file = json_string_field(params, "file");
        if (!file) return file.error();
        auto analysis = analyze_rust(file.value(), true, true, true, true);
        if (!analysis) return analysis.error();
        const auto& rust = analysis.value();
        JsonValue result = JsonValue::object();
        result["format"] = JsonValue(rust.image.format_name());
        result["bits"] = JsonValue(static_cast<std::uint64_t>(rust.image.bits()));
        result["symbols"] = JsonValue(static_cast<std::uint64_t>(rust.image.symbols().size()));
        JsonValue demangled = JsonValue::array();
        for (const auto& symbol : rust.symbols) {
            JsonValue entry = JsonValue::object();
            entry["mangled"] = JsonValue(symbol.mangled);
            entry["demangled"] = JsonValue(symbol.demangled);
            entry["crate"] = JsonValue(symbol.crate);
            entry["v0"] = JsonValue(symbol.is_v0);
            demangled.push(std::move(entry));
        }
        result["rust_symbols"] = std::move(demangled);
        result["strings"] = strings_to_json(rust.strings);
        result["vtables"] = vtables_to_json(rust.vtables);
        result["tagged_unions"] = JsonValue(static_cast<std::uint64_t>(rust.tagged_unions.size()));
        result["niches"] = JsonValue(static_cast<std::uint64_t>(rust.niches.size()));
        return result;
    }
    if (method == "inspect" || method == "typemorph.inspect") {
        auto file = json_string_field(params, "file");
        if (!file) return file.error();
        auto view_result = BinaryView::open(file.value());
        if (!view_result) return view_result.error();
        auto view = std::move(view_result).value();
        infer::DiffOptions options;
        options.confidence_threshold = 0.50;
        infer::DiffEngine engine(options);
        auto sample = infer::Sample{view, file.value(), std::nullopt};
        auto inference = engine.infer(std::span<const infer::Sample>(&sample, 1));
        if (!inference) return inference.error();
        JsonValue result = inference_to_json(inference.value());
        result["source"] = JsonValue(file.value());
        return result;
    }
    if (method == "unxor" || method == "typemorph.unxor") {
        auto file = json_string_field(params, "file");
        if (!file) return file.error();
        auto view_result = BinaryView::open(file.value());
        if (!view_result) return view_result.error();
        const auto& view = view_result.value();

        std::vector<deobf::XorCandidate> candidates;
        if (auto key_hex = json_string_field(params, "key", false); key_hex && !key_hex.value().empty()) {
            auto key_bytes = parse_hex_string(key_hex.value());
            if (!key_bytes) return key_bytes.error();
            deobf::Unxorer unxorer;
            auto mode = key_bytes.value().size() == 1 ? deobf::XorMode::single_byte : deobf::XorMode::multi_byte;
            auto decrypted = unxorer.decrypt(view, key_bytes.value(), mode);
            deobf::XorCandidate cand;
            cand.key = std::move(key_bytes).value();
            cand.mode = mode;
            cand.confidence = 1.0;
            cand.entropy = core::shannon_entropy(decrypted.bytes());
            cand.printable_ratio = 1.0;
            std::string preview_text;
            for (std::size_t i = 0; i < std::min<std::size_t>(decrypted.size(), 64); ++i) {
                uint8_t c = decrypted.bytes()[i];
                preview_text.push_back((c >= 0x20 && c <= 0x7E) ? static_cast<char>(c) : '.');
            }
            cand.preview = std::move(preview_text);
            cand.rationale = "User-specified key";
            cand.decrypted = std::move(decrypted);
            candidates.push_back(std::move(cand));
        } else {
            deobf::Unxorer unxorer;
            candidates = unxorer.crack(view);
        }

        if (auto out_path = json_string_field(params, "out", false); out_path && !out_path.value().empty() && !candidates.empty()) {
            auto written = write_binary_file(out_path.value(), candidates.front().decrypted.bytes());
            if (!written) return written.error();
        }

        JsonValue result = JsonValue::object();
        result["file"] = JsonValue(file.value());
        result["candidates"] = xor_candidates_to_json(candidates);
        return result;
    }
    if (method == "strings" || method == "typemorph.strings") {
        auto file = json_string_field(params, "file");
        if (!file) return file.error();
        auto view_result = BinaryView::open(file.value());
        if (!view_result) return view_result.error();
        deobf::StringScanOptions options;
        if (const auto* min_len = params.find("min_len")) {
            if (const auto number = min_len->as_int()) options.min_length = static_cast<std::size_t>(*number);
        }
        deobf::StringRevealer revealer(options);
        auto strings = revealer.extract(view_result.value());
        JsonValue result = JsonValue::object();
        result["file"] = JsonValue(file.value());
        result["strings"] = extracted_strings_to_json(strings);
        return result;
    }
    if (method == "devirt" || method == "typemorph.devirt") {
        auto file = json_string_field(params, "file");
        if (!file) return file.error();
        auto view_result = BinaryView::open(file.value());
        if (!view_result) return view_result.error();
        auto image_result = core::ExecutableImage::parse(view_result.value());
        if (!image_result) return image_result.error();
        deobf::DevirtOptions options;
        if (const auto* min_h = params.find("min_handlers")) {
            if (const auto number = min_h->as_int()) options.min_handlers = static_cast<std::size_t>(*number);
        }
        deobf::Devirtualizer devirt(options);
        auto instances = devirt.analyze(image_result.value());
        JsonValue result = JsonValue::object();
        result["file"] = JsonValue(file.value());
        result["instances"] = devirt_instances_to_json(instances);
        return result;
    }
    if (method == "entropy" || method == "typemorph.entropy") {
        auto file = json_string_field(params, "file");
        if (!file) return file.error();
        auto view_result = BinaryView::open(file.value());
        if (!view_result) return view_result.error();
        const auto& view = view_result.value();
        std::size_t block_size = 512;
        if (const auto* bs = params.find("block_size")) {
            if (const auto number = bs->as_int()) block_size = static_cast<std::size_t>(*number);
        } else {
            if (view.size() > 48 * 512) {
                block_size = (view.size() + 31) / 32;
                block_size = ((block_size + 63) / 64) * 64;
            } else if (view.size() < 16 * 512) {
                block_size = std::max<std::size_t>(16, view.size() / 16);
            }
        }
        auto blocks_res = core::block_entropy(view.bytes(), block_size);
        if (!blocks_res) return blocks_res.error();
        const auto& blocks = blocks_res.value();
        const double total_entropy = core::shannon_entropy(view.bytes());
        double min_ent = 8.0, max_ent = 0.0, sum_ent = 0.0;
        for (double ent : blocks) {
            if (ent < min_ent) min_ent = ent;
            if (ent > max_ent) max_ent = ent;
            sum_ent += ent;
        }
        const double mean_ent = blocks.empty() ? 0.0 : sum_ent / static_cast<double>(blocks.size());

        JsonValue doc = JsonValue::object();
        doc["file"] = JsonValue(file.value());
        doc["size"] = JsonValue(view.size());
        doc["total_entropy"] = JsonValue(total_entropy);
        doc["min_entropy"] = JsonValue(min_ent);
        doc["max_entropy"] = JsonValue(max_ent);
        doc["mean_entropy"] = JsonValue(mean_ent);
        doc["block_size"] = JsonValue(static_cast<std::uint64_t>(block_size));
        JsonValue json_blocks = JsonValue::array();
        for (std::size_t i = 0; i < blocks.size(); ++i) {
            JsonValue b = JsonValue::object();
            const std::uint64_t offset = static_cast<std::uint64_t>(i) * block_size;
            const std::uint64_t end = std::min<std::uint64_t>(offset + block_size, view.size());
            b["offset"] = JsonValue(offset);
            b["size"] = JsonValue(end - offset);
            b["entropy"] = JsonValue(blocks[i]);
            b["classification"] = JsonValue(std::string(core::entropy_label(blocks[i])));
            json_blocks.push(std::move(b));
        }
        doc["blocks"] = std::move(json_blocks);
        return doc;
    }
    if (method == "sig" || method == "typemorph.sig") {
        auto file = json_string_field(params, "file");
        if (!file) return file.error();
        auto view_result = BinaryView::open(file.value());
        if (!view_result) return view_result.error();
        const auto& view = view_result.value();
        std::string rule_name = json_string_field(params, "name", false).value_or("");
        if (rule_name.empty()) {
            std::filesystem::path p(file.value());
            std::string stem = p.stem().string();
            for (char c : stem) {
                if (std::isalnum(static_cast<unsigned char>(c)) || c == '_') rule_name.push_back(c);
                else rule_name.push_back('_');
            }
            if (rule_name.empty() || std::isdigit(static_cast<unsigned char>(rule_name.front()))) {
                rule_name = "typemorph_" + rule_name;
            }
        }
        std::string magic_hex;
        if (view.size() >= 4) {
            auto slice = view.slice_unchecked(0, 4);
            magic_hex = to_hex_string(slice);
        }
        deobf::StringScanOptions str_opts;
        str_opts.min_length = 5;
        deobf::StringRevealer revealer(str_opts);
        auto extracted = revealer.extract(view);
        std::vector<std::string> rule_strings;
        for (const auto& s : extracted) {
            if (s.value.size() >= 6 && s.confidence >= 0.85) {
                rule_strings.push_back(s.value);
                if (rule_strings.size() >= 6) break;
            }
        }
        std::ostringstream yara;
        yara << "rule " << rule_name << " {\n"
             << "    meta:\n"
             << "        description = \"Generated by TypeMorph Binary Signature Engine\"\n"
             << "        generator = \"TypeMorph " << kVersion << "\"\n"
             << "        target_file = \"" << json_escape(file.value()) << "\"\n"
             << "        target_size = " << view.size() << "\n"
             << "    strings:\n";
        if (!magic_hex.empty()) {
            yara << "        $magic = { ";
            for (std::size_t i = 0; i < magic_hex.size(); i += 2) yara << magic_hex[i] << magic_hex[i + 1] << " ";
            yara << "} // offset 0x0\n";
        }
        int str_idx = 0;
        for (const auto& str_val : rule_strings) {
            yara << "        $s" << str_idx++ << " = \"" << json_escape(str_val) << "\" ascii\n";
        }
        yara << "    condition:\n";
        if (!magic_hex.empty()) {
            yara << "        $magic at 0";
            if (!rule_strings.empty()) yara << " and " << (rule_strings.size() > 2 ? "2 of ($s*)" : "all of ($s*)");
        } else if (!rule_strings.empty()) {
            yara << "        " << (rule_strings.size() > 2 ? "2 of ($s*)" : "all of ($s*)");
        } else {
            yara << "        filesize == " << view.size();
        }
        yara << "\n}\n";
        JsonValue doc = JsonValue::object();
        doc["rule_name"] = JsonValue(rule_name);
        doc["target_file"] = JsonValue(file.value());
        doc["target_size"] = JsonValue(view.size());
        doc["yara_rule"] = JsonValue(yara.str());
        return doc;
    }
    if (method == "crypto" || method == "typemorph.crypto") {
        auto file = json_string_field(params, "file");
        if (!file) return file.error();
        auto view_result = BinaryView::open(file.value());
        if (!view_result) return view_result.error();
        const auto& view = view_result.value();
        crypto::CryptoScanOptions opts;
        crypto::CryptoScanner scanner(opts);
        auto matches = scanner.scan(view);

        JsonValue doc = JsonValue::object();
        doc["file"] = JsonValue(file.value());
        doc["size"] = JsonValue(view.size());
        doc["match_count"] = JsonValue(static_cast<std::uint64_t>(matches.size()));
        JsonValue array = JsonValue::array();
        for (const auto& m : matches) {
            JsonValue entry = JsonValue::object();
            entry["offset"] = JsonValue(m.offset);
            entry["size"] = JsonValue(static_cast<std::uint64_t>(m.size));
            entry["algorithm"] = JsonValue(m.algorithm);
            entry["role"] = JsonValue(m.role);
            entry["category"] = JsonValue(std::string(crypto::to_string(m.category)));
            entry["endianness"] = JsonValue(m.endianness);
            entry["confidence"] = JsonValue(m.confidence);
            entry["description"] = JsonValue(m.description);
            array.push(std::move(entry));
        }
        doc["matches"] = std::move(array);
        return doc;
    }
    if (method == "diff" || method == "typemorph.diff") {
        auto file_a = json_string_field(params, "file_a");
        if (!file_a) return file_a.error();
        auto file_b = json_string_field(params, "file_b");
        if (!file_b) return file_b.error();
        auto view_a = BinaryView::open(file_a.value());
        if (!view_a) return view_a.error();
        auto view_b = BinaryView::open(file_b.value());
        if (!view_b) return view_b.error();

        diff::BinaryDiffEngine engine;
        auto res = engine.compare(view_a.value(), view_b.value(), file_a.value(), file_b.value());

        JsonValue doc = JsonValue::object();
        doc["file_a"] = JsonValue(res.file_a);
        doc["file_b"] = JsonValue(res.file_b);
        doc["size_a"] = JsonValue(res.size_a);
        doc["size_b"] = JsonValue(res.size_b);
        doc["size_delta"] = JsonValue(res.size_delta);
        doc["entropy_a"] = JsonValue(res.entropy_a);
        doc["entropy_b"] = JsonValue(res.entropy_b);
        doc["similarity"] = JsonValue(res.similarity);
        doc["both_executables"] = JsonValue(res.both_executables);
        if (res.both_executables) {
            doc["format_a"] = JsonValue(res.format_a);
            doc["format_b"] = JsonValue(res.format_b);
            JsonValue secs = JsonValue::array();
            for (const auto& s : res.section_diffs) {
                JsonValue entry = JsonValue::object();
                entry["name"] = JsonValue(s.name);
                entry["status"] = JsonValue(s.status);
                entry["size_a"] = JsonValue(s.size_a);
                entry["size_b"] = JsonValue(s.size_b);
                entry["entropy_a"] = JsonValue(s.entropy_a);
                entry["entropy_b"] = JsonValue(s.entropy_b);
                secs.push(std::move(entry));
            }
            doc["sections"] = std::move(secs);

            JsonValue syms = JsonValue::array();
            for (const auto& s : res.symbol_diffs) {
                JsonValue entry = JsonValue::object();
                entry["name"] = JsonValue(s.name);
                entry["status"] = JsonValue(s.status);
                entry["addr_a"] = JsonValue(s.addr_a);
                entry["addr_b"] = JsonValue(s.addr_b);
                syms.push(std::move(entry));
            }
            doc["symbols"] = std::move(syms);
        }
        JsonValue ranges = JsonValue::array();
        for (const auto& r : res.ranges) {
            JsonValue entry = JsonValue::object();
            entry["offset_a"] = JsonValue(r.offset_a);
            entry["size_a"] = JsonValue(r.size_a);
            entry["offset_b"] = JsonValue(r.offset_b);
            entry["size_b"] = JsonValue(r.size_b);
            entry["kind"] = JsonValue(r.kind);
            ranges.push(std::move(entry));
        }
        doc["ranges"] = std::move(ranges);
        return doc;
    }
    err << "TypeMorph: unknown JSON-RPC method " << method << '\n';
    return make_error(ErrorCode::not_found, "unknown method: " + method);
}

int command_serve(const Arguments& args, std::ostream& out, std::ostream& err) {
    if (args.has("help")) {
        out << command_help("serve");
        return 0;
    }
    if (!args.has("stdio")) {
        err << usage_error("only the --stdio transport is supported") << '\n';
        return 2;
    }

    std::string line;
    while (std::getline(std::cin, line)) {
        if (line.empty()) continue;
        auto request = parse_json(line);
        if (!request) {
            out << rpc_error(JsonValue(nullptr), -32700, "parse error: " + request.error().message)
                       .dump(0)
                << '\n';
            out.flush();
            continue;
        }
        const auto* object = request.value().as_object();
        if (object == nullptr) {
            out << rpc_error(JsonValue(nullptr), -32600, "invalid request").dump(0) << '\n';
            out.flush();
            continue;
        }

        const JsonValue* id = request.value().find("id");
        const bool notification = id == nullptr;
        JsonValue id_value = notification ? JsonValue(nullptr) : *id;

        const auto* method_value = request.value().find("method");
        const auto* method = method_value ? method_value->as_string() : nullptr;
        if (method == nullptr) {
            if (!notification) {
                out << rpc_error(id_value, -32600, "missing method").dump(0) << '\n';
                out.flush();
            }
            continue;
        }

        const JsonValue* params = request.value().find("params");
        static const JsonValue empty_params = JsonValue::object();
        auto dispatch = rpc_dispatch(*method, params != nullptr ? *params : empty_params, err);
        if (notification) continue;  // JSON-RPC notifications never receive a response
        if (!dispatch) {
            const int code = dispatch.error().code == ErrorCode::not_found ? -32601 : -32000;
            out << rpc_error(id_value, code, dispatch.error().message).dump(0) << '\n';
        } else {
            out << rpc_result(id_value, std::move(dispatch).value()).dump(0) << '\n';
        }
        out.flush();
    }
    return 0;
}

}  // namespace

Application::Application(std::ostream& out, std::ostream& err, AppConfig config)
    : out_(out), err_(err), config_(std::move(config)) {}

int Application::run(const std::vector<std::string>& args) {
    std::vector<std::string_view> views;
    views.reserve(args.size());
    for (const auto& arg : args) views.emplace_back(arg);
    return run(std::span<const std::string_view>(views.data(), views.size()));
}

int Application::run(std::span<const std::string_view> args) {
    if (args.empty()) {
        out_ << command_help("");
        return 0;
    }
    const std::string command(args.front());
    const auto rest = args.subspan(1);

    if (command == "help" || command == "--help" || command == "-h") {
        if (!rest.empty()) {
            out_ << command_help(rest.front());
        } else {
            out_ << command_help("");
        }
        return 0;
    }
    if (command == "version" || command == "--version") {
        out_ << version_line() << '\n';
        return 0;
    }

    if (command == "infer") {
        auto parsed = parse_arguments(
            rest, {"format", "out", "min-array-elements", "confidence-threshold", "max-fields",
                   "endian"},
            {}, 0, 4096);
        if (!parsed) {
            err_ << usage_error(parsed.error().message) << '\n';
            return 2;
        }
        return command_infer(parsed.value(), out_, err_);
    }
    if (command == "inspect") {
        auto parsed = parse_arguments(
            rest, {"width", "height"}, {"render-once", "no-tui"}, 0, 1);
        if (!parsed) {
            err_ << usage_error(parsed.error().message) << '\n';
            return 2;
        }
        return command_inspect(parsed.value(), out_, err_);
    }
    if (command == "rust") {
        auto parsed = parse_arguments(
            rest, {"extract-strings", "dump-vtables", "emit-types"},
            {"demangle", "enums"}, 0, 1);
        if (!parsed) {
            err_ << usage_error(parsed.error().message) << '\n';
            return 2;
        }
        return command_rust(parsed.value(), out_, err_);
    }
    if (command == "hybrid") {
        auto parsed = parse_arguments(rest, {"section", "format", "out"}, {}, 0, 1);
        if (!parsed) {
            err_ << usage_error(parsed.error().message) << '\n';
            return 2;
        }
        return command_hybrid(parsed.value(), out_, err_);
    }
    if (command == "serve") {
        auto parsed = parse_arguments(rest, {}, {"stdio"}, 0, 0);
        if (!parsed) {
            err_ << usage_error(parsed.error().message) << '\n';
            return 2;
        }
        return command_serve(parsed.value(), out_, err_);
    }
    if (command == "unxor") {
        auto parsed = parse_arguments(
            rest, {"key", "out", "min-key-length", "max-key-length"},
            {}, 1, 1);
        if (!parsed) {
            err_ << usage_error(parsed.error().message) << '\n';
            return 2;
        }
        return command_unxor(parsed.value(), out_, err_);
    }
    if (command == "strings") {
        auto parsed = parse_arguments(
            rest, {"min-len"},
            {"no-stack", "no-xor", "no-utf16"}, 1, 1);
        if (!parsed) {
            err_ << usage_error(parsed.error().message) << '\n';
            return 2;
        }
        return command_strings(parsed.value(), out_, err_);
    }
    if (command == "devirt") {
        auto parsed = parse_arguments(
            rest, {"min-handlers"},
            {}, 1, 1);
        if (!parsed) {
            err_ << usage_error(parsed.error().message) << '\n';
            return 2;
        }
        return command_devirt(parsed.value(), out_, err_);
    }
    if (command == "entropy") {
        auto parsed = parse_arguments(
            rest, {"block-size"},
            {}, 1, 1);
        if (!parsed) {
            err_ << usage_error(parsed.error().message) << '\n';
            return 2;
        }
        return command_entropy(parsed.value(), out_, err_);
    }
    if (command == "sig") {
        auto parsed = parse_arguments(
            rest, {"name", "out"},
            {}, 1, 1);
        if (!parsed) {
            err_ << usage_error(parsed.error().message) << '\n';
            return 2;
        }
        return command_sig(parsed.value(), out_, err_);
    }
    if (command == "crypto") {
        auto parsed = parse_arguments(
            rest, {},
            {}, 1, 1);
        if (!parsed) {
            err_ << usage_error(parsed.error().message) << '\n';
            return 2;
        }
        return command_crypto(parsed.value(), out_, err_);
    }
    if (command == "diff") {
        auto parsed = parse_arguments(
            rest, {},
            {}, 2, 2);
        if (!parsed) {
            err_ << usage_error(parsed.error().message) << '\n';
            return 2;
        }
        return command_diff(parsed.value(), out_, err_);
    }

    err_ << "TypeMorph: unknown command '" << command << "'\nTry 'typemorph help'.\n";
    return 2;
}

int run_cli(int argc, char** argv) {
    Application application(std::cout, std::cerr);
    std::vector<std::string> args;
    args.reserve(argc > 1 ? static_cast<std::size_t>(argc - 1) : 0U);
    for (int index = 1; index < argc; ++index) args.emplace_back(argv[index]);
    return application.run(args);
}

}  // namespace typemorph::cli
