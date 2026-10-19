#include "typemorph/cli/app.hpp"

#include "typemorph/cli/json.hpp"
#include "typemorph/core/binary_view.hpp"
#include "typemorph/core/entropy.hpp"
#include "typemorph/core/executable.hpp"
#include "typemorph/core/result.hpp"
#include "typemorph/crypto/crypto_scanner.hpp"
#include "typemorph/crypto/aes_recovery.hpp"
#include "typemorph/deobf/api_hash_resolver.hpp"
#include "typemorph/deobf/cff_reconstructor.hpp"
#include "typemorph/deobf/devirtualizer.hpp"
#include "typemorph/deobf/opaque_predicates.hpp"
#include "typemorph/deobf/strings.hpp"
#include "typemorph/deobf/unxorer.hpp"
#include "typemorph/infer/bitfield_detector.hpp"
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
#include "typemorph/go/go_analyzer.hpp"
#include "typemorph/pe/rich_header.hpp"
#include "typemorph/abi/calling_convention.hpp"
#include "typemorph/rtti/rtti_analyzer.hpp"
#include "typemorph/security/security_analyzer.hpp"
#include "typemorph/dotnet/dotnet_analyzer.hpp"
#include "typemorph/dotnet/dotnet_deobf.hpp"
#include "typemorph/lua/lua_decompiler.hpp"
#include "typemorph/decompile/c_decompiler.hpp"
#include "typemorph/derust/rust_source.hpp"
#include "typemorph/detect/detect_engine.hpp"
#include "typemorph/pe/iat_reconstructor.hpp"
#include "typemorph/tui/dashboard.hpp"
#include "typemorph/delphi/delphi_analyzer.hpp"
#include "typemorph/dex/dex_analyzer.hpp"
#include "typemorph/vb/vb_analyzer.hpp"
#include "typemorph/autoit/autoit_decompiler.hpp"
#include "typemorph/unpack/vfs_extractor.hpp"
#ifdef _WIN32
#include "typemorph/gui/studio_app.hpp"
#endif

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

    if (!parsed.has("help") && parsed.positional.size() < min_positional) {
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
    if (command == "cff") {
        return "Usage: typemorph cff <binary> [--function=VA] [--format=dot|mermaid|json] [--json]\n"
               "Reconstruct Control Flow Flattening (CFF) state transitions and unflatten CFG.\n";
    }
    if (command == "apihash") {
        return "Usage: typemorph apihash <binary|hash> [--json]\n"
               "Resolves API hashes or scans binary for obfuscated API calls (ROR13, DJB2, SDBM, FNV-1a, CRC32).\n";
    }
    if (command == "opaque") {
        return "Usage: typemorph opaque <binary> [--json]\n"
               "Scans binary for x86/x64 invariant opaque predicates and dead branches.\n";
    }
    if (command == "rtti") {
        return "Usage: typemorph rtti <binary> [--format=cpp|json] [--json]\n"
               "Reconstruct C++ polymorphic class names, inheritance hierarchy, and vftables from RTTI.\n";
    }
    if (command == "go") {
        return "Usage: typemorph go <binary> [--source] [--out=FILE] [--json]\n"
               "Reconstruct Golang functions, packages, structs, interfaces, itabs, and Go source code from stripped binaries.\n";
    }
    if (command == "rich") {
        return "Usage: typemorph rich <binary> [--json]\n"
               "Extract and decode MSVC Rich Header compiler artifacts, tool IDs, and build fingerprints.\n";
    }
    if (command == "checksec") {
        return "Usage: typemorph checksec <binary> [--json]\n"
               "Inspect binary security mitigations (ASLR, DEP, CFG, SafeSEH, CET), packers, and section anomalies.\n";
    }
    if (command == "abi") {
        return "Usage: typemorph abi <binary> [--function=VA] [--json]\n"
               "Classify calling conventions (__cdecl, __stdcall, __fastcall, __thiscall, __win64, __sysv), argument registers, and recover C prototypes.\n";
    }
    if (command == "csharp" || command == "dotnet") {
        return "Usage: typemorph csharp <binary> [--out=FILE] [--json]\n"
               "Extract ECMA-335 CLI metadata, TypeDef, MethodDef, Field tables and decompile C# source code.\n";
    }
    if (command == "decompile") {
        return "Usage: typemorph decompile <binary> [--function=VA] [--lang=c|rust] [--out=FILE] [--json]\n"
               "Decompile machine code into structured C pseudocode, infer struct layouts, or reconstruct Rust code.\n";
    }
    if (command == "detect" || command == "die") {
        return "Usage: typemorph detect <binary> [--json]\n"
               "Deep compiler, linker, packer, protector, and installer detection (DIE Engine style).\n";
    }
    if (command == "fixiat" || command == "importfix") {
        return "Usage: typemorph fixiat <dump.exe> [--out=fixed.exe] [--section=.typem] [--no-trace] [--json]\n"
               "Reconstruct corrupted/dumped PE Import Address Tables (IAT), trace stubs, and rebuild PE import directory.\n";
    }
    if (command == "classinformer" || command == "classes") {
        return "Usage: typemorph classinformer <binary> [--format=cpp|csv|json] [--json]\n"
               "ClassInformer RTTI explorer: discovers MSVC/Itanium C++ polymorphic classes, CompleteObjectLocators, vftables, and class hierarchies.\n";
    }
    if (command == "sigmake" || command == "sigmaker") {
        return "Usage: typemorph sigmake <binary> [--function=VA] [--format=ida|yara|byte|json] [--min-len=N] [--json]\n"
               "Signature Maker: generates robust byte patterns with wildcards ('??') across relocations and immediate offsets for subroutines.\n";
    }
    if (command == "applycalletype" || command == "applycalletypeex") {
        return "Usage: typemorph applycalletype <binary> [--function=VA] [--apply-ida] [--json]\n"
               "ApplyCalleeType: resolves call sites, matches callee prototypes and calling conventions, and propagates argument types.\n";
    }
    if (command == "dumpsubs" || command == "subsdump") {
        return "Usage: typemorph dumpsubs <binary> [--out=subs.csv] [--min-size=N] [--json]\n"
               "Dump Subroutines: extracts all function addresses, sizes, names, calling conventions, and prototypes into CSV/JSON.\n";
    }
    if (command == "dotnet-clean" || command == "dotnet-deobf" || command == "deobf-dotnet") {
        return "Usage: typemorph dotnet-clean <assembly.exe> [--out=clean.cs] [--json]\n"
               "Advanced .NET Deobfuscator: inlines ConfuserEx/.NET Reactor proxy calls, decrypts strings, and kills switch dispatchers.\n";
    }
    if (command == "lua" || command == "luajit") {
        return "Usage: typemorph lua <bytecode.luac> [--disasm] [--out=decompiled.lua] [--json]\n"
               "Lua & LuaJIT Bytecode Decompiler: decompiles Lua 5.1/5.2/5.3/5.4 and LuaJIT 2.0/2.1 chunks.\n";
    }
    if (command == "aes-recovery" || command == "time-aes" || command == "aesfind") {
        return "Usage: typemorph aes-recovery <binary> [--json]\n"
               "AES Key Recovery & White-box Analyzer: recovers master keys from expanded key schedules, inverts round keys, and identifies White-box AES T-Boxes.\n";
    }
    if (command == "delphi" || command == "dede" || command == "idr") {
        return "Usage: typemorph delphi <binary> [--pascal] [--json]\n"
               "Delphi / C++Builder VCL & Form Rescuer: extracts DFM resources, maps GUI events to code addresses, and reconstructs Pascal units.\n";
    }
    if (command == "dex" || command == "jadx" || command == "dalvik") {
        return "Usage: typemorph dex <classes.dex> [--java] [--json]\n"
               "Android Dalvik Executable (DEX) & Java Decompiler Engine (JADX style): decompiles Dalvik bytecode to Java classes.\n";
    }
    if (command == "vb" || command == "vbdecompiler" || command == "vb6") {
        return "Usage: typemorph vb <binary> [--source] [--json]\n"
               "Visual Basic 5.0/6.0 Native & P-Code Analyzer: extracts forms, maps event procedures, and reconstructs VB source code.\n";
    }
    if (command == "autoit" || command == "exe2aut" || command == "au3") {
        return "Usage: typemorph autoit <binary> [--out=script.au3] [--json]\n"
               "AutoIt v3 Script Extractor & Decompiler (Exe2Aut engine): extracts embedded .au3 scripts and decodes tokens.\n";
    }
    if (command == "vfs-extract" || command == "spoondec" || command == "evbunpack") {
        return "Usage: typemorph vfs-extract <binary> [--json]\n"
               "Virtual Filesystem (VFS) Extractor (spoondec / evbunpack): extracts virtual files & registry from Spoon Studio, Enigma Virtual Box, and BoxedApp.\n";
    }
    if (command == "studio" || command == "gui" || command == "dnspy") {
        return "Usage: typemorph studio [assembly.exe]\n"
               "Launch standalone native desktop decompiler & deobfuscator GUI (dnSpy / dotPeek style).\n";
    }
    if (command == "serve") {
        return "Usage: typemorph serve --stdio\n"
               "Line-delimited JSON-RPC 2.0 daemon for Ghidra/IDA/editor integration.\n";
    }
    return "TypeMorph - binary structure inference, Rust recovery & deobfuscation.\n\n"
           "Commands:\n"
           "  studio [assembly]    Launch native desktop GUI decompiler (dnSpy / dotPeek architecture)\n"
           "  inspect <file>       Interactive TUI dashboard\n"
           "  infer <samples...>   Differential format inference\n"
           "  rust <binary>        Rust semantic recovery\n"
           "  decompile <binary>   Structured C / Rust decompiler & struct layout reconstructor\n"
           "  csharp <binary>      .NET / CLR assembly metadata extractor & C# code decompiler\n"
           "  dotnet-clean <bin>   Advanced .NET deobfuscator (inlines proxies, decrypts strings, kills switch)\n"
           "  delphi <binary>      Delphi / C++Builder VCL Form Rescuer & event handler mapper (IDR / DeDe)\n"
           "  dex <classes.dex>    Android Dalvik DEX & Java decompiler engine (JADX style)\n"
           "  vb <binary>          Visual Basic 5.0/6.0 P-Code & Native analyzer (VB Decompiler)\n"
           "  autoit <binary>      AutoIt v3 Script Extractor & token decompiler (Exe2Aut)\n"
           "  vfs-extract <bin>    Virtual Filesystem Extractor (Spoon Studio, Enigma Virtual Box, BoxedApp)\n"
           "  lua <bytecode.luac>  Lua & LuaJIT bytecode decompiler and disassembler (5.1-5.4, LuaJIT 2.x)\n"
           "  aes-recovery <bin>   AES key schedule recovery, master key inversion & White-box T-Boxes\n"
           "  detect <binary>      Deep compiler, packer & protection identifier (DIE engine)\n"
           "  fixiat <dump.exe>    Reconstruct PE Import Address Table (IAT) & rebuild import directory\n"
           "  hybrid <binary>      Infer an embedded executable section\n"
           "  unxor <file>         XOR key discovery and deobfuscation\n"
           "  strings <file>       String revealer (ASCII, UTF-16, stack, XOR, base64)\n"
           "  devirt <binary>      Devirtualizer (VM dispatchers & handlers)\n"
           "  cff <binary>         Control flow unflattening & CFG recovery\n"
           "  apihash <file|hash>  Resolve API hashes & scan for hidden imports\n"
           "  opaque <binary>      Detect invariant opaque predicates & dead code\n"
           "  rtti <binary>        Reconstruct C++ RTTI classes & vftables\n"
           "  go <binary>          Recover Go functions, packages & pclntab symbols\n"
           "  rich <binary>        Decode MSVC Rich Header & compiler telemetry\n"
           "  checksec <binary>    Inspect binary hardening, packers & anomalies\n"
           "  abi <binary>         Classify calling conventions & recover C prototypes\n"
           "  classinformer <bin>  ClassInformer: RTTI class explorer, vftables & inheritance trees\n"
           "  sigmake <binary>     Signature Maker: generate IDA / YARA byte patterns with '??' wildcards\n"
           "  applycalletype <bin> ApplyCalleeType: cross-reference call sites & propagate callee prototypes\n"
           "  dumpsubs <binary>    Dump all subroutines, VAs, sizes, calling conventions to CSV/JSON\n"
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

    if (args.has("html")) {
        // Read the dnSpy / dotPeek UI template and output it or write to file
        const std::string template_path = "C:/Users/dev_null/.gemini/antigravity/brain/57049001-375c-4ba4-9c66-51b42c51d0e2/dnspy_studio.html";
        std::ifstream file(template_path);
        if (file) {
            std::string content((std::istreambuf_iterator<char>(file)), std::istreambuf_iterator<char>());
            if (auto out_path = args.get("out")) {
                auto wr = write_file(*out_path, content);
                if (!wr) {
                    err << "TypeMorph: failed to write HTML dashboard to " << *out_path << '\n';
                    return 1;
                }
                out << "TypeMorph dnSpy Studio UI exported to: " << *out_path << "\n";
                return 0;
            }
            out << content;
            return 0;
        }
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

int command_cff(const Arguments& args, std::ostream& out, std::ostream& err) {
    if (args.has("help") || args.positional.empty()) {
        out << "Usage: typemorph cff <file> [--function <va>] [--format dot|mermaid|json] [--json]\n\n"
            << "Detects and reconstructs Control Flow Flattening (CFF) state transition loops.\n"
            << "Recovers dispatcher state keys, eliminates the central switch dispatcher, and\n"
            << "outputs the unflattened control flow sequence as DOT, Mermaid, or JSON.\n";
        return 0;
    }
    const auto path = args.positional[0];
    auto view = BinaryView::open(path);
    if (!view) {
        err << "typemorph cff: " << format_error(view.error()) << '\n';
        return 1;
    }
    auto image_res = core::ExecutableImage::parse(view.value());
    if (!image_res) {
        err << "typemorph cff: " << format_error(image_res.error()) << '\n';
        return 1;
    }

    deobf::CffOptions opts;
    deobf::CffReconstructor reconstructor(opts);
    std::vector<deobf::CffFunction> fns;

    if (args.has("function")) {
        auto func_va_res = parse_u64(args.get_or("function", "0"), "function");
        if (!func_va_res) {
            err << "typemorph cff: " << format_error(func_va_res.error()) << '\n';
            return 1;
        }
        fns = reconstructor.analyze_function(image_res.value(), func_va_res.value());
    } else {
        fns = reconstructor.analyze(image_res.value());
    }

    const std::string fmt = args.get_or("format", "");
    const bool json_out = args.has("json") || fmt == "json";

    if (json_out) {
        JsonValue doc = JsonValue::object();
        doc["file"] = JsonValue(path);
        doc["count"] = JsonValue(static_cast<std::uint64_t>(fns.size()));
        JsonValue array = JsonValue::array();
        for (const auto& fn : fns) {
            JsonValue entry = JsonValue::object();
            entry["dispatcher_va"] = JsonValue(fn.dispatcher_va);
            entry["state_variable"] = JsonValue(fn.state_variable);
            entry["block_count"] = JsonValue(static_cast<std::uint64_t>(fn.blocks.size()));
            entry["transition_count"] = JsonValue(static_cast<std::uint64_t>(fn.transitions.size()));
            entry["confidence"] = JsonValue(fn.confidence);
            entry["rationale"] = JsonValue(fn.rationale);
            entry["dot"] = JsonValue(fn.to_dot());
            entry["mermaid"] = JsonValue(fn.to_mermaid());

            JsonValue blocks_arr = JsonValue::array();
            for (const auto& b : fn.blocks) {
                JsonValue blk = JsonValue::object();
                blk["state_id"] = JsonValue(static_cast<std::uint64_t>(b.state_id));
                blk["va"] = JsonValue(b.block_va);
                blk["size"] = JsonValue(static_cast<std::uint64_t>(b.size));
                blk["is_entry"] = JsonValue(b.is_entry);
                blk["is_exit"] = JsonValue(b.is_exit);
                blocks_arr.push(std::move(blk));
            }
            entry["blocks"] = std::move(blocks_arr);

            JsonValue trans_arr = JsonValue::array();
            for (const auto& t : fn.transitions) {
                JsonValue tr = JsonValue::object();
                tr["from"] = JsonValue(static_cast<std::uint64_t>(t.from_state));
                tr["to"] = JsonValue(static_cast<std::uint64_t>(t.to_state));
                trans_arr.push(std::move(tr));
            }
            entry["transitions"] = std::move(trans_arr);

            array.push(std::move(entry));
        }
        doc["functions"] = std::move(array);
        out << doc.dump(2) << '\n';
        return 0;
    }

    if (fmt == "dot") {
        for (const auto& fn : fns) {
            out << fn.to_dot() << '\n';
        }
        return 0;
    }

    if (fmt == "mermaid") {
        for (const auto& fn : fns) {
            out << fn.to_mermaid() << '\n';
        }
        return 0;
    }

    out << "TypeMorph Control Flow Flattening (CFF) Deobfuscator\n"
        << "  Target: " << path << "\n"
        << "  Flattened Functions Detected: " << fns.size() << "\n\n";

    if (fns.empty()) {
        out << "  No control flow flattening dispatchers detected.\n";
        return 0;
    }

    for (std::size_t i = 0; i < fns.size(); ++i) {
        const auto& fn = fns[i];
        char va_buf[64];
        std::snprintf(va_buf, sizeof(va_buf), "0x%llx", static_cast<unsigned long long>(fn.dispatcher_va));
        out << "Function #" << i + 1 << ": Dispatcher at " << va_buf
            << " (State Var: " << fn.state_variable << ", Confidence: "
            << std::fixed << std::setprecision(1) << (fn.confidence * 100.0) << "%)\n"
            << "  Blocks: " << fn.blocks.size() << " | Recovered Transitions: "
            << fn.transitions.size() << "\n"
            << "  " << fn.rationale << "\n";

        out << "  State Transitions (Reconstructed Sequence):\n";
        for (const auto& t : fn.transitions) {
            char t_buf[128];
            std::snprintf(t_buf, sizeof(t_buf), "    State 0x%X -> State 0x%X%s",
                          t.from_state, t.to_state,
                          t.condition.empty() ? "" : (" [" + t.condition + "]").c_str());
            out << t_buf << "\n";
        }
        out << "\n";
    }
    return 0;
}

int command_apihash(const Arguments& args, std::ostream& out, std::ostream& err) {
    if (args.has("help") || args.positional.empty()) {
        out << "Usage: typemorph apihash <file|hash> [--json]\n\n"
            << "Resolves API hashes or scans binary for obfuscated API calls.\n"
            << "Supports ROR13, DJB2, SDBM, FNV-1a, and CRC32 across standard Windows and POSIX APIs.\n";
        return 0;
    }

    const std::string& target = args.positional[0];
    deobf::ApiHashResolver resolver;

    bool is_number = false;
    std::uint32_t hash_val = 0;
    try {
        if (target.size() > 2 && target[0] == '0' && (target[1] == 'x' || target[1] == 'X')) {
            hash_val = static_cast<std::uint32_t>(std::stoul(target, nullptr, 16));
            is_number = true;
        } else if (!target.empty() && std::all_of(target.begin(), target.end(), [](unsigned char c) { return std::isdigit(c); })) {
            hash_val = static_cast<std::uint32_t>(std::stoul(target, nullptr, 10));
            is_number = true;
        }
    } catch (...) {
        is_number = false;
    }

    if (is_number) {
        auto matches = resolver.resolve(hash_val);
        if (args.has("json")) {
            JsonValue doc = JsonValue::object();
            doc["hash"] = JsonValue(static_cast<std::uint64_t>(hash_val));
            JsonValue array = JsonValue::array();
            for (const auto& m : matches) {
                JsonValue item = JsonValue::object();
                item["api"] = JsonValue(m.api_name);
                item["module"] = JsonValue(m.module_name);
                item["algorithm"] = JsonValue(to_string(m.algorithm));
                item["confidence"] = JsonValue(m.confidence);
                array.push(std::move(item));
            }
            doc["matches"] = std::move(array);
            out << doc.dump(2) << '\n';
            return 0;
        }

        out << "Resolving API Hash 0x" << std::hex << std::uppercase << hash_val << std::dec << ":\n";
        if (matches.empty()) {
            out << "  No matches found in API database.\n";
            return 0;
        }
        for (const auto& m : matches) {
            out << "  -> " << m.module_name << "!" << m.api_name
                << " (" << to_string(m.algorithm) << ", confidence "
                << std::fixed << std::setprecision(1) << (m.confidence * 100.0) << "%)\n";
        }
        return 0;
    }

    auto view = BinaryView::open(target);
    if (!view) {
        err << "typemorph apihash: " << format_error(view.error()) << '\n';
        return 1;
    }

    auto matches = resolver.scan(view.value());

    if (args.has("json")) {
        JsonValue doc = JsonValue::object();
        doc["file"] = JsonValue(target);
        doc["count"] = JsonValue(static_cast<std::int64_t>(matches.size()));
        JsonValue array = JsonValue::array();
        for (const auto& m : matches) {
            JsonValue item = JsonValue::object();
            item["offset"] = JsonValue(static_cast<std::uint64_t>(m.offset));
            item["hash"] = JsonValue(static_cast<std::uint64_t>(m.hash_value));
            item["api"] = JsonValue(m.api_name);
            item["module"] = JsonValue(m.module_name);
            item["algorithm"] = JsonValue(to_string(m.algorithm));
            item["confidence"] = JsonValue(m.confidence);
            array.push(std::move(item));
        }
        doc["matches"] = std::move(array);
        out << doc.dump(2) << '\n';
        return 0;
    }

    out << "TypeMorph API Hash Scanner\n"
        << "  Target: " << target << "\n"
        << "  Matches Detected: " << matches.size() << "\n\n";

    if (matches.empty()) {
        out << "  No known API hashes identified.\n";
        return 0;
    }

    for (const auto& m : matches) {
        char off_buf[32];
        char hash_buf[32];
        std::snprintf(off_buf, sizeof(off_buf), "0x%llx", static_cast<unsigned long long>(m.offset));
        std::snprintf(hash_buf, sizeof(hash_buf), "0x%08X", m.hash_value);
        out << "  [" << off_buf << "] " << hash_buf << " -> "
            << m.module_name << "!" << m.api_name
            << " (" << to_string(m.algorithm) << ")\n";
    }
    return 0;
}

int command_opaque(const Arguments& args, std::ostream& out, std::ostream& err) {
    if (args.has("help") || args.positional.empty()) {
        out << "Usage: typemorph opaque <file> [--json]\n\n"
            << "Scans executable binary for x86/x64 invariant opaque predicates and dead code branches.\n";
        return 0;
    }

    const std::string& path = args.positional[0];
    auto view = BinaryView::open(path);
    if (!view) {
        err << "typemorph opaque: " << format_error(view.error()) << '\n';
        return 1;
    }

    deobf::OpaquePredicateDetector detector;
    auto matches = detector.scan(view.value());

    if (args.has("json")) {
        JsonValue doc = JsonValue::object();
        doc["file"] = JsonValue(path);
        doc["count"] = JsonValue(static_cast<std::int64_t>(matches.size()));
        JsonValue array = JsonValue::array();
        for (const auto& m : matches) {
            JsonValue item = JsonValue::object();
            item["offset"] = JsonValue(static_cast<std::uint64_t>(m.offset));
            item["length"] = JsonValue(static_cast<std::uint64_t>(m.instruction_length));
            item["outcome"] = JsonValue(to_string(m.outcome));
            item["pattern"] = JsonValue(m.pattern_name);
            item["disassembly"] = JsonValue(m.disassembly_hint);
            item["rationale"] = JsonValue(m.rationale);
            item["confidence"] = JsonValue(m.confidence);
            array.push(std::move(item));
        }
        doc["predicates"] = std::move(array);
        out << doc.dump(2) << '\n';
        return 0;
    }

    out << "TypeMorph Opaque Predicate & Dead Code Detector\n"
        << "  Target: " << path << "\n"
        << "  Opaque Invariants Detected: " << matches.size() << "\n\n";

    if (matches.empty()) {
        out << "  No invariant opaque predicates detected.\n";
        return 0;
    }

    for (const auto& m : matches) {
        char off_buf[32];
        std::snprintf(off_buf, sizeof(off_buf), "0x%llx", static_cast<unsigned long long>(m.offset));
        out << "  [" << off_buf << "] " << m.disassembly_hint
            << " => " << (m.outcome == deobf::PredicateOutcome::always_true ? "ALWAYS TAKEN" : "NEVER TAKEN (DEAD)")
            << " (" << m.pattern_name << ")\n"
            << "     " << m.rationale << "\n";
    }
    return 0;
}

JsonValue rtti_classes_to_json(const std::string& path, const std::vector<rtti::RttiClass>& classes) {
    JsonValue doc = JsonValue::object();
    doc["file"] = JsonValue(path);
    doc["count"] = JsonValue(static_cast<std::int64_t>(classes.size()));
    JsonValue arr = JsonValue::array();
    for (const auto& cls : classes) {
        JsonValue c = JsonValue::object();
        c["name"] = JsonValue(cls.name);
        c["mangled_name"] = JsonValue(cls.mangled_name);
        c["vftable_va"] = JsonValue(cls.vftable_va);
        c["locator_va"] = JsonValue(cls.locator_va);
        c["confidence"] = JsonValue(cls.confidence);

        JsonValue bases = JsonValue::array();
        for (const auto& b : cls.base_classes) {
            JsonValue bj = JsonValue::object();
            bj["name"] = JsonValue(b.name);
            bj["mangled_name"] = JsonValue(b.mangled_name);
            bj["offset"] = JsonValue(static_cast<std::int64_t>(b.offset));
            bj["attributes"] = JsonValue(static_cast<std::uint64_t>(b.attributes));
            bases.push(std::move(bj));
        }
        c["base_classes"] = std::move(bases);

        JsonValue methods = JsonValue::array();
        for (const auto& m : cls.methods) {
            JsonValue mj = JsonValue::object();
            mj["slot"] = JsonValue(static_cast<std::uint64_t>(m.slot));
            mj["virtual_address"] = JsonValue(m.virtual_address);
            mj["name"] = JsonValue(m.name);
            methods.push(std::move(mj));
        }
        c["methods"] = std::move(methods);
        arr.push(std::move(c));
    }
    doc["classes"] = std::move(arr);
    return doc;
}

JsonValue security_report_to_json(const std::string& path, const security::SecurityReport& rep) {
    JsonValue doc = JsonValue::object();
    doc["file"] = JsonValue(path);
    doc["format"] = JsonValue(std::string(core::to_string(rep.format)));
    doc["bits"] = JsonValue(static_cast<std::uint64_t>(rep.bits));
    doc["entry_point"] = JsonValue(rep.entry_point);
    doc["entry_point_outside_code"] = JsonValue(rep.entry_point_outside_code);
    doc["has_tls_callbacks"] = JsonValue(rep.has_tls_callbacks);

    JsonValue mits = JsonValue::object();
    mits["aslr"] = JsonValue(rep.mitigations.aslr);
    mits["high_entropy_va"] = JsonValue(rep.mitigations.high_entropy_va);
    mits["dep_nx"] = JsonValue(rep.mitigations.dep_nx);
    mits["cfg"] = JsonValue(rep.mitigations.cfg);
    mits["cet_shadow_stack"] = JsonValue(rep.mitigations.cet_shadow_stack);
    mits["safe_seh"] = JsonValue(rep.mitigations.safe_seh);
    mits["isolated"] = JsonValue(rep.mitigations.isolated);
    mits["signed_binary"] = JsonValue(rep.mitigations.signed_binary);
    mits["pie"] = JsonValue(rep.mitigations.pie);
    mits["relro"] = JsonValue(rep.mitigations.relro);
    mits["stack_canary"] = JsonValue(rep.mitigations.stack_canary);
    doc["mitigations"] = std::move(mits);

    JsonValue packers = JsonValue::array();
    for (const auto& p : rep.packers) {
        JsonValue pj = JsonValue::object();
        pj["name"] = JsonValue(p.name);
        pj["confidence"] = JsonValue(p.confidence);
        pj["rationale"] = JsonValue(p.rationale);
        packers.push(std::move(pj));
    }
    doc["packers"] = std::move(packers);

    JsonValue anomalies = JsonValue::array();
    for (const auto& a : rep.section_anomalies) {
        JsonValue aj = JsonValue::object();
        aj["name"] = JsonValue(a.name);
        aj["virtual_address"] = JsonValue(a.virtual_address);
        aj["virtual_size"] = JsonValue(a.virtual_size);
        aj["file_offset"] = JsonValue(a.file_offset);
        aj["file_size"] = JsonValue(a.file_size);
        aj["is_wx"] = JsonValue(a.is_wx);
        aj["is_empty_raw"] = JsonValue(a.is_empty_raw);
        aj["expansion_ratio"] = JsonValue(a.expansion_ratio);
        aj["note"] = JsonValue(a.note);
        anomalies.push(std::move(aj));
    }
    doc["section_anomalies"] = std::move(anomalies);

    JsonValue overlay = JsonValue::object();
    overlay["present"] = JsonValue(rep.overlay.present);
    overlay["offset"] = JsonValue(rep.overlay.offset);
    overlay["size"] = JsonValue(rep.overlay.size);
    overlay["entropy"] = JsonValue(rep.overlay.entropy);
    doc["overlay"] = std::move(overlay);

    JsonValue anti = JsonValue::array();
    for (const auto& ind : rep.anti_analysis_indicators) {
        anti.push(JsonValue(ind));
    }
    doc["anti_analysis_indicators"] = std::move(anti);

    return doc;
}

int command_rtti(const Arguments& args, std::ostream& out, std::ostream& err) {
    if (args.has("help") || args.positional.empty()) {
        out << command_help("rtti");
        return 0;
    }

    const std::string& path = args.positional[0];
    auto view = BinaryView::open(path);
    if (!view) {
        err << "typemorph rtti: " << format_error(view.error()) << '\n';
        return 1;
    }

    rtti::RttiAnalyzer analyzer;
    auto classes = analyzer.analyze_view(view.value());

    std::string fmt = args.get_or("format", "");
    if (args.has("json") || fmt == "json") {
        auto doc = rtti_classes_to_json(path, classes);
        out << doc.dump(2) << '\n';
        return 0;
    }

    if (fmt == "cpp") {
        out << rtti::RttiAnalyzer::to_cpp_header(classes) << '\n';
        return 0;
    }

    out << "TypeMorph C++ RTTI & Class Hierarchy Reconstructor\n"
        << "  Target: " << path << "\n"
        << "  Polymorphic Classes Detected: " << classes.size() << "\n\n";

    if (classes.empty()) {
        out << "  No C++ RTTI CompleteObjectLocator or TypeDescriptor entries found.\n";
        return 0;
    }

    for (std::size_t i = 0; i < classes.size(); ++i) {
        const auto& cls = classes[i];
        char vf_buf[32], loc_buf[32];
        std::snprintf(vf_buf, sizeof(vf_buf), "0x%llx", static_cast<unsigned long long>(cls.vftable_va));
        std::snprintf(loc_buf, sizeof(loc_buf), "0x%llx", static_cast<unsigned long long>(cls.locator_va));

        out << "[" << (i + 1) << "] class " << cls.name;
        if (!cls.base_classes.empty()) {
            out << " : ";
            for (std::size_t b = 0; b < cls.base_classes.size(); ++b) {
                if (b > 0) out << ", ";
                out << "public " << cls.base_classes[b].name;
            }
        }
        out << "\n"
            << "     vftable: " << vf_buf << " | locator: " << loc_buf
            << " | confidence: " << std::fixed << std::setprecision(1) << (cls.confidence * 100.0) << "%\n";

        if (!cls.base_classes.empty()) {
            out << "     Base Classes:\n";
            for (const auto& b : cls.base_classes) {
                out << "       - " << b.name << " (offset " << b.offset << ")\n";
            }
        }
        if (!cls.methods.empty()) {
            out << "     Virtual Method Slots (" << cls.methods.size() << "):\n";
            for (const auto& m : cls.methods) {
                char m_buf[32];
                std::snprintf(m_buf, sizeof(m_buf), "0x%llx", static_cast<unsigned long long>(m.virtual_address));
                out << "       [" << m.slot << "] " << m_buf << ": " << m.name << "\n";
            }
        }
        out << "\n";
    }

    out << "(Tip: Use --format=cpp to generate C++ header definitions)\n";
    return 0;
}

int command_checksec(const Arguments& args, std::ostream& out, std::ostream& err) {
    if (args.has("help") || args.positional.empty()) {
        out << command_help("checksec");
        return 0;
    }

    const std::string& path = args.positional[0];
    auto view = BinaryView::open(path);
    if (!view) {
        err << "typemorph checksec: " << format_error(view.error()) << '\n';
        return 1;
    }

    security::SecurityAnalyzer analyzer;
    auto report = analyzer.analyze_view(view.value());

    if (args.has("json")) {
        auto doc = security_report_to_json(path, report);
        out << doc.dump(2) << '\n';
        return 0;
    }

    char ep_buf[32];
    std::snprintf(ep_buf, sizeof(ep_buf), "0x%llx", static_cast<unsigned long long>(report.entry_point));

    out << "TypeMorph Binary Hardening & Security Inspector (checksec)\n"
        << "  Target:      " << path << " (" << core::to_string(report.format) << ", " << report.bits << "-bit)\n"
        << "  Entry Point: " << ep_buf
        << (report.entry_point_outside_code ? " [WARNING: Outside code section!]" : " [Code section]") << "\n\n";

    out << "Mitigations & Protections:\n";
    const auto& m = report.mitigations;
    out << "  ASLR:                  " << (m.aslr ? "Enabled" : "Disabled") << "\n";
    out << "  High-Entropy VA:       " << (m.high_entropy_va ? "Enabled" : "Disabled") << "\n";
    out << "  DEP / NX:              " << (m.dep_nx ? "Enabled" : "Disabled") << "\n";
    out << "  Control Flow Guard:    " << (m.cfg ? "Enabled" : "Disabled") << "\n";
    out << "  CET Shadow Stack:      " << (m.cet_shadow_stack ? "Enabled" : "Disabled") << "\n";
    if (report.format == core::ImageFormat::pe) {
        out << "  SafeSEH:               " << (m.safe_seh ? "Enabled" : "Disabled / N/A") << "\n";
        out << "  Authenticode Signed:   " << (m.signed_binary ? "Signed" : "No signature") << "\n";
        out << "  TLS Callbacks:         " << (report.has_tls_callbacks ? "Present" : "None") << "\n";
    } else {
        out << "  PIE:                   " << (m.pie ? "Enabled" : "Disabled") << "\n";
        out << "  RELRO:                 " << (m.relro ? "Enabled" : "Disabled") << "\n";
        out << "  Stack Canary:          " << (m.stack_canary ? "Found" : "Not detected") << "\n";
    }

    out << "\nPackers & Protections Detected:\n";
    if (report.packers.empty()) {
        out << "  None detected (standard compiler output)\n";
    } else {
        for (const auto& p : report.packers) {
            out << "  - " << p.name << " (confidence "
                << std::fixed << std::setprecision(1) << (p.confidence * 100.0) << "%): "
                << p.rationale << "\n";
        }
    }

    out << "\nSection Anomalies:\n";
    if (report.section_anomalies.empty()) {
        out << "  None (W^X respected, normal section ratios)\n";
    } else {
        for (const auto& a : report.section_anomalies) {
            out << "  - Section '" << a.name << "': " << a.note;
            if (a.is_wx) out << " [W^X VIOLATION]";
            out << "\n";
        }
    }

    out << "\nOverlay Data:\n";
    if (!report.overlay.present) {
        out << "  None\n";
    } else {
        char ov_buf[32];
        std::snprintf(ov_buf, sizeof(ov_buf), "0x%llx", static_cast<unsigned long long>(report.overlay.offset));
        out << "  Present at offset " << ov_buf << " (" << report.overlay.size << " bytes, entropy: "
            << std::fixed << std::setprecision(2) << report.overlay.entropy << " - "
            << core::entropy_label(report.overlay.entropy) << ")\n";
    }

    out << "\nAnti-Analysis & Evasion Indicators:\n";
    if (report.anti_analysis_indicators.empty()) {
        out << "  None detected\n";
    } else {
        for (const auto& ind : report.anti_analysis_indicators) {
            out << "  - " << ind << "\n";
        }
    }

    return 0;
}

JsonValue go_report_to_json(const std::string& path, const golang::GoAnalysisReport& rep) {
    JsonValue doc = JsonValue::object();
    doc["file"] = JsonValue(path);
    doc["detected"] = JsonValue(rep.detected);
    doc["version"] = JsonValue(std::string(golang::to_string(rep.version)));
    doc["ptr_size"] = JsonValue(static_cast<std::uint64_t>(rep.ptr_size));
    doc["quantum"] = JsonValue(static_cast<std::uint64_t>(rep.quantum));
    doc["pclntab_va"] = JsonValue(rep.pclntab_va);
    doc["function_count"] = JsonValue(static_cast<std::uint64_t>(rep.functions.size()));
    doc["user_functions"] = JsonValue(static_cast<std::uint64_t>(rep.user_functions));
    doc["runtime_functions"] = JsonValue(static_cast<std::uint64_t>(rep.runtime_functions));
    doc["struct_count"] = JsonValue(static_cast<std::uint64_t>(rep.structs.size()));
    doc["interface_count"] = JsonValue(static_cast<std::uint64_t>(rep.interfaces.size()));
    doc["itab_count"] = JsonValue(static_cast<std::uint64_t>(rep.itabs.size()));
    doc["golang_source"] = JsonValue(rep.golang_source);

    JsonValue pkgs = JsonValue::array();
    for (const auto& pkg : rep.packages) {
        pkgs.push(JsonValue(pkg));
    }
    doc["packages"] = std::move(pkgs);

    JsonValue structs_arr = JsonValue::array();
    for (const auto& s : rep.structs) {
        JsonValue s_obj = JsonValue::object();
        s_obj["name"] = JsonValue(s.name);
        s_obj["size"] = JsonValue(s.size);
        s_obj["type_va"] = JsonValue(s.type_va);
        JsonValue flds = JsonValue::array();
        for (const auto& f : s.fields) {
            JsonValue f_obj = JsonValue::object();
            f_obj["name"] = JsonValue(f.name);
            f_obj["type"] = JsonValue(f.type_name);
            f_obj["offset"] = JsonValue(f.offset);
            flds.push(std::move(f_obj));
        }
        s_obj["fields"] = std::move(flds);
        structs_arr.push(std::move(s_obj));
    }
    doc["structs"] = std::move(structs_arr);

    JsonValue itabs_arr = JsonValue::array();
    for (const auto& itab : rep.itabs) {
        JsonValue itab_obj = JsonValue::object();
        itab_obj["interface"] = JsonValue(itab.interface_name);
        itab_obj["concrete_type"] = JsonValue(itab.concrete_type_name);
        itab_obj["itab_va"] = JsonValue(itab.itab_va);
        JsonValue methods = JsonValue::array();
        for (const auto& m : itab.methods) {
            JsonValue m_obj = JsonValue::object();
            m_obj["name"] = JsonValue(m.name);
            m_obj["va"] = JsonValue(m.fn_va);
            methods.push(std::move(m_obj));
        }
        itab_obj["methods"] = std::move(methods);
        itabs_arr.push(std::move(itab_obj));
    }
    doc["itabs"] = std::move(itabs_arr);

    JsonValue fns = JsonValue::array();
    for (const auto& fn : rep.functions) {
        JsonValue f = JsonValue::object();
        f["name"] = JsonValue(fn.name);
        f["package"] = JsonValue(fn.package_name);
        f["entry_va"] = JsonValue(fn.entry_va);
        fns.push(std::move(f));
    }
    doc["functions"] = std::move(fns);

    return doc;
}

int command_go(const Arguments& args, std::ostream& out, std::ostream& err) {
    if (args.has("help") || args.positional.empty()) {
        out << command_help("go");
        return 0;
    }

    const std::string& path = args.positional[0];
    auto view = BinaryView::open(path);
    if (!view) {
        err << "typemorph go: " << format_error(view.error()) << '\n';
        return 1;
    }

    golang::GoAnalyzer analyzer;
    auto image_res = core::ExecutableImage::parse(view.value());
    golang::GoAnalysisReport rep = image_res
        ? analyzer.analyze(image_res.value())
        : analyzer.analyze_view(view.value());

    if (auto out_path = args.get("out")) {
        auto wr = write_file(*out_path, rep.golang_source);
        if (!wr) {
            err << "typemorph go: failed to write output file: " << *out_path << '\n';
            return 1;
        }
        out << "Reconstructed Go source saved to: " << *out_path << "\n";
    }

    if (args.has("source")) {
        out << rep.golang_source;
        return 0;
    }

    if (args.has("json")) {
        auto doc = go_report_to_json(path, rep);
        out << doc.dump(2) << '\n';
        return 0;
    }

    out << "TypeMorph Golang pclntab & Metadata Reconstructor\n"
        << "  Target: " << path << "\n";

    if (!rep.detected) {
        out << "  No Go pclntab runtime structures detected (not a Go binary or heavily stripped/encrypted).\n";
        return 0;
    }

    char va_buf[32];
    std::snprintf(va_buf, sizeof(va_buf), "0x%llx", static_cast<unsigned long long>(rep.pclntab_va));
    out << "  Go Runtime Version: " << golang::to_string(rep.version) << " (" << rep.ptr_size * 8 << "-bit)\n"
        << "  Pclntab Base VA:    " << va_buf << "\n"
        << "  Functions Total:    " << rep.functions.size() << " (User: " << rep.user_functions
        << ", Runtime: " << rep.runtime_functions << ")\n"
        << "  Unique Packages:    " << rep.packages.size() << "\n"
        << "  Recovered Structs:  " << rep.structs.size() << "\n"
        << "  Recovered itabs:    " << rep.itabs.size() << "\n\n";

    if (!rep.structs.empty()) {
        out << "Recovered Struct Types:\n";
        for (const auto& s : rep.structs) {
            out << "  - type " << s.name << " struct (" << s.fields.size() << " fields, " << s.size << " bytes)\n";
        }
        out << "\n";
    }

    if (!rep.itabs.empty()) {
        out << "Interface Tables (itabs):\n";
        for (const auto& itab : rep.itabs) {
            out << "  - " << itab.concrete_type_name << " implements " << itab.interface_name
                << " (" << itab.methods.size() << " methods)\n";
        }
        out << "\n";
    }

    if (!rep.packages.empty()) {
        out << "Packages Detected:\n";
        for (const auto& pkg : rep.packages) {
            out << "  - " << pkg << "\n";
        }
        out << "\n";
    }

    out << "Functions Sample (first 50):\n";
    std::size_t limit = std::min<std::size_t>(rep.functions.size(), 50);
    for (std::size_t i = 0; i < limit; ++i) {
        const auto& fn = rep.functions[i];
        char f_buf[32];
        std::snprintf(f_buf, sizeof(f_buf), "0x%llx", static_cast<unsigned long long>(fn.entry_va));
        out << "  [" << f_buf << "] " << fn.name << "\n";
    }
    if (rep.functions.size() > limit) {
        out << "  ... and " << (rep.functions.size() - limit) << " more functions (use --json to view all).\n";
    }

    return 0;
}

JsonValue rich_report_to_json(const std::string& path, const pe::RichHeaderReport& rep) {
    JsonValue doc = JsonValue::object();
    doc["file"] = JsonValue(path);
    doc["present"] = JsonValue(rep.present);
    doc["xor_key"] = JsonValue(static_cast<std::uint64_t>(rep.xor_key));
    doc["offset"] = JsonValue(rep.offset);
    doc["size"] = JsonValue(static_cast<std::uint64_t>(rep.size));
    doc["checksum"] = JsonValue(static_cast<std::uint64_t>(rep.checksum));
    doc["hash"] = JsonValue(rep.hash);

    JsonValue versions = JsonValue::array();
    for (const auto& vs : rep.compiler_versions) {
        versions.push(JsonValue(vs));
    }
    doc["compiler_versions"] = std::move(versions);

    JsonValue recs = JsonValue::array();
    for (const auto& r : rep.records) {
        JsonValue item = JsonValue::object();
        item["tool_id"] = JsonValue(static_cast<std::uint64_t>(r.tool_id));
        item["tool_name"] = JsonValue(r.tool_name);
        item["build_number"] = JsonValue(static_cast<std::uint64_t>(r.build_number));
        item["count"] = JsonValue(static_cast<std::uint64_t>(r.count));
        item["vs_version"] = JsonValue(r.vs_version);
        recs.push(std::move(item));
    }
    doc["records"] = std::move(recs);

    return doc;
}

int command_rich(const Arguments& args, std::ostream& out, std::ostream& err) {
    if (args.has("help") || args.positional.empty()) {
        out << command_help("rich");
        return 0;
    }

    const std::string& path = args.positional[0];
    auto view = BinaryView::open(path);
    if (!view) {
        err << "typemorph rich: " << format_error(view.error()) << '\n';
        return 1;
    }

    pe::RichHeaderParser parser;
    auto rep = parser.parse(view.value());

    if (args.has("json")) {
        auto doc = rich_report_to_json(path, rep);
        out << doc.dump(2) << '\n';
        return 0;
    }

    out << "TypeMorph MSVC Rich Header & Compiler Fingerprinter\n"
        << "  Target: " << path << "\n";

    if (!rep.present) {
        out << "  No MSVC Rich header present (binary not built with MSVC or stripped).\n";
        return 0;
    }

    char key_buf[32], off_buf[32];
    std::snprintf(key_buf, sizeof(key_buf), "0x%08X", rep.xor_key);
    std::snprintf(off_buf, sizeof(off_buf), "0x%llx", static_cast<unsigned long long>(rep.offset));

    out << "  Offset:      " << off_buf << " (" << rep.size << " bytes)\n"
        << "  XOR Key:     " << key_buf << "\n"
        << "  Checksum:    0x" << std::hex << std::uppercase << rep.checksum << std::dec << "\n"
        << "  RichPE Hash: " << rep.hash << "\n\n";

    if (!rep.compiler_versions.empty()) {
        out << "Compilers / Toolsets Identified:\n";
        for (const auto& vs : rep.compiler_versions) {
            out << "  - " << vs << "\n";
        }
        out << "\n";
    }

    out << "Decoded Tool Records (" << rep.records.size() << "):\n";
    for (const auto& rec : rep.records) {
        char comp_buf[32];
        std::snprintf(comp_buf, sizeof(comp_buf), "0x%04X", rec.tool_id);
        out << "  [" << comp_buf << "] " << rec.tool_name << " (Build " << rec.build_number
            << "): " << rec.count << " artifact(s) [" << rec.vs_version << "]\n";
    }

    return 0;
}

JsonValue abi_report_to_json(const std::string& path, const abi::AbiReport& rep) {
    JsonValue doc = JsonValue::object();
    doc["file"] = JsonValue(path);
    doc["total_functions"] = JsonValue(static_cast<std::uint64_t>(rep.total_functions));

    JsonValue dist = JsonValue::object();
    for (const auto& [k, v] : rep.convention_distribution) {
        dist[k] = JsonValue(static_cast<std::uint64_t>(v));
    }
    doc["conventions"] = std::move(dist);

    JsonValue fns = JsonValue::array();
    for (const auto& sig : rep.signatures) {
        JsonValue item = JsonValue::object();
        item["entry_va"] = JsonValue(sig.entry_va);
        item["name"] = JsonValue(sig.name);
        item["convention"] = JsonValue(std::string(abi::to_string(sig.convention)));
        item["return_kind"] = JsonValue(std::string(abi::to_string(sig.return_kind)));
        item["return_type"] = JsonValue(sig.return_type_hint);
        item["stack_frame_size"] = JsonValue(static_cast<std::uint64_t>(sig.stack_frame_size));
        item["stack_purge_bytes"] = JsonValue(static_cast<std::uint64_t>(sig.stack_purge_bytes));
        item["prototype"] = JsonValue(sig.prototype);
        item["rationale"] = JsonValue(sig.rationale);
        item["confidence"] = JsonValue(sig.confidence);

        JsonValue args = JsonValue::array();
        for (const auto& a : sig.arguments) {
            JsonValue a_item = JsonValue::object();
            a_item["index"] = JsonValue(static_cast<std::uint64_t>(a.index));
            a_item["name"] = JsonValue(a.name);
            a_item["location"] = JsonValue(a.location);
            a_item["type_hint"] = JsonValue(a.type_hint);
            args.push(std::move(a_item));
        }
        item["arguments"] = std::move(args);
        fns.push(std::move(item));
    }
    doc["signatures"] = std::move(fns);
    return doc;
}

int command_abi(const Arguments& args, std::ostream& out, std::ostream& err) {
    if (args.has("help") || args.positional.empty()) {
        out << command_help("abi");
        return 0;
    }

    const std::string& path = args.positional[0];
    auto view = BinaryView::open(path);
    if (!view) {
        err << "typemorph abi: " << format_error(view.error()) << '\n';
        return 1;
    }

    auto image_res = core::ExecutableImage::parse(view.value());
    if (!image_res) {
        err << "typemorph abi: " << format_error(image_res.error()) << '\n';
        return 1;
    }

    std::optional<std::uint64_t> target_va;
    if (auto fn_str = args.get("function")) {
        auto val = parse_u64(*fn_str, "function");
        if (!val) {
            std::string_view sv = *fn_str;
            if (sv.starts_with("0x") || sv.starts_with("0X")) sv.remove_prefix(2);
            char* end_ptr = nullptr;
            std::string clean(sv);
            std::uint64_t hex_va = std::strtoull(clean.c_str(), &end_ptr, 16);
            if (end_ptr != clean.c_str() && *end_ptr == '\0') {
                target_va = hex_va;
            } else {
                err << "typemorph abi: invalid function address " << *fn_str << '\n';
                return 1;
            }
        } else {
            target_va = val.value();
        }
    }

    abi::AbiClassifier classifier;
    auto rep = classifier.analyze(image_res.value(), target_va);

    if (args.has("json")) {
        auto doc = abi_report_to_json(path, rep);
        out << doc.dump(2) << '\n';
        return 0;
    }

    out << "TypeMorph Calling Convention & ABI Classifier\n"
        << "  Target: " << path << "\n"
        << "  Functions Analyzed: " << rep.total_functions << "\n\n";

    if (!rep.convention_distribution.empty()) {
        out << "Calling Convention Distribution:\n";
        for (const auto& [conv, count] : rep.convention_distribution) {
            double pct = (rep.total_functions > 0) ? (100.0 * static_cast<double>(count) / static_cast<double>(rep.total_functions)) : 0.0;
            out << "  - " << std::left << std::setw(16) << conv << ": " << count
                << " (" << std::fixed << std::setprecision(1) << pct << "%)\n";
        }
        out << "\n";
    }

    out << "Recovered Function Signatures (" << rep.signatures.size() << "):\n";
    std::size_t limit = std::min<std::size_t>(rep.signatures.size(), 50);
    for (std::size_t i = 0; i < limit; ++i) {
        const auto& sig = rep.signatures[i];
        char va_buf[32];
        std::snprintf(va_buf, sizeof(va_buf), "0x%llx", static_cast<unsigned long long>(sig.entry_va));
        out << "  [" << va_buf << "] " << sig.prototype << "\n"
            << "     Convention: " << to_string(sig.convention)
            << " | Frame: " << sig.stack_frame_size << "B";
        if (sig.stack_purge_bytes > 0) {
            out << " | Purge: " << sig.stack_purge_bytes << "B";
        }
        out << " | " << sig.rationale << "\n";
    }
    if (rep.signatures.size() > limit) {
        out << "  ... and " << (rep.signatures.size() - limit) << " more functions (use --json to view all).\n";
    }

    return 0;
}

JsonValue dotnet_report_to_json(const std::string& path, const dotnet::DotNetReport& rep) {
    JsonValue doc = JsonValue::object();
    doc["file"] = JsonValue(path);
    doc["is_dotnet"] = JsonValue(rep.is_dotnet);
    doc["runtime_version"] = JsonValue(rep.runtime_version);
    doc["cli_header_rva"] = JsonValue(static_cast<std::uint64_t>(rep.cli_header_rva));
    doc["metadata_rva"] = JsonValue(static_cast<std::uint64_t>(rep.metadata_rva));
    doc["entry_point_token"] = JsonValue(static_cast<std::uint64_t>(rep.entry_point_token));
    doc["type_count"] = JsonValue(static_cast<std::uint64_t>(rep.type_count));
    doc["method_count"] = JsonValue(static_cast<std::uint64_t>(rep.method_count));
    doc["field_count"] = JsonValue(static_cast<std::uint64_t>(rep.field_count));
    doc["csharp_source"] = JsonValue(rep.csharp_source);

    JsonValue types_arr = JsonValue::array();
    for (const auto& t : rep.types) {
        JsonValue t_obj = JsonValue::object();
        t_obj["name"] = JsonValue(t.name);
        t_obj["namespace"] = JsonValue(t.namespace_name);
        t_obj["full_name"] = JsonValue(t.full_name);
        t_obj["base_type"] = JsonValue(t.base_type);
        t_obj["is_interface"] = JsonValue(t.is_interface);
        t_obj["is_enum"] = JsonValue(t.is_enum);
        t_obj["is_value_type"] = JsonValue(t.is_value_type);

        JsonValue f_arr = JsonValue::array();
        for (const auto& f : t.fields) {
            JsonValue f_obj = JsonValue::object();
            f_obj["name"] = JsonValue(f.name);
            f_obj["type"] = JsonValue(f.type_name);
            f_obj["is_public"] = JsonValue(f.is_public);
            f_obj["is_private"] = JsonValue(f.is_private);
            f_obj["is_static"] = JsonValue(f.is_static);
            f_arr.push(std::move(f_obj));
        }
        t_obj["fields"] = std::move(f_arr);

        JsonValue m_arr = JsonValue::array();
        for (const auto& m : t.methods) {
            JsonValue m_obj = JsonValue::object();
            m_obj["name"] = JsonValue(m.name);
            m_obj["return_type"] = JsonValue(m.return_type);
            m_obj["rva"] = JsonValue(static_cast<std::uint64_t>(m.rva));
            m_obj["is_public"] = JsonValue(m.is_public);
            m_obj["is_static"] = JsonValue(m.is_static);
            m_arr.push(std::move(m_obj));
        }
        t_obj["methods"] = std::move(m_arr);

        types_arr.push(std::move(t_obj));
    }
    doc["types"] = std::move(types_arr);
    return doc;
}

int command_csharp(const Arguments& args, std::ostream& out, std::ostream& err) {
    if (args.has("help") || args.positional.empty()) {
        out << command_help("csharp");
        return 0;
    }

    const std::string& path = args.positional[0];
    auto view = BinaryView::open(path);
    if (!view) {
        err << "typemorph csharp: " << format_error(view.error()) << '\n';
        return 1;
    }

    dotnet::DotNetAnalyzer analyzer;
    auto rep = analyzer.analyze_view(view.value());
    if (!rep.is_dotnet) {
        err << "typemorph csharp: target is not a valid .NET / CLR binary (no CLI header found)\n";
        return 1;
    }
    rep.csharp_source = dotnet::DotNetAnalyzer::to_csharp(rep);

    if (auto out_path = args.get("out")) {
        auto wr = write_file(*out_path, rep.csharp_source);
        if (!wr) {
            err << "typemorph csharp: failed to write output file: " << *out_path << '\n';
            return 1;
        }
        out << "Decompiled C# source saved to: " << *out_path << "\n";
    }

    if (args.has("json")) {
        auto doc = dotnet_report_to_json(path, rep);
        out << doc.dump(2) << '\n';
        return 0;
    }

    if (!args.has("out")) {
        out << rep.csharp_source;
    }
    return 0;
}

JsonValue decompile_report_to_json(const std::string& path, const decompile::DecompileReport& rep) {
    JsonValue doc = JsonValue::object();
    doc["file"] = JsonValue(path);
    doc["total_functions"] = JsonValue(static_cast<std::uint64_t>(rep.total_functions));
    doc["combined_source"] = JsonValue(rep.combined_source);

    JsonValue structs_arr = JsonValue::array();
    for (const auto& s : rep.global_structs) {
        JsonValue s_obj = JsonValue::object();
        s_obj["name"] = JsonValue(s.name);
        s_obj["total_size"] = JsonValue(static_cast<std::uint64_t>(s.total_size));
        s_obj["c_declaration"] = JsonValue(s.c_declaration);
        structs_arr.push(std::move(s_obj));
    }
    doc["structs"] = std::move(structs_arr);

    JsonValue fns_arr = JsonValue::array();
    for (const auto& fn : rep.functions) {
        JsonValue fn_obj = JsonValue::object();
        fn_obj["entry_va"] = JsonValue(fn.entry_va);
        fn_obj["name"] = JsonValue(fn.name);
        fn_obj["prototype"] = JsonValue(fn.prototype);
        fn_obj["pseudocode"] = JsonValue(fn.pseudocode);
        fns_arr.push(std::move(fn_obj));
    }
    doc["functions"] = std::move(fns_arr);
    return doc;
}

int command_decompile(const Arguments& args, std::ostream& out, std::ostream& err) {
    if (args.has("help") || args.positional.empty()) {
        out << command_help("decompile");
        return 0;
    }

    const std::string& path = args.positional[0];
    auto view = BinaryView::open(path);
    if (!view) {
        err << "typemorph decompile: " << format_error(view.error()) << '\n';
        return 1;
    }

    auto image_res = core::ExecutableImage::parse(view.value());
    if (!image_res) {
        err << "typemorph decompile: " << format_error(image_res.error()) << '\n';
        return 1;
    }

    std::string lang = args.get_or("lang", "c");
    if (lang == "rust" || lang == "rs") {
        derust::RustSourceReconstructor reconstructor;
        auto rust_rep = reconstructor.reconstruct(image_res.value());
        rust_rep.rust_source = derust::RustSourceReconstructor::to_rust_source(rust_rep);

        if (auto out_path = args.get("out")) {
            auto wr = write_file(*out_path, rust_rep.rust_source);
            if (!wr) {
                err << "typemorph decompile: failed to write output: " << *out_path << '\n';
                return 1;
            }
            out << "Reconstructed Rust source saved to: " << *out_path << "\n";
        }
        if (args.has("json")) {
            JsonValue doc = JsonValue::object();
            doc["file"] = JsonValue(path);
            doc["lang"] = JsonValue("rust");
            doc["has_rust_artifacts"] = JsonValue(rust_rep.has_rust_artifacts);
            doc["trait_count"] = JsonValue(static_cast<std::uint64_t>(rust_rep.traits.size()));
            doc["rust_source"] = JsonValue(rust_rep.rust_source);
            out << doc.dump(2) << '\n';
            return 0;
        }
        if (!args.has("out")) {
            out << rust_rep.rust_source;
        }
        return 0;
    }

    std::optional<std::uint64_t> target_va;
    if (auto fn_str = args.get("function")) {
        auto val = parse_u64(*fn_str, "function");
        if (!val) {
            std::string_view sv = *fn_str;
            if (sv.starts_with("0x") || sv.starts_with("0X")) sv.remove_prefix(2);
            char* end_ptr = nullptr;
            std::string clean(sv);
            std::uint64_t hex_va = std::strtoull(clean.c_str(), &end_ptr, 16);
            if (end_ptr != clean.c_str() && *end_ptr == '\0') {
                target_va = hex_va;
            } else {
                err << "typemorph decompile: invalid function address " << *fn_str << '\n';
                return 1;
            }
        } else {
            target_va = val.value();
        }
    }

    decompile::CDecompiler decompiler;
    auto rep = decompiler.decompile(image_res.value(), target_va);

    if (auto out_path = args.get("out")) {
        auto wr = write_file(*out_path, rep.combined_source);
        if (!wr) {
            err << "typemorph decompile: failed to write output: " << *out_path << '\n';
            return 1;
        }
        out << "Decompiled C code saved to: " << *out_path << "\n";
    }

    if (args.has("json")) {
        auto doc = decompile_report_to_json(path, rep);
        out << doc.dump(2) << '\n';
        return 0;
    }

    if (!args.has("out")) {
        out << rep.combined_source;
    }
    return 0;
}

JsonValue detect_report_to_json(const std::string& path, const detect::DetectionReport& rep) {
    JsonValue doc = JsonValue::object();
    doc["file"] = JsonValue(path);
    doc["format"] = JsonValue(std::string(core::to_string(rep.format)));
    doc["bits"] = JsonValue(static_cast<std::uint64_t>(rep.bits));
    doc["arch"] = JsonValue(rep.arch);
    doc["entry_point"] = JsonValue(rep.entry_point);
    doc["entry_point_file_offset"] = JsonValue(rep.entry_point_file_offset);
    doc["is_packed"] = JsonValue(rep.is_packed());
    doc["primary_compiler"] = JsonValue(rep.primary_compiler);
    doc["primary_packer"] = JsonValue(rep.primary_packer);
    doc["primary_protector"] = JsonValue(rep.primary_protector);
    doc["primary_runtime"] = JsonValue(rep.primary_runtime);

    JsonValue matches = JsonValue::array();
    for (const auto& m : rep.matches) {
        JsonValue item = JsonValue::object();
        item["category"] = JsonValue(std::string(detect::to_string(m.category)));
        item["name"] = JsonValue(m.name);
        item["version"] = JsonValue(m.version);
        item["confidence"] = JsonValue(m.confidence);
        item["rationale"] = JsonValue(m.rationale);
        item["matched_offset"] = JsonValue(m.matched_offset);
        matches.push(std::move(item));
    }
    doc["matches"] = std::move(matches);
    return doc;
}

int command_detect(const Arguments& args, std::ostream& out, std::ostream& err) {
    if (args.has("help") || args.positional.empty()) {
        out << command_help("detect");
        return 0;
    }

    const std::string& path = args.positional[0];
    auto view = BinaryView::open(path);
    if (!view) {
        err << "typemorph detect: " << format_error(view.error()) << '\n';
        return 1;
    }

    detect::DetectorEngine engine;
    auto img_res = core::ExecutableImage::parse(view.value());
    auto rep = img_res ? engine.detect(img_res.value()) : engine.detect_view(view.value());

    if (args.has("json")) {
        auto doc = detect_report_to_json(path, rep);
        out << doc.dump(2) << '\n';
        return 0;
    }

    out << detect::DetectorEngine::to_text_summary(rep);
    return 0;
}

JsonValue fixiat_report_to_json(const std::string& path, const pe::IatReconstructionReport& rep) {
    JsonValue doc = JsonValue::object();
    doc["file"] = JsonValue(path);
    doc["success"] = JsonValue(rep.success);
    doc["bits"] = JsonValue(static_cast<std::uint64_t>(rep.bits));
    doc["image_base"] = JsonValue(rep.image_base);
    doc["entry_point"] = JsonValue(rep.entry_point);
    doc["original_import_rva"] = JsonValue(static_cast<std::uint64_t>(rep.original_import_rva));
    doc["original_import_size"] = JsonValue(static_cast<std::uint64_t>(rep.original_import_size));
    doc["original_import_valid"] = JsonValue(rep.original_import_valid);
    doc["total_functions"] = JsonValue(static_cast<std::uint64_t>(rep.total_functions));
    doc["resolved_functions"] = JsonValue(static_cast<std::uint64_t>(rep.resolved_functions));
    doc["redirected_thunks"] = JsonValue(static_cast<std::uint64_t>(rep.redirected_thunks));
    doc["binary_patched"] = JsonValue(rep.binary_patched);
    if (rep.binary_patched) {
        doc["new_import_rva"] = JsonValue(static_cast<std::uint64_t>(rep.new_import_rva));
        doc["new_import_size"] = JsonValue(static_cast<std::uint64_t>(rep.new_import_size));
        doc["new_section_name"] = JsonValue(rep.new_section_name);
        doc["patched_binary_size"] = JsonValue(static_cast<std::uint64_t>(rep.patched_binary_size));
    }

    JsonValue ranges_arr = JsonValue::array();
    for (const auto& rng : rep.discovered_ranges) {
        JsonValue item = JsonValue::object();
        item["start_va"] = JsonValue(rng.start_va);
        item["end_va"] = JsonValue(rng.end_va);
        item["size"] = JsonValue(static_cast<std::uint64_t>(rng.size));
        item["section_name"] = JsonValue(rng.section_name);
        item["candidate_pointers"] = JsonValue(static_cast<std::uint64_t>(rng.candidate_pointer_count));
        item["resolved_apis"] = JsonValue(static_cast<std::uint64_t>(rng.resolved_api_count));
        ranges_arr.push(std::move(item));
    }
    doc["discovered_ranges"] = std::move(ranges_arr);

    JsonValue modules_arr = JsonValue::array();
    for (const auto& mod : rep.modules) {
        JsonValue m_obj = JsonValue::object();
        m_obj["module_name"] = JsonValue(mod.module_name);
        m_obj["first_thunk_rva"] = JsonValue(static_cast<std::uint64_t>(mod.first_thunk_rva));
        m_obj["valid_functions"] = JsonValue(static_cast<std::uint64_t>(mod.valid_count()));

        JsonValue fns_arr = JsonValue::array();
        for (const auto& fn : mod.functions) {
            JsonValue f_obj = JsonValue::object();
            f_obj["name"] = JsonValue(fn.name);
            f_obj["ordinal"] = JsonValue(static_cast<std::uint64_t>(fn.ordinal));
            f_obj["iat_va"] = JsonValue(fn.iat_va);
            f_obj["iat_rva"] = JsonValue(static_cast<std::uint64_t>(fn.iat_rva));
            f_obj["target_va"] = JsonValue(fn.target_va);
            f_obj["resolved_target_va"] = JsonValue(fn.resolved_target_va);
            f_obj["resolution_type"] = JsonValue(std::string(pe::to_string(fn.resolution_type)));
            f_obj["valid"] = JsonValue(fn.valid);
            f_obj["comment"] = JsonValue(fn.comment);
            fns_arr.push(std::move(f_obj));
        }
        m_obj["functions"] = std::move(fns_arr);
        modules_arr.push(std::move(m_obj));
    }
    doc["modules"] = std::move(modules_arr);
    return doc;
}

int command_fixiat(const Arguments& args, std::ostream& out, std::ostream& err) {
    if (args.has("help") || args.positional.empty()) {
        out << command_help("fixiat");
        return 0;
    }

    const std::string& path = args.positional[0];
    auto view = BinaryView::open(path);
    if (!view) {
        err << "typemorph fixiat: " << format_error(view.error()) << '\n';
        return 1;
    }

    pe::IatReconstructionOptions opts;
    opts.trace_redirections = !args.has("no-trace");
    if (auto sec_opt = args.get("section")) {
        opts.new_section_name = *sec_opt;
    }

    pe::IatReconstructor reconstructor(opts);
    pe::IatReconstructionReport rep;

    if (auto out_path = args.get("out")) {
        auto rebuild_res = reconstructor.rebuild_pe(view.value(), &rep);
        if (!rebuild_res) {
            err << "typemorph fixiat: " << format_error(rebuild_res.error()) << '\n';
            return 1;
        }
        auto wr = write_binary_file(*out_path, rebuild_res.value());
        if (!wr) {
            err << "typemorph fixiat: failed to write output file: " << *out_path << '\n';
            return 1;
        }
        out << "Fixed PE with reconstructed import table written to: " << *out_path << "\n";
    } else {
        rep = reconstructor.analyze(view.value());
    }

    if (args.has("json")) {
        auto doc = fixiat_report_to_json(path, rep);
        out << doc.dump(2) << '\n';
        return 0;
    }

    out << pe::IatReconstructor::to_text_summary(rep);
    return 0;
}

// ---------------------------------------------------------------------------
// ClassInformer, SigMaker, ApplyCalleeType, DumpSubs
// ---------------------------------------------------------------------------

JsonValue classinformer_to_json(const std::string& path, const std::vector<rtti::RttiClass>& classes) {
    JsonValue doc = JsonValue::object();
    doc["file"] = JsonValue(path);
    doc["count"] = JsonValue(static_cast<std::uint64_t>(classes.size()));

    JsonValue list = JsonValue::array();
    for (const auto& cls : classes) {
        JsonValue item = JsonValue::object();
        item["name"] = JsonValue(cls.name);
        item["mangled_name"] = JsonValue(cls.mangled_name);
        item["vftable_va"] = JsonValue(cls.vftable_va);
        item["locator_va"] = JsonValue(cls.locator_va);
        item["confidence"] = JsonValue(cls.confidence);

        JsonValue bases = JsonValue::array();
        for (const auto& b : cls.base_classes) {
            JsonValue b_obj = JsonValue::object();
            b_obj["name"] = JsonValue(b.name);
            b_obj["offset"] = JsonValue(static_cast<std::int64_t>(b.offset));
            bases.push(std::move(b_obj));
        }
        item["base_classes"] = std::move(bases);

        JsonValue methods = JsonValue::array();
        for (const auto& m : cls.methods) {
            JsonValue m_obj = JsonValue::object();
            m_obj["slot"] = JsonValue(static_cast<std::uint64_t>(m.slot));
            m_obj["virtual_address"] = JsonValue(m.virtual_address);
            m_obj["name"] = JsonValue(m.name);
            methods.push(std::move(m_obj));
        }
        item["methods"] = std::move(methods);
        list.push(std::move(item));
    }
    doc["classes"] = std::move(list);
    return doc;
}

int command_classinformer(const Arguments& args, std::ostream& out, std::ostream& err) {
    if (args.has("help") || args.positional.empty()) {
        out << command_help("classinformer");
        return 0;
    }

    const std::string& path = args.positional[0];
    auto view = BinaryView::open(path);
    if (!view) {
        err << "typemorph classinformer: " << format_error(view.error()) << '\n';
        return 1;
    }

    rtti::RttiAnalyzer analyzer;
    auto classes = analyzer.analyze_view(view.value());

    std::string fmt = args.get_or("format", "");
    if (args.has("json") || fmt == "json") {
        auto doc = classinformer_to_json(path, classes);
        out << doc.dump(2) << '\n';
        return 0;
    }

    if (fmt == "cpp") {
        out << rtti::RttiAnalyzer::to_cpp_header(classes) << '\n';
        return 0;
    }

    if (fmt == "csv") {
        out << "Class,VftableVA,LocatorVA,BaseCount,MethodCount,Bases\n";
        for (const auto& cls : classes) {
            char vf_buf[32], loc_buf[32];
            std::snprintf(vf_buf, sizeof(vf_buf), "0x%llX", static_cast<unsigned long long>(cls.vftable_va));
            std::snprintf(loc_buf, sizeof(loc_buf), "0x%llX", static_cast<unsigned long long>(cls.locator_va));
            out << "\"" << cls.name << "\"," << vf_buf << "," << loc_buf << ","
                << cls.base_classes.size() << "," << cls.methods.size() << ",\"";
            for (std::size_t b = 0; b < cls.base_classes.size(); ++b) {
                if (b > 0) out << " -> ";
                out << cls.base_classes[b].name;
            }
            out << "\"\n";
        }
        return 0;
    }

    out << "TypeMorph ClassInformer - C++ RTTI & Polymorphic Hierarchy\n"
        << "===========================================================\n"
        << "Target: " << path << "\n"
        << "Found " << classes.size() << " polymorphic C++ class(es):\n\n";

    if (classes.empty()) {
        out << "  No C++ RTTI / vftables found in binary.\n";
        return 0;
    }

    for (std::size_t i = 0; i < classes.size(); ++i) {
        const auto& cls = classes[i];
        char vf_buf[32], loc_buf[32];
        std::snprintf(vf_buf, sizeof(vf_buf), "0x%llX", static_cast<unsigned long long>(cls.vftable_va));
        std::snprintf(loc_buf, sizeof(loc_buf), "0x%llX", static_cast<unsigned long long>(cls.locator_va));

        out << "  [" << (i + 1) << "] class " << cls.name;
        if (!cls.base_classes.empty()) {
            out << " : ";
            for (std::size_t b = 0; b < cls.base_classes.size(); ++b) {
                if (b > 0) out << ", ";
                out << "public " << cls.base_classes[b].name;
            }
        }
        out << "\n      Vftable: " << vf_buf << " | Locator: " << loc_buf
            << " | Methods: " << cls.methods.size() << "\n";

        if (!cls.base_classes.empty()) {
            out << "      Hierarchy: ";
            for (std::size_t b = 0; b < cls.base_classes.size(); ++b) {
                if (b > 0) out << " -> ";
                out << cls.base_classes[b].name << " (+0x" << std::hex << cls.base_classes[b].offset << std::dec << ")";
            }
            out << "\n";
        }
        if (!cls.methods.empty()) {
            std::size_t limit = std::min<std::size_t>(cls.methods.size(), 8);
            for (std::size_t m = 0; m < limit; ++m) {
                char m_buf[32];
                std::snprintf(m_buf, sizeof(m_buf), "0x%llX", static_cast<unsigned long long>(cls.methods[m].virtual_address));
                out << "        slot[" << cls.methods[m].slot << "] " << m_buf << ": " << cls.methods[m].name << "()\n";
            }
            if (cls.methods.size() > limit) {
                out << "        ... and " << (cls.methods.size() - limit) << " more virtual slots\n";
            }
        }
        out << "\n";
    }

    return 0;
}

struct GeneratedSignature {
    std::uint64_t function_va = 0;
    std::string function_name;
    std::size_t length = 0;
    std::string pattern_ida;    // "55 8B EC 83 EC ?? 53"
    std::string pattern_yara;   // "{ 55 8b ec 83 ec ?? 53 }"
    std::string pattern_bytes;  // "\x55\x8B\xEC\x83\xEC\x00\x53"
    std::string pattern_mask;   // "xxxxx?x"
    std::size_t wildcard_count = 0;
    bool is_unique = true;
};

JsonValue sigmake_to_json(const std::string& path, const std::vector<GeneratedSignature>& sigs) {
    JsonValue doc = JsonValue::object();
    doc["file"] = JsonValue(path);
    doc["count"] = JsonValue(static_cast<std::uint64_t>(sigs.size()));
    JsonValue arr = JsonValue::array();
    for (const auto& s : sigs) {
        JsonValue item = JsonValue::object();
        item["function_va"] = JsonValue(s.function_va);
        item["name"] = JsonValue(s.function_name);
        item["length"] = JsonValue(static_cast<std::uint64_t>(s.length));
        item["pattern_ida"] = JsonValue(s.pattern_ida);
        item["pattern_yara"] = JsonValue(s.pattern_yara);
        item["pattern_bytes"] = JsonValue(s.pattern_bytes);
        item["pattern_mask"] = JsonValue(s.pattern_mask);
        item["wildcards"] = JsonValue(static_cast<std::uint64_t>(s.wildcard_count));
        item["is_unique"] = JsonValue(s.is_unique);
        arr.push(std::move(item));
    }
    doc["signatures"] = std::move(arr);
    return doc;
}

GeneratedSignature make_func_signature(const core::ExecutableImage& image,
                                       const core::BinaryView& view,
                                       std::uint64_t func_va,
                                       std::string func_name,
                                       std::size_t desired_len) {
    GeneratedSignature sig;
    sig.function_va = func_va;
    sig.function_name = std::move(func_name);

    auto off_res = image.va_to_offset(func_va);
    if (!off_res || off_res.value() >= view.size()) return sig;

    const std::uint64_t file_off = off_res.value();
    const std::size_t max_avail = static_cast<std::size_t>(view.size() - file_off);
    const std::size_t len = std::min<std::size_t>(desired_len, max_avail);
    sig.length = len;

    const std::uint8_t* bytes = view.data() + file_off;
    std::ostringstream ida_ss, yara_ss, bytes_ss, mask_ss;
    yara_ss << "{ ";

    for (std::size_t i = 0; i < len; ++i) {
        bool wildcard = false;

        // Heuristic masking: call/jmp rel32 offsets (E8 xx xx xx xx, E9 xx xx xx xx)
        if (i >= 1 && (bytes[i - 1] == 0xE8 || bytes[i - 1] == 0xE9) && i + 3 <= len) {
            wildcard = true;
        } else if (i >= 2 && i <= len && (bytes[i - 2] == 0xE8 || bytes[i - 2] == 0xE9)) {
            wildcard = true;
        } else if (i >= 3 && i <= len && (bytes[i - 3] == 0xE8 || bytes[i - 3] == 0xE9)) {
            wildcard = true;
        } else if (i >= 4 && i <= len && (bytes[i - 4] == 0xE8 || bytes[i - 4] == 0xE9)) {
            wildcard = true;
        }
        // RIP-relative memory disp32: 48 8B / 48 8D / FF 15 / FF 25
        if (image.bits() == 64 && i >= 3 && i + 1 <= len) {
            if (bytes[i - 3] == 0x48 && (bytes[i - 2] == 0x8B || bytes[i - 2] == 0x8D) && (bytes[i - 1] & 0xC7) == 0x05) {
                wildcard = true;
            }
        }

        if (wildcard) {
            ++sig.wildcard_count;
            if (i > 0) ida_ss << " ";
            ida_ss << "??";
            yara_ss << "?? ";
            bytes_ss << "\\x00";
            mask_ss << "?";
        } else {
            char hex_byte[8];
            std::snprintf(hex_byte, sizeof(hex_byte), "%02X", bytes[i]);
            if (i > 0) ida_ss << " ";
            ida_ss << hex_byte;
            std::snprintf(hex_byte, sizeof(hex_byte), "%02x ", bytes[i]);
            yara_ss << hex_byte;
            std::snprintf(hex_byte, sizeof(hex_byte), "\\x%02X", bytes[i]);
            bytes_ss << hex_byte;
            mask_ss << "x";
        }
    }
    yara_ss << "}";

    sig.pattern_ida = ida_ss.str();
    sig.pattern_yara = yara_ss.str();
    sig.pattern_bytes = bytes_ss.str();
    sig.pattern_mask = mask_ss.str();
    return sig;
}

int command_sigmake(const Arguments& args, std::ostream& out, std::ostream& err) {
    if (args.has("help") || args.positional.empty()) {
        out << command_help("sigmake");
        return 0;
    }

    const std::string& path = args.positional[0];
    auto view = BinaryView::open(path);
    if (!view) {
        err << "typemorph sigmake: " << format_error(view.error()) << '\n';
        return 1;
    }

    auto img_res = core::ExecutableImage::parse(view.value());
    if (!img_res) {
        err << "typemorph sigmake: " << format_error(img_res.error()) << '\n';
        return 1;
    }
    const auto& image = img_res.value();

    std::size_t min_len = 32;
    if (auto len_opt = args.get("min-len")) {
        auto val = parse_u64(*len_opt, "min-len");
        if (val) min_len = static_cast<std::size_t>(*val);
    }

    std::vector<GeneratedSignature> sigs;

    if (auto fn_str = args.get("function")) {
        std::optional<std::uint64_t> target_va;
        auto val = parse_u64(*fn_str, "function");
        if (!val) {
            std::string_view sv = *fn_str;
            if (sv.starts_with("0x") || sv.starts_with("0X")) sv.remove_prefix(2);
            char* end_ptr = nullptr;
            std::string clean(sv);
            std::uint64_t hex_va = std::strtoull(clean.c_str(), &end_ptr, 16);
            if (end_ptr != clean.c_str() && *end_ptr == '\0') target_va = hex_va;
        } else {
            target_va = *val;
        }

        if (!target_va) {
            err << "typemorph sigmake: invalid function address " << *fn_str << '\n';
            return 1;
        }

        char name_buf[64];
        std::snprintf(name_buf, sizeof(name_buf), "sub_%llX", static_cast<unsigned long long>(*target_va));
        sigs.push_back(make_func_signature(image, view.value(), *target_va, name_buf, min_len));
    } else {
        // Run ABI classifier to identify all function entry points
        abi::AbiClassifier classifier;
        auto abi_rep = classifier.analyze(image);
        std::size_t limit = std::min<std::size_t>(abi_rep.signatures.size(), 20);
        for (std::size_t i = 0; i < limit; ++i) {
            const auto& fn = abi_rep.signatures[i];
            sigs.push_back(make_func_signature(image, view.value(), fn.entry_va, fn.name, min_len));
        }
    }

    std::string fmt = args.get_or("format", "ida");
    if (args.has("json") || fmt == "json") {
        auto doc = sigmake_to_json(path, sigs);
        out << doc.dump(2) << '\n';
        return 0;
    }

    out << "TypeMorph Signature Maker (SigMaker)\n"
        << "====================================\n"
        << "Target: " << path << "\n"
        << "Generated " << sigs.size() << " signature pattern(s):\n\n";

    for (const auto& s : sigs) {
        char va_buf[32];
        std::snprintf(va_buf, sizeof(va_buf), "0x%llX", static_cast<unsigned long long>(s.function_va));
        out << "Function: " << s.function_name << " (" << va_buf << ", len: " << s.length
            << ", wildcards: " << s.wildcard_count << ")\n";

        if (fmt == "yara") {
            out << "  YARA  : " << s.pattern_yara << "\n\n";
        } else if (fmt == "byte" || fmt == "c") {
            out << "  Bytes : \"" << s.pattern_bytes << "\"\n";
            out << "  Mask  : \"" << s.pattern_mask << "\"\n\n";
        } else {
            out << "  IDA   : " << s.pattern_ida << "\n\n";
        }
    }

    return 0;
}

int command_applycalletype(const Arguments& args, std::ostream& out, std::ostream& err) {
    if (args.has("help") || args.positional.empty()) {
        out << command_help("applycalletype");
        return 0;
    }

    const std::string& path = args.positional[0];
    auto view = BinaryView::open(path);
    if (!view) {
        err << "typemorph applycalletype: " << format_error(view.error()) << '\n';
        return 1;
    }

    auto img_res = core::ExecutableImage::parse(view.value());
    if (!img_res) {
        err << "typemorph applycalletype: " << format_error(img_res.error()) << '\n';
        return 1;
    }

    abi::AbiClassifier classifier;
    auto rep = classifier.analyze(img_res.value());

    if (args.has("json")) {
        auto doc = abi_report_to_json(path, rep);
        doc["tool"] = JsonValue("applycalletype");
        out << doc.dump(2) << '\n';
        return 0;
    }

    out << "TypeMorph ApplyCalleeType - Call Site Type & Prototype Propagator\n"
        << "================================================================\n"
        << "Target: " << path << "\n"
        << "Classified " << rep.signatures.size() << " callee signature(s) across "
        << rep.total_functions << " analyzed functions:\n\n";

    for (const auto& sig : rep.signatures) {
        char va_buf[32];
        std::snprintf(va_buf, sizeof(va_buf), "0x%llX", static_cast<unsigned long long>(sig.entry_va));
        out << "  [" << va_buf << "] " << sig.prototype << "\n"
            << "     Convention: " << to_string(sig.convention)
            << " | Arguments: " << sig.arguments.size()
            << " | Frame: " << sig.stack_frame_size << "B";
        if (sig.stack_purge_bytes > 0) out << " | Purge: " << sig.stack_purge_bytes << "B";
        out << "\n";
        for (const auto& arg : sig.arguments) {
            out << "       arg[" << arg.index << "] " << arg.location << " (" << arg.type_hint << ")\n";
        }
        out << "\n";
    }

    out << "(Status: Ready to propagate to IDA / Ghidra / Binary Ninja via typemorph_sync)\n";
    return 0;
}

int command_dumpsubs(const Arguments& args, std::ostream& out, std::ostream& err) {
    if (args.has("help") || args.positional.empty()) {
        out << command_help("dumpsubs");
        return 0;
    }

    const std::string& path = args.positional[0];
    auto view = BinaryView::open(path);
    if (!view) {
        err << "typemorph dumpsubs: " << format_error(view.error()) << '\n';
        return 1;
    }

    auto img_res = core::ExecutableImage::parse(view.value());
    if (!img_res) {
        err << "typemorph dumpsubs: " << format_error(img_res.error()) << '\n';
        return 1;
    }

    abi::AbiClassifier classifier;
    auto rep = classifier.analyze(img_res.value());

    std::size_t min_size = 0;
    if (auto ms_opt = args.get("min-size")) {
        auto val = parse_u64(*ms_opt, "min-size");
        if (val) min_size = static_cast<std::size_t>(*val);
    }

    if (args.has("json")) {
        auto doc = abi_report_to_json(path, rep);
        out << doc.dump(2) << '\n';
        return 0;
    }

    std::ostringstream csv;
    csv << "Address,Name,Convention,ReturnType,StackFrame,StackPurge,Arguments,Prototype\n";
    for (const auto& sig : rep.signatures) {
        if (sig.stack_frame_size < min_size) continue;
        char va_buf[32];
        std::snprintf(va_buf, sizeof(va_buf), "0x%llX", static_cast<unsigned long long>(sig.entry_va));
        csv << va_buf << ",\"" << sig.name << "\"," << to_string(sig.convention) << ",\""
            << sig.return_type_hint << "\"," << sig.stack_frame_size << ","
            << sig.stack_purge_bytes << "," << sig.arguments.size() << ",\""
            << sig.prototype << "\"\n";
    }

    if (auto out_path = args.get("out")) {
        auto wr = write_file(*out_path, csv.str());
        if (!wr) {
            err << "typemorph dumpsubs: failed to write: " << *out_path << '\n';
            return 1;
        }
        out << "Subroutines dumped successfully to: " << *out_path << "\n";
        return 0;
    }

    out << csv.str();
    return 0;
}

JsonValue dotnet_deobf_report_to_json(const std::string& path, const dotnet::DotNetDeobfReport& rep) {
    JsonValue doc = JsonValue::object();
    doc["file"] = JsonValue(path);
    doc["is_dotnet"] = JsonValue(rep.is_dotnet);
    doc["protector"] = JsonValue(std::string(dotnet::to_string(rep.detected_protector)));
    doc["protector_details"] = JsonValue(rep.protector_details);
    doc["total_proxies_inlined"] = JsonValue(static_cast<std::uint64_t>(rep.total_proxies_inlined));
    doc["total_strings_decrypted"] = JsonValue(static_cast<std::uint64_t>(rep.total_strings_decrypted));
    doc["total_switches_killed"] = JsonValue(static_cast<std::uint64_t>(rep.total_switches_killed));
    doc["clean_csharp_source"] = JsonValue(rep.clean_csharp_source);

    JsonValue proxies_arr = JsonValue::array();
    for (const auto& p : rep.inlined_proxies) {
        JsonValue item = JsonValue::object();
        item["proxy"] = JsonValue(p.proxy_method_name);
        item["target_name"] = JsonValue(p.target_name);
        item["target_type"] = JsonValue(p.target_type);
        item["target_token"] = JsonValue(static_cast<std::uint64_t>(p.target_token));
        proxies_arr.push(std::move(item));
    }
    doc["inlined_proxies"] = std::move(proxies_arr);

    JsonValue strings_arr = JsonValue::array();
    for (const auto& s : rep.decrypted_strings) {
        JsonValue item = JsonValue::object();
        item["token"] = JsonValue(static_cast<std::uint64_t>(s.token));
        item["algorithm"] = JsonValue(s.algorithm);
        item["value"] = JsonValue(s.decrypted_value);
        item["offset"] = JsonValue(s.call_site_offset);
        strings_arr.push(std::move(item));
    }
    doc["decrypted_strings"] = std::move(strings_arr);

    JsonValue methods_arr = JsonValue::array();
    for (const auto& m : rep.reconstructed_methods) {
        JsonValue item = JsonValue::object();
        item["method"] = JsonValue(m.method_name);
        item["cases"] = JsonValue(static_cast<std::uint64_t>(m.switch_table_cases));
        item["strategy"] = JsonValue(m.strategy);
        methods_arr.push(std::move(item));
    }
    doc["flattened_methods"] = std::move(methods_arr);

    return doc;
}

int command_dotnet_clean(const Arguments& args, std::ostream& out, std::ostream& err) {
    if (args.has("help") || args.positional.empty()) {
        out << command_help("dotnet-clean");
        return 0;
    }

    const std::string& path = args.positional[0];
    auto view = BinaryView::open(path);
    if (!view) {
        err << "typemorph dotnet-clean: " << format_error(view.error()) << '\n';
        return 1;
    }

    auto img_res = core::ExecutableImage::parse(view.value());
    if (!img_res) {
        err << "typemorph dotnet-clean: " << format_error(img_res.error()) << '\n';
        return 1;
    }

    dotnet::DotNetDeobfuscator deobfuscator;
    dotnet::DotNetDeobfReport rep = deobfuscator.deobfuscate(img_res.value());

    if (!rep.is_dotnet) {
        err << "typemorph dotnet-clean: file is not a valid .NET / CLI executable\n";
        return 1;
    }

    if (args.has("json")) {
        auto doc = dotnet_deobf_report_to_json(path, rep);
        out << doc.dump(2) << '\n';
        return 0;
    }

    if (auto out_path = args.get("out")) {
        auto wr = write_file(*out_path, rep.clean_csharp_source);
        if (!wr) {
            err << "typemorph dotnet-clean: failed to write: " << *out_path << '\n';
            return 1;
        }
        out << dotnet::DotNetDeobfuscator::to_text_summary(rep) << "\n";
        out << "Clean C# source written to: " << *out_path << "\n";
        return 0;
    }

    out << dotnet::DotNetDeobfuscator::to_text_summary(rep) << "\n";
    out << rep.clean_csharp_source << "\n";
    return 0;
}

JsonValue lua_report_to_json(const std::string& path, const lua::LuaDecompileReport& rep) {
    JsonValue doc = JsonValue::object();
    doc["file"] = JsonValue(path);
    doc["is_lua_bytecode"] = JsonValue(rep.is_lua_bytecode);
    doc["flavor"] = JsonValue(std::string(lua::to_string(rep.flavor)));
    doc["total_functions"] = JsonValue(static_cast<std::uint64_t>(rep.total_functions));
    doc["total_instructions"] = JsonValue(static_cast<std::uint64_t>(rep.total_instructions));
    doc["total_constants"] = JsonValue(static_cast<std::uint64_t>(rep.total_constants));
    doc["source"] = JsonValue(rep.lua_source);
    return doc;
}

int command_lua(const Arguments& args, std::ostream& out, std::ostream& err) {
    if (args.has("help") || args.positional.empty()) {
        out << command_help("lua");
        return 0;
    }

    const std::string& path = args.positional[0];
    auto view = BinaryView::open(path);
    if (!view) {
        err << "typemorph lua: " << format_error(view.error()) << '\n';
        return 1;
    }

    lua::LuaDecompiler decompiler;
    lua::LuaDecompileReport rep = decompiler.decompile(view.value());

    if (!rep.is_lua_bytecode) {
        err << "typemorph lua: file is not a valid Lua or LuaJIT bytecode file\n";
        return 1;
    }

    if (args.has("json")) {
        auto doc = lua_report_to_json(path, rep);
        out << doc.dump(2) << '\n';
        return 0;
    }

    std::string text_output = args.has("disasm") ? lua::LuaDecompiler::to_disassembly(rep)
                                                 : rep.lua_source;

    if (auto out_path = args.get("out")) {
        auto wr = write_file(*out_path, text_output);
        if (!wr) {
            err << "typemorph lua: failed to write: " << *out_path << '\n';
            return 1;
        }
        out << "Lua " << (args.has("disasm") ? "disassembly" : "decompilation")
            << " written to: " << *out_path << "\n";
        return 0;
    }

    out << text_output;
    return 0;
}

int command_aes_recovery(const Arguments& args, std::ostream& out, std::ostream& err) {
    if (args.has("help") || args.positional.empty()) {
        out << command_help("aes-recovery");
        return 0;
    }

    const std::string& path = args.positional[0];
    auto view = BinaryView::open(path);
    if (!view) {
        err << "typemorph aes-recovery: " << format_error(view.error()) << '\n';
        return 1;
    }

    crypto::AesKeyRecoveryEngine engine;
    auto rep = engine.analyze(view.value());

    if (args.has("json")) {
        out << crypto::AesKeyRecoveryEngine::to_json(rep) << '\n';
        return 0;
    }

    out << crypto::AesKeyRecoveryEngine::to_text_report(rep) << '\n';
    return 0;
}

int command_delphi(const Arguments& args, std::ostream& out, std::ostream& err) {
    if (args.has("help") || args.positional.empty()) {
        out << command_help("delphi");
        return 0;
    }

    const std::string& path = args.positional[0];
    auto view = BinaryView::open(path);
    if (!view) {
        err << "typemorph delphi: " << format_error(view.error()) << '\n';
        return 1;
    }

    auto rep = delphi::DelphiAnalyzer::analyze(view.value());
    if (!rep.is_delphi) {
        err << "typemorph delphi: no Borland/Embarcadero Delphi or C++Builder signatures found in " << path << ".\n";
        return 1;
    }

    if (args.has("pascal")) {
        out << delphi::DelphiAnalyzer::to_pascal_source(rep);
        return 0;
    }

    out << delphi::DelphiAnalyzer::format_report(rep);
    return 0;
}

int command_dex(const Arguments& args, std::ostream& out, std::ostream& err) {
    if (args.has("help") || args.positional.empty()) {
        out << command_help("dex");
        return 0;
    }

    const std::string& path = args.positional[0];
    auto view = BinaryView::open(path);
    if (!view) {
        err << "typemorph dex: " << format_error(view.error()) << '\n';
        return 1;
    }

    auto rep = dex::DexAnalyzer::analyze(view.value());
    if (!rep.is_dex) {
        err << "typemorph dex: " << path << " is not a valid Android Dalvik Executable (DEX).\n";
        return 1;
    }

    if (args.has("java")) {
        out << dex::DexAnalyzer::to_java_source(rep);
        return 0;
    }

    out << dex::DexAnalyzer::format_report(rep);
    return 0;
}

int command_vb(const Arguments& args, std::ostream& out, std::ostream& err) {
    if (args.has("help") || args.positional.empty()) {
        out << command_help("vb");
        return 0;
    }

    const std::string& path = args.positional[0];
    auto view = BinaryView::open(path);
    if (!view) {
        err << "typemorph vb: " << format_error(view.error()) << '\n';
        return 1;
    }

    auto rep = vb::VbAnalyzer::analyze(view.value());
    if (!rep.is_vb) {
        err << "typemorph vb: no Visual Basic 5.0/6.0 signatures found in " << path << ".\n";
        return 1;
    }

    if (args.has("source")) {
        out << vb::VbAnalyzer::to_vb_source(rep);
        return 0;
    }

    out << vb::VbAnalyzer::format_report(rep);
    return 0;
}

int command_autoit(const Arguments& args, std::ostream& out, std::ostream& err) {
    if (args.has("help") || args.positional.empty()) {
        out << command_help("autoit");
        return 0;
    }

    const std::string& path = args.positional[0];
    auto view = BinaryView::open(path);
    if (!view) {
        err << "typemorph autoit: " << format_error(view.error()) << '\n';
        return 1;
    }

    auto rep = autoit::AutoItDecompiler::analyze(view.value());
    if (!rep.is_autoit) {
        err << "typemorph autoit: no AutoIt v3 signatures found in " << path << ".\n";
        return 1;
    }

    if (args.has("out")) {
        const std::string out_path = args.get("out").value();
        std::ofstream file(out_path);
        if (!file) {
            err << "typemorph autoit: cannot open " << out_path << " for writing.\n";
            return 1;
        }
        file << rep.primary_script;
        out << "typemorph autoit: decompiled script saved to " << out_path << "\n";
        return 0;
    }

    out << autoit::AutoItDecompiler::format_report(rep);
    return 0;
}

int command_vfs_extract(const Arguments& args, std::ostream& out, std::ostream& err) {
    if (args.has("help") || args.positional.empty()) {
        out << command_help("vfs-extract");
        return 0;
    }

    const std::string& path = args.positional[0];
    auto view = BinaryView::open(path);
    if (!view) {
        err << "typemorph vfs-extract: " << format_error(view.error()) << '\n';
        return 1;
    }

    auto rep = unpack::VfsExtractor::analyze(view.value());
    if (!rep.is_container) {
        err << "typemorph vfs-extract: no application virtualization container signatures found in " << path << ".\n";
        return 1;
    }

    out << unpack::VfsExtractor::format_report(rep);
    return 0;
}


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
        capabilities.push(JsonValue("cff"));
        capabilities.push(JsonValue("bitfield"));
        capabilities.push(JsonValue("apihash"));
        capabilities.push(JsonValue("opaque"));
        capabilities.push(JsonValue("rtti"));
        capabilities.push(JsonValue("checksec"));
        capabilities.push(JsonValue("go"));
        capabilities.push(JsonValue("rich"));
        capabilities.push(JsonValue("abi"));
        capabilities.push(JsonValue("csharp"));
        capabilities.push(JsonValue("dotnet"));
        capabilities.push(JsonValue("dotnet-clean"));
        capabilities.push(JsonValue("lua"));
        capabilities.push(JsonValue("aes-recovery"));
        capabilities.push(JsonValue("decompile"));
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
    if (method == "cff" || method == "typemorph.cff") {
        auto file = json_string_field(params, "file");
        if (!file) return file.error();
        auto view_result = BinaryView::open(file.value());
        if (!view_result) return view_result.error();
        auto image_result = core::ExecutableImage::parse(view_result.value());
        if (!image_result) return image_result.error();
        deobf::CffOptions opts;
        deobf::CffReconstructor reconstructor(opts);
        auto fns = reconstructor.analyze(image_result.value());

        JsonValue doc = JsonValue::object();
        doc["file"] = JsonValue(file.value());
        doc["count"] = JsonValue(static_cast<std::uint64_t>(fns.size()));
        JsonValue array = JsonValue::array();
        for (const auto& fn : fns) {
            JsonValue entry = JsonValue::object();
            entry["dispatcher_va"] = JsonValue(fn.dispatcher_va);
            entry["state_variable"] = JsonValue(fn.state_variable);
            entry["block_count"] = JsonValue(static_cast<std::uint64_t>(fn.blocks.size()));
            entry["transition_count"] = JsonValue(static_cast<std::uint64_t>(fn.transitions.size()));
            entry["confidence"] = JsonValue(fn.confidence);
            entry["rationale"] = JsonValue(fn.rationale);
            entry["dot"] = JsonValue(fn.to_dot());
            entry["mermaid"] = JsonValue(fn.to_mermaid());

            JsonValue blocks_arr = JsonValue::array();
            for (const auto& b : fn.blocks) {
                JsonValue blk = JsonValue::object();
                blk["state_id"] = JsonValue(static_cast<std::uint64_t>(b.state_id));
                blk["va"] = JsonValue(b.block_va);
                blk["size"] = JsonValue(static_cast<std::uint64_t>(b.size));
                blk["is_entry"] = JsonValue(b.is_entry);
                blk["is_exit"] = JsonValue(b.is_exit);
                blocks_arr.push(std::move(blk));
            }
            entry["blocks"] = std::move(blocks_arr);

            JsonValue trans_arr = JsonValue::array();
            for (const auto& t : fn.transitions) {
                JsonValue tr = JsonValue::object();
                tr["from"] = JsonValue(static_cast<std::uint64_t>(t.from_state));
                tr["to"] = JsonValue(static_cast<std::uint64_t>(t.to_state));
                trans_arr.push(std::move(tr));
            }
            entry["transitions"] = std::move(trans_arr);

            array.push(std::move(entry));
        }
        doc["functions"] = std::move(array);
        return doc;
    }
    if (method == "apihash" || method == "typemorph.apihash") {
        deobf::ApiHashResolver resolver;
        const auto* hash_num = params.find("hash");
        if (hash_num != nullptr && hash_num->as_int()) {
            std::uint32_t val = static_cast<std::uint32_t>(*hash_num->as_int());
            auto matches = resolver.resolve(val);
            JsonValue doc = JsonValue::object();
            doc["hash"] = JsonValue(static_cast<std::uint64_t>(val));
            JsonValue array = JsonValue::array();
            for (const auto& m : matches) {
                JsonValue item = JsonValue::object();
                item["api"] = JsonValue(m.api_name);
                item["module"] = JsonValue(m.module_name);
                item["algorithm"] = JsonValue(to_string(m.algorithm));
                item["confidence"] = JsonValue(m.confidence);
                array.push(std::move(item));
            }
            doc["matches"] = std::move(array);
            return doc;
        }
        auto file = json_string_field(params, "file");
        if (!file) return file.error();
        auto view_result = BinaryView::open(file.value());
        if (!view_result) return view_result.error();
        auto matches = resolver.scan(view_result.value());
        JsonValue doc = JsonValue::object();
        doc["file"] = JsonValue(file.value());
        doc["count"] = JsonValue(static_cast<std::int64_t>(matches.size()));
        JsonValue array = JsonValue::array();
        for (const auto& m : matches) {
            JsonValue item = JsonValue::object();
            item["offset"] = JsonValue(static_cast<std::uint64_t>(m.offset));
            item["hash"] = JsonValue(static_cast<std::uint64_t>(m.hash_value));
            item["api"] = JsonValue(m.api_name);
            item["module"] = JsonValue(m.module_name);
            item["algorithm"] = JsonValue(to_string(m.algorithm));
            item["confidence"] = JsonValue(m.confidence);
            array.push(std::move(item));
        }
        doc["matches"] = std::move(array);
        return doc;
    }
    if (method == "opaque" || method == "typemorph.opaque") {
        auto file = json_string_field(params, "file");
        if (!file) return file.error();
        auto view_result = BinaryView::open(file.value());
        if (!view_result) return view_result.error();
        deobf::OpaquePredicateDetector detector;
        auto matches = detector.scan(view_result.value());
        JsonValue doc = JsonValue::object();
        doc["file"] = JsonValue(file.value());
        doc["count"] = JsonValue(static_cast<std::int64_t>(matches.size()));
        JsonValue array = JsonValue::array();
        for (const auto& m : matches) {
            JsonValue item = JsonValue::object();
            item["offset"] = JsonValue(static_cast<std::uint64_t>(m.offset));
            item["length"] = JsonValue(static_cast<std::uint64_t>(m.instruction_length));
            item["outcome"] = JsonValue(to_string(m.outcome));
            item["pattern"] = JsonValue(m.pattern_name);
            item["disassembly"] = JsonValue(m.disassembly_hint);
            item["rationale"] = JsonValue(m.rationale);
            item["confidence"] = JsonValue(m.confidence);
            array.push(std::move(item));
        }
        doc["predicates"] = std::move(array);
        return doc;
    }
    if (method == "rtti" || method == "typemorph.rtti") {
        auto file = json_string_field(params, "file");
        if (!file) return file.error();
        auto view_result = BinaryView::open(file.value());
        if (!view_result) return view_result.error();
        rtti::RttiAnalyzer analyzer;
        auto classes = analyzer.analyze_view(view_result.value());
        auto doc = rtti_classes_to_json(file.value(), classes);
        auto fmt = json_string_field(params, "format", false).value_or("");
        if (fmt == "cpp") {
            doc["cpp_header"] = JsonValue(rtti::RttiAnalyzer::to_cpp_header(classes));
        }
        return doc;
    }
    if (method == "checksec" || method == "typemorph.checksec") {
        auto file = json_string_field(params, "file");
        if (!file) return file.error();
        auto view_result = BinaryView::open(file.value());
        if (!view_result) return view_result.error();
        security::SecurityAnalyzer analyzer;
        auto report = analyzer.analyze_view(view_result.value());
        return security_report_to_json(file.value(), report);
    }
    if (method == "go" || method == "typemorph.go") {
        auto file = json_string_field(params, "file");
        if (!file) return file.error();
        auto view_result = BinaryView::open(file.value());
        if (!view_result) return view_result.error();
        golang::GoAnalyzer analyzer;
        auto image_res = core::ExecutableImage::parse(view_result.value());
        golang::GoAnalysisReport rep = image_res
            ? analyzer.analyze(image_res.value())
            : analyzer.analyze_view(view_result.value());
        return go_report_to_json(file.value(), rep);
    }
    if (method == "rich" || method == "typemorph.rich") {
        auto file = json_string_field(params, "file");
        if (!file) return file.error();
        auto view_result = BinaryView::open(file.value());
        if (!view_result) return view_result.error();
        pe::RichHeaderParser parser;
        auto report = parser.parse(view_result.value());
        return rich_report_to_json(file.value(), report);
    }
    if (method == "abi" || method == "typemorph.abi") {
        auto file = json_string_field(params, "file");
        if (!file) return file.error();
        auto view_result = BinaryView::open(file.value());
        if (!view_result) return view_result.error();
        auto image_res = core::ExecutableImage::parse(view_result.value());
        if (!image_res) return image_res.error();
        abi::AbiClassifier classifier;
        std::optional<std::uint64_t> target_va;
        const auto* fn_val = params.find("function");
        if (fn_val && fn_val->as_int()) {
            target_va = static_cast<std::uint64_t>(*fn_val->as_int());
        }
        auto rep = classifier.analyze(image_res.value(), target_va);
        return abi_report_to_json(file.value(), rep);
    }
    if (method == "csharp" || method == "typemorph.csharp" ||
        method == "dotnet" || method == "typemorph.dotnet") {
        auto file = json_string_field(params, "file");
        if (!file) return file.error();
        auto view_result = BinaryView::open(file.value());
        if (!view_result) return view_result.error();
        dotnet::DotNetAnalyzer analyzer;
        auto rep = analyzer.analyze_view(view_result.value());
        rep.csharp_source = dotnet::DotNetAnalyzer::to_csharp(rep);
        return dotnet_report_to_json(file.value(), rep);
    }
    if (method == "dotnet-clean" || method == "typemorph.dotnet-clean" ||
        method == "dotnet-deobf" || method == "typemorph.dotnet-deobf" ||
        method == "deobf-dotnet" || method == "typemorph.deobf-dotnet") {
        auto file = json_string_field(params, "file");
        if (!file) return file.error();
        auto view_result = BinaryView::open(file.value());
        if (!view_result) return view_result.error();
        auto img_res = core::ExecutableImage::parse(view_result.value());
        if (!img_res) return img_res.error();
        dotnet::DotNetDeobfuscator deobfuscator;
        auto rep = deobfuscator.deobfuscate(img_res.value());
        return dotnet_deobf_report_to_json(file.value(), rep);
    }
    if (method == "lua" || method == "typemorph.lua" ||
        method == "luajit" || method == "typemorph.luajit") {
        auto file = json_string_field(params, "file");
        if (!file) return file.error();
        auto view_result = BinaryView::open(file.value());
        if (!view_result) return view_result.error();
        lua::LuaDecompiler decompiler;
        auto rep = decompiler.decompile(view_result.value());
        return lua_report_to_json(file.value(), rep);
    }
    if (method == "aes-recovery" || method == "typemorph.aes-recovery" ||
        method == "time-aes" || method == "typemorph.time-aes") {
        auto file = json_string_field(params, "file");
        if (!file) return file.error();
        auto view_result = BinaryView::open(file.value());
        if (!view_result) return view_result.error();
        crypto::AesKeyRecoveryEngine engine;
        auto rep = engine.analyze(view_result.value());
        auto parsed = parse_json(crypto::AesKeyRecoveryEngine::to_json(rep));
        if (parsed) return parsed.value();
        return JsonValue::object();
    }
    if (method == "decompile" || method == "typemorph.decompile") {
        auto file = json_string_field(params, "file");
        if (!file) return file.error();
        auto view_result = BinaryView::open(file.value());
        if (!view_result) return view_result.error();
        auto image_res = core::ExecutableImage::parse(view_result.value());
        if (!image_res) return image_res.error();
        auto lang = json_string_field(params, "lang", false).value_or("c");
        if (lang == "rust" || lang == "rs") {
            derust::RustSourceReconstructor reconstructor;
            auto rust_rep = reconstructor.reconstruct(image_res.value());
            rust_rep.rust_source = derust::RustSourceReconstructor::to_rust_source(rust_rep);
            JsonValue doc = JsonValue::object();
            doc["file"] = JsonValue(file.value());
            doc["lang"] = JsonValue("rust");
            doc["has_rust_artifacts"] = JsonValue(rust_rep.has_rust_artifacts);
            doc["trait_count"] = JsonValue(static_cast<std::uint64_t>(rust_rep.traits.size()));
            doc["rust_source"] = JsonValue(rust_rep.rust_source);
            return doc;
        }
        std::optional<std::uint64_t> target_va;
        const auto* fn_val = params.find("function");
        if (fn_val && fn_val->as_int()) {
            target_va = static_cast<std::uint64_t>(*fn_val->as_int());
        }
        decompile::CDecompiler decompiler;
        auto rep = decompiler.decompile(image_res.value(), target_va);
        return decompile_report_to_json(file.value(), rep);
    }
    if (method == "detect" || method == "typemorph.detect" ||
        method == "die" || method == "typemorph.die") {
        auto file = json_string_field(params, "file");
        if (!file) return file.error();
        auto view_result = BinaryView::open(file.value());
        if (!view_result) return view_result.error();
        detect::DetectorEngine engine;
        auto img_res = core::ExecutableImage::parse(view_result.value());
        auto rep = img_res ? engine.detect(img_res.value()) : engine.detect_view(view_result.value());
        return detect_report_to_json(file.value(), rep);
    }
    if (method == "fixiat" || method == "typemorph.fixiat" ||
        method == "importfix" || method == "typemorph.importfix") {
        auto file = json_string_field(params, "file");
        if (!file) return file.error();
        auto view_result = BinaryView::open(file.value());
        if (!view_result) return view_result.error();
        pe::IatReconstructionOptions opts;
        const auto* trace_val = params.find("trace_redirections");
        if (trace_val && trace_val->as_bool()) {
            opts.trace_redirections = *trace_val->as_bool();
        }
        pe::IatReconstructor reconstructor(opts);
        auto rep = reconstructor.analyze(view_result.value());
        return fixiat_report_to_json(file.value(), rep);
    }
    if (method == "classinformer" || method == "typemorph.classinformer" ||
        method == "classes" || method == "typemorph.classes") {
        auto file = json_string_field(params, "file");
        if (!file) return file.error();
        auto view_result = BinaryView::open(file.value());
        if (!view_result) return view_result.error();
        rtti::RttiAnalyzer analyzer;
        auto classes = analyzer.analyze_view(view_result.value());
        auto doc = classinformer_to_json(file.value(), classes);
        auto fmt = json_string_field(params, "format", false).value_or("");
        if (fmt == "cpp") {
            doc["cpp_header"] = JsonValue(rtti::RttiAnalyzer::to_cpp_header(classes));
        }
        return doc;
    }
    if (method == "sigmake" || method == "typemorph.sigmake" ||
        method == "sigmaker" || method == "typemorph.sigmaker") {
        auto file = json_string_field(params, "file");
        if (!file) return file.error();
        auto view_result = BinaryView::open(file.value());
        if (!view_result) return view_result.error();
        auto img_res = core::ExecutableImage::parse(view_result.value());
        if (!img_res) return img_res.error();
        std::size_t min_len = 32;
        if (const auto* ml = params.find("min_len")) {
            if (ml->as_int()) min_len = static_cast<std::size_t>(*ml->as_int());
        }
        std::vector<GeneratedSignature> sigs;
        const auto* fn_val = params.find("function");
        if (fn_val && fn_val->as_int()) {
            std::uint64_t target_va = static_cast<std::uint64_t>(*fn_val->as_int());
            char name_buf[64];
            std::snprintf(name_buf, sizeof(name_buf), "sub_%llX", static_cast<unsigned long long>(target_va));
            sigs.push_back(make_func_signature(img_res.value(), view_result.value(), target_va, name_buf, min_len));
        } else {
            abi::AbiClassifier classifier;
            auto abi_rep = classifier.analyze(img_res.value());
            std::size_t limit = std::min<std::size_t>(abi_rep.signatures.size(), 20);
            for (std::size_t i = 0; i < limit; ++i) {
                const auto& fn = abi_rep.signatures[i];
                sigs.push_back(make_func_signature(img_res.value(), view_result.value(), fn.entry_va, fn.name, min_len));
            }
        }
        return sigmake_to_json(file.value(), sigs);
    }
    if (method == "applycalletype" || method == "typemorph.applycalletype" ||
        method == "applycalletypeex" || method == "typemorph.applycalletypeex") {
        auto file = json_string_field(params, "file");
        if (!file) return file.error();
        auto view_result = BinaryView::open(file.value());
        if (!view_result) return view_result.error();
        auto img_res = core::ExecutableImage::parse(view_result.value());
        if (!img_res) return img_res.error();
        abi::AbiClassifier classifier;
        auto rep = classifier.analyze(img_res.value());
        auto doc = abi_report_to_json(file.value(), rep);
        doc["tool"] = JsonValue("applycalletype");
        return doc;
    }
    if (method == "dumpsubs" || method == "typemorph.dumpsubs" ||
        method == "subsdump" || method == "typemorph.subsdump") {
        auto file = json_string_field(params, "file");
        if (!file) return file.error();
        auto view_result = BinaryView::open(file.value());
        if (!view_result) return view_result.error();
        auto img_res = core::ExecutableImage::parse(view_result.value());
        if (!img_res) return img_res.error();
        abi::AbiClassifier classifier;
        auto rep = classifier.analyze(img_res.value());
        return abi_report_to_json(file.value(), rep);
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
            rest, {"width", "height", "out"}, {"render-once", "no-tui", "html"}, 0, 1);
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
    if (command == "cff") {
        auto parsed = parse_arguments(
            rest, {"function", "format"},
            {}, 1, 1);
        if (!parsed) {
            err_ << usage_error(parsed.error().message) << '\n';
            return 2;
        }
        return command_cff(parsed.value(), out_, err_);
    }
    if (command == "apihash") {
        auto parsed = parse_arguments(
            rest, {},
            {}, 1, 1);
        if (!parsed) {
            err_ << usage_error(parsed.error().message) << '\n';
            return 2;
        }
        return command_apihash(parsed.value(), out_, err_);
    }
    if (command == "opaque") {
        auto parsed = parse_arguments(
            rest, {},
            {}, 1, 1);
        if (!parsed) {
            err_ << usage_error(parsed.error().message) << '\n';
            return 2;
        }
        return command_opaque(parsed.value(), out_, err_);
    }
    if (command == "rtti") {
        auto parsed = parse_arguments(
            rest, {"format"},
            {}, 1, 1);
        if (!parsed) {
            err_ << usage_error(parsed.error().message) << '\n';
            return 2;
        }
        return command_rtti(parsed.value(), out_, err_);
    }
    if (command == "checksec") {
        auto parsed = parse_arguments(
            rest, {},
            {}, 1, 1);
        if (!parsed) {
            err_ << usage_error(parsed.error().message) << '\n';
            return 2;
        }
        return command_checksec(parsed.value(), out_, err_);
    }
    if (command == "go") {
        auto parsed = parse_arguments(
            rest, {"out"},
            {"source"}, 1, 1);
        if (!parsed) {
            err_ << usage_error(parsed.error().message) << '\n';
            return 2;
        }
        return command_go(parsed.value(), out_, err_);
    }
    if (command == "rich") {
        auto parsed = parse_arguments(
            rest, {},
            {}, 1, 1);
        if (!parsed) {
            err_ << usage_error(parsed.error().message) << '\n';
            return 2;
        }
        return command_rich(parsed.value(), out_, err_);
    }
    if (command == "abi") {
        auto parsed = parse_arguments(
            rest, {"function"},
            {}, 1, 1);
        if (!parsed) {
            err_ << usage_error(parsed.error().message) << '\n';
            return 2;
        }
        return command_abi(parsed.value(), out_, err_);
    }
    if (command == "csharp" || command == "dotnet") {
        auto parsed = parse_arguments(
            rest, {"out"},
            {}, 1, 1);
        if (!parsed) {
            err_ << usage_error(parsed.error().message) << '\n';
            return 2;
        }
        return command_csharp(parsed.value(), out_, err_);
    }
    if (command == "decompile") {
        auto parsed = parse_arguments(
            rest, {"function", "lang", "out"},
            {}, 1, 1);
        if (!parsed) {
            err_ << usage_error(parsed.error().message) << '\n';
            return 2;
        }
        return command_decompile(parsed.value(), out_, err_);
    }
    if (command == "detect" || command == "die") {
        auto parsed = parse_arguments(
            rest, {},
            {}, 1, 1);
        if (!parsed) {
            err_ << usage_error(parsed.error().message) << '\n';
            return 2;
        }
        return command_detect(parsed.value(), out_, err_);
    }
    if (command == "fixiat" || command == "importfix") {
        auto parsed = parse_arguments(
            rest, {"out", "section"},
            {"no-trace"}, 1, 1);
        if (!parsed) {
            err_ << usage_error(parsed.error().message) << '\n';
            return 2;
        }
        return command_fixiat(parsed.value(), out_, err_);
    }
    if (command == "classinformer" || command == "classes") {
        auto parsed = parse_arguments(
            rest, {"format"},
            {}, 1, 1);
        if (!parsed) {
            err_ << usage_error(parsed.error().message) << '\n';
            return 2;
        }
        return command_classinformer(parsed.value(), out_, err_);
    }
    if (command == "sigmake" || command == "sigmaker") {
        auto parsed = parse_arguments(
            rest, {"function", "format", "min-len"},
            {}, 1, 1);
        if (!parsed) {
            err_ << usage_error(parsed.error().message) << '\n';
            return 2;
        }
        return command_sigmake(parsed.value(), out_, err_);
    }
    if (command == "applycalletype" || command == "applycalletypeex") {
        auto parsed = parse_arguments(
            rest, {"function"},
            {"apply-ida"}, 1, 1);
        if (!parsed) {
            err_ << usage_error(parsed.error().message) << '\n';
            return 2;
        }
        return command_applycalletype(parsed.value(), out_, err_);
    }
    if (command == "dumpsubs" || command == "subsdump") {
        auto parsed = parse_arguments(
            rest, {"out", "min-size"},
            {}, 1, 1);
        if (!parsed) {
            err_ << usage_error(parsed.error().message) << '\n';
            return 2;
        }
        return command_dumpsubs(parsed.value(), out_, err_);
    }
    if (command == "dotnet-clean" || command == "dotnet-deobf" || command == "deobf-dotnet") {
        auto parsed = parse_arguments(
            rest, {"out"},
            {}, 1, 1);
        if (!parsed) {
            err_ << usage_error(parsed.error().message) << '\n';
            return 2;
        }
        return command_dotnet_clean(parsed.value(), out_, err_);
    }
    if (command == "lua" || command == "luajit") {
        auto parsed = parse_arguments(
            rest, {"out"},
            {"disasm"}, 1, 1);
        if (!parsed) {
            err_ << usage_error(parsed.error().message) << '\n';
            return 2;
        }
        return command_lua(parsed.value(), out_, err_);
    }
    if (command == "aes-recovery" || command == "time-aes" || command == "aesfind") {
        auto parsed = parse_arguments(
            rest, {},
            {}, 1, 1);
        if (!parsed) {
            err_ << usage_error(parsed.error().message) << '\n';
            return 2;
        }
        return command_aes_recovery(parsed.value(), out_, err_);
    }
    if (command == "delphi" || command == "dede" || command == "idr") {
        auto parsed = parse_arguments(
            rest, {},
            {"pascal"}, 1, 1);
        if (!parsed) {
            err_ << usage_error(parsed.error().message) << '\n';
            return 2;
        }
        return command_delphi(parsed.value(), out_, err_);
    }
    if (command == "dex" || command == "jadx" || command == "dalvik") {
        auto parsed = parse_arguments(
            rest, {},
            {"java"}, 1, 1);
        if (!parsed) {
            err_ << usage_error(parsed.error().message) << '\n';
            return 2;
        }
        return command_dex(parsed.value(), out_, err_);
    }
    if (command == "vb" || command == "vbdecompiler" || command == "vb6") {
        auto parsed = parse_arguments(
            rest, {},
            {"source"}, 1, 1);
        if (!parsed) {
            err_ << usage_error(parsed.error().message) << '\n';
            return 2;
        }
        return command_vb(parsed.value(), out_, err_);
    }
    if (command == "autoit" || command == "exe2aut" || command == "au3") {
        auto parsed = parse_arguments(
            rest, {"out"},
            {}, 1, 1);
        if (!parsed) {
            err_ << usage_error(parsed.error().message) << '\n';
            return 2;
        }
        return command_autoit(parsed.value(), out_, err_);
    }
    if (command == "vfs-extract" || command == "spoondec" || command == "evbunpack") {
        auto parsed = parse_arguments(
            rest, {},
            {}, 1, 1);
        if (!parsed) {
            err_ << usage_error(parsed.error().message) << '\n';
            return 2;
        }
        return command_vfs_extract(parsed.value(), out_, err_);
    }
    if (command == "studio" || command == "gui" || command == "dnspy") {
        if (!rest.empty() && (rest.front() == "--help" || rest.front() == "-h")) {
            out_ << command_help("studio");
            return 0;
        }
#ifdef _WIN32
        std::string target;
        if (!rest.empty()) {
            target = std::string(rest.front());
        }
        gui::StudioApp app;
        return app.run(target);
#else
        err_ << "typemorph studio: Native GUI requires Windows platform.\n";
        return 1;
#endif
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
