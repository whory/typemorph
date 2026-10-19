// TypeMorph - AutoIt v3 Script Extractor & Decompiler Implementation (Exe2Aut engine)
#include "typemorph/autoit/autoit_decompiler.hpp"

#include <algorithm>
#include <iomanip>
#include <sstream>

namespace typemorph::autoit {

namespace {

inline std::uint32_t read_u32(const std::uint8_t* p) {
    return static_cast<std::uint32_t>(p[0] | (static_cast<std::uint32_t>(p[1]) << 8) |
                                      (static_cast<std::uint32_t>(p[2]) << 16) |
                                      (static_cast<std::uint32_t>(p[3]) << 24));
}

inline bool contains_str(const std::uint8_t* data, std::size_t size, std::string_view sig) {
    if (sig.empty() || sig.size() > size) return false;
    const auto* it = std::search(
        data, data + size,
        reinterpret_cast<const std::uint8_t*>(sig.data()),
        reinterpret_cast<const std::uint8_t*>(sig.data() + sig.size()));
    return it != (data + size);
}

} // namespace

bool AutoItDecompiler::is_autoit(const BinaryView& view) {
    if (view.size() < 128) return false;
    const auto* data = view.data();
    std::size_t size = view.size();

    const std::vector<std::string> signatures = {
        "AU3!EA06",
        "AU3!EA05",
        "AU3!EA04",
        ">>>AUTOIT SCRIPT<<<",
        ">>>AUTOIT NO-EXECUTE<<<",
        "AutoIt v3 Script",
        "AutoIt3"
    };

    for (const auto& sig : signatures) {
        if (contains_str(data, size, sig)) return true;
    }

    return false;
}

std::string AutoItDecompiler::decompile_tokens(std::span<const std::uint8_t> data) {
    if (data.empty()) return "";

    // Check if the data is already plain ASCII/UTF-8 AutoIt script text
    bool is_plain_text = true;
    for (std::size_t i = 0; i < std::min(data.size(), static_cast<std::size_t>(256)); ++i) {
        std::uint8_t b = data[i];
        if (b < 9 || (b > 13 && b < 32 && b != 10) || b > 126) {
            is_plain_text = false;
            break;
        }
    }

    if (is_plain_text) {
        return std::string(reinterpret_cast<const char*>(data.data()), data.size());
    }

    // Tokenized bytecode stream decompiler
    std::ostringstream ss;
    std::size_t pos = 0;
    int indent = 0;
    bool at_line_start = true;

    auto print_indent = [&]() {
        if (at_line_start) {
            for (int k = 0; k < indent; ++k) ss << "    ";
            at_line_start = false;
        }
    };

    while (pos < data.size()) {
        std::uint8_t token = data[pos++];

        switch (token) {
        case 0x00: // End of line / newline
            ss << "\n";
            at_line_start = true;
            break;
        case 0x01: { // Func <name>
            print_indent();
            std::size_t name_len = (pos < data.size()) ? data[pos++] : 0;
            std::string fname;
            while (name_len-- > 0 && pos < data.size()) fname.push_back(static_cast<char>(data[pos++]));
            ss << "Func " << fname << "(";
            indent++;
            break;
        }
        case 0x02: // EndFunc
            indent = std::max(0, indent - 1);
            print_indent();
            ss << "EndFunc\n";
            at_line_start = true;
            break;
        case 0x03: // If
            print_indent();
            ss << "If ";
            indent++;
            break;
        case 0x04: // Else
            indent = std::max(0, indent - 1);
            print_indent();
            ss << "Else\n";
            indent++;
            at_line_start = true;
            break;
        case 0x05: // EndIf
            indent = std::max(0, indent - 1);
            print_indent();
            ss << "EndIf\n";
            at_line_start = true;
            break;
        case 0x06: // While
            print_indent();
            ss << "While ";
            indent++;
            break;
        case 0x07: // WEnd
            indent = std::max(0, indent - 1);
            print_indent();
            ss << "WEnd\n";
            at_line_start = true;
            break;
        case 0x08: // For
            print_indent();
            ss << "For ";
            indent++;
            break;
        case 0x09: // Next
            indent = std::max(0, indent - 1);
            print_indent();
            ss << "Next\n";
            at_line_start = true;
            break;
        case 0x0A: // Return
            print_indent();
            ss << "Return ";
            break;
        case 0x0B: // Local
            print_indent();
            ss << "Local ";
            break;
        case 0x0C: // Global
            print_indent();
            ss << "Global ";
            break;
        case 0x10: { // Variable: $var
            print_indent();
            std::size_t var_len = (pos < data.size()) ? data[pos++] : 0;
            std::string vname = "$";
            while (var_len-- > 0 && pos < data.size()) vname.push_back(static_cast<char>(data[pos++]));
            ss << vname << " ";
            break;
        }
        case 0x11: { // Function identifier: MsgBox, etc.
            print_indent();
            std::size_t fn_len = (pos < data.size()) ? data[pos++] : 0;
            std::string fn_name;
            while (fn_len-- > 0 && pos < data.size()) fn_name.push_back(static_cast<char>(data[pos++]));
            ss << fn_name;
            break;
        }
        case 0x12: { // String literal: "..."
            print_indent();
            std::size_t s_len = (pos < data.size()) ? data[pos++] : 0;
            std::string s_val;
            while (s_len-- > 0 && pos < data.size()) s_val.push_back(static_cast<char>(data[pos++]));
            ss << "\"" << s_val << "\"";
            break;
        }
        case 0x13: { // Integer literal
            print_indent();
            if (pos + 4 <= data.size()) {
                std::uint32_t val = read_u32(data.data() + pos);
                pos += 4;
                ss << val << " ";
            }
            break;
        }
        case 0x20: // =
            ss << "= ";
            break;
        case 0x21: // +
            ss << "+ ";
            break;
        case 0x22: // -
            ss << "- ";
            break;
        case 0x25: // &
            ss << "& ";
            break;
        case 0x26: // ==
            ss << "== ";
            break;
        case 0x28: // ,
            ss << ", ";
            break;
        case 0x29: // (
            ss << "(";
            break;
        case 0x2A: // )
            ss << ") ";
            break;
        default:
            break;
        }
    }

    return ss.str();
}

AutoItReport AutoItDecompiler::analyze(const BinaryView& view) {
    AutoItReport report;
    report.is_autoit = is_autoit(view);
    if (!report.is_autoit) return report;

    const auto* data = view.data();
    std::size_t size = view.size();

    // 1. Identify AutoIt version
    if (contains_str(data, size, "AU3!EA06")) {
        report.version = "AU3!EA06 (AutoIt v3.2.6+ / modern)";
    } else if (contains_str(data, size, "AU3!EA05")) {
        report.version = "AU3!EA05 (AutoIt v3.1 - v3.2.5)";
    } else if (contains_str(data, size, "AU3!EA04")) {
        report.version = "AU3!EA04 (Legacy AutoIt v3.0)";
    } else {
        report.version = "AutoIt v3 (Auto-detected)";
    }

    // 2. Locate AU3!EA06 or script header
    const std::uint8_t ea06_magic[8] = {'A', 'U', '3', '!', 'E', 'A', '0', '6'};
    auto it = std::search(data, data + size, ea06_magic, ea06_magic + 8);
    if (it != data + size) {
        report.script_offset = static_cast<std::uint64_t>(it - data);
        std::size_t cur = static_cast<std::size_t>(report.script_offset + 8);

        // Check for directory of files
        if (cur + 16 <= size) {
            AutoItEmbeddedFile main_file;
            main_file.filename = "script.au3";
            main_file.offset = cur;
            main_file.is_script = true;

            std::size_t script_len = std::min(size - cur, static_cast<std::size_t>(64 * 1024));
            main_file.compressed_size = script_len;
            main_file.uncompressed_size = script_len;

            std::span<const std::uint8_t> script_data(data + cur, script_len);
            main_file.decompiled_source = decompile_tokens(script_data);
            report.primary_script = main_file.decompiled_source;
            report.files.push_back(main_file);
        }
    } else {
        // Fallback: search for ">>>AUTOIT SCRIPT<<<" tag
        const std::string tag = ">>>AUTOIT SCRIPT<<<";
        auto tag_it = std::search(data, data + size, tag.begin(), tag.end());
        if (tag_it != data + size) {
            report.script_offset = static_cast<std::uint64_t>(tag_it - data);
            std::size_t cur = static_cast<std::size_t>(report.script_offset + tag.size());

            AutoItEmbeddedFile main_file;
            main_file.filename = "extracted.au3";
            main_file.offset = cur;
            main_file.is_script = true;

            std::size_t script_len = std::min(size - cur, static_cast<std::size_t>(64 * 1024));
            std::span<const std::uint8_t> script_data(data + cur, script_len);
            main_file.decompiled_source = decompile_tokens(script_data);
            report.primary_script = main_file.decompiled_source;
            report.files.push_back(main_file);
        }
    }

    return report;
}

std::string AutoItDecompiler::format_report(const AutoItReport& report) {
    std::ostringstream ss;
    ss << "=== TypeMorph AutoIt v3 Script Extractor & Decompiler (Exe2Aut) ===\n\n"
       << "AutoIt Version   : " << report.version << "\n"
       << "Payload Offset   : 0x" << std::hex << report.script_offset << std::dec << "\n"
       << "Embedded Files   : " << report.files.size() << "\n\n";

    for (std::size_t i = 0; i < report.files.size(); ++i) {
        const auto& f = report.files[i];
        ss << "[" << (i + 1) << "] File: " << f.filename << " ("
           << f.uncompressed_size << " bytes, offset 0x" << std::hex << f.offset << std::dec << ")\n";
    }

    if (!report.primary_script.empty()) {
        ss << "\n--- Decompiled Primary AutoIt Script (.au3) ---\n"
           << report.primary_script << "\n";
    }

    return ss.str();
}

} // namespace typemorph::autoit
