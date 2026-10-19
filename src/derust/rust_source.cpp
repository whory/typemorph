// TypeMorph - Rust High-Level Source Code Reconstructor.
#include "typemorph/derust/rust_source.hpp"

#include <cstdio>
#include <iomanip>
#include <map>
#include <set>
#include <sstream>

namespace typemorph::derust {

namespace {

std::string format_hex(std::uint64_t val) {
    char buf[32];
    std::snprintf(buf, sizeof(buf), "0x%llX", static_cast<unsigned long long>(val));
    return std::string(buf);
}

std::string sanitize_ident(std::string_view name) {
    std::string s;
    for (char c : name) {
        if ((c >= 'a' && c <= 'z') || (c >= 'A' && c <= 'Z') || (c >= '0' && c <= '9') || c == '_') {
            s.push_back(c);
        } else {
            s.push_back('_');
        }
    }
    if (s.empty()) s = "unnamed";
    if (s[0] >= '0' && s[0] <= '9') s = "_" + s;
    return s;
}

constexpr const char* niche_kind_to_string(NicheKind kind) noexcept {
    switch (kind) {
    case NicheKind::nullable_pointer: return "nullable_pointer";
    case NicheKind::non_zero_integer: return "non_zero_integer";
    case NicheKind::invalid_enum_value: return "invalid_enum_value";
    case NicheKind::pointer_alignment_hole: return "pointer_alignment_hole";
    }
    return "unknown";
}

}  // namespace

std::string RustSourceReconstructor::to_rust_source(const RustSourceReport& report) {
    if (!report.has_rust_artifacts && report.traits.empty() && report.tagged_unions.empty() && report.symbols.empty()) {
        return "// No Rust semantics detected\n";
    }

    std::ostringstream ss;
    ss << "// Reconstructed with TypeMorph v0.6.0\n"
       << "// Rust High-Level Semantic Representation\n"
       << "#![allow(dead_code, non_snake_case, unused_variables, non_camel_case_types)]\n\n";

    // 1. Recovered Traits
    if (!report.traits.empty()) {
        ss << "// ==========================================================================\n"
           << "// Recovered Trait Definitions & VTables (" << report.traits.size() << ")\n"
           << "// ==========================================================================\n\n";

        for (const auto& tr : report.traits) {
            ss << "/// VTable: " << format_hex(tr.vtable_va) << " (Object Size: "
               << tr.size << " bytes, Align: " << tr.align << ")\n"
               << "pub trait " << tr.trait_name << " {\n";

            for (std::size_t i = 0; i < tr.method_names.size(); ++i) {
                ss << "    /// Method slot " << i << " @ " << format_hex(tr.method_vas[i]) << "\n"
                   << "    fn " << sanitize_ident(tr.method_names[i]) << "(&self);\n";
            }
            ss << "}\n\n";
        }
    }

    // 2. Recovered Enums & Tagged Unions
    if (!report.tagged_unions.empty() || !report.niches.empty()) {
        ss << "// ==========================================================================\n"
           << "// Recovered Enums & Niche Encoded Types (" << report.tagged_unions.size() + report.niches.size() << ")\n"
           << "// ==========================================================================\n\n";

        for (std::size_t i = 0; i < report.tagged_unions.size(); ++i) {
            const auto& tu = report.tagged_unions[i];
            ss << "/// Tagged Union @ Offset " << format_hex(tu.offset)
               << " (Tag: " << static_cast<int>(tu.tag_width) << "B, Variants: " << tu.variants.size() << ")\n"
               << "#[repr(C)]\n"
               << "pub enum TaggedUnion_" << i << " {\n";

            for (std::size_t v = 0; v < tu.variants.size(); ++v) {
                ss << "    Variant" << v << " = " << tu.variants[v].tag << ",\n";
            }
            ss << "}\n\n";
        }

        for (std::size_t i = 0; i < report.niches.size(); ++i) {
            const auto& n = report.niches[i];
            ss << "/// Niche Candidate @ Offset " << format_hex(n.offset)
               << " (Kind: " << niche_kind_to_string(n.kind) << ")\n"
               << "/// " << n.rationale << "\n"
               << "#[repr(C)]\n"
               << "pub struct NicheType_" << i << "(pub usize);\n\n";
        }
    }

    // 3. Recovered Demangled Functions
    if (!report.symbols.empty()) {
        ss << "// ==========================================================================\n"
           << "// Recovered Functions & Methods (" << report.symbols.size() << ")\n"
           << "// ==========================================================================\n\n";

        std::size_t limit = std::min<std::size_t>(report.symbols.size(), 100);
        for (std::size_t i = 0; i < limit; ++i) {
            const auto& s = report.symbols[i];
            ss << "/// Original: " << s.mangled << "\n"
               << "pub fn " << sanitize_ident(s.demangled) << "() {\n"
               << "    // Implementation stub\n"
               << "}\n\n";
        }
    }

    return ss.str();
}

RustSourceReport RustSourceReconstructor::reconstruct_view(const core::BinaryView& view) const {
    auto image_res = core::ExecutableImage::parse(view);
    if (!image_res) return {};
    return reconstruct(image_res.value());
}

RustSourceReport RustSourceReconstructor::reconstruct(const core::ExecutableImage& image) const {
    RustSourceReport report;

    // 1. Scan strings
    SliceScanner scanner;
    auto str_res = scanner.scan(image);
    if (str_res) {
        report.strings = std::move(str_res).value();
    }

    // 2. Scan vtables / trait objects
    VTableAnalyzer vt_analyzer;
    auto vt_res = vt_analyzer.analyze(image);
    if (vt_res) {
        const auto& vtables = vt_res.value();
        for (std::size_t i = 0; i < vtables.size(); ++i) {
            const auto& cand = vtables[i];
            RustTraitDefinition td;
            td.trait_name = "Trait_" + std::to_string(i) + "_" + format_hex(cand.address).substr(2);
            td.vtable_va = cand.address;
            td.drop_in_place_va = cand.drop_in_place;
            td.size = static_cast<std::size_t>(cand.object_size);
            td.align = static_cast<std::size_t>(cand.object_align);

            const std::size_t header_skip = std::min<std::size_t>(cand.entries.size(), 3);
            for (std::size_t m = header_skip; m < cand.entries.size(); ++m) {
                td.method_vas.push_back(cand.entries[m].address);
                td.method_names.push_back(cand.entries[m].symbol.empty()
                    ? ("method_" + std::to_string(m - header_skip))
                    : cand.entries[m].symbol);
            }
            report.traits.push_back(std::move(td));
        }
    }

    // 3. Scan enums / niches
    EnumReconstructor enum_recon;
    report.tagged_unions = enum_recon.scan_tagged_unions(image.view(), &image);
    report.niches = enum_recon.scan_niches(image.view(), &image);

    // 4. Demangle symbols
    for (const auto& sym : image.symbols()) {
        if (looks_like_rust_symbol(sym.name)) {
            auto dem = demangle(sym.name);
            if (dem) {
                report.symbols.push_back(std::move(dem).value());
            } else {
                DemangledSymbol ds;
                ds.mangled = sym.name;
                ds.demangled = sym.name;
                ds.is_rust = true;
                report.symbols.push_back(std::move(ds));
            }
        }
    }

    report.has_rust_artifacts = (!report.strings.empty() || !report.traits.empty() ||
                                 !report.symbols.empty() || !report.tagged_unions.empty());
    report.rust_source = to_rust_source(report);

    return report;
}

}  // namespace typemorph::derust
