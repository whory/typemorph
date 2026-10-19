// TypeMorph - Structural & binary diffing engine implementation.
#include "typemorph/diff/binary_diff.hpp"

#include "typemorph/core/entropy.hpp"
#include "typemorph/core/executable.hpp"

#include <algorithm>
#include <cmath>
#include <cstddef>
#include <cstdint>
#include <map>
#include <set>
#include <span>
#include <string>
#include <utility>
#include <vector>

namespace typemorph::diff {

BinaryDiffResult BinaryDiffEngine::compare(const core::BinaryView& view_a,
                                           const core::BinaryView& view_b,
                                           std::string name_a,
                                           std::string name_b) const {
    BinaryDiffResult res;
    res.file_a = std::move(name_a);
    res.file_b = std::move(name_b);
    res.size_a = view_a.size();
    res.size_b = view_b.size();
    res.size_delta = static_cast<std::int64_t>(res.size_b) - static_cast<std::int64_t>(res.size_a);
    res.entropy_a = view_a.empty() ? 0.0 : core::shannon_entropy(view_a.bytes());
    res.entropy_b = view_b.empty() ? 0.0 : core::shannon_entropy(view_b.bytes());

    const auto bytes_a = view_a.bytes();
    const auto bytes_b = view_b.bytes();

    // 1. Byte-level alignment & diff ranges
    std::uint64_t matched_bytes = 0;
    std::uint64_t pos_a = 0;
    std::uint64_t pos_b = 0;
    const std::uint64_t min_len = std::min(res.size_a, res.size_b);

    while (pos_a < min_len && pos_b < min_len) {
        if (bytes_a[pos_a] == bytes_b[pos_b]) {
            std::uint64_t start_match = pos_a;
            while (pos_a < min_len && bytes_a[pos_a] == bytes_b[pos_b]) {
                ++pos_a;
                ++pos_b;
            }
            std::uint64_t match_len = pos_a - start_match;
            matched_bytes += match_len;
            DiffRange range;
            range.offset_a = start_match;
            range.size_a = match_len;
            range.offset_b = start_match;
            range.size_b = match_len;
            range.kind = "match";
            res.ranges.push_back(range);
        } else {
            std::uint64_t start_mod = pos_a;
            while (pos_a < min_len && bytes_a[pos_a] != bytes_b[pos_b]) {
                ++pos_a;
                ++pos_b;
            }
            std::uint64_t mod_len = pos_a - start_mod;
            DiffRange range;
            range.offset_a = start_mod;
            range.size_a = mod_len;
            range.offset_b = start_mod;
            range.size_b = mod_len;
            range.kind = "modified";
            res.ranges.push_back(range);
        }
    }

    if (res.size_a > min_len) {
        DiffRange range;
        range.offset_a = min_len;
        range.size_a = res.size_a - min_len;
        range.offset_b = min_len;
        range.size_b = 0;
        range.kind = "deleted";
        res.ranges.push_back(range);
    } else if (res.size_b > min_len) {
        DiffRange range;
        range.offset_a = min_len;
        range.size_a = 0;
        range.offset_b = min_len;
        range.size_b = res.size_b - min_len;
        range.kind = "inserted";
        res.ranges.push_back(range);
    }

    const std::uint64_t max_size = std::max(res.size_a, res.size_b);
    res.similarity = max_size == 0 ? 1.0 : static_cast<double>(matched_bytes) / static_cast<double>(max_size);

    // 2. Executable image comparison
    auto exe_a = core::ExecutableImage::parse(view_a);
    auto exe_b = core::ExecutableImage::parse(view_b);
    if (exe_a && exe_b) {
        res.both_executables = true;
        res.format_a = std::string(core::to_string(exe_a.value().format()));
        res.format_b = std::string(core::to_string(exe_b.value().format()));

        // Section comparison
        std::map<std::string, const core::Section*> sec_map_a;
        for (const auto& sec : exe_a.value().sections()) {
            sec_map_a[sec.name] = &sec;
        }
        std::set<std::string> seen_secs;

        for (const auto& sec_b : exe_b.value().sections()) {
            seen_secs.insert(sec_b.name);
            auto it = sec_map_a.find(sec_b.name);
            SectionDiff sd;
            sd.name = sec_b.name;
            sd.size_b = sec_b.file_size;
            auto bytes_sb = exe_b.value().section_bytes(sec_b);
            sd.entropy_b = (bytes_sb && !bytes_sb.value().empty())
                               ? core::shannon_entropy(bytes_sb.value())
                               : 0.0;
            if (it != sec_map_a.end()) {
                sd.size_a = it->second->file_size;
                auto bytes_sa = exe_a.value().section_bytes(*it->second);
                sd.entropy_a = (bytes_sa && !bytes_sa.value().empty())
                                   ? core::shannon_entropy(bytes_sa.value())
                                   : 0.0;
                if (sd.size_a == sd.size_b && std::abs(sd.entropy_a - sd.entropy_b) < 0.01) {
                    sd.status = "matched";
                } else {
                    sd.status = "modified";
                }
            } else {
                sd.status = "added";
            }
            res.section_diffs.push_back(sd);
        }

        for (const auto& sec_a : exe_a.value().sections()) {
            if (seen_secs.find(sec_a.name) == seen_secs.end()) {
                SectionDiff sd;
                sd.name = sec_a.name;
                sd.size_a = sec_a.file_size;
                auto bytes_sa = exe_a.value().section_bytes(sec_a);
                sd.entropy_a = (bytes_sa && !bytes_sa.value().empty())
                                   ? core::shannon_entropy(bytes_sa.value())
                                   : 0.0;
                sd.status = "removed";
                res.section_diffs.push_back(sd);
            }
        }

        // Symbol comparison
        std::map<std::string, const core::Symbol*> sym_map_a;
        for (const auto& sym : exe_a.value().symbols()) {
            if (!sym.name.empty()) sym_map_a[sym.name] = &sym;
        }
        std::set<std::string> seen_syms;

        for (const auto& sym_b : exe_b.value().symbols()) {
            if (sym_b.name.empty()) continue;
            seen_syms.insert(sym_b.name);
            auto it = sym_map_a.find(sym_b.name);
            SymbolDiff sym_diff;
            sym_diff.name = sym_b.name;
            sym_diff.addr_b = sym_b.address;
            if (it != sym_map_a.end()) {
                sym_diff.addr_a = it->second->address;
                if (sym_diff.addr_a == sym_diff.addr_b) {
                    sym_diff.status = "matched";
                } else {
                    sym_diff.status = "address_changed";
                }
            } else {
                sym_diff.status = "added";
            }
            res.symbol_diffs.push_back(sym_diff);
        }

        for (const auto& sym_a : exe_a.value().symbols()) {
            if (!sym_a.name.empty() && seen_syms.find(sym_a.name) == seen_syms.end()) {
                SymbolDiff sym_diff;
                sym_diff.name = sym_a.name;
                sym_diff.addr_a = sym_a.address;
                sym_diff.status = "removed";
                res.symbol_diffs.push_back(sym_diff);
            }
        }
    }

    return res;
}

}  // namespace typemorph::diff
