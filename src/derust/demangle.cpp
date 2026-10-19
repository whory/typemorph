// TypeMorph - Rust symbol demangler (legacy `_ZN...E` and v0 `_R...` schemes).
//
// The two encodings are unrelated:
//
//   * Legacy: an Itanium-style ``_ZN <len><ident>... E`` path where the final
//     segment is a ``17h<16 hex digits>`` crate/instance disambiguator.  Every
//     identifier is escaped: ``$LT$``, ``$GT$``, ``$RF$``, ``$BP$``, ``$C$``,
//     ``$SP$``, ``$LP$``, ``$RP$`` and ``$u<hex>$`` for everything else.  When
//     an identifier begins with ``$`` it is prefixed with ``_`` so that the
//     whole segment remains a valid C identifier; that prefix is stripped again
//     when decoding.  ``..`` inside an identifier is the encoding of ``::``
//     (used by impl paths such as ``_$LT$T$u20$as$u20$Trait$GT$``).
//
//   * v0 (RFC 2603): a compact grammar with explicit tags, base-62 integers,
//     Punycode identifiers and a backreference table.  The backreference table
//     is filled in pre-order, once per first occurrence of a path / type /
//     const entity - the same traversal order the rustc encoder uses.
//
// Everything here is defensive: length prefixes are bounds checked, recursion
// is depth limited and malformed input returns a ``parse_error`` instead of
// reading out of bounds.  ``demangle_or_original`` is the best-effort entry
// point; ``looks_like_rust_symbol`` only accepts symbols that actually parse
// as Rust so that C++ Itanium names are not misclassified.

#include "typemorph/derust/demangle.hpp"

#include <cstddef>
#include <cstdint>
#include <optional>
#include <string>
#include <string_view>
#include <utility>
#include <vector>

namespace typemorph::derust {
namespace {

constexpr std::size_t kMaxSymbolLength = 1U << 16U;
constexpr int kMaxDepth = 96;

[[nodiscard]] constexpr bool is_digit(char c) noexcept { return c >= '0' && c <= '9'; }

[[nodiscard]] constexpr bool is_hex(char c) noexcept {
    return (c >= '0' && c <= '9') || (c >= 'a' && c <= 'f') || (c >= 'A' && c <= 'F');
}

[[nodiscard]] constexpr unsigned hex_value(char c) noexcept {
    if (c >= '0' && c <= '9') return static_cast<unsigned>(c - '0');
    if (c >= 'a' && c <= 'f') return static_cast<unsigned>(c - 'a') + 10U;
    return static_cast<unsigned>(c - 'A') + 10U;
}

[[nodiscard]] bool append_utf8(std::string& out, std::uint32_t code_point) {
    if (code_point > 0x10FFFFU) return false;
    if (code_point >= 0xD800U && code_point <= 0xDFFFU) return false;
    if (code_point < 0x80U) {
        out.push_back(static_cast<char>(code_point));
    } else if (code_point < 0x800U) {
        out.push_back(static_cast<char>(0xC0U | (code_point >> 6U)));
        out.push_back(static_cast<char>(0x80U | (code_point & 0x3FU)));
    } else if (code_point < 0x10000U) {
        out.push_back(static_cast<char>(0xE0U | (code_point >> 12U)));
        out.push_back(static_cast<char>(0x80U | ((code_point >> 6U) & 0x3FU)));
        out.push_back(static_cast<char>(0x80U | (code_point & 0x3FU)));
    } else {
        out.push_back(static_cast<char>(0xF0U | (code_point >> 18U)));
        out.push_back(static_cast<char>(0x80U | ((code_point >> 12U) & 0x3FU)));
        out.push_back(static_cast<char>(0x80U | ((code_point >> 6U) & 0x3FU)));
        out.push_back(static_cast<char>(0x80U | (code_point & 0x3FU)));
    }
    return true;
}

// Minimal UTF-8 validator; a decoded legacy identifier can legitimately contain
// multibyte characters and we refuse to emit invalid byte sequences.
[[nodiscard]] bool is_valid_utf8(std::string_view bytes) noexcept {
    std::size_t i = 0;
    while (i < bytes.size()) {
        const auto lead = static_cast<unsigned char>(bytes[i]);
        std::size_t extra = 0;
        std::uint32_t code_point = 0;
        if (lead < 0x80U) {
            ++i;
            continue;
        } else if ((lead & 0xE0U) == 0xC0U) {
            extra = 1;
            code_point = lead & 0x1FU;
        } else if ((lead & 0xF0U) == 0xE0U) {
            extra = 2;
            code_point = lead & 0x0FU;
        } else if ((lead & 0xF8U) == 0xF0U) {
            extra = 3;
            code_point = lead & 0x07U;
        } else {
            return false;
        }
        if (i + extra >= bytes.size()) return false;
        for (std::size_t k = 1; k <= extra; ++k) {
            const auto cont = static_cast<unsigned char>(bytes[i + k]);
            if ((cont & 0xC0U) != 0x80U) return false;
            code_point = (code_point << 6U) | (cont & 0x3FU);
        }
        // Reject overlong encodings, surrogates and out-of-range values.
        const std::uint32_t minimum = extra == 1 ? 0x80U : (extra == 2 ? 0x800U : 0x10000U);
        if (code_point < minimum || code_point > 0x10FFFFU) return false;
        if (code_point >= 0xD800U && code_point <= 0xDFFFU) return false;
        i += extra + 1;
    }
    return true;
}

// Mach-O prefixes every symbol with an extra underscore.
[[nodiscard]] std::string_view strip_macho_underscore(std::string_view symbol) noexcept {
    if (symbol.starts_with("__ZN") || symbol.starts_with("__R")) {
        symbol.remove_prefix(1);
    }
    return symbol;
}

// ---------------------------------------------------------------------------
// Legacy (_ZN...E) decoding
// ---------------------------------------------------------------------------

struct LegacySegment {
    std::string decoded;
    bool hash = false;
};

struct LegacyParsed {
    std::vector<LegacySegment> segments;
    std::string crate;
    bool has_hash = false;
};

[[nodiscard]] bool decode_legacy_ident(std::string_view raw, std::string& out) {
    // Impl paths and closures are emitted as `_$...$` so that the segment is a
    // valid C identifier; the leading underscore is not part of the name.
    if (raw.size() >= 2 && raw[0] == '_' && raw[1] == '$') raw.remove_prefix(1);

    std::size_t i = 0;
    while (i < raw.size()) {
        const char c = raw[i];
        if (c != '$') {
            out.push_back(c);
            ++i;
            continue;
        }
        const std::size_t close = raw.find('$', i + 1);
        if (close == std::string_view::npos) return false;
        const std::string_view payload = raw.substr(i + 1, close - i - 1);
        i = close + 1;
        if (payload.empty()) return false;

        if (payload == "C") {
            out.push_back(',');
        } else if (payload == "SP") {
            out.push_back('@');
        } else if (payload == "BP") {
            out.push_back('*');
        } else if (payload == "RF") {
            out.push_back('&');
        } else if (payload == "LT") {
            out.push_back('<');
        } else if (payload == "GT") {
            out.push_back('>');
        } else if (payload == "LP") {
            out.push_back('(');
        } else if (payload == "RP") {
            out.push_back(')');
        } else if (payload[0] == 'u') {
            const std::string_view hex = payload.substr(1);
            if (hex.empty() || hex.size() > 8) return false;
            std::uint32_t value = 0;
            for (const char h : hex) {
                if (!is_hex(h)) return false;
                value = (value << 4U) | hex_value(h);
            }
            if (value <= 0x7FU) {
                out.push_back(static_cast<char>(value));
            } else if (hex.size() <= 2) {
                // Two hex digits can mean either a raw UTF-8 byte (rustc emits
                // one `$uXX$` per byte) or a small code point.  Gather the run
                // of following two-digit escapes: if it forms valid UTF-8 the
                // byte interpretation is the right one, otherwise treat the
                // value as a code point (which also handles `$ue9$` for 'e').
                std::string run;
                run.push_back(static_cast<char>(value));
                std::size_t cursor = i;
                while (true) {
                    if (cursor + 1 >= raw.size() || raw[cursor] != '$') break;
                    const std::size_t next_close = raw.find('$', cursor + 1);
                    if (next_close == std::string_view::npos) break;
                    const std::string_view next = raw.substr(cursor + 1, next_close - cursor - 1);
                    if (next.size() != 3 || next[0] != 'u' || !is_hex(next[1]) || !is_hex(next[2])) {
                        break;
                    }
                    const auto byte = static_cast<unsigned char>((hex_value(next[1]) << 4U) |
                                                                 hex_value(next[2]));
                    if (byte < 0x80U) break;
                    run.push_back(static_cast<char>(byte));
                    cursor = next_close + 1;
                }
                if (run.size() > 1 && is_valid_utf8(run)) {
                    out += run;
                    i = cursor;
                } else if (append_utf8(out, value)) {
                    // code-point interpretation, keep `i` where it is
                } else {
                    return false;
                }
            } else if (!append_utf8(out, value)) {
                return false;
            }
        } else {
            return false;
        }
    }
    // `..` is how `::` is encoded inside a single identifier (impl paths).
    std::string normalised;
    normalised.reserve(out.size() + 4);
    for (std::size_t j = 0; j < out.size(); ++j) {
        if (out[j] == '.' && j + 1 < out.size() && out[j + 1] == '.') {
            normalised += "::";
            ++j;
        } else {
            normalised.push_back(out[j]);
        }
    }
    out.swap(normalised);
    return true;
}

[[nodiscard]] bool is_hash_segment(std::string_view raw) noexcept {
    if (raw.size() != 17 || raw[0] != 'h') return false;
    for (std::size_t i = 1; i < raw.size(); ++i) {
        if (!is_hex(raw[i])) return false;
    }
    return true;
}

// Parses a legacy Rust symbol.  When `require_hash` is true only symbols that
// carry the `17h<hash>` disambiguator are accepted (all real rustc legacy
// symbols do); this is what keeps C++ Itanium symbols out.
[[nodiscard]] bool parse_legacy(std::string_view symbol, bool require_hash, LegacyParsed& parsed) {
    std::string_view rest = strip_macho_underscore(symbol);
    if (!rest.starts_with("_ZN")) return false;
    rest.remove_prefix(3);

    std::vector<std::pair<std::string_view, bool>> raw_segments;  // raw, is_hash
    while (true) {
        if (rest.empty()) return false;
        if (rest.front() == 'E') {
            rest.remove_prefix(1);
            break;
        }
        std::size_t length = 0;
        std::size_t digits = 0;
        while (digits < rest.size() && is_digit(rest[digits])) {
            if (length > kMaxSymbolLength) return false;
            length = length * 10U + static_cast<std::size_t>(rest[digits] - '0');
            ++digits;
            if (length > kMaxSymbolLength) return false;
        }
        if (digits == 0) return false;
        if (length == 0) return false;
        rest.remove_prefix(digits);
        if (length > rest.size()) return false;
        raw_segments.emplace_back(rest.substr(0, length), false);
        rest.remove_prefix(length);
    }
    // Only an optional vendor suffix may follow the closing 'E'.
    if (!rest.empty() && rest.front() != '.') return false;
    if (raw_segments.empty()) return false;

    if (is_hash_segment(raw_segments.back().first)) {
        raw_segments.back().second = true;
        parsed.has_hash = true;
        raw_segments.pop_back();
    }
    if (require_hash && !parsed.has_hash) return false;
    if (raw_segments.empty()) return false;

    parsed.segments.clear();
    parsed.segments.reserve(raw_segments.size());
    for (const auto& [raw, is_hash] : raw_segments) {
        LegacySegment segment;
        segment.hash = is_hash;
        if (!decode_legacy_ident(raw, segment.decoded)) return false;
        parsed.segments.push_back(std::move(segment));
    }
    if (parsed.segments.front().decoded.size() >= 1 &&
        parsed.segments.front().decoded.front() != '<' &&
        parsed.segments.front().decoded.front() != '{') {
        parsed.crate = parsed.segments.front().decoded;
    }
    return true;
}

[[nodiscard]] std::string join_segments(const std::vector<LegacySegment>& segments) {
    std::string out;
    for (const auto& segment : segments) {
        if (!out.empty()) out += "::";
        out += segment.decoded;
    }
    return out;
}

// ---------------------------------------------------------------------------
// v0 (_R...) decoding
// ---------------------------------------------------------------------------

[[nodiscard]] std::optional<std::uint32_t> punycode_digit(char c) noexcept {
    if (c >= 'a' && c <= 'z') return static_cast<std::uint32_t>(c - 'a');
    if (c >= 'A' && c <= 'Z') return static_cast<std::uint32_t>(c - 'A') + 26U;
    if (c >= '0' && c <= '9') return static_cast<std::uint32_t>(c - '0') + 52U;
    return std::nullopt;
}

[[nodiscard]] std::uint64_t punycode_adapt(std::uint64_t delta, std::uint64_t num_points,
                                           bool first_time) noexcept {
    constexpr std::uint64_t base = 36;
    constexpr std::uint64_t tmin = 1;
    constexpr std::uint64_t tmax = 26;
    constexpr std::uint64_t skew = 38;
    constexpr std::uint64_t damp = 700;
    delta = first_time ? delta / damp : delta / 2;
    delta += delta / num_points;
    std::uint64_t k = 0;
    while (delta > ((base - tmin) * tmax) / 2) {
        delta /= base - tmin;
        k += base;
    }
    return k + (((base - tmin + 1) * delta) / (delta + skew));
}

// RFC 3492 Punycode decoder.  Rust v0 marks non-ASCII identifiers with a `u`
// prefix and stores them Punycode encoded.  Pure-ASCII payloads decode through
// the same path, which keeps one implementation for both cases.
[[nodiscard]] bool decode_punycode(std::string_view input, std::string& out) {
    constexpr std::uint32_t base = 36;
    constexpr std::uint32_t tmin = 1;
    constexpr std::uint32_t tmax = 26;
    constexpr std::uint32_t initial_bias = 72;
    constexpr std::uint32_t initial_n = 128;

    std::vector<std::uint32_t> code_points;
    std::size_t position = 0;
    const std::size_t delimiter = input.rfind('-');
    if (delimiter != std::string_view::npos) {
        for (std::size_t i = 0; i < delimiter; ++i) {
            const auto c = static_cast<unsigned char>(input[i]);
            if (c >= 0x80U) return false;
            code_points.push_back(c);
        }
        position = delimiter + 1;
    }

    std::uint64_t n = initial_n;
    std::uint64_t i = 0;
    std::uint64_t bias = initial_bias;
    while (position < input.size()) {
        const std::uint64_t old_i = i;
        std::uint64_t weight = 1;
        for (std::uint32_t k = base;; k += base) {
            if (position >= input.size()) return false;
            const char c = input[position++];
            const auto digit = punycode_digit(c);
            if (!digit) return false;
            if (*digit > (0x7FFFFFFFU - i) / weight) return false;
            i += static_cast<std::uint64_t>(*digit) * weight;
            const std::uint32_t threshold =
                k <= bias ? tmin : (k >= bias + tmax ? tmax : static_cast<std::uint32_t>(k - bias));
            if (*digit < threshold) break;
            if (weight > 0x7FFFFFFFU / (base - threshold)) return false;
            weight *= base - threshold;
        }
        const auto out_length = static_cast<std::uint64_t>(code_points.size()) + 1;
        bias = punycode_adapt(i - old_i, out_length, old_i == 0);
        if (i / out_length > 0x7FFFFFFFU - n) return false;
        n += i / out_length;
        i %= out_length;
        if (n > 0x10FFFFU || (n >= 0xD800U && n <= 0xDFFFU)) return false;
        code_points.insert(code_points.begin() + static_cast<std::ptrdiff_t>(i),
                           static_cast<std::uint32_t>(n));
        ++i;
    }

    std::string decoded;
    for (const std::uint32_t code_point : code_points) {
        if (!append_utf8(decoded, code_point)) return false;
    }
    out += decoded;
    return true;
}

class V0Parser {
public:
    explicit V0Parser(std::string_view symbol) : symbol_(symbol) {}

    [[nodiscard]] bool parse(DemangledSymbol& out) {
        if (!symbol_.starts_with("_R")) return false;
        position_ = 2;
        // Optional encoding version (currently always absent or a single 0).
        while (position_ < symbol_.size() && is_digit(symbol_[position_])) ++position_;
        if (position_ >= symbol_.size()) return false;
        std::string path;
        if (!parse_path(path)) return false;
        // An instantiating crate (only present for cross-crate instances) is a
        // path production itself.
        if (position_ < symbol_.size() && symbol_[position_] == 'C') {
            std::string instantiating;
            if (!parse_path(instantiating)) return false;
            if (crate_.empty()) crate_ = instantiating;
        }
        // Only an optional vendor suffix may remain.
        if (position_ < symbol_.size()) {
            if (symbol_[position_] != '.') return false;
            position_ = symbol_.size();
        }
        out.demangled = std::move(path);
        out.path = out.demangled;
        out.crate = crate_;
        out.generic_args = std::move(generic_args_);
        out.is_rust = true;
        out.is_v0 = true;
        return true;
    }

private:
    struct DepthGuard {
        int& depth;
        explicit DepthGuard(int& value) : depth(value) { ++depth; }
        ~DepthGuard() { --depth; }
        DepthGuard(const DepthGuard&) = delete;
        DepthGuard& operator=(const DepthGuard&) = delete;
    };

    [[nodiscard]] bool at_end() const noexcept { return position_ >= symbol_.size(); }

    [[nodiscard]] char peek() const noexcept { return at_end() ? '\0' : symbol_[position_]; }

    [[nodiscard]] bool consume(char expected) noexcept {
        if (at_end() || symbol_[position_] != expected) return false;
        ++position_;
        return true;
    }

    [[nodiscard]] bool parse_digits(std::uint64_t& value) noexcept {
        std::size_t digits = 0;
        std::uint64_t result = 0;
        while (!at_end() && is_digit(symbol_[position_])) {
            result = result * 10U + static_cast<std::uint64_t>(symbol_[position_] - '0');
            ++position_;
            ++digits;
            if (result > kMaxSymbolLength) return false;
        }
        if (digits == 0) return false;
        value = result;
        return true;
    }

    [[nodiscard]] bool parse_base62(std::uint64_t& value) noexcept {
        std::uint64_t result = 0;
        while (true) {
            if (at_end()) return false;
            const char c = symbol_[position_++];
            if (c == '_') {
                value = result;
                return true;
            }
            std::uint32_t digit = 0;
            if (c >= '0' && c <= '9') {
                digit = static_cast<std::uint32_t>(c - '0');
            } else if (c >= 'a' && c <= 'z') {
                digit = static_cast<std::uint32_t>(c - 'a') + 10U;
            } else if (c >= 'A' && c <= 'Z') {
                digit = static_cast<std::uint32_t>(c - 'A') + 36U;
            } else {
                return false;
            }
            if (result > (UINT64_MAX - digit) / 62U) return false;
            result = result * 62U + digit;
        }
    }

    [[nodiscard]] bool parse_disambiguator() {
        if (peek() != 's') return true;
        ++position_;
        std::uint64_t ignored = 0;
        return parse_base62(ignored);
    }

    [[nodiscard]] bool parse_identifier(std::string& out) {
        if (!parse_disambiguator()) return false;
        bool punycode = false;
        if (peek() == 'u') {
            ++position_;
            punycode = true;
        }
        std::uint64_t length = 0;
        if (!parse_digits(length)) return false;
        if (!at_end() && symbol_[position_] == '_') ++position_;
        if (length > symbol_.size() - position_) return false;
        const std::string_view bytes = symbol_.substr(position_, static_cast<std::size_t>(length));
        position_ += static_cast<std::size_t>(length);
        if (punycode) return decode_punycode(bytes, out);
        out.append(bytes);
        return true;
    }

    // A backref points at an earlier first-occurrence entry in the table.
    [[nodiscard]] bool parse_backref(std::string& out) {
        std::uint64_t index = 0;
        if (!parse_base62(index)) return false;
        if (index >= backrefs_.size() || backrefs_[index].empty()) return false;
        out += backrefs_[index];
        return true;
    }

    // Registers the entity at the current position in the backref table and
    // records its rendering.  Must be called *before* parsing the entity so
    // that table indices line up with the encoder's pre-order numbering.
    [[nodiscard]] std::size_t register_entity() {
        backrefs_.emplace_back();
        return backrefs_.size() - 1;
    }

    [[nodiscard]] bool parse_path(std::string& out) {
        DepthGuard guard(depth_);
        if (depth_ > kMaxDepth) return false;
        if (at_end()) return false;
        const char tag = symbol_[position_];
        if (tag == 'B') {
            ++position_;
            return parse_backref(out);
        }
        const std::size_t slot = register_entity();
        std::string path;
        ++position_;
        switch (tag) {
        case 'C': {
            std::string name;
            if (!parse_identifier(name)) return false;
            if (crate_.empty()) crate_ = name;
            path = name;
            break;
        }
        case 'M': {
            // <impl-path> <type>: inherent impl, printed as <Type>.
            if (!parse_disambiguator()) return false;
            std::string impl_path;
            if (!parse_path(impl_path)) return false;
            path.push_back('<');
            if (!parse_type(path)) return false;
            path.push_back('>');
            break;
        }
        case 'X': {
            // <impl-path> <type> <path>: trait impl, printed as <Type as Trait>.
            if (!parse_disambiguator()) return false;
            std::string impl_path;
            if (!parse_path(impl_path)) return false;
            path.push_back('<');
            if (!parse_type(path)) return false;
            path += " as ";
            if (!parse_path(path)) return false;
            path.push_back('>');
            break;
        }
        case 'Y': {
            // <type> <path>: trait definition, printed as <Type as Trait>.
            path.push_back('<');
            if (!parse_type(path)) return false;
            path += " as ";
            if (!parse_path(path)) return false;
            path.push_back('>');
            break;
        }
        case 'N': {
            if (at_end()) return false;
            const char ns = symbol_[position_++];
            if (!parse_path(path)) return false;
            path += "::";
            if (ns == 'C') {
                std::string ignored;
                if (!parse_identifier(ignored)) return false;
                path += "{closure}";
            } else if (ns == 'S') {
                std::string ignored;
                if (!parse_identifier(ignored)) return false;
                path += "{shim}";
            } else if (ns >= 'A' && ns <= 'Z') {
                std::string ignored;
                if (!parse_identifier(ignored)) return false;
                path.push_back('{');
                path.push_back(ns);
                path.push_back('}');
            } else if (ns >= 'a' && ns <= 'z') {
                if (!parse_identifier(path)) return false;
            } else {
                return false;
            }
            break;
        }
        case 'I': {
            if (!parse_path(path)) return false;
            path += "::<";
            const bool collect = !generic_args_collected_;
            if (collect) generic_args_collected_ = true;
            bool first = true;
            while (true) {
                if (at_end()) return false;
                if (symbol_[position_] == 'E') {
                    ++position_;
                    break;
                }
                std::string argument;
                if (!parse_generic_arg(argument)) return false;
                if (!first) path += ", ";
                path += argument;
                if (collect) generic_args_.push_back(std::move(argument));
                first = false;
            }
            path.push_back('>');
            break;
        }
        default: return false;
        }
        if (slot < backrefs_.size()) backrefs_[slot] = path;
        out += path;
        return true;
    }

    [[nodiscard]] bool parse_generic_arg(std::string& out) {
        if (peek() == 'L') {
            return parse_lifetime(out);
        }
        if (peek() == 'K') {
            ++position_;
            return parse_const(out);
        }
        return parse_type(out);
    }

    [[nodiscard]] bool parse_lifetime(std::string& out) {
        if (!consume('L')) return false;
        std::uint64_t index = 0;
        if (!parse_base62(index)) return false;
        out += "'";
        if (index == 0) {
            out += "_";
        } else {
            out += "_";
            out += std::to_string(index);
        }
        return true;
    }

    [[nodiscard]] bool parse_const(std::string& out) {
        DepthGuard guard(depth_);
        if (depth_ > kMaxDepth) return false;
        const std::size_t slot = register_entity();
        std::string text;
        if (!parse_type(text)) return false;
        if (peek() == 'p' || at_end()) {
            if (peek() == 'p') ++position_;
            out += "{_}";
            if (slot < backrefs_.size()) backrefs_[slot] = out;
            return true;
        }
        const char tag = symbol_[position_++];
        switch (tag) {
        case 'b': {  // bool
            if (at_end()) return false;
            const char value = symbol_[position_++];
            if (value == '0') {
                out += "{false}";
            } else if (value == '1') {
                out += "{true}";
            } else {
                return false;
            }
            break;
        }
        case 'c': {  // char
            std::uint64_t value = 0;
            if (!parse_hex_number(value)) return false;
            out += "{'";
            if (!append_utf8(out, static_cast<std::uint32_t>(value))) return false;
            out += "'}";
            break;
        }
        case 'n': {  // negative integer
            std::uint64_t value = 0;
            if (!parse_hex_number(value)) return false;
            out += "{-";
            out += std::to_string(value);
            out += "}";
            break;
        }
        case 'e': {  // string / opaque constant, print the raw payload
            std::uint64_t length = 0;
            if (!parse_hex_number(length)) return false;
            if (length > symbol_.size() - position_) return false;
            out += "{";
            out.append(symbol_.substr(position_, static_cast<std::size_t>(length)));
            position_ += static_cast<std::size_t>(length);
            out += "}";
            break;
        }
        default: {  // unsigned integer, tag is the first digit
            --position_;
            std::uint64_t value = 0;
            if (!parse_hex_number(value)) return false;
            out += "{";
            out += std::to_string(value);
            out += "}";
            break;
        }
        }
        if (slot < backrefs_.size()) backrefs_[slot] = out;
        return true;
    }

    [[nodiscard]] bool parse_hex_number(std::uint64_t& value) {
        std::uint64_t result = 0;
        std::size_t digits = 0;
        while (!at_end()) {
            const char c = symbol_[position_];
            if (!is_hex(c)) break;
            if (result > (UINT64_MAX >> 4U)) return false;
            result = (result << 4U) | hex_value(c);
            ++position_;
            ++digits;
        }
        if (digits == 0) return false;
        if (!consume('_')) return false;
        value = result;
        return true;
    }

    [[nodiscard]] bool parse_fn_sig(std::string& out) {
        if (peek() == 'G') {  // binder
            ++position_;
            std::uint64_t ignored = 0;
            if (!parse_base62(ignored)) return false;
        }
        bool is_unsafe = false;
        if (peek() == 'U') {
            ++position_;
            is_unsafe = true;
        }
        std::string abi;
        if (peek() == 'K') {
            ++position_;
            if (!at_end() && symbol_[position_] != 'C' && !is_digit(symbol_[position_]) &&
                symbol_[position_] != '_') {
                if (!parse_identifier(abi)) return false;
            } else if (consume('C')) {
                abi = "C";
            } else {
                std::uint64_t ignored = 0;
                if (!parse_base62(ignored)) return false;
            }
        }
        std::string args;
        bool first = true;
        while (true) {
            if (at_end()) return false;
            if (symbol_[position_] == 'E') {
                ++position_;
                break;
            }
            std::string argument;
            if (!parse_type(argument)) return false;
            if (!first) args += ", ";
            args += argument;
            first = false;
        }
        std::string result;
        if (!parse_type(result)) return false;
        out += "fn";
        if (!abi.empty()) {
            out += "extern \"";
            out += abi;
            out += "\" ";
        }
        if (is_unsafe) out += "unsafe ";
        out += "(";
        out += args;
        out += ")";
        if (result != "()") {
            out += " -> ";
            out += result;
        }
        return true;
    }

    [[nodiscard]] bool parse_type(std::string& out) {
        DepthGuard guard(depth_);
        if (depth_ > kMaxDepth) return false;
        if (at_end()) return false;
        const char tag = symbol_[position_];
        if (tag == 'B') {
            ++position_;
            return parse_backref(out);
        }
        const std::size_t slot = register_entity();
        ++position_;
        std::string type;
        switch (tag) {
        case 'a': type = "i8"; break;
        case 'b': type = "bool"; break;
        case 'c': type = "char"; break;
        case 'd': type = "f64"; break;
        case 'e': type = "str"; break;
        case 'f': type = "f32"; break;
        case 'h': type = "u8"; break;
        case 'i': type = "isize"; break;
        case 'j': type = "usize"; break;
        case 'l': type = "i32"; break;
        case 'm': type = "u32"; break;
        case 'n': type = "i128"; break;
        case 'o': type = "u128"; break;
        case 'p': type = "_"; break;
        case 's': type = "i16"; break;
        case 't': type = "u16"; break;
        case 'u': type = "()"; break;
        case 'v': type = "..."; break;
        case 'x': type = "i64"; break;
        case 'y': type = "u64"; break;
        case 'z': type = "!"; break;
        case 'A': {  // [T; N]
            std::string element;
            if (!parse_type(element)) return false;
            std::string count;
            if (!parse_const(count)) return false;
            type = "[";
            type += element;
            type += "; ";
            type += count;
            type += "]";
            break;
        }
        case 'S': {  // [T]
            std::string element;
            if (!parse_type(element)) return false;
            type = "[";
            type += element;
            type += "]";
            break;
        }
        case 'T': {  // tuple
            std::string elements;
            std::size_t count = 0;
            while (true) {
                if (at_end()) return false;
                if (symbol_[position_] == 'E') {
                    ++position_;
                    break;
                }
                std::string element;
                if (!parse_type(element)) return false;
                if (count != 0) elements += ", ";
                elements += element;
                ++count;
            }
            type = "(";
            type += elements;
            if (count == 1) type += ",";
            type += ")";
            break;
        }
        case 'R': {  // &T
            if (peek() == 'L') {
                std::string ignored;
                if (!parse_lifetime(ignored)) return false;
            }
            std::string pointee;
            if (!parse_type(pointee)) return false;
            type = "&";
            type += pointee;
            break;
        }
        case 'Q': {  // &mut T
            if (peek() == 'L') {
                std::string ignored;
                if (!parse_lifetime(ignored)) return false;
            }
            std::string pointee;
            if (!parse_type(pointee)) return false;
            type = "&mut ";
            type += pointee;
            break;
        }
        case 'P': {  // *const T
            std::string pointee;
            if (!parse_type(pointee)) return false;
            type = "*const ";
            type += pointee;
            break;
        }
        case 'O': {  // *mut T
            std::string pointee;
            if (!parse_type(pointee)) return false;
            type = "*mut ";
            type += pointee;
            break;
        }
        case 'D': {  // dyn Trait
            if (peek() == 'L') {
                std::string ignored;
                if (!parse_lifetime(ignored)) return false;
            }
            std::string trait;
            if (!parse_type(trait)) return false;
            type = "dyn ";
            type += trait;
            break;
        }
        case 'F': {  // fn(..) -> ..
            if (!parse_fn_sig(type)) return false;
            break;
        }
        case 'C':
        case 'M':
        case 'X':
        case 'Y':
        case 'N':
        case 'I': {
            --position_;
            std::string path;
            if (!parse_path(path)) return false;
            type = std::move(path);
            break;
        }
        default: return false;
        }
        if (slot < backrefs_.size()) backrefs_[slot] = type;
        out += type;
        return true;
    }

    std::string_view symbol_;
    std::size_t position_ = 0;
    int depth_ = 0;
    std::vector<std::string> backrefs_;
    std::vector<std::string> generic_args_;
    std::string crate_;
    bool generic_args_collected_ = false;
};

}  // namespace

bool looks_like_rust_symbol(std::string_view symbol) noexcept {
    if (symbol.size() < 4 || symbol.size() > kMaxSymbolLength) return false;
    const std::string_view candidate = strip_macho_underscore(symbol);
    if (!candidate.starts_with("_R") && !candidate.starts_with("_ZN")) return false;
    try {
        // The strict parser is the only reliable discriminator: arbitrary C++
        // Itanium names are `_ZN...E<return type>` and legacy Rust names always
        // carry the 17h hash disambiguator.
        return demangle(symbol).has_value();
    } catch (...) {
        return false;
    }
}

core::Result<DemangledSymbol> demangle(std::string_view symbol) {
    if (symbol.size() < 4 || symbol.size() > kMaxSymbolLength) {
        return core::make_error(core::ErrorCode::parse_error, "symbol has implausible length",
                                std::string(symbol));
    }
    const std::string_view candidate = strip_macho_underscore(symbol);

    DemangledSymbol result;
    result.mangled = std::string(symbol);

    if (candidate.starts_with("_R")) {
        V0Parser parser(candidate);
        if (!parser.parse(result)) {
            return core::make_error(core::ErrorCode::parse_error, "malformed Rust v0 symbol",
                                    std::string(symbol));
        }
        return result;
    }

    if (candidate.starts_with("_ZN")) {
        LegacyParsed parsed;
        if (!parse_legacy(candidate, /*require_hash=*/true, parsed)) {
            return core::make_error(core::ErrorCode::parse_error, "malformed Rust legacy symbol",
                                    std::string(symbol));
        }
        result.demangled = join_segments(parsed.segments);
        result.path = result.demangled;
        result.crate = parsed.crate;
        result.is_rust = true;
        result.is_v0 = false;
        return result;
    }

    return core::make_error(core::ErrorCode::parse_error, "not a Rust symbol", std::string(symbol));
}

std::string demangle_or_original(std::string_view symbol) {
    const auto result = demangle(symbol);
    if (result.has_value()) return result.value().demangled;
    return std::string(symbol);
}

}  // namespace typemorph::derust
