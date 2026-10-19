// TypeMorph - UnXORer engine implementation.
#include "typemorph/deobf/unxorer.hpp"
#include "typemorph/core/entropy.hpp"

#include <algorithm>
#include <array>
#include <cmath>
#include <cstddef>
#include <cstdint>
#include <map>
#include <string_view>

namespace typemorph::deobf {
namespace {

constexpr bool is_printable_char(std::uint8_t byte) noexcept {
    return (byte >= 0x20 && byte <= 0x7E) || byte == '\n' || byte == '\r' || byte == '\t';
}

// Letter frequency table based on standard English prose.
double english_char_score(std::uint8_t byte) noexcept {
    if (byte >= 'a' && byte <= 'z') {
        static constexpr double kFreq[] = {
            8.167, 1.492, 2.782, 4.253, 12.702, 2.228, 2.015, 6.094, 6.966,
            0.153, 0.772, 4.025, 2.406, 6.749, 7.507, 1.929, 0.095, 5.987,
            6.327, 9.056, 2.758, 0.978, 2.360, 0.150, 1.974, 0.074
        };
        return kFreq[byte - 'a'] * 1.5;
    }
    if (byte >= 'A' && byte <= 'Z') {
        return 5.0;
    }
    if (byte == ' ') return 14.0;
    if (byte >= '0' && byte <= '9') return 3.0;
    if (byte == '.' || byte == ',' || byte == ':' || byte == '/' || byte == '_' || byte == '-') {
        return 2.5;
    }
    if (is_printable_char(byte)) return 1.0;
    if (byte == 0x00) return -10.0;
    return -25.0; // Strong penalty for non-printable noise
}

double score_buffer(std::span<const std::uint8_t> buffer, double& printable_ratio) noexcept {
    if (buffer.empty()) {
        printable_ratio = 0.0;
        return 0.0;
    }
    std::size_t printable_count = 0;
    double score = 0.0;
    for (const std::uint8_t b : buffer) {
        if (is_printable_char(b)) ++printable_count;
        score += english_char_score(b);
    }
    printable_ratio = static_cast<double>(printable_count) / static_cast<double>(buffer.size());
    // Normalize score per byte
    score /= static_cast<double>(buffer.size());
    return score;
}

std::string make_preview(std::span<const std::uint8_t> buffer, std::size_t max_len = 64) {
    std::string preview;
    preview.reserve(std::min(buffer.size(), max_len));
    for (std::size_t i = 0; i < buffer.size() && preview.size() < max_len; ++i) {
        const std::uint8_t b = buffer[i];
        if (b >= 0x20 && b <= 0x7E) {
            preview.push_back(static_cast<char>(b));
        } else if (b == '\n') {
            preview += "\\n";
        } else if (b == '\r') {
            preview += "\\r";
        } else if (b == '\t') {
            preview += "\\t";
        } else {
            preview.push_back('.');
        }
    }
    return preview;
}

std::string hex_format(std::span<const std::uint8_t> bytes) {
    static constexpr char kHex[] = "0123456789abcdef";
    std::string out;
    out.reserve(bytes.size() * 2 + 2);
    out += "0x";
    for (const std::uint8_t b : bytes) {
        out.push_back(kHex[(b >> 4U) & 0x0F]);
        out.push_back(kHex[b & 0x0F]);
    }
    return out;
}

}  // namespace

Unxorer::Unxorer(UnxorOptions options) : options_(std::move(options)) {
    if (options_.min_key_length == 0) options_.min_key_length = 1;
    if (options_.max_key_length < options_.min_key_length) {
        options_.max_key_length = options_.min_key_length;
    }
    if (options_.max_candidates == 0) options_.max_candidates = 5;
}

core::BinaryView Unxorer::decrypt(const core::BinaryView& view,
                                  std::span<const std::uint8_t> key,
                                  XorMode mode) const {
    if (!view.valid() || view.empty() || key.empty()) return view;
    std::vector<std::uint8_t> buffer(view.size());
    const auto src = view.bytes();

    if (mode == XorMode::single_byte) {
        const std::uint8_t k = key[0];
        for (std::size_t i = 0; i < src.size(); ++i) {
            buffer[i] = src[i] ^ k;
        }
    } else if (mode == XorMode::rolling) {
        const std::uint8_t k = key[0];
        for (std::size_t i = 0; i < src.size(); ++i) {
            buffer[i] = static_cast<std::uint8_t>(src[i] ^ (k + static_cast<std::uint8_t>(i)));
        }
    } else {
        const std::size_t klen = key.size();
        for (std::size_t i = 0; i < src.size(); ++i) {
            buffer[i] = src[i] ^ key[i % klen];
        }
    }

    return core::BinaryView::from_owned(std::move(buffer));
}

std::vector<XorCandidate> Unxorer::crack_single_byte(const core::BinaryView& view) const {
    std::vector<XorCandidate> candidates;
    if (!view.valid() || view.empty()) return candidates;

    const auto src = view.bytes();
    const std::size_t sample_len = std::min<std::size_t>(src.size(), 4096);
    std::vector<std::uint8_t> decrypted_sample(sample_len);

    struct ScoredKey {
        std::uint8_t key = 0;
        double score = 0.0;
        double printable_ratio = 0.0;
    };
    std::vector<ScoredKey> scored;
    scored.reserve(255);

    for (unsigned k = 1; k <= 255; ++k) {
        const std::uint8_t key_byte = static_cast<std::uint8_t>(k);
        for (std::size_t i = 0; i < sample_len; ++i) {
            decrypted_sample[i] = src[i] ^ key_byte;
        }
        double ratio = 0.0;
        const double s = score_buffer(decrypted_sample, ratio);
        if (ratio >= options_.min_printable_ratio || s > 2.0) {
            scored.push_back({key_byte, s, ratio});
        }
    }

    std::sort(scored.begin(), scored.end(), [](const ScoredKey& a, const ScoredKey& b) {
        return a.score > b.score;
    });

    for (std::size_t i = 0; i < std::min(scored.size(), options_.max_candidates); ++i) {
        const auto& item = scored[i];
        std::vector<std::uint8_t> key = {item.key};
        core::BinaryView full_decrypted = decrypt(view, key, XorMode::single_byte);

        XorCandidate candidate;
        candidate.key = key;
        candidate.mode = XorMode::single_byte;
        candidate.printable_ratio = item.printable_ratio;
        candidate.confidence = std::clamp((item.score + 10.0) / 20.0, 0.1, 0.99);
        candidate.entropy = core::shannon_entropy(full_decrypted.bytes());
        candidate.preview = make_preview(full_decrypted.bytes());
        candidate.rationale = "single-byte key " + hex_format(key) + " (printable " +
                              std::to_string(static_cast<int>(item.printable_ratio * 100)) + "%)";
        candidate.decrypted = std::move(full_decrypted);
        candidates.push_back(std::move(candidate));
    }

    return candidates;
}

std::vector<XorCandidate> Unxorer::crack_multi_byte(const core::BinaryView& view) const {
    std::vector<XorCandidate> candidates;
    if (!view.valid() || view.size() < 4) return candidates;

    const auto src = view.bytes();
    const std::size_t sample_len = std::min<std::size_t>(src.size(), 8192);

    for (std::size_t klen = std::max<std::size_t>(options_.min_key_length, 2);
         klen <= std::min<std::size_t>(options_.max_key_length, sample_len / 4); ++klen) {
        std::vector<std::uint8_t> derived_key(klen, 0);
        bool valid_key = true;

        for (std::size_t offset = 0; offset < klen; ++offset) {
            std::vector<std::uint8_t> slice;
            slice.reserve(sample_len / klen + 1);
            for (std::size_t i = offset; i < sample_len; i += klen) {
                slice.push_back(src[i]);
            }
            if (slice.empty()) {
                valid_key = false;
                break;
            }

            std::uint8_t best_b = 0;
            double best_score = -1000.0;
            std::vector<std::uint8_t> test_sub(slice.size());

            for (unsigned k = 0; k <= 255; ++k) {
                const std::uint8_t kb = static_cast<std::uint8_t>(k);
                for (std::size_t j = 0; j < slice.size(); ++j) {
                    test_sub[j] = slice[j] ^ kb;
                }
                double ratio = 0.0;
                const double sc = score_buffer(test_sub, ratio);
                if (sc > best_score) {
                    best_score = sc;
                    best_b = kb;
                }
            }
            derived_key[offset] = best_b;
        }

        if (!valid_key) continue;

        // Reduce repeating periods (e.g. [A, A] -> [A], [A, B, A, B] -> [A, B])
        for (std::size_t p = 1; p <= derived_key.size() / 2; ++p) {
            if (derived_key.size() % p != 0) continue;
            bool matches = true;
            for (std::size_t i = p; i < derived_key.size(); ++i) {
                if (derived_key[i] != derived_key[i % p]) {
                    matches = false;
                    break;
                }
            }
            if (matches) {
                derived_key.resize(p);
                break;
            }
        }

        core::BinaryView full_decrypted = decrypt(view, derived_key, XorMode::multi_byte);
        double full_ratio = 0.0;
        const double full_score = score_buffer(full_decrypted.bytes().subspan(0, sample_len), full_ratio);

        if (full_ratio >= options_.min_printable_ratio && full_score > 1.5) {
            XorCandidate candidate;
            candidate.key = derived_key;
            candidate.mode = derived_key.size() == 1 ? XorMode::single_byte : XorMode::multi_byte;
            candidate.printable_ratio = full_ratio;
            candidate.confidence = std::clamp((full_score + 10.0) / 20.0, 0.2, 0.98);
            candidate.entropy = core::shannon_entropy(full_decrypted.bytes());
            candidate.preview = make_preview(full_decrypted.bytes());
            candidate.rationale = (derived_key.size() == 1 ? "single-byte key " : "multi-byte repeating key ") +
                                  hex_format(derived_key) + " (printable " +
                                  std::to_string(static_cast<int>(full_ratio * 100)) + "%)";
            candidate.decrypted = std::move(full_decrypted);
            candidates.push_back(std::move(candidate));
        }
    }

    return candidates;
}

std::vector<XorCandidate> Unxorer::crack_rolling(const core::BinaryView& view) const {
    std::vector<XorCandidate> candidates;
    if (!view.valid() || view.empty() || !options_.search_rolling) return candidates;

    const auto src = view.bytes();
    const std::size_t sample_len = std::min<std::size_t>(src.size(), 2048);
    std::vector<std::uint8_t> decrypted_sample(sample_len);

    for (unsigned k = 0; k <= 255; ++k) {
        const std::uint8_t base_k = static_cast<std::uint8_t>(k);
        for (std::size_t i = 0; i < sample_len; ++i) {
            decrypted_sample[i] = static_cast<std::uint8_t>(src[i] ^ (base_k + static_cast<std::uint8_t>(i)));
        }
        double ratio = 0.0;
        const double score = score_buffer(decrypted_sample, ratio);
        if (ratio >= options_.min_printable_ratio && score > 2.5) {
            std::vector<std::uint8_t> key = {base_k};
            core::BinaryView full_decrypted = decrypt(view, key, XorMode::rolling);

            XorCandidate candidate;
            candidate.key = key;
            candidate.mode = XorMode::rolling;
            candidate.printable_ratio = ratio;
            candidate.confidence = std::clamp((score + 10.0) / 20.0, 0.3, 0.95);
            candidate.entropy = core::shannon_entropy(full_decrypted.bytes());
            candidate.preview = make_preview(full_decrypted.bytes());
            candidate.rationale = "rolling XOR key " + hex_format(key) + " + index";
            candidate.decrypted = std::move(full_decrypted);
            candidates.push_back(std::move(candidate));
            break;
        }
    }

    return candidates;
}

std::vector<XorCandidate> Unxorer::crack_null_runs(const core::BinaryView& view) const {
    std::vector<XorCandidate> candidates;
    if (!view.valid() || view.size() < 16) return candidates;

    const auto src = view.bytes();
    // Look for repeating sequences of bytes of period 2..16 that occur consecutively >= 3 times
    for (std::size_t period = 2; period <= std::min<std::size_t>(16, options_.max_key_length); ++period) {
        for (std::size_t i = 0; i + period * 3 <= src.size(); i += period) {
            bool matches = true;
            for (std::size_t rep = 1; rep < 3; ++rep) {
                for (std::size_t p = 0; p < period; ++p) {
                    if (src[i + p] != src[i + rep * period + p]) {
                        matches = false;
                        break;
                    }
                }
                if (!matches) break;
            }
            if (matches) {
                std::vector<std::uint8_t> candidate_key(src.data() + i, src.data() + i + period);
                core::BinaryView full_decrypted = decrypt(view, candidate_key, XorMode::multi_byte);
                double ratio = 0.0;
                const double score = score_buffer(full_decrypted.bytes().subspan(0, std::min<std::size_t>(src.size(), 2048)), ratio);
                if (ratio >= options_.min_printable_ratio) {
                    XorCandidate candidate;
                    candidate.key = candidate_key;
                    candidate.mode = XorMode::multi_byte;
                    candidate.printable_ratio = ratio;
                    candidate.confidence = std::clamp((score + 10.0) / 20.0, 0.70, 0.99);
                    candidate.entropy = core::shannon_entropy(full_decrypted.bytes());
                    candidate.preview = make_preview(full_decrypted.bytes());
                    candidate.rationale = "key derived from suspected zero-run at offset 0x" +
                                          hex_format({reinterpret_cast<const std::uint8_t*>(&i), sizeof(i)});
                    candidate.decrypted = std::move(full_decrypted);
                    candidates.push_back(std::move(candidate));
                    return candidates;
                }
            }
        }
    }
    return candidates;
}

std::vector<XorCandidate> Unxorer::crack(const core::BinaryView& view) const {
    if (!options_.known_key.empty()) {
        core::BinaryView full_decrypted = decrypt(view, options_.known_key, XorMode::multi_byte);
        XorCandidate c;
        c.key = options_.known_key;
        c.mode = options_.known_key.size() == 1 ? XorMode::single_byte : XorMode::multi_byte;
        double ratio = 0.0;
        score_buffer(full_decrypted.bytes(), ratio);
        c.printable_ratio = ratio;
        c.confidence = 1.0;
        c.entropy = core::shannon_entropy(full_decrypted.bytes());
        c.preview = make_preview(full_decrypted.bytes());
        c.rationale = "decrypted with user-supplied key";
        c.decrypted = std::move(full_decrypted);
        return {c};
    }

    std::vector<XorCandidate> all;

    auto null_cands = crack_null_runs(view);
    all.insert(all.end(), null_cands.begin(), null_cands.end());

    auto single_cands = crack_single_byte(view);
    all.insert(all.end(), single_cands.begin(), single_cands.end());

    auto multi_cands = crack_multi_byte(view);
    all.insert(all.end(), multi_cands.begin(), multi_cands.end());

    auto rolling_cands = crack_rolling(view);
    all.insert(all.end(), rolling_cands.begin(), rolling_cands.end());

    std::sort(all.begin(), all.end(), [](const XorCandidate& a, const XorCandidate& b) {
        if (std::abs(a.confidence - b.confidence) > 0.05) {
            return a.confidence > b.confidence;
        }
        if (std::abs(a.printable_ratio - b.printable_ratio) > 0.05) {
            return a.printable_ratio > b.printable_ratio;
        }
        // Prefer shorter keys for similar scores (Occam's razor: simpler hypothesis)
        return a.key.size() < b.key.size();
    });

    std::vector<XorCandidate> unique_cands;
    for (auto& cand : all) {
        bool duplicate = false;
        for (const auto& existing : unique_cands) {
            if (existing.key == cand.key && existing.mode == cand.mode) {
                duplicate = true;
                break;
            }
        }
        if (!duplicate) {
            unique_cands.push_back(std::move(cand));
            if (unique_cands.size() >= options_.max_candidates) break;
        }
    }

    return unique_cands;
}

}  // namespace typemorph::deobf
