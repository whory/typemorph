// TypeMorph - memory mapped, bounds checked, zero-copy binary buffer views.
#pragma once

#include "typemorph/core/result.hpp"

#include <bit>
#include <cstddef>
#include <cstdint>
#include <filesystem>
#include <memory>
#include <span>
#include <string>
#include <string_view>
#include <vector>

namespace typemorph::core {

enum class ByteOrder : std::uint8_t { little, big };

[[nodiscard]] constexpr std::uint16_t byteswap16(std::uint16_t value) noexcept {
    return static_cast<std::uint16_t>((value >> 8U) | (value << 8U));
}

[[nodiscard]] constexpr std::uint32_t byteswap32(std::uint32_t value) noexcept {
    return ((value & 0x000000FFU) << 24U) | ((value & 0x0000FF00U) << 8U) |
           ((value & 0x00FF0000U) >> 8U) | ((value & 0xFF000000U) >> 24U);
}

[[nodiscard]] constexpr std::uint64_t byteswap64(std::uint64_t value) noexcept {
    return (static_cast<std::uint64_t>(byteswap32(static_cast<std::uint32_t>(value))) << 32U) |
           static_cast<std::uint64_t>(byteswap32(static_cast<std::uint32_t>(value >> 32U)));
}

[[nodiscard]] constexpr std::uint64_t bswap(std::uint64_t value) noexcept { return byteswap64(value); }
[[nodiscard]] constexpr std::uint32_t bswap(std::uint32_t value) noexcept { return byteswap32(value); }
[[nodiscard]] constexpr std::uint16_t bswap(std::uint16_t value) noexcept { return byteswap16(value); }

namespace detail {
template <class T>
[[nodiscard]] inline T load_unsigned(const std::uint8_t* data, ByteOrder order) noexcept {
    if constexpr (sizeof(T) == 1) {
        return static_cast<T>(data[0]);
    } else {
        T value{};
        if (order == ByteOrder::little) {
            for (std::size_t i = 0; i < sizeof(T); ++i) {
                value |= static_cast<T>(data[i]) << static_cast<unsigned>(i * 8U);
            }
        } else {
            for (std::size_t i = 0; i < sizeof(T); ++i) {
                value = static_cast<T>((value << 8U) | static_cast<T>(data[i]));
            }
        }
        return value;
    }
}
}  // namespace detail

// BinaryView is a cheap-to-copy handle over a byte range.  File-backed views
// own a read-only mapping through shared storage, so copies are safe and keep
// the mapping alive.  External spans are non-owning by design (zero copy); the
// caller must keep the pointed-to memory alive.
class BinaryView {
public:
    BinaryView() noexcept = default;
    BinaryView(const BinaryView&) noexcept = default;
    BinaryView& operator=(const BinaryView&) noexcept = default;
    BinaryView(BinaryView&&) noexcept = default;
    BinaryView& operator=(BinaryView&&) noexcept = default;
    ~BinaryView() = default;

    // Memory-map a file read-only.  Empty files are accepted and map to an
    // empty span; their storage remains valid so `valid()` is true.
    [[nodiscard]] static Result<BinaryView> open(const std::filesystem::path& path);

    // Take ownership of an in-memory buffer (useful for fuzzing and tests).
    [[nodiscard]] static BinaryView from_owned(std::vector<std::uint8_t> bytes,
                                               std::string name = "<memory>");

    // Non-owning view over an external buffer.  The caller owns the lifetime.
    [[nodiscard]] static BinaryView from_external(std::span<const std::uint8_t> bytes,
                                                  std::string name = "<external>");

    [[nodiscard]] bool valid() const noexcept { return storage_ != nullptr; }
    [[nodiscard]] bool empty() const noexcept { return view_.empty(); }
    [[nodiscard]] std::size_t size() const noexcept { return view_.size(); }
    [[nodiscard]] const std::uint8_t* data() const noexcept { return view_.data(); }
    [[nodiscard]] std::span<const std::uint8_t> bytes() const noexcept { return view_; }
    [[nodiscard]] const std::string& name() const noexcept;

    [[nodiscard]] std::span<const std::uint8_t> slice_unchecked(std::size_t offset,
                                                                std::size_t length) const noexcept {
        return view_.subspan(offset, length);
    }

    [[nodiscard]] Result<std::span<const std::uint8_t>> slice(std::uint64_t offset,
                                                              std::uint64_t length) const {
        if (offset > view_.size() || length > view_.size() - static_cast<std::size_t>(offset)) {
            return make_error(ErrorCode::out_of_range, "binary view slice out of range",
                              "offset=" + std::to_string(offset) + " length=" + std::to_string(length) +
                                  " size=" + std::to_string(view_.size()));
        }
        return view_.subspan(static_cast<std::size_t>(offset), static_cast<std::size_t>(length));
    }

    [[nodiscard]] Result<std::span<const std::uint8_t>> tail(std::uint64_t offset) const {
        if (offset > view_.size()) {
            return make_error(ErrorCode::out_of_range, "binary view tail offset out of range");
        }
        return view_.subspan(static_cast<std::size_t>(offset));
    }

    [[nodiscard]] Result<std::uint8_t> u8(std::uint64_t offset) const {
        auto s = slice(offset, 1);
        if (!s) return s.error();
        return s.value()[0];
    }

    [[nodiscard]] Result<std::uint64_t> read_uint(std::uint64_t offset, std::size_t width,
                                                   ByteOrder order = ByteOrder::little) const {
        if (width != 1 && width != 2 && width != 4 && width != 8) {
            return make_error(ErrorCode::invalid_argument, "unsupported integer width",
                              std::to_string(width));
        }
        auto s = slice(offset, width);
        if (!s) return s.error();
        switch (width) {
        case 1: return static_cast<std::uint64_t>(s.value()[0]);
        case 2: return detail::load_unsigned<std::uint16_t>(s.value().data(), order);
        case 4: return detail::load_unsigned<std::uint32_t>(s.value().data(), order);
        default: return detail::load_unsigned<std::uint64_t>(s.value().data(), order);
        }
    }

    [[nodiscard]] Result<std::int64_t> read_int(std::uint64_t offset, std::size_t width,
                                                 ByteOrder order = ByteOrder::little) const {
        auto raw = read_uint(offset, width, order);
        if (!raw) return raw.error();
        const std::uint64_t value = raw.value();
        if (width == 8) return static_cast<std::int64_t>(value);
        const unsigned bits = static_cast<unsigned>(width * 8);
        const std::uint64_t sign = std::uint64_t{1} << (bits - 1U);
        std::uint64_t extended = value;
        if ((value & sign) != 0) extended |= ~((std::uint64_t{1} << bits) - 1U);
        return static_cast<std::int64_t>(extended);
    }

    [[nodiscard]] Result<double> read_f32(std::uint64_t offset,
                                          ByteOrder order = ByteOrder::little) const {
        auto raw = read_uint(offset, 4, order);
        if (!raw) return raw.error();
        return static_cast<double>(std::bit_cast<float>(static_cast<std::uint32_t>(raw.value())));
    }

    [[nodiscard]] Result<double> read_f64(std::uint64_t offset,
                                          ByteOrder order = ByteOrder::little) const {
        auto raw = read_uint(offset, 8, order);
        if (!raw) return raw.error();
        return std::bit_cast<double>(raw.value());
    }

    [[nodiscard]] bool starts_with(std::span<const std::uint8_t> prefix) const noexcept {
        return view_.size() >= prefix.size() &&
               std::equal(prefix.begin(), prefix.end(), view_.begin());
    }

    // Copies a range out of the view.  Used by parsers that need normalised
    // (endian-swapped) auxiliary buffers; ordinary analysis stays zero-copy.
    [[nodiscard]] Result<std::vector<std::uint8_t>> copy(std::uint64_t offset,
                                                         std::uint64_t length) const {
        auto s = slice(offset, length);
        if (!s) return s.error();
        return std::vector<std::uint8_t>(s.value().begin(), s.value().end());
    }

private:
    struct Storage {
        const std::uint8_t* data = nullptr;
        std::size_t size = 0;
        std::string name;
        std::vector<std::uint8_t> owned;
        bool mapped = false;
#ifdef _WIN32
        void* file = nullptr;
        void* mapping = nullptr;
#else
        int fd = -1;
#endif
        ~Storage();
    };

    std::shared_ptr<Storage> storage_{};
    std::span<const std::uint8_t> view_{};
};

}  // namespace typemorph::core
