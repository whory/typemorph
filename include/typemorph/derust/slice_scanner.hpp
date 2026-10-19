// TypeMorph - Rust fat pointer (&str / &[T]) discovery in image data sections.
#pragma once

#include "typemorph/core/executable.hpp"
#include "typemorph/core/result.hpp"

#include <cstddef>
#include <cstdint>
#include <span>
#include <string>
#include <vector>

namespace typemorph::derust {

struct SliceScannerOptions {
    std::size_t min_length = 1;
    std::size_t max_length = 1U << 20U;
    bool require_utf8 = true;
    bool allow_empty = false;
    bool scan_writable_sections = true;
    std::size_t max_results = 100000;
};

struct RustString {
    // Address of the (pointer, length) pair in the image's virtual layout.
    std::uint64_t pair_address = 0;
    std::uint64_t pair_file_offset = 0;
    std::uint64_t data_address = 0;
    std::uint64_t data_file_offset = 0;
    std::uint64_t length = 0;
    std::string value;
    double confidence = 0.0;
};

class SliceScanner {
public:
    explicit SliceScanner(SliceScannerOptions options = {});

    [[nodiscard]] core::Result<std::vector<RustString>> scan(const core::ExecutableImage& image) const;

    // Lower-level helper used by tests and hybrid analysis: scans a data range
    // with an explicit address translation callback.
    [[nodiscard]] static bool valid_utf8(std::span<const std::uint8_t> bytes) noexcept;

    [[nodiscard]] const SliceScannerOptions& options() const noexcept { return options_; }

private:
    SliceScannerOptions options_;
};

}  // namespace typemorph::derust
