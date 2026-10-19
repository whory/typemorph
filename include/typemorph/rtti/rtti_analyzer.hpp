// TypeMorph - C++ RTTI (Run-Time Type Information) & Class Hierarchy Analyzer.
//
// Reconstructs C++ polymorphic class names, inheritance graphs, and vftables
// from MSVC CompleteObjectLocator and Itanium ABI typeinfo structures.
#pragma once

#include "typemorph/core/binary_view.hpp"
#include "typemorph/core/executable.hpp"
#include "typemorph/core/result.hpp"

#include <cstdint>
#include <string>
#include <string_view>
#include <vector>

namespace typemorph::rtti {

struct RttiBaseClass {
    std::string name;
    std::string mangled_name;
    std::int32_t offset = 0;
    std::uint32_t attributes = 0;
};

struct RttiMethod {
    std::size_t slot = 0;
    std::uint64_t virtual_address = 0;
    std::string name;
};

struct RttiClass {
    std::string name;
    std::string mangled_name;
    std::uint64_t vftable_va = 0;
    std::uint64_t locator_va = 0;
    std::vector<RttiBaseClass> base_classes;
    std::vector<RttiMethod> methods;
    double confidence = 0.95;
};

class RttiAnalyzer {
public:
    RttiAnalyzer() = default;

    [[nodiscard]] std::vector<RttiClass> analyze(const core::ExecutableImage& image) const;
    [[nodiscard]] std::vector<RttiClass> analyze_view(const core::BinaryView& view) const;

    // Demangles MSVC type descriptor name (e.g. ".?AVDog@Zoo@@" -> "Zoo::Dog")
    static std::string demangle_msvc_typename(std::string_view mangled);

    // Formats reconstructed classes into compilable C++ class definitions
    static std::string to_cpp_header(const std::vector<RttiClass>& classes);

private:
    [[nodiscard]] std::vector<RttiClass> analyze_msvc(const core::ExecutableImage& image) const;
    [[nodiscard]] std::vector<RttiClass> analyze_itanium(const core::ExecutableImage& image) const;
};

}  // namespace typemorph::rtti
