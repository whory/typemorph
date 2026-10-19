// TypeMorph - C++ RTTI Analyzer tests.
#include "test_framework.hpp"

#include "typemorph/rtti/rtti_analyzer.hpp"

#include <cstdint>
#include <cstring>
#include <string>
#include <vector>

using namespace typemorph::rtti;
using namespace typemorph::core;

TEST_CASE("rtti: MSVC type name demangling") {
    CHECK_EQ(RttiAnalyzer::demangle_msvc_typename(".?AVMyClass@@"), std::string("MyClass"));
    CHECK_EQ(RttiAnalyzer::demangle_msvc_typename(".?AVDog@Zoo@@"), std::string("Zoo::Dog"));
    CHECK_EQ(RttiAnalyzer::demangle_msvc_typename(".?AVShape@Graphics@Engine@@"), std::string("Engine::Graphics::Shape"));
    CHECK_EQ(RttiAnalyzer::demangle_msvc_typename(".?AUPoint@@"), std::string("Point"));
    CHECK_EQ(RttiAnalyzer::demangle_msvc_typename("?AVSimple@@"), std::string("Simple"));
}

TEST_CASE("rtti: header generation") {
    RttiClass cls;
    cls.name = "Dog";
    cls.mangled_name = ".?AVDog@@";
    cls.vftable_va = 0x140010000;
    cls.base_classes.push_back({"Animal", ".?AVAnimal@@", 0, 0});
    cls.methods.push_back({0, 0x140001000, "sub_140001000"});
    cls.methods.push_back({1, 0x140001050, "sub_140001050"});

    auto header = RttiAnalyzer::to_cpp_header({cls});
    CHECK(header.find("class Dog : public Animal") != std::string::npos);
    CHECK(header.find("virtual void sub_140001000();") != std::string::npos);
    CHECK(header.find("virtual ~Dog() = default;") != std::string::npos);
}

TEST_CASE("rtti: synthetic MSVC64 binary RTTI recovery") {
    // Construct a synthetic 64-bit PE-like memory image with:
    // .text: code function at 0x140001000
    // .rdata:
    //   - TypeDescriptor for Animal at 0x140002000 (name ".?AVAnimal@@")
    //   - TypeDescriptor for Dog at 0x140002050 (name ".?AVDog@@")
    //   - RTTICompleteObjectLocator for Dog at 0x140002100
    //   - vtable for Dog at 0x140002208 (preceded at 0x140002200 by locator pointer)

    constexpr std::uint64_t kImageBase = 0x140000000;
    std::vector<std::uint8_t> buffer(0x4000, 0x00);

    // Section 1: .text (VA 0x140001000, raw 0x1000, size 0x1000, Executable)
    // Section 2: .rdata (VA 0x140002000, raw 0x2000, size 0x2000, Readable)
    Section text_sec;
    text_sec.name = ".text";
    text_sec.virtual_address = kImageBase + 0x1000;
    text_sec.virtual_size = 0x1000;
    text_sec.file_offset = 0x1000;
    text_sec.file_size = 0x1000;
    text_sec.flags = SectionFlag::readable | SectionFlag::executable | SectionFlag::code;

    // Fill some code bytes at .text (ret instruction 0xC3)
    buffer[0x1000] = 0xC3;

    Section rdata_sec;
    rdata_sec.name = ".rdata";
    rdata_sec.virtual_address = kImageBase + 0x2000;
    rdata_sec.virtual_size = 0x2000;
    rdata_sec.file_offset = 0x2000;
    rdata_sec.file_size = 0x2000;
    rdata_sec.flags = SectionFlag::readable | SectionFlag::data | SectionFlag::read_only;

    // Put TypeDescriptor for Dog at RVA 0x2050 (file offset 0x2050)
    // In 64-bit TypeDescriptor: [pVFTable (8)] [spare (8)] [name: ".?AVDog@@\0"]
    const std::string dog_name = ".?AVDog@@";
    std::memcpy(&buffer[0x2050 + 16], dog_name.c_str(), dog_name.size() + 1);

    // Put RTTICompleteObjectLocator for Dog at RVA 0x2100 (file offset 0x2100)
    // [signature (4) = 1]
    // [offset (4) = 0]
    // [cdOffset (4) = 0]
    // [pTypeDescriptor RVA (4) = 0x2050]
    // [pClassDescriptor RVA (4) = 0]
    // [pSelf RVA (4) = 0x2100]
    *reinterpret_cast<std::uint32_t*>(&buffer[0x2100 + 0]) = 1;
    *reinterpret_cast<std::uint32_t*>(&buffer[0x2100 + 4]) = 0;
    *reinterpret_cast<std::uint32_t*>(&buffer[0x2100 + 8]) = 0;
    *reinterpret_cast<std::uint32_t*>(&buffer[0x2100 + 12]) = 0x2050; // RVA to Dog TypeDescriptor
    *reinterpret_cast<std::uint32_t*>(&buffer[0x2100 + 16]) = 0;      // No base classes
    *reinterpret_cast<std::uint32_t*>(&buffer[0x2100 + 20]) = 0x2100; // pSelf

    // Put vtable at RVA 0x2208 (file offset 0x2208)
    // Preceded by pointer to locator at RVA 0x2200 (file offset 0x2200)
    *reinterpret_cast<std::uint64_t*>(&buffer[0x2200]) = kImageBase + 0x2100;

    // Slot 0 in vtable points to code in .text (0x140001000)
    *reinterpret_cast<std::uint64_t*>(&buffer[0x2208]) = kImageBase + 0x1000;

    ImageParts parts;
    parts.format = ImageFormat::pe;
    parts.bits = 64;
    parts.image_base = kImageBase;
    parts.entry_point = kImageBase + 0x1000;
    parts.sections = {text_sec, rdata_sec};

    BinaryView view = BinaryView::from_owned(std::move(buffer));
    auto image = ExecutableImage::from_parts(view, std::move(parts));
    REQUIRE(image.valid());

    RttiAnalyzer analyzer;
    auto classes = analyzer.analyze(image);

    REQUIRE_EQ(classes.size(), std::size_t{1});
    CHECK_EQ(classes[0].name, std::string("Dog"));
    CHECK_EQ(classes[0].vftable_va, kImageBase + 0x2208);
    REQUIRE_EQ(classes[0].methods.size(), std::size_t{1});
    CHECK_EQ(classes[0].methods[0].virtual_address, kImageBase + 0x1000);
}
