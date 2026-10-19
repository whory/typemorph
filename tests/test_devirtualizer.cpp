#include "test_framework.hpp"

#include "typemorph/deobf/devirtualizer.hpp"
#include "typemorph/core/executable.hpp"

#include <vector>

using namespace typemorph::deobf;
using namespace typemorph::core;

TEST_CASE("devirtualizer: detects vm handler table") {
    // Build synthetic image:
    // .text at VA 0x1000 (size 0x100, file_offset 0x0)
    // .rodata at VA 0x2000 (size 0x100, file_offset 0x100)
    // 5 handlers in .text at: 0x1000, 0x1010, 0x1020, 0x1030, 0x1040
    // Table in .rodata at 0x2000 containing the 5 pointers.
    std::vector<std::uint8_t> buffer(0x200, 0x00);

    // Populate handlers in .text (push rbp (0x55), ret (0xC3))
    for (std::uint64_t h_va = 0x1000; h_va <= 0x1040; h_va += 0x10) {
        const std::size_t off = static_cast<std::size_t>(h_va - 0x1000);
        buffer[off] = 0x55;
        buffer[off + 1] = 0xC3;
    }

    // Populate handler table in .rodata (file_offset 0x100)
    const std::uint64_t handler_vas[] = {0x1000, 0x1010, 0x1020, 0x1030, 0x1040};
    for (std::size_t i = 0; i < 5; ++i) {
        const std::uint64_t va = handler_vas[i];
        for (std::size_t b = 0; b < 8; ++b) {
            buffer[0x100 + i * 8 + b] = static_cast<std::uint8_t>((va >> (b * 8U)) & 0xFFU);
        }
    }

    ImageParts parts;
    parts.format = ImageFormat::elf;
    parts.bits = 64;
    parts.endian = ByteOrder::little;
    parts.image_base = 0x1000;

    Section text_sec;
    text_sec.name = ".text";
    text_sec.virtual_address = 0x1000;
    text_sec.virtual_size = 0x100;
    text_sec.file_offset = 0x0;
    text_sec.file_size = 0x100;
    text_sec.flags = SectionFlag::executable | SectionFlag::readable;
    parts.sections.push_back(text_sec);

    Section rodata_sec;
    rodata_sec.name = ".rodata";
    rodata_sec.virtual_address = 0x2000;
    rodata_sec.virtual_size = 0x100;
    rodata_sec.file_offset = 0x100;
    rodata_sec.file_size = 0x100;
    rodata_sec.flags = SectionFlag::readable | SectionFlag::read_only;
    parts.sections.push_back(rodata_sec);

    ExecutableImage image = ExecutableImage::from_parts(
        BinaryView::from_owned(std::move(buffer)),
        parts
    );

    Devirtualizer devirt;
    auto instances = devirt.analyze(image);

    REQUIRE_EQ(instances.size(), std::size_t{1});
    CHECK_EQ(instances[0].table_va, std::uint64_t{0x2000});
    CHECK_EQ(instances[0].opcode_count, std::size_t{5});
    CHECK_EQ(instances[0].handlers[0].handler_va, std::uint64_t{0x1000});
    CHECK_EQ(instances[0].handlers[4].handler_va, std::uint64_t{0x1040});
    CHECK_EQ(instances[0].handlers[2].mnemonic, std::string("OP_0x02"));
    CHECK(instances[0].confidence >= 0.70);
}
