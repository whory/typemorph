// TypeMorph - Control Flow Flattening (CFF) Reconstructor unit tests.
#include "test_framework.hpp"

#include "typemorph/deobf/cff_reconstructor.hpp"
#include "typemorph/core/executable.hpp"

#include <vector>

using namespace typemorph::deobf;
using namespace typemorph::core;

TEST_CASE("cff reconstructor: detects dispatcher and recovers state transitions") {
    // Total buffer size 0x200 bytes for .text
    std::vector<std::uint8_t> buffer(0x200, 0x90); // fill with NOPs

    // 0x00: Initial state assignment: mov eax, 1 (B8 01 00 00 00)
    buffer[0x00] = 0xB8;
    buffer[0x01] = 0x01;
    buffer[0x02] = 0x00;
    buffer[0x03] = 0x00;
    buffer[0x04] = 0x00;

    // Dispatcher starts at offset 0x10 (VA 0x1010)
    // Case 1 (state 1): 3D 01 00 00 00 (cmp eax, 1) + 0F 84 2B 00 00 00 (je -> 0x1010 + 11 + 0x2B = 0x1046, offset 0x46)
    buffer[0x10] = 0x3D; buffer[0x11] = 0x01; buffer[0x12] = 0x00; buffer[0x13] = 0x00; buffer[0x14] = 0x00;
    buffer[0x15] = 0x0F; buffer[0x16] = 0x84;
    buffer[0x17] = 0x2B; buffer[0x18] = 0x00; buffer[0x19] = 0x00; buffer[0x1A] = 0x00; // rel = 0x2B

    // Case 2 (state 2): 3D 02 00 00 00 (cmp eax, 2) + 0F 84 3B 00 00 00 (je -> 0x101B + 11 + 0x3B = 0x1061, offset 0x61)
    buffer[0x1B] = 0x3D; buffer[0x1C] = 0x02; buffer[0x1D] = 0x00; buffer[0x1E] = 0x00; buffer[0x1F] = 0x00;
    buffer[0x20] = 0x0F; buffer[0x21] = 0x84;
    buffer[0x22] = 0x3B; buffer[0x23] = 0x00; buffer[0x24] = 0x00; buffer[0x25] = 0x00; // rel = 0x3B

    // Case 3 (state 3): 3D 03 00 00 00 (cmp eax, 3) + 0F 84 4B 00 00 00 (je -> 0x1026 + 11 + 0x4B = 0x107C, offset 0x7C)
    buffer[0x26] = 0x3D; buffer[0x27] = 0x03; buffer[0x28] = 0x00; buffer[0x29] = 0x00; buffer[0x2A] = 0x00;
    buffer[0x2B] = 0x0F; buffer[0x2C] = 0x84;
    buffer[0x2D] = 0x4B; buffer[0x2E] = 0x00; buffer[0x2F] = 0x00; buffer[0x30] = 0x00; // rel = 0x4B

    // Block 1 (at offset 0x46 / VA 0x1046):
    // Updates state to 2: mov eax, 2 (B8 02 00 00 00)
    // Jumps back to dispatcher 0x1010: E9 [disp32]
    // Jump origin is 0x1046 + 5 (mov) + 5 (jmp) = 0x1050; disp = 0x1010 - 0x1050 = -0x40 (0xFFFFFFC0)
    buffer[0x46] = 0xB8; buffer[0x47] = 0x02; buffer[0x48] = 0x00; buffer[0x49] = 0x00; buffer[0x4A] = 0x00;
    buffer[0x4B] = 0xE9;
    buffer[0x4C] = 0xC0; buffer[0x4D] = 0xFF; buffer[0x4E] = 0xFF; buffer[0x4F] = 0xFF;

    // Block 2 (at offset 0x61 / VA 0x1061):
    // Updates state to 3: mov eax, 3 (B8 03 00 00 00)
    // Jumps back to dispatcher 0x1010: E9 [disp32]
    // Jump origin is 0x1061 + 5 + 5 = 0x106B; disp = 0x1010 - 0x106B = -0x5B (0xFFFFFFA5)
    buffer[0x61] = 0xB8; buffer[0x62] = 0x03; buffer[0x63] = 0x00; buffer[0x64] = 0x00; buffer[0x65] = 0x00;
    buffer[0x66] = 0xE9;
    buffer[0x67] = 0xA5; buffer[0x68] = 0xFF; buffer[0x69] = 0xFF; buffer[0x6A] = 0xFF;

    // Block 3 (at offset 0x7C / VA 0x107C):
    // Exit block: ret (C3)
    buffer[0x7C] = 0xC3;

    ImageParts parts;
    parts.format = ImageFormat::elf;
    parts.bits = 64;
    parts.endian = ByteOrder::little;
    parts.image_base = 0x1000;

    Section sec;
    sec.name = ".text";
    sec.virtual_address = 0x1000;
    sec.virtual_size = 0x200;
    sec.file_offset = 0x0;
    sec.file_size = 0x200;
    sec.flags = SectionFlag::executable | SectionFlag::readable;
    parts.sections.push_back(sec);

    ExecutableImage image = ExecutableImage::from_parts(
        BinaryView::from_owned(std::move(buffer)),
        std::move(parts));

    CffOptions opts;
    opts.min_blocks = 3;
    CffReconstructor reconstructor(opts);
    auto fns = reconstructor.analyze(image);

    REQUIRE(fns.size() == 1);
    const auto& fn = fns.front();
    CHECK(fn.dispatcher_va == 0x1010);
    CHECK(fn.blocks.size() == 3);
    CHECK(fn.transitions.size() == 2);
    CHECK(fn.confidence >= 0.70);

    // Verify DOT and Mermaid graph outputs
    std::string dot = fn.to_dot();
    CHECK(dot.find("digraph CFF_Recovered") != std::string::npos);
    CHECK(dot.find("node_0x1 -> node_0x2") != std::string::npos);
    CHECK(dot.find("node_0x2 -> node_0x3") != std::string::npos);

    std::string mermaid = fn.to_mermaid();
    CHECK(mermaid.find("flowchart TD") != std::string::npos);
    CHECK(mermaid.find("S_0x1 --> S_0x2") != std::string::npos);
    CHECK(mermaid.find("S_0x2 --> S_0x3") != std::string::npos);
}
