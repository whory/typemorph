// TypeMorph - Bitfield detector and emitter unit tests.
#include "test_framework.hpp"

#include "typemorph/core/types.hpp"
#include "typemorph/emitter/cpp_emitter.hpp"
#include "typemorph/emitter/imhex_emitter.hpp"
#include "typemorph/emitter/kaitai_emitter.hpp"
#include "typemorph/emitter/rust_emitter.hpp"
#include "typemorph/infer/bitfield_detector.hpp"

#include <vector>

using namespace typemorph;

TEST_CASE("bitfield detector: flag set with powers of two is recognized") {
    infer::BitfieldDetector detector;
    // Values resembling file/packet flags (Read=0x1, Write=0x2, Exec=0x4, Compress=0x10)
    std::vector<std::uint64_t> samples = {
        0x01, 0x02, 0x04, 0x05, 0x10, 0x14, 0x00, 0x11, 0x02, 0x15
    };
    auto res = detector.analyze(samples, core::PrimitiveKind::u32);
    REQUIRE(res.is_bitfield);
    CHECK(res.confidence >= 0.70);
    CHECK(!res.members.empty());
    CHECK(res.underlying == core::PrimitiveKind::u32);
}

TEST_CASE("bitfield detector: sequential counter is rejected") {
    infer::BitfieldDetector detector;
    std::vector<std::uint64_t> counter = {
        100, 101, 102, 103, 104, 105, 106, 107
    };
    auto res = detector.analyze(counter, core::PrimitiveKind::u32);
    CHECK(!res.is_bitfield);
}

TEST_CASE("bitfield: emitters output correct syntax for bitfield types") {
    core::BitfieldMember m0{"is_read", 0, 1, "read permission"};
    core::BitfieldMember m1{"is_write", 1, 1, "write permission"};
    core::BitfieldMember m2{"reserved", 2, 14, "reserved padding"};
    auto bf_node = core::TypeNode::bitfield(core::PrimitiveKind::u16, {m0, m1, m2}, core::ByteOrder::little, "AccessFlags");

    core::TypeField field;
    field.name = "flags";
    field.type = bf_node;
    field.offset = 0;

    auto root = core::TypeNode::structure({field}, "FileHeader");

    emit::EmitOptions opts;

    // 1. Kaitai Struct
    emit::KaitaiEmitter kaitai;
    auto ksy = kaitai.generate(*root, opts);
    REQUIRE(ksy.has_value());
    CHECK(ksy.value().find("type: b1") != std::string::npos);
    CHECK(ksy.value().find("type: b14") != std::string::npos);

    // 2. C++ Emitter
    emit::CppEmitter cpp;
    auto hpp = cpp.generate(*root, opts);
    REQUIRE(hpp.has_value());
    CHECK(hpp.value().find(": 1;") != std::string::npos);
    CHECK(hpp.value().find(": 14;") != std::string::npos);

    // 3. Rust Emitter
    emit::RustEmitter rust;
    auto rs = rust.generate(*root, opts);
    REQUIRE(rs.has_value());
    CHECK(rs.value().find("pub struct AccessFlags(pub u16);") != std::string::npos);
    CHECK(rs.value().find("pub const IS_READ: u16") != std::string::npos);

    // 4. ImHex Emitter
    emit::ImHexEmitter imhex;
    auto pat = imhex.generate(*root, opts);
    REQUIRE(pat.has_value());
    CHECK(pat.value().find("bitfield AccessFlags") != std::string::npos);
    CHECK(pat.value().find(": 1;") != std::string::npos);
}
