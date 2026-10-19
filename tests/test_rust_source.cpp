// TypeMorph - Rust High-Level Source Code Reconstructor tests.
#include "test_framework.hpp"

#include "typemorph/derust/rust_source.hpp"

#include <cstdint>
#include <string>
#include <vector>

using namespace typemorph::derust;

TEST_CASE("rust_source: empty report returns fallback message") {
    RustSourceReport report;
    report.has_rust_artifacts = false;
    std::string src = RustSourceReconstructor::to_rust_source(report);
    CHECK_EQ(src, std::string("// No Rust semantics detected\n"));
}

TEST_CASE("rust_source: trait definitions and vtables emission") {
    RustSourceReport report;
    report.has_rust_artifacts = true;

    RustTraitDefinition tr;
    tr.trait_name = "StreamParser";
    tr.vtable_va = 0x501000;
    tr.drop_in_place_va = 0x402000;
    tr.size = 64;
    tr.align = 8;
    tr.method_names = {"parse_header", "decode_frame", "flush"};
    tr.method_vas = {0x402100, 0x402200, 0x402300};
    report.traits.push_back(tr);

    std::string src = RustSourceReconstructor::to_rust_source(report);

    CHECK(src.find("#![allow(dead_code") != std::string::npos);
    CHECK(src.find("pub trait StreamParser {") != std::string::npos);
    CHECK(src.find("fn parse_header(&self);") != std::string::npos);
    CHECK(src.find("fn decode_frame(&self);") != std::string::npos);
    CHECK(src.find("fn flush(&self);") != std::string::npos);
    CHECK(src.find("VTable: 0x501000") != std::string::npos);
}

TEST_CASE("rust_source: tagged union enum and niche type reconstruction") {
    RustSourceReport report;
    report.has_rust_artifacts = true;

    TaggedUnionCandidate tu;
    tu.offset = 0x2000;
    tu.tag_width = 1;
    tu.payload_offset = 0x2004;
    tu.confidence = 0.95;
    tu.variants.push_back({0, 0x2004, 8, ""});
    tu.variants.push_back({1, 0x2004, 8, ""});
    tu.variants.push_back({2, 0x2004, 8, ""});
    report.tagged_unions.push_back(tu);

    NicheCandidate niche;
    niche.offset = 0x2100;
    niche.kind = NicheKind::nullable_pointer;
    niche.confidence = 0.90;
    niche.rationale = "Zero pointer sentinel niche";
    report.niches.push_back(niche);

    std::string src = RustSourceReconstructor::to_rust_source(report);

    CHECK(src.find("#[repr(C)]") != std::string::npos);
    CHECK(src.find("pub enum TaggedUnion_0 {") != std::string::npos);
    CHECK(src.find("Variant0 = 0,") != std::string::npos);
    CHECK(src.find("Variant1 = 1,") != std::string::npos);
    CHECK(src.find("Variant2 = 2,") != std::string::npos);
    CHECK(src.find("pub struct NicheType_0(pub usize);") != std::string::npos);
}

TEST_CASE("rust_source: demangled function stubs synthesis") {
    RustSourceReport report;
    report.has_rust_artifacts = true;

    DemangledSymbol sym1;
    sym1.mangled = "_RNvCs1234_4core3fmt4impl3foo";
    sym1.demangled = "core::fmt::Formatter::pad";
    sym1.crate = "core";
    sym1.path = "fmt::Formatter::pad";
    sym1.is_v0 = true;
    sym1.is_rust = true;
    report.symbols.push_back(sym1);

    DemangledSymbol sym2;
    sym2.mangled = "_ZN3app4main17h1234567890abcdefE";
    sym2.demangled = "app::main";
    sym2.crate = "app";
    sym2.path = "main";
    sym2.is_rust = true;
    report.symbols.push_back(sym2);

    std::string src = RustSourceReconstructor::to_rust_source(report);

    CHECK(src.find("pub fn core__fmt__Formatter__pad()") != std::string::npos);
    CHECK(src.find("pub fn app__main()") != std::string::npos);
}
