// TypeMorph - tests for Rust struct and type emitter.
#include "test_framework.hpp"

#include "typemorph/core/types.hpp"
#include "typemorph/emitter/emit_options.hpp"
#include "typemorph/emitter/rust_emitter.hpp"

namespace {

using typemorph::core::ByteOrder;
using typemorph::core::PrimitiveKind;
using typemorph::core::TypeField;
using typemorph::core::TypeNode;
using typemorph::core::TypePtr;
using typemorph::emit::EmitOptions;
using typemorph::emit::RustEmitter;

TEST_CASE("rust emitter: produces valid rust struct and field definitions") {
    std::vector<TypeField> fields;

    TypeField magic;
    magic.name = "magic";
    magic.offset = 0;
    magic.confidence = 1.0;
    magic.type = TypeNode::primitive(PrimitiveKind::u32, ByteOrder::little, "magic", 0);
    fields.push_back(std::move(magic));

    TypeField count;
    count.name = "count";
    count.offset = 4;
    count.confidence = 0.95;
    count.type = TypeNode::primitive(PrimitiveKind::u16, ByteOrder::little, "count", 4);
    fields.push_back(std::move(count));

    TypeField flags;
    flags.name = "type";  // Rust keyword!
    flags.offset = 6;
    flags.confidence = 0.9;
    flags.type = TypeNode::primitive(PrimitiveKind::u16, ByteOrder::little, "type", 6);
    fields.push_back(std::move(flags));

    TypePtr root = TypeNode::structure(std::move(fields), "Header", 8, 8, 0.95);

    EmitOptions options;
    options.root_type_name = "Header";

    RustEmitter emitter;
    auto res = emitter.generate(*root, options);
    REQUIRE(res.has_value());
    const std::string& code = res.value();

    CHECK(code.find("pub struct Header {") != std::string::npos);
    CHECK(code.find("pub magic: u32,") != std::string::npos);
    CHECK(code.find("pub count: u16,") != std::string::npos);
    CHECK(code.find("pub r#type: u16,") != std::string::npos);  // keyword escaped
    CHECK(code.find("#[repr(C)]") != std::string::npos);
}

TEST_CASE("rust emitter: handles fixed arrays and enum nodes") {
    typemorph::core::EnumNode en;
    en.underlying = PrimitiveKind::u32;
    en.variants.push_back({"None", 0});
    en.variants.push_back({"Active", 1});
    en.variants.push_back({"Suspended", 2});
    TypePtr enum_node = TypeNode::enumeration(std::move(en), "Status", 0, 0.9);

    std::vector<TypeField> fields;
    TypeField status_field;
    status_field.name = "status";
    status_field.offset = 0;
    status_field.type = enum_node;
    fields.push_back(std::move(status_field));

    TypeField array_field;
    array_field.name = "payload";
    array_field.offset = 4;
    auto elem_type = TypeNode::primitive(PrimitiveKind::u8, ByteOrder::little, "u8", 0);
    array_field.type = TypeNode::array(elem_type, 16, "payload", 4, 1, 0.9);
    fields.push_back(std::move(array_field));

    TypePtr root = TypeNode::structure(std::move(fields), "Config", 20, 20, 0.95);

    EmitOptions options;
    options.root_type_name = "Config";

    RustEmitter emitter;
    auto res = emitter.generate(*root, options);
    REQUIRE(res.has_value());
    const std::string& code = res.value();

    CHECK(code.find("pub enum Status {") != std::string::npos);
    CHECK(code.find("Active = 1,") != std::string::npos);
    CHECK(code.find("pub struct Config {") != std::string::npos);
    CHECK(code.find("pub payload: [u8; 16],") != std::string::npos);
}

}  // namespace
