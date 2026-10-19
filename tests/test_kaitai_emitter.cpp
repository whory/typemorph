// TypeMorph - emitter tests (Kaitai 0.10 YAML, ImHex .hexpat, C++20 header).
//
// The tests build a TypeNode tree by hand that exercises every node kind the
// emitters must handle (primitives, enums, nested records, counted arrays,
// pointers, slices, padding, opaque payloads) and validate the generated text
// structurally.  When the committed fixtures are present the inference result is
// also round-tripped through the Kaitai emitter to prove that repeat-expr links
// to the recovered count field.
#include "test_framework.hpp"

#include <cstdint>
#include <filesystem>
#include <fstream>
#include <iterator>
#include <memory>
#include <span>
#include <string>
#include <string_view>
#include <vector>

#include "typemorph/core/binary_view.hpp"
#include "typemorph/core/types.hpp"
#include "typemorph/emitter/cpp_emitter.hpp"
#include "typemorph/emitter/emit_options.hpp"
#include "typemorph/emitter/imhex_emitter.hpp"
#include "typemorph/emitter/kaitai_emitter.hpp"
#include "typemorph/infer/diff_engine.hpp"

namespace {

using typemorph::core::ByteOrder;
using typemorph::core::EnumNode;
using typemorph::core::EnumVariant;
using typemorph::core::PrimitiveKind;
using typemorph::core::TypeField;
using typemorph::core::TypeNode;
using typemorph::core::TypePtr;
using typemorph::emit::CppEmitter;
using typemorph::emit::EmitOptions;
using typemorph::emit::ImHexEmitter;
using typemorph::emit::KaitaiEmitter;

TypePtr primitive(PrimitiveKind kind, std::string name, std::uint64_t offset) {
    return TypeNode::primitive(kind, ByteOrder::little, std::move(name), offset);
}

TypePtr make_record_element() {
    std::vector<TypeField> fields;
    TypeField id;
    id.name = "id";
    id.offset = 0;
    id.confidence = 0.95;
    id.type = primitive(PrimitiveKind::u32, "id", 0);
    fields.push_back(std::move(id));
    TypeField tag;
    tag.name = "tag";
    tag.offset = 4;
    tag.confidence = 0.99;
    tag.type = primitive(PrimitiveKind::u16, "tag", 4);
    fields.push_back(std::move(tag));
    auto element = TypeNode::structure(std::move(fields), "item", 0, 6, 0.9);
    return element;
}

TypePtr make_root() {
    std::vector<TypeField> fields;

    TypeField magic;
    magic.name = "magic";
    magic.offset = 0;
    magic.confidence = 1.0;
    magic.comment = "it's a \"magic\" value\nwith a newline";
    magic.type = primitive(PrimitiveKind::u32, "magic", 0);
    fields.push_back(std::move(magic));

    TypeField kind;
    kind.name = "kind";
    kind.offset = 4;
    kind.confidence = 0.9;
    kind.comment = "record kind";
    EnumNode enumeration;
    enumeration.underlying = PrimitiveKind::u16;
    enumeration.variants.push_back(EnumVariant{"zero", 0});
    enumeration.variants.push_back(EnumVariant{"one", 1});
    enumeration.variants.push_back(EnumVariant{"two", 2});
    kind.type = TypeNode::enumeration(enumeration, "kind_enum", 4, 0.9);
    fields.push_back(std::move(kind));

    TypeField count;
    count.name = "count_field";
    count.offset = 6;
    count.confidence = 0.93;
    count.type = primitive(PrimitiveKind::u16, "count_field", 6);
    fields.push_back(std::move(count));

    const TypePtr element = make_record_element();
    TypeField items;
    items.name = "items";
    items.offset = 8;
    items.confidence = 0.93;
    items.comment = "counted records";
    auto array = TypeNode::array(element, 3, "items", 8, 6, 0.93);
    if (auto* array_node = array->get_if<typemorph::core::ArrayNode>()) {
        array_node->count_field_offset = 6;
        array_node->count_expression = "count_field";
    }
    array->size = 3 * 6;
    items.type = std::move(array);
    fields.push_back(std::move(items));

    TypeField pointer;
    pointer.name = "next_record";
    pointer.offset = 26;
    pointer.confidence = 0.6;
    pointer.type = TypeNode::pointer(8, 8, true, "next_record", 26, 0.6);
    fields.push_back(std::move(pointer));

    TypeField padding;
    padding.name = "padding";
    padding.offset = 34;
    padding.confidence = 1.0;
    padding.type = TypeNode::padding(2, 0, "padding", 34);
    fields.push_back(std::move(padding));

    TypeField opaque;
    opaque.name = "payload";
    opaque.offset = 36;
    opaque.confidence = 0.3;
    opaque.type = TypeNode::unknown(4, "payload", 36);
    fields.push_back(std::move(opaque));

    TypeField slice;
    slice.name = "rest";
    slice.offset = 40;
    slice.confidence = 0.5;
    slice.type = std::make_shared<TypeNode>();
    typemorph::core::SliceNode slice_node;
    slice_node.element_type = primitive(PrimitiveKind::u8, "byte", 40);
    slice_node.element_primitive = PrimitiveKind::u8;
    slice_node.length_source = "fat-pointer";
    slice.type->node = slice_node;
    slice.type->name = "rest";
    slice.type->offset = 40;
    slice.type->size = 2;
    fields.push_back(std::move(slice));

    auto root = TypeNode::structure(std::move(fields), "packet", 0, 64, 0.9);
    return root;
}

[[nodiscard]] EmitOptions make_options() {
    EmitOptions options;
    options.format_name = "MyFormat";
    options.root_type_name = "Packet";
    options.file_size = 1234;
    options.endian = ByteOrder::little;
    options.indent = 2;
    options.emit_comments = true;
    options.emit_instances = true;
    options.source_name = "synthetic";
    return options;
}

// Minimal structural YAML validation: no tabs, indentation on even columns,
// every non-comment line is either a list item or a key/value pair.
bool valid_yaml_structure(const std::string& text) {
    std::size_t position = 0;
    while (position <= text.size()) {
        const std::size_t end = text.find('\n', position);
        const std::size_t line_end = end == std::string::npos ? text.size() : end;
        const std::string_view line(text.data() + position, line_end - position);
        if (!line.empty()) {
            if (line.find('\t') != std::string_view::npos) return false;
            std::size_t indent = 0;
            while (indent < line.size() && line[indent] == ' ') ++indent;
            if (indent % 2 != 0) return false;
            const std::string_view trimmed = line.substr(indent);
            if (trimmed.empty()) return false;
            if (trimmed.front() != '#' && trimmed.front() != '-') {
                if (trimmed.find(':') == std::string_view::npos) return false;
            }
        }
        if (end == std::string::npos) break;
        position = end + 1;
    }
    return true;
}

bool contains(const std::string& haystack, std::string_view needle) {
    return haystack.find(needle) != std::string::npos;
}

std::size_t count_char(const std::string& text, char character) {
    std::size_t total = 0;
    for (const char value : text) {
        if (value == character) ++total;
    }
    return total;
}

}  // namespace

TEST_CASE("kaitai emitter: produces structurally valid ksy 0.10 YAML") {
    const TypePtr root = make_root();
    const EmitOptions options = make_options();
    const auto generated = KaitaiEmitter().generate(*root, options);
    REQUIRE(generated.has_value());
    const std::string& text = generated.value();

    CHECK(valid_yaml_structure(text));
    CHECK(contains(text, "meta:"));
    CHECK(contains(text, "id: myformat"));
    CHECK(contains(text, "title: 'Packet'"));
    CHECK(contains(text, "endian: le"));
    CHECK(contains(text, "ks-version: '0.10'"));
    CHECK(contains(text, "file-extension: bin"));
    CHECK(contains(text, "seq:"));
    CHECK(contains(text, "- id: magic"));
    CHECK(contains(text, "type: u4"));
    CHECK(contains(text, "- id: kind"));
    CHECK(contains(text, "enum: kind_enum"));
    CHECK(contains(text, "- id: count_field"));
    CHECK(contains(text, "- id: items"));
    CHECK(contains(text, "repeat: expr"));
    CHECK(contains(text, "repeat-expr: count_field"));
    CHECK(contains(text, "types:"));
    CHECK(contains(text, "- id: id"));
    CHECK(contains(text, "instances:"));
    CHECK(contains(text, "value: _io.size"));
    // YAML single-quote escaping for the comment containing an apostrophe.
    CHECK(contains(text, "it''s"));
    CHECK(contains(text, "expected file size: 1234"));

    // Every attribute id in the generated file is a valid Kaitai identifier.
    std::size_t position = 0;
    while ((position = text.find("- id: ", position)) != std::string::npos) {
        position += 6;
        std::size_t end = position;
        while (end < text.size() && text[end] != '\n') ++end;
        const std::string id = text.substr(position, end - position);
        REQUIRE(!id.empty());
        CHECK(id.front() >= 'a' && id.front() <= 'z');
        for (const char character : id) {
            CHECK((character >= 'a' && character <= 'z') ||
                  (character >= '0' && character <= '9') || character == '_');
        }
        position = end;
    }
}

TEST_CASE("kaitai emitter: honours endian, indent and format name options") {
    const TypePtr root = make_root();
    EmitOptions options = make_options();
    options.indent = 4;
    options.endian = ByteOrder::big;
    options.format_name = "Big Format!";
    const auto generated = KaitaiEmitter().generate(*root, options);
    REQUIRE(generated.has_value());
    const std::string& text = generated.value();
    CHECK(contains(text, "id: big_format"));
    CHECK(contains(text, "endian: be"));
    CHECK(contains(text, "    - id: magic"));  // one indentation step == 4 spaces
}

TEST_CASE("imhex emitter: produces a complete pattern") {
    const TypePtr root = make_root();
    const EmitOptions options = make_options();
    const auto generated = ImHexEmitter().generate(*root, options);
    REQUIRE(generated.has_value());
    const std::string& text = generated.value();

    CHECK(contains(text, "#pragma endian little"));
    CHECK(contains(text, "#include <std/mem.pat>"));
    CHECK(contains(text, "struct Packet {"));
    CHECK(contains(text, "u32 magic;"));
    CHECK(contains(text, "padding[2];"));
    CHECK(contains(text, "Items[count_field];") == false);  // struct type is Item
    CHECK(contains(text, "Item items[count_field];"));
    CHECK(contains(text, "enum "));
    CHECK(contains(text, "root @ 0x00;"));
    CHECK(count_char(text, '{') == count_char(text, '}'));

    EmitOptions big = make_options();
    big.endian = ByteOrder::big;
    const auto big_generated = ImHexEmitter().generate(*root, big);
    REQUIRE(big_generated.has_value());
    CHECK(contains(big_generated.value(), "#pragma endian big"));
}

TEST_CASE("cpp emitter: produces a self-contained C++20 header") {
    const TypePtr root = make_root();
    const EmitOptions options = make_options();
    const auto generated = CppEmitter().generate(*root, options);
    REQUIRE(generated.has_value());
    const std::string& text = generated.value();

    CHECK(contains(text, "#pragma once"));
    CHECK(contains(text, "namespace myformat {"));
    CHECK(contains(text, "inline constexpr std::uint64_t kExpectedFileSize = 1234;"));
    CHECK(contains(text, "class Reader {"));
    CHECK(contains(text, "struct Packet {"));
    CHECK(contains(text, "std::uint32_t magic;"));
    CHECK(contains(text, "enum class KindEnum"));
    CHECK(contains(text, "std::vector<Item> items;"));
    CHECK(contains(text, "items.resize(item_count)"));
    CHECK(contains(text, "static Packet read(detail::Reader& reader)"));
    CHECK(contains(text, "parse(std::span<const std::uint8_t> bytes)"));
    CHECK(count_char(text, '{') == count_char(text, '}'));
    CHECK(count_char(text, '(') == count_char(text, ')'));
}

TEST_CASE("emitters: write() persists generated text and reports io errors") {
    const TypePtr root = make_root();
    const EmitOptions options = make_options();
    const std::filesystem::path directory = std::filesystem::current_path();
    const std::filesystem::path kaitai_path = directory / "typemorph_test_unique.ksy";
    const std::filesystem::path imhex_path = directory / "typemorph_test_unique.hexpat";
    const std::filesystem::path cpp_path = directory / "typemorph_test_unique.hpp";

    REQUIRE(KaitaiEmitter().write(kaitai_path, *root, options).has_value());
    REQUIRE(ImHexEmitter().write(imhex_path, *root, options).has_value());
    REQUIRE(CppEmitter().write(cpp_path, *root, options).has_value());

    const auto expected_kaitai = KaitaiEmitter().generate(*root, options);
    REQUIRE(expected_kaitai.has_value());
    std::string written;
    {
        std::ifstream stream(kaitai_path, std::ios::binary);
        REQUIRE(stream.good());
        written.assign((std::istreambuf_iterator<char>(stream)), std::istreambuf_iterator<char>());
    }
    CHECK(written == expected_kaitai.value());

    std::error_code ignored;
    std::filesystem::remove(kaitai_path, ignored);
    std::filesystem::remove(imhex_path, ignored);
    std::filesystem::remove(cpp_path, ignored);

    const std::filesystem::path missing_directory =
        directory / "typemorph_definitely_missing_directory" / "out.ksy";
    const auto failed = KaitaiEmitter().write(missing_directory, *root, options);
    REQUIRE(!failed.has_value());
    CHECK_EQ(static_cast<int>(failed.error().code),
             static_cast<int>(typemorph::core::ErrorCode::io));
}

TEST_CASE("emitters: non-struct root and empty struct are handled") {
    const TypePtr primitive_root = primitive(PrimitiveKind::u32, "value", 0);
    EmitOptions options = make_options();
    options.root_type_name = "Single";

    const auto kaitai = KaitaiEmitter().generate(*primitive_root, options);
    REQUIRE(kaitai.has_value());
    CHECK(contains(kaitai.value(), "seq:"));
    CHECK(contains(kaitai.value(), "- id: data"));

    const auto imhex = ImHexEmitter().generate(*primitive_root, options);
    REQUIRE(imhex.has_value());
    CHECK(contains(imhex.value(), "struct Single {"));
    CHECK(contains(imhex.value(), "Single root @ 0x00;"));

    const auto cpp = CppEmitter().generate(*primitive_root, options);
    REQUIRE(cpp.has_value());
    CHECK(contains(cpp.value(), "struct Single {"));
    CHECK(contains(cpp.value(), "static Single read(detail::Reader& reader)"));

    const TypePtr empty_struct = TypeNode::structure({}, "empty", 0, 0, 0.1);
    const auto empty_kaitai = KaitaiEmitter().generate(*empty_struct, options);
    REQUIRE(empty_kaitai.has_value());
    CHECK(contains(empty_kaitai.value(), "seq:"));
    CHECK(valid_yaml_structure(empty_kaitai.value()));
}

TEST_CASE("kaitai emitter: fixture inference links repeat-expr to count field") {
#ifdef TYPEMORPH_TEST_FIXTURES
    const std::filesystem::path fixtures{TYPEMORPH_TEST_FIXTURES};
    const std::filesystem::path paths[3] = {fixtures / "sample_v1.bin", fixtures / "sample_v2.bin",
                                            fixtures / "sample_v3.bin"};
    for (const auto& path : paths) {
        if (!std::filesystem::exists(path)) return;
    }
    std::vector<typemorph::infer::Sample> samples;
    for (const auto& path : paths) {
        const auto view = typemorph::core::BinaryView::open(path);
        REQUIRE(view.has_value());
        typemorph::infer::Sample sample;
        sample.view = view.value();
        sample.name = path.filename().string();
        samples.push_back(std::move(sample));
    }
    const typemorph::infer::DiffEngine engine;
    const auto inferred = engine.infer(std::span<const typemorph::infer::Sample>(samples));
    REQUIRE(inferred.has_value());
    REQUIRE(inferred.value().root != nullptr);

    EmitOptions options;
    options.format_name = "tmsx";
    options.root_type_name = "TmsxFile";
    options.file_size = inferred.value().max_size;
    options.endian = inferred.value().endian;

    const auto kaitai = KaitaiEmitter().generate(*inferred.value().root, options);
    REQUIRE(kaitai.has_value());
    const std::string& text = kaitai.value();
    CHECK(valid_yaml_structure(text));
    CHECK(contains(text, "id: tmsx"));
    CHECK(contains(text, "- id: items"));
    CHECK(contains(text, "repeat: expr"));
    CHECK(contains(text, "repeat-expr: count_10"));
    CHECK(contains(text, "types:"));
    CHECK(contains(text, "- id: field_0"));
    CHECK(contains(text, "- id: const_6"));

    const auto imhex = ImHexEmitter().generate(*inferred.value().root, options);
    REQUIRE(imhex.has_value());
    CHECK(contains(imhex.value(), "items[count_10]"));
    CHECK(contains(imhex.value(), "root @ 0x00;"));

    const auto cpp = CppEmitter().generate(*inferred.value().root, options);
    REQUIRE(cpp.has_value());
    CHECK(contains(cpp.value(), "items.resize(item_count)"));
    CHECK(count_char(cpp.value(), '{') == count_char(cpp.value(), '}'));
#else
    CHECK(true);
#endif
}
