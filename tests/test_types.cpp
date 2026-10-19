#include "test_framework.hpp"

#include "typemorph/core/types.hpp"

#include <cstdint>
#include <memory>
#include <vector>

using namespace typemorph::core;

TEST_CASE("types: primitive factories and sizes") {
    auto u32 = TypeNode::primitive(PrimitiveKind::u32, ByteOrder::little, "count", 4);
    CHECK(u32 != nullptr);
    CHECK_EQ(u32->size, std::uint64_t{4});
    CHECK_EQ(u32->offset, std::uint64_t{4});
    CHECK_EQ(u32->kind_name(), std::string("primitive"));
    CHECK(u32->is<PrimitiveNode>());
    CHECK_EQ(to_string(u32->get_if<PrimitiveNode>()->kind), std::string("u32"));

    auto f64 = TypeNode::primitive(PrimitiveKind::f64, ByteOrder::big);
    CHECK_EQ(f64->size, std::uint64_t{8});
    CHECK(is_signed(PrimitiveKind::i16));
    CHECK(!is_signed(PrimitiveKind::u64));
    CHECK(is_integer(PrimitiveKind::u8));
    CHECK(!is_integer(PrimitiveKind::f32));
}

TEST_CASE("types: arrays compute size from count and stride") {
    auto element = TypeNode::primitive(PrimitiveKind::u16, ByteOrder::little, "item");
    auto array = TypeNode::array(element, 5, "items", 8);
    CHECK_EQ(array->size, std::uint64_t{10});
    CHECK(array->is<ArrayNode>());
    CHECK_EQ(array->get_if<ArrayNode>()->element_stride, std::uint64_t{2});
    CHECK_EQ(array->get_if<ArrayNode>()->count.value(), std::uint64_t{5});

    auto dynamic = TypeNode::array(element, std::nullopt, "rest", 8);
    CHECK_EQ(dynamic->size, std::uint64_t{0});
}

TEST_CASE("types: structs compute layout and visit nested nodes") {
    std::vector<TypeField> fields;
    fields.push_back(TypeField{"magic", TypeNode::primitive(PrimitiveKind::u32, ByteOrder::little),
                               0, "invariant", 1.0});
    auto item = TypeNode::structure(
        {TypeField{"id", TypeNode::primitive(PrimitiveKind::u16, ByteOrder::little), 0}},
        "Item", 0, 2);
    fields.push_back(TypeField{"items", TypeNode::array(item, 3, "items", 4), 4, "", 0.9});
    auto root = TypeNode::structure(fields, "Root", 0, 0);
    CHECK_EQ(root->size, std::uint64_t{10});
    CHECK_EQ(root->get_if<StructNode>()->declared_size, std::uint64_t{10});

    const auto* array = root->get_if<StructNode>()->fields[1].type.get();
    CHECK_EQ(array->size, std::uint64_t{6});

    std::size_t visited = 0;
    visit_type(*root, [&visited](const TypeNode&) { ++visited; });
    CHECK_EQ(visited, std::size_t{5});  // root, magic, items array, Item struct, id

    TypeNode mutable_root = *root;
    mutable_root.size = 0;
    mutable_root.get_if<StructNode>()->declared_size = 0;
    recompute_struct_size(mutable_root);
    CHECK_EQ(mutable_root.size, std::uint64_t{10});
}

TEST_CASE("types: enums, pointers, padding and unknown nodes") {
    EnumNode enum_node;
    enum_node.underlying = PrimitiveKind::u8;
    enum_node.variants = {{"red", 1}, {"green", 2}};
    auto enumeration = TypeNode::enumeration(enum_node, "Color", 16);
    CHECK_EQ(enumeration->size, std::uint64_t{1});
    CHECK_EQ(enumeration->kind_name(), std::string("enum"));

    auto pointer = TypeNode::pointer(0x100, 8, true, "next", 32);
    CHECK_EQ(pointer->size, std::uint64_t{8});
    CHECK_EQ(pointer->kind_name(), std::string("pointer"));

    auto padding = TypeNode::padding(3, 0xCC, "pad", 40);
    CHECK_EQ(padding->size, std::uint64_t{3});
    CHECK_EQ(padding->kind_name(), std::string("padding"));

    auto opaque = TypeNode::unknown(12, "blob", 48);
    CHECK_EQ(opaque->size, std::uint64_t{12});
    CHECK_EQ(opaque->kind_name(), std::string("unknown"));

    CHECK(enumeration->describe().find("enum") != std::string::npos);
}

TEST_CASE("types: string nodes and encodings") {
    auto cstr = TypeNode::string(StringForm::null_terminated, StringEncoding::ascii, "name", 0, 16);
    CHECK_EQ(cstr->kind_name(), std::string("string"));
    CHECK(cstr->is<StringNode>());
    CHECK(cstr->describe().find("null_term") != std::string::npos);

    auto pascal = TypeNode::string(StringForm::length_prefixed, StringEncoding::utf8, "desc", 16, 32, "", "len_desc");
    CHECK_EQ(pascal->get_if<StringNode>()->length_expression, std::string("len_desc"));
    CHECK(pascal->describe().find("pascal:len_desc") != std::string::npos);

    auto magic = TypeNode::string(StringForm::magic_sequence, StringEncoding::ascii, "magic", 0, 4, "TMSX");
    CHECK_EQ(magic->get_if<StringNode>()->literal_value, std::string("TMSX"));
    CHECK(magic->describe().find("magic:\"TMSX\"") != std::string::npos);
}
