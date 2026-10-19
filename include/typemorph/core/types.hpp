// TypeMorph - recovered type AST.
//
// The AST is deliberately simple and lossless enough to round-trip through the
// Kaitai, ImHex and C++ emitters.  Nodes own their children through shared_ptr
// because a recovered array and its length field may be referenced by more than
// one emitter/diagnostic.  Acyclic use is expected; pointers are represented as
// PointerNode without recursively materialising a pointee graph.
#pragma once

#include "typemorph/core/binary_view.hpp"

#include <cstdint>
#include <memory>
#include <optional>
#include <string>
#include <string_view>
#include <utility>
#include <variant>
#include <vector>

namespace typemorph::core {

enum class PrimitiveKind : std::uint8_t {
    u8,
    u16,
    u32,
    u64,
    i8,
    i16,
    i32,
    i64,
    f32,
    f64,
    boolean,
    character,
};

[[nodiscard]] constexpr std::uint8_t primitive_size(PrimitiveKind kind) noexcept {
    switch (kind) {
    case PrimitiveKind::u8:
    case PrimitiveKind::i8:
    case PrimitiveKind::boolean:
    case PrimitiveKind::character: return 1;
    case PrimitiveKind::u16:
    case PrimitiveKind::i16: return 2;
    case PrimitiveKind::u32:
    case PrimitiveKind::i32:
    case PrimitiveKind::f32: return 4;
    case PrimitiveKind::u64:
    case PrimitiveKind::i64:
    case PrimitiveKind::f64: return 8;
    }
    return 1;
}

[[nodiscard]] constexpr std::string_view to_string(PrimitiveKind kind) noexcept {
    switch (kind) {
    case PrimitiveKind::u8: return "u8";
    case PrimitiveKind::u16: return "u16";
    case PrimitiveKind::u32: return "u32";
    case PrimitiveKind::u64: return "u64";
    case PrimitiveKind::i8: return "i8";
    case PrimitiveKind::i16: return "i16";
    case PrimitiveKind::i32: return "i32";
    case PrimitiveKind::i64: return "i64";
    case PrimitiveKind::f32: return "f32";
    case PrimitiveKind::f64: return "f64";
    case PrimitiveKind::boolean: return "bool";
    case PrimitiveKind::character: return "char";
    }
    return "u8";
}

[[nodiscard]] constexpr bool is_integer(PrimitiveKind kind) noexcept {
    switch (kind) {
    case PrimitiveKind::u8:
    case PrimitiveKind::u16:
    case PrimitiveKind::u32:
    case PrimitiveKind::u64:
    case PrimitiveKind::i8:
    case PrimitiveKind::i16:
    case PrimitiveKind::i32:
    case PrimitiveKind::i64: return true;
    default: return false;
    }
}

[[nodiscard]] constexpr bool is_signed(PrimitiveKind kind) noexcept {
    switch (kind) {
    case PrimitiveKind::i8:
    case PrimitiveKind::i16:
    case PrimitiveKind::i32:
    case PrimitiveKind::i64: return true;
    default: return false;
    }
}

class TypeNode;
using TypePtr = std::shared_ptr<TypeNode>;
using ConstTypePtr = std::shared_ptr<const TypeNode>;

struct PrimitiveNode {
    PrimitiveKind kind = PrimitiveKind::u8;
    ByteOrder endian = ByteOrder::little;
};

struct TypeField {
    std::string name;
    TypePtr type;
    // Offset relative to the beginning of the owning struct.
    std::uint64_t offset = 0;
    std::string comment;
    double confidence = 1.0;
};

struct ArrayNode {
    TypePtr element;
    std::optional<std::uint64_t> count;
    // Absolute offset of the field holding the element count, when known.
    std::optional<std::uint64_t> count_field_offset;
    // Useful when the count expression references a recovered field by name.
    std::string count_expression;
    std::uint64_t element_stride = 0;
};

struct StructNode {
    std::vector<TypeField> fields;
    std::uint64_t declared_size = 0;
    std::uint64_t alignment = 1;
    bool packed = false;
};

struct EnumVariant {
    std::string name;
    std::int64_t value = 0;
};

struct EnumNode {
    PrimitiveKind underlying = PrimitiveKind::u8;
    std::vector<EnumVariant> variants;
    bool tagged_union = false;
};

// Rust slice / fat pointer view.  `element_type` may be null for raw bytes.
struct SliceNode {
    TypePtr element_type;
    PrimitiveKind element_primitive = PrimitiveKind::u8;
    std::string length_source = "fat-pointer";
};

struct PointerNode {
    std::uint64_t target_offset = 0;
    std::uint8_t width = 8;
    bool nullable = true;
    std::string target_hint;
};

enum class StringForm : std::uint8_t {
    null_terminated,   // C-string: terminates with 0x00
    length_prefixed,   // Pascal string: length integer + bytes
    fixed_size,        // Fixed size character array
    magic_sequence,    // Constant signature / FourCC
};

enum class StringEncoding : std::uint8_t {
    ascii,
    utf8,
    utf16le,
    utf16be,
};

[[nodiscard]] constexpr std::string_view to_string(StringEncoding encoding) noexcept {
    switch (encoding) {
    case StringEncoding::ascii: return "ASCII";
    case StringEncoding::utf8: return "UTF-8";
    case StringEncoding::utf16le: return "UTF-16LE";
    case StringEncoding::utf16be: return "UTF-16BE";
    }
    return "UTF-8";
}

struct StringNode {
    StringForm form = StringForm::null_terminated;
    StringEncoding encoding = StringEncoding::utf8;
    std::string length_expression;
    PrimitiveKind length_primitive = PrimitiveKind::u16;
    std::string literal_value;
};

struct UnknownNode {
    std::uint64_t fill = 0;
};

struct PaddingNode {
    std::uint8_t fill = 0;
};

struct BitfieldMember {
    std::string name;
    std::uint8_t bit_offset = 0;  // 0-indexed from LSB
    std::uint8_t bit_width = 1;   // Number of bits
    std::string comment;
};

struct BitfieldNode {
    PrimitiveKind underlying = PrimitiveKind::u32;
    std::vector<BitfieldMember> members;
    ByteOrder endian = ByteOrder::little;
};

class TypeNode {
public:
    using Variant = std::variant<PrimitiveNode, ArrayNode, StructNode, EnumNode, SliceNode, PointerNode,
                                 StringNode, UnknownNode, PaddingNode, BitfieldNode>;

    Variant node = UnknownNode{};
    std::string name;
    // Offset relative to the parent node (root nodes use absolute file offset).
    std::uint64_t offset = 0;
    std::uint64_t size = 0;
    double confidence = 1.0;
    std::string comment;

    TypeNode() = default;
    explicit TypeNode(Variant value) : node(std::move(value)) {}

    [[nodiscard]] std::uint64_t end() const noexcept { return offset + size; }

    template <class T>
    [[nodiscard]] bool is() const noexcept {
        return std::holds_alternative<T>(node);
    }

    template <class T>
    [[nodiscard]] T* get_if() noexcept {
        return std::get_if<T>(&node);
    }

    template <class T>
    [[nodiscard]] const T* get_if() const noexcept {
        return std::get_if<T>(&node);
    }

    [[nodiscard]] std::string kind_name() const;
    [[nodiscard]] std::string describe() const;

    [[nodiscard]] static TypePtr primitive(PrimitiveKind kind, ByteOrder endian, std::string name = {},
                                           std::uint64_t offset = 0, std::uint64_t size = 0,
                                           double confidence = 1.0);
    [[nodiscard]] static TypePtr structure(std::vector<TypeField> fields, std::string name = {},
                                           std::uint64_t offset = 0, std::uint64_t size = 0,
                                           double confidence = 1.0);
    [[nodiscard]] static TypePtr array(TypePtr element, std::optional<std::uint64_t> count,
                                       std::string name = {}, std::uint64_t offset = 0,
                                       std::uint64_t element_stride = 0, double confidence = 1.0);
    [[nodiscard]] static TypePtr enumeration(EnumNode node, std::string name = {},
                                             std::uint64_t offset = 0, double confidence = 1.0);
    [[nodiscard]] static TypePtr pointer(std::uint64_t target_offset, std::uint8_t width = 8,
                                         bool nullable = true, std::string name = {},
                                         std::uint64_t offset = 0, double confidence = 1.0);
    [[nodiscard]] static TypePtr string(StringForm form, StringEncoding encoding,
                                        std::string name = {}, std::uint64_t offset = 0,
                                        std::uint64_t size = 0, std::string literal = {},
                                        std::string length_expr = {}, double confidence = 1.0);
    [[nodiscard]] static TypePtr bitfield(PrimitiveKind underlying, std::vector<BitfieldMember> members,
                                          ByteOrder endian = ByteOrder::little, std::string name = {},
                                          std::uint64_t offset = 0, double confidence = 1.0);
    [[nodiscard]] static TypePtr unknown(std::uint64_t size, std::string name = {},
                                         std::uint64_t offset = 0);
    [[nodiscard]] static TypePtr padding(std::uint64_t size, std::uint8_t fill = 0,
                                         std::string name = {}, std::uint64_t offset = 0);
};

// Recompute a struct's declared_size from its fields when it has no explicit
// size.  Existing sizes are preserved when larger (covers explicit padding).
void recompute_struct_size(TypeNode& node);

// Visits a node and all nested fields/array elements depth-first.
template <class F>
void visit_type(const TypeNode& node, F&& visitor) {
    visitor(node);
    if (const auto* s = node.get_if<StructNode>()) {
        for (const auto& field : s->fields) {
            if (field.type) visit_type(*field.type, visitor);
        }
    } else if (const auto* a = node.get_if<ArrayNode>()) {
        if (a->element) visit_type(*a->element, visitor);
    } else if (const auto* sl = node.get_if<SliceNode>()) {
        if (sl->element_type) visit_type(*sl->element_type, visitor);
    }
}

}  // namespace typemorph::core
