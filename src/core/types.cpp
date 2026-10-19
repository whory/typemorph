#include "typemorph/core/types.hpp"

#include <algorithm>
#include <sstream>

namespace typemorph::core {

std::string TypeNode::kind_name() const {
    switch (node.index()) {
    case 0: return "primitive";
    case 1: return "array";
    case 2: return "struct";
    case 3: return "enum";
    case 4: return "slice";
    case 5: return "pointer";
    case 6: return "string";
    case 7: return "unknown";
    case 8: return "padding";
    default: return "invalid";
    }
}

std::string TypeNode::describe() const {
    std::ostringstream out;
    if (!name.empty()) {
        out << name;
        if (size != 0) out << " (" << size << " bytes)";
        out << ": ";
    }
    if (const auto* p = get_if<PrimitiveNode>()) {
        out << to_string(p->kind);
    } else if (const auto* a = get_if<ArrayNode>()) {
        out << "array<";
        if (a->element) {
            out << (a->element->name.empty() ? a->element->kind_name() : a->element->name);
        } else {
            out << "u8";
        }
        out << ">";
        if (a->count) {
            out << '[' << *a->count << ']';
        } else {
            out << "[dynamic]";
        }
    } else if (const auto* s = get_if<StructNode>()) {
        out << "struct{";
        out << s->fields.size() << " fields";
        out << '}';
    } else if (const auto* e = get_if<EnumNode>()) {
        out << "enum(" << to_string(e->underlying) << "){";
        out << e->variants.size() << " variants";
        out << '}';
    } else if (const auto* sl = get_if<SliceNode>()) {
        out << "slice<" << to_string(sl->element_primitive) << ">";
    } else if (const auto* pointer = get_if<PointerNode>()) {
        out << "pointer<" << pointer->width * 8 << ">";
        if (pointer->nullable) out << "?";
    } else if (const auto* str = get_if<StringNode>()) {
        out << "string(";
        switch (str->form) {
        case StringForm::null_terminated: out << "null_term"; break;
        case StringForm::length_prefixed: out << "pascal:" << str->length_expression; break;
        case StringForm::fixed_size: out << "fixed:" << size; break;
        case StringForm::magic_sequence: out << "magic:\"" << str->literal_value << "\""; break;
        }
        out << ")";
    } else if (const auto* u = get_if<UnknownNode>()) {
        out << "opaque[" << u->fill << ']';
    } else if (const auto* pad = get_if<PaddingNode>()) {
        out << "padding[" << pad->fill << ']';
    }
    return out.str();
}

TypePtr TypeNode::primitive(PrimitiveKind kind, ByteOrder endian, std::string name,
                            std::uint64_t offset, std::uint64_t size, double confidence) {
    auto node = std::make_shared<TypeNode>();
    node->node = PrimitiveNode{kind, endian};
    node->name = std::move(name);
    node->offset = offset;
    node->size = size != 0 ? size : primitive_size(kind);
    node->confidence = confidence;
    return node;
}

TypePtr TypeNode::structure(std::vector<TypeField> fields, std::string name, std::uint64_t offset,
                            std::uint64_t size, double confidence) {
    auto node = std::make_shared<TypeNode>();
    StructNode struct_node;
    struct_node.fields = std::move(fields);
    for (const auto& field : struct_node.fields) {
        if (field.type) {
            struct_node.declared_size =
                std::max(struct_node.declared_size, field.offset + field.type->size);
        }
    }
    if (size != 0) struct_node.declared_size = std::max(struct_node.declared_size, size);
    struct_node.alignment = 1;
    node->node = std::move(struct_node);
    node->name = std::move(name);
    node->offset = offset;
    node->size = size != 0 ? size : std::get<StructNode>(node->node).declared_size;
    node->confidence = confidence;
    return node;
}

TypePtr TypeNode::array(TypePtr element, std::optional<std::uint64_t> count, std::string name,
                        std::uint64_t offset, std::uint64_t element_stride, double confidence) {
    auto node = std::make_shared<TypeNode>();
    ArrayNode array_node;
    array_node.element = std::move(element);
    array_node.count = count;
    array_node.element_stride =
        element_stride != 0 ? element_stride : (array_node.element ? array_node.element->size : 1);
    node->node = std::move(array_node);
    node->name = std::move(name);
    node->offset = offset;
    const auto& stored = std::get<ArrayNode>(node->node);
    node->size = count ? (*count * stored.element_stride) : 0;
    node->confidence = confidence;
    return node;
}

TypePtr TypeNode::enumeration(EnumNode enumeration_node, std::string name, std::uint64_t offset,
                              double confidence) {
    auto node = std::make_shared<TypeNode>();
    node->node = std::move(enumeration_node);
    node->name = std::move(name);
    node->offset = offset;
    node->size = primitive_size(std::get<EnumNode>(node->node).underlying);
    node->confidence = confidence;
    return node;
}

TypePtr TypeNode::pointer(std::uint64_t target_offset, std::uint8_t width, bool nullable,
                          std::string name, std::uint64_t offset, double confidence) {
    auto node = std::make_shared<TypeNode>();
    PointerNode pointer_node;
    pointer_node.target_offset = target_offset;
    pointer_node.width = width;
    pointer_node.nullable = nullable;
    node->node = std::move(pointer_node);
    node->name = std::move(name);
    node->offset = offset;
    node->size = width;
    node->confidence = confidence;
    return node;
}

TypePtr TypeNode::string(StringForm form, StringEncoding encoding, std::string name,
                         std::uint64_t offset, std::uint64_t size, std::string literal,
                         std::string length_expr, double confidence) {
    auto node = std::make_shared<TypeNode>();
    StringNode str_node;
    str_node.form = form;
    str_node.encoding = encoding;
    str_node.literal_value = std::move(literal);
    str_node.length_expression = std::move(length_expr);
    node->node = std::move(str_node);
    node->name = std::move(name);
    node->offset = offset;
    node->size = size;
    node->confidence = confidence;
    return node;
}

TypePtr TypeNode::unknown(std::uint64_t size, std::string name, std::uint64_t offset) {
    auto node = std::make_shared<TypeNode>();
    node->node = UnknownNode{size};
    node->name = std::move(name);
    node->offset = offset;
    node->size = size;
    node->confidence = 0.0;
    return node;
}

TypePtr TypeNode::padding(std::uint64_t size, std::uint8_t fill, std::string name,
                          std::uint64_t offset) {
    auto node = std::make_shared<TypeNode>();
    node->node = PaddingNode{fill};
    node->name = std::move(name);
    node->offset = offset;
    node->size = size;
    node->confidence = 1.0;
    return node;
}

void recompute_struct_size(TypeNode& node) {
    auto* structure = node.get_if<StructNode>();
    if (structure == nullptr) return;
    std::uint64_t computed = 0;
    for (auto& field : structure->fields) {
        if (field.type) {
            computed = std::max(computed, field.offset + field.type->size);
        }
    }
    structure->declared_size = std::max(structure->declared_size, computed);
    node.size = std::max(node.size, structure->declared_size);
}

}  // namespace typemorph::core
