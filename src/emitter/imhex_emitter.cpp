// TypeMorph - ImHex pattern language (.hexpat) emitter.
//
// The generated pattern defines a struct per recovered record (children before
// parents so references resolve), all primitive/enum/array members, explicit
// padding, and a root pattern placed at offset 0.  Length fields are referenced
// by name in dynamic array declarations.
#include <algorithm>
#include <cstddef>
#include <cstdint>
#include <fstream>
#include <map>
#include <set>
#include <string>
#include <string_view>
#include <vector>

#include "typemorph/core/result.hpp"
#include "typemorph/core/types.hpp"
#include "typemorph/emitter/emit_options.hpp"
#include "typemorph/emitter/imhex_emitter.hpp"

namespace typemorph::emit {
namespace {

using core::ErrorCode;
using core::TypeNode;

constexpr int kMaxDepth = 64;

[[nodiscard]] std::string lower_snake(std::string_view raw, std::string_view fallback) {
    std::string out;
    out.reserve(raw.size() + 1);
    for (const char character : raw) {
        const unsigned char value = static_cast<unsigned char>(character);
        if ((value >= 'a' && value <= 'z') || (value >= '0' && value <= '9')) {
            out.push_back(static_cast<char>(value));
        } else if (value >= 'A' && value <= 'Z') {
            out.push_back(static_cast<char>(value - 'A' + 'a'));
        } else {
            out.push_back('_');
        }
    }
    std::string collapsed;
    for (const char character : out) {
        if (character == '_' && (collapsed.empty() || collapsed.back() == '_')) continue;
        collapsed.push_back(character);
    }
    while (!collapsed.empty() && collapsed.back() == '_') collapsed.pop_back();
    if (collapsed.empty()) return std::string(fallback);
    if (collapsed.front() >= '0' && collapsed.front() <= '9') collapsed.insert(collapsed.begin(), 'x');
    return collapsed;
}

[[nodiscard]] bool is_keyword(std::string_view name) {
    static const std::vector<std::string_view> keywords = {
        "alignas", "alignof", "and", "asm", "auto", "bool", "break", "case", "catch", "char",
        "class", "const", "constexpr", "continue", "default", "delete", "do", "double", "else",
        "enum", "explicit", "export", "extern", "false", "float", "for", "friend", "goto", "if",
        "inline", "int", "long", "namespace", "new", "noexcept", "not", "nullptr", "operator",
        "or", "private", "protected", "public", "register", "return", "short", "signed", "sizeof",
        "static", "struct", "switch", "template", "this", "throw", "true", "try", "typedef",
        "typename", "union", "unsigned", "using", "virtual", "void", "volatile", "while", "xor",
        "padding", "u8", "u16", "u32", "u64", "s8", "s16", "s32", "s64", "root", "match",
    };
    return std::find(keywords.begin(), keywords.end(), name) != keywords.end();
}

[[nodiscard]] std::string make_member_name(std::string_view raw, std::string_view fallback,
                                           std::set<std::string>& used) {
    std::string candidate = lower_snake(raw, fallback);
    if (is_keyword(candidate)) candidate += "_field";
    std::string unique = candidate;
    int suffix = 2;
    while (!used.insert(unique).second) {
        unique = candidate + "_" + std::to_string(suffix++);
    }
    return unique;
}

[[nodiscard]] std::string upper_snake(std::string_view raw, std::string_view fallback) {
    std::string out = lower_snake(raw, fallback);
    for (char& character : out) {
        if (character >= 'a' && character <= 'z') character = static_cast<char>(character - 'a' + 'A');
    }
    return out;
}

[[nodiscard]] std::string upper_camel(std::string_view raw, std::string_view fallback) {
    std::string out;
    bool capitalise = true;
    for (const char character : raw) {
        const unsigned char value = static_cast<unsigned char>(character);
        const bool alnum = (value >= 'a' && value <= 'z') || (value >= 'A' && value <= 'Z') ||
                           (value >= '0' && value <= '9');
        if (!alnum) {
            capitalise = true;
            continue;
        }
        char out_char = character;
        if (capitalise && value >= 'a' && value <= 'z') {
            out_char = static_cast<char>(value - 'a' + 'A');
        }
        out.push_back(out_char);
        capitalise = false;
    }
    if (out.empty()) return std::string(fallback);
    if (out.front() >= '0' && out.front() <= '9') out.insert(out.begin(), 'T');
    return out;
}

[[nodiscard]] std::string primitive_type(core::PrimitiveKind kind) {
    using core::PrimitiveKind;
    switch (kind) {
    case PrimitiveKind::u8: return "u8";
    case PrimitiveKind::u16: return "u16";
    case PrimitiveKind::u32: return "u32";
    case PrimitiveKind::u64: return "u64";
    case PrimitiveKind::i8: return "s8";
    case PrimitiveKind::i16: return "s16";
    case PrimitiveKind::i32: return "s32";
    case PrimitiveKind::i64: return "s64";
    case PrimitiveKind::f32: return "float";
    case PrimitiveKind::f64: return "double";
    case PrimitiveKind::boolean: return "bool";
    case PrimitiveKind::character: return "char";
    }
    return "u8";
}

class ImHexGenerator {
public:
    ImHexGenerator(const TypeNode& root, const EmitOptions& options)
        : root_(&root), options_(options) {
        root_type_name_ = make_type_name(
            options_.root_type_name.empty() ? "RecoveredFile" : options_.root_type_name, "Root");
        collect(&root, 0);
    }

    [[nodiscard]] core::Result<std::string> generate() {
        out_.clear();
        write_preamble();
        for (const TypeNode* type : definition_order_) {
            write_struct(type);
        }
        write_root_struct();
        write_placement();
        return out_;
    }

private:
    void raw(std::string_view text) { out_ += text; }
    void line(std::string_view text) {
        out_ += text;
        out_.push_back('\n');
    }
    [[nodiscard]] std::string indent(unsigned level) const {
        const unsigned step = options_.indent == 0 ? 4U : std::min(options_.indent, 8U);
        return std::string(static_cast<std::size_t>(level) * step, ' ');
    }

    [[nodiscard]] std::string make_type_name(std::string_view raw_name, std::string_view fallback) {
        std::string candidate = upper_camel(raw_name, fallback);
        if (is_keyword(candidate)) candidate += "Type";
        std::string unique = candidate;
        int suffix = 2;
        while (!used_type_names_.insert(unique).second) {
            unique = candidate + std::to_string(suffix++);
        }
        return unique;
    }

    void collect(const TypeNode* node, int depth) {
        if (node == nullptr || depth > kMaxDepth) return;
        if (node != root_ && node->is<core::StructNode>() &&
            type_names_.find(node) == type_names_.end()) {
            type_names_.emplace(node, make_type_name(node->name, "Record"));
        }
        if (node->is<core::EnumNode>() && enum_names_.find(node) == enum_names_.end()) {
            enum_names_.emplace(node, make_type_name(
                                         node->name.empty() ? std::string("Enum") : node->name,
                                         "Enum"));
        }
        if (node->is<core::BitfieldNode>() && bitfield_names_.find(node) == bitfield_names_.end()) {
            bitfield_names_.emplace(node, make_type_name(
                                              node->name.empty() ? std::string("Flags") : node->name,
                                              "Flags"));
            if (std::find(definition_order_.begin(), definition_order_.end(), node) ==
                definition_order_.end()) {
                definition_order_.push_back(node);
            }
        }
        if (const auto* structure = node->get_if<core::StructNode>()) {
            for (const auto& field : structure->fields) {
                if (!field.type) continue;
                collect(field.type.get(), depth + 1);
                if (field.type->is<core::StructNode>()) {
                    // children are emitted before their parent
                    if (std::find(definition_order_.begin(), definition_order_.end(),
                                  field.type.get()) == definition_order_.end()) {
                        definition_order_.push_back(field.type.get());
                    }
                }
            }
            if (node != root_) {
                if (std::find(definition_order_.begin(), definition_order_.end(), node) ==
                    definition_order_.end()) {
                    definition_order_.push_back(node);
                }
            }
        } else if (const auto* array = node->get_if<core::ArrayNode>()) {
            if (array->element) collect(array->element.get(), depth + 1);
        } else if (const auto* slice = node->get_if<core::SliceNode>()) {
            if (slice->element_type) collect(slice->element_type.get(), depth + 1);
        }
    }

    void write_preamble() {
        line("// Generated by TypeMorph from recovered binary structure.");
        if (!options_.source_name.empty()) line("// source: " + options_.source_name);
        if (options_.file_size != 0) {
            line("// expected file size: " + std::to_string(options_.file_size) + " bytes");
        }
        line("// endianness: " + std::string(options_.endian == core::ByteOrder::little ? "little"
                                                                                       : "big"));
        line(std::string("#pragma endian ") +
             std::string(options_.endian == core::ByteOrder::little ? "little" : "big"));
        line("#include <std/mem.pat>");
        line("");
    }

    [[nodiscard]] std::string count_expression(const core::ArrayNode& array,
                                               const std::map<std::string, std::string>& names) const {
        if (!array.count_expression.empty()) {
            const auto referenced = names.find(array.count_expression);
            if (referenced != names.end()) return referenced->second;
            const std::string candidate = lower_snake(array.count_expression, "");
            if (!candidate.empty()) return candidate;
        }
        if (array.count.has_value()) return std::to_string(array.count.value());
        return {};
    }

    [[nodiscard]] std::string element_type_name(const core::TypeNode* element) const {
        if (element == nullptr) return "u8";
        if (const auto* primitive = element->get_if<core::PrimitiveNode>()) {
            return primitive_type(primitive->kind);
        }
        if (element->is<core::EnumNode>()) {
            const auto found = enum_names_.find(element);
            if (found != enum_names_.end()) return found->second;
            return "u8";
        }
        if (element->is<core::StructNode>()) {
            const auto found = type_names_.find(element);
            if (found != type_names_.end()) return found->second;
            return "u8";
        }
        if (const auto* pointer = element->get_if<core::PointerNode>()) {
            return pointer->width == 4 ? "u32" : "u64";
        }
        return "u8";
    }

    // Pre-assigns deterministic, unique member names so that array length
    // expressions can reference the exact emitted identifier of the count field.
    [[nodiscard]] std::map<std::string, std::string> assign_member_names(
        const std::vector<core::TypeField>& fields) {
        std::map<std::string, std::string> names;
        std::set<std::string> used;
        for (const auto& field : fields) {
            if (!field.type || field.type->size == 0) continue;
            const std::string name = make_member_name(field.name, "field", used);
            names.emplace(field.name, name);
        }
        return names;
    }

    void write_member(const core::TypeField& field, const std::string& name,
                      const std::map<std::string, std::string>& names) {
        if (!field.type || field.type->size == 0) return;
        const TypeNode& type = *field.type;
        const std::string pad = indent(1);

        if (const auto* primitive = type.get_if<core::PrimitiveNode>()) {
            line(pad + primitive_type(primitive->kind) + " " + name + ";");
            return;
        }
        if (type.is<core::EnumNode>()) {
            const auto found = enum_names_.find(&type);
            line(pad + (found != enum_names_.end() ? found->second : std::string("u8")) + " " +
                 name + ";");
            return;
        }
        if (type.is<core::BitfieldNode>()) {
            const auto found = bitfield_names_.find(&type);
            line(pad + (found != bitfield_names_.end() ? found->second : std::string("u32")) + " " +
                 name + ";");
            return;
        }
        if (type.is<core::StructNode>()) {
            const auto found = type_names_.find(&type);
            line(pad + (found != type_names_.end() ? found->second : std::string("u8")) + " " +
                 name + ";");
            return;
        }
        if (const auto* pointer = type.get_if<core::PointerNode>()) {
            line(pad + std::string(pointer->width == 4 ? "u32" : "u64") + " " + name + ";");
            return;
        }
        if (const auto* array = type.get_if<core::ArrayNode>()) {
            const std::string element_type = element_type_name(array->element.get());
            const std::uint64_t stride =
                array->element_stride == 0
                    ? (array->element ? std::max<std::uint64_t>(array->element->size, 1) : 1)
                    : array->element_stride;
            const std::string count = count_expression(*array, names);
            std::string size_expression;
            if (!count.empty()) {
                if (element_type == "u8" && stride > 1) {
                    size_expression = count + " * " + std::to_string(stride);
                } else {
                    size_expression = count;
                }
            } else {
                size_expression = "while(!std::mem::eof())";
            }
            line(pad + element_type + " " + name + "[" + size_expression + "];");
            return;
        }
        if (type.is<core::PaddingNode>()) {
            line(pad + "padding[" + std::to_string(type.size) + "];");
            return;
        }
        if (const auto* slice = type.get_if<core::SliceNode>()) {
            (void)slice;
            const std::uint64_t size = type.size == 0 ? 1 : type.size;
            line(pad + "u8 " + name + "[" + std::to_string(size) + "];");
            return;
        }
        if (const auto* str = type.get_if<core::StringNode>()) {
            if (str->form == core::StringForm::null_terminated) {
                line(pad + "char " + name + "[];");
            } else {
                const std::uint64_t size = type.size == 0 ? 1 : type.size;
                line(pad + "char " + name + "[" + std::to_string(size) + "];");
            }
            return;
        }
        // Unknown / opaque payload.
        line(pad + "u8 " + name + "[" + std::to_string(type.size) + "];");
    }

    void write_enum_definition(const TypeNode* node) {
        const auto found = enum_names_.find(node);
        if (found == enum_names_.end()) return;
        if (!emitted_enums_.insert(node).second) return;
        const auto* enumeration = node->get_if<core::EnumNode>();
        if (enumeration == nullptr) return;
        line("enum " + found->second + " : " + primitive_type(enumeration->underlying) + " {");
        std::set<std::string> used;
        for (std::size_t i = 0; i < enumeration->variants.size(); ++i) {
            const auto& variant = enumeration->variants[i];
            std::string name = upper_snake(variant.name, "VALUE_" + std::to_string(i));
            if (is_keyword(name)) name += "_";
            std::string unique = name;
            int suffix = 2;
            while (!used.insert(unique).second) {
                unique = name + "_" + std::to_string(suffix++);
            }
            line(indent(1) + unique + " = " + std::to_string(variant.value) +
                 (i + 1 < enumeration->variants.size() ? "," : ""));
        }
        line("};");
        line("");
    }

    void write_struct(const TypeNode* node) {
        if (const auto* bitfield = node->get_if<core::BitfieldNode>()) {
            const auto found_bf = bitfield_names_.find(node);
            if (found_bf == bitfield_names_.end()) return;
            line("bitfield " + found_bf->second + " {");
            std::set<std::string> used;
            for (std::size_t i = 0; i < bitfield->members.size(); ++i) {
                const auto& member = bitfield->members[i];
                std::string member_name = lower_snake(member.name, "flag_" + std::to_string(i));
                if (is_keyword(member_name)) member_name += "_";
                std::string unique = member_name;
                int suffix = 2;
                while (!used.insert(unique).second) {
                    unique = member_name + "_" + std::to_string(suffix++);
                }
                line(indent(1) + unique + " : " + std::to_string(member.bit_width) + ";");
            }
            line("};");
            line("");
            return;
        }
        const auto found = type_names_.find(node);
        if (found == type_names_.end()) return;
        const auto* structure = node->get_if<core::StructNode>();
        if (structure == nullptr) return;
        for (const auto& field : structure->fields) {
            if (field.type && field.type->is<core::EnumNode>()) {
                write_enum_definition(field.type.get());
            }
        }
        line("struct " + found->second + " {");
        const auto names = assign_member_names(structure->fields);
        for (const auto& field : structure->fields) {
            const auto name = names.find(field.name);
            if (name == names.end()) continue;
            write_member(field, name->second, names);
        }
        line("};");
        line("");
    }

    void write_root_struct() {
        std::vector<core::TypeField> fields;
        if (const auto* structure = root_->get_if<core::StructNode>()) {
            fields = structure->fields;
        } else {
            core::TypeField field;
            field.name = "data";
            field.offset = 0;
            field.type = std::make_shared<TypeNode>(*root_);
            fields.push_back(std::move(field));
        }
        for (const auto& field : fields) {
            if (field.type && field.type->is<core::EnumNode>()) {
                write_enum_definition(field.type.get());
            }
        }
        line("struct " + root_type_name_ + " {");
        const auto names = assign_member_names(fields);
        for (const auto& field : fields) {
            const auto name = names.find(field.name);
            if (name == names.end()) continue;
            write_member(field, name->second, names);
        }
        line("};");
        line("");
    }

    void write_placement() {
        line(root_type_name_ + " root @ 0x00;");
    }

    const TypeNode* root_ = nullptr;
    const EmitOptions& options_;
    std::string out_;
    std::string root_type_name_;
    std::map<const TypeNode*, std::string> type_names_;
    std::map<const TypeNode*, std::string> enum_names_;
    std::map<const TypeNode*, std::string> bitfield_names_;
    std::vector<const TypeNode*> definition_order_;
    std::set<std::string> used_type_names_;
    std::set<const TypeNode*> emitted_enums_;
};

}  // namespace

core::Result<std::string> ImHexEmitter::generate(const core::TypeNode& root,
                                                 const EmitOptions& options) const {
    ImHexGenerator generator(root, options);
    return generator.generate();
}

core::Result<void> ImHexEmitter::write(const std::filesystem::path& path, const core::TypeNode& root,
                                       const EmitOptions& options) const {
    auto generated = generate(root, options);
    if (!generated) return generated.error();
    std::ofstream stream(path, std::ios::binary | std::ios::trunc);
    if (!stream) {
        return core::make_error(ErrorCode::io, "failed to open output file for writing",
                                path.string());
    }
    stream << generated.value();
    if (!stream) {
        return core::make_error(ErrorCode::io, "failed to write ImHex pattern", path.string());
    }
    return {};
}

}  // namespace typemorph::emit
