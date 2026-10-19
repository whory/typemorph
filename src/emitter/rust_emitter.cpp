// TypeMorph - Idiomatic Rust struct & type emitter.
#include "typemorph/emitter/rust_emitter.hpp"

#include "typemorph/core/result.hpp"
#include "typemorph/core/types.hpp"
#include "typemorph/emitter/emit_options.hpp"

#include <algorithm>
#include <cstddef>
#include <cstdint>
#include <fstream>
#include <map>
#include <set>
#include <sstream>
#include <string>
#include <string_view>
#include <utility>
#include <vector>

namespace typemorph::emit {
namespace {

using core::ErrorCode;
using core::TypeNode;

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

[[nodiscard]] bool is_rust_keyword(std::string_view name) {
    static const std::vector<std::string_view> keywords = {
        "as", "break", "const", "continue", "crate", "else", "enum", "extern", "false", "fn",
        "for", "if", "impl", "in", "let", "loop", "match", "mod", "move", "mut", "pub",
        "ref", "return", "self", "Self", "static", "struct", "super", "trait", "true", "type",
        "unsafe", "use", "where", "while", "async", "await", "dyn", "abstract", "become",
        "box", "do", "final", "macro", "override", "priv", "typeof", "unsized", "virtual", "yield", "try"
    };
    return std::find(keywords.begin(), keywords.end(), name) != keywords.end();
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

[[nodiscard]] std::string upper_snake(std::string_view raw, std::string_view fallback) {
    std::string out = lower_snake(raw, fallback);
    for (char& character : out) {
        if (character >= 'a' && character <= 'z') character = static_cast<char>(character - 'a' + 'A');
    }
    return out;
}

[[nodiscard]] std::string rust_primitive(core::PrimitiveKind kind) {
    using core::PrimitiveKind;
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
    case PrimitiveKind::character: return "u8";
    }
    return "u8";
}

class RustGenerator {
public:
    RustGenerator(const TypeNode& root, const EmitOptions& options)
        : root_(&root), options_(options) {
        root_name_ = upper_camel(options_.root_type_name.empty() ? "RecoveredFile" : options_.root_type_name, "RecoveredFile");
        collect_types(*root_, root_name_);
    }

    [[nodiscard]] std::string run() {
        write_header();
        write_enums();
        write_structs();
        return stream_.str();
    }

private:
    void line(const std::string& text = "") {
        stream_ << text << '\n';
    }

    [[nodiscard]] std::string indent(unsigned level = 1) const {
        return std::string(level * options_.indent, ' ');
    }

    void collect_types(const TypeNode& node, const std::string& hint) {
        if (const auto* structure = node.get_if<core::StructNode>()) {
            if (struct_names_.find(&node) != struct_names_.end()) return;
            std::string name = hint.empty() ? "Record" : hint;
            std::string unique = name;
            int suffix = 2;
            while (!used_names_.insert(unique).second) {
                unique = name + std::to_string(suffix++);
            }
            struct_names_.emplace(&node, unique);

            for (const auto& field : structure->fields) {
                if (!field.type) continue;
                std::string child_hint = upper_camel(field.name, "Field");
                collect_types(*field.type, child_hint);
            }
            ordered_structs_.push_back(&node);
        } else if (const auto* array = node.get_if<core::ArrayNode>()) {
            if (array->element) {
                collect_types(*array->element, hint + "Item");
            }
        } else if (const auto* enumeration = node.get_if<core::EnumNode>()) {
            if (enum_names_.find(&node) != enum_names_.end()) return;
            std::string name = hint.empty() ? "Enum" : hint;
            std::string unique = name;
            int suffix = 2;
            while (!used_names_.insert(unique).second) {
                unique = name + std::to_string(suffix++);
            }
            enum_names_.emplace(&node, unique);
            ordered_enums_.push_back(&node);
        }
    }

    void write_header() {
        line("// Automatically generated by TypeMorph " + std::string(options_.source_name.empty() ? "" : "(" + options_.source_name + ")"));
        line("#![allow(dead_code, non_camel_case_types, non_snake_case)]");
        line("");
        line("use std::io::{self, Read};");
        line("");
    }

    void write_enums() {
        for (const auto* node : ordered_enums_) {
            const auto* enumeration = node->get_if<core::EnumNode>();
            if (!enumeration) continue;
            const std::string& name = enum_names_[node];
            line("#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]");
            line("#[repr(" + rust_primitive(enumeration->underlying) + ")]");
            line("pub enum " + name + " {");
            std::set<std::string> used_variants;
            for (std::size_t i = 0; i < enumeration->variants.size(); ++i) {
                const auto& var = enumeration->variants[i];
                std::string var_name = upper_camel(var.name, "Variant" + std::to_string(i));
                if (is_rust_keyword(var_name)) var_name += "_";
                line(indent(1) + var_name + " = " + std::to_string(var.value) + ",");
            }
            line("}");
            line("");
        }
    }

    void write_structs() {
        for (const auto* node : ordered_structs_) {
            const auto* structure = node->get_if<core::StructNode>();
            if (!structure) continue;
            const std::string& name = struct_names_[node];

            line("#[derive(Debug, Clone, PartialEq)]");
            line("#[repr(C)]");
            line("pub struct " + name + " {");

            std::set<std::string> field_names;
            for (const auto& field : structure->fields) {
                if (!field.type || field.type->size == 0) continue;
                std::string f_name = lower_snake(field.name, "field");
                if (is_rust_keyword(f_name)) f_name = "r#" + f_name;
                std::string unique_f = f_name;
                int suffix = 2;
                while (!field_names.insert(unique_f).second) {
                    unique_f = f_name + "_" + std::to_string(suffix++);
                }

                std::string type_str = rust_type_of(*field.type);
                if (options_.emit_comments && !field.comment.empty()) {
                    line(indent(1) + "/// " + field.comment);
                }
                line(indent(1) + "pub " + unique_f + ": " + type_str + ",");
            }
            line("}");
            line("");
        }
    }

    [[nodiscard]] std::string rust_type_of(const TypeNode& type) {
        if (const auto* primitive = type.get_if<core::PrimitiveNode>()) {
            return rust_primitive(primitive->kind);
        }
        if (type.is<core::EnumNode>()) {
            auto it = enum_names_.find(&type);
            return it != enum_names_.end() ? it->second : "u8";
        }
        if (type.is<core::StructNode>()) {
            auto it = struct_names_.find(&type);
            return it != struct_names_.end() ? it->second : "u8";
        }
        if (const auto* pointer = type.get_if<core::PointerNode>()) {
            return pointer->width == 4 ? "u32" : "u64";
        }
        if (const auto* array = type.get_if<core::ArrayNode>()) {
            std::string elem_type = "u8";
            if (array->element) {
                elem_type = rust_type_of(*array->element);
            }
            if (array->count.has_value()) {
                return "[" + elem_type + "; " + std::to_string(array->count.value()) + "]";
            }
            return "Vec<" + elem_type + ">";
        }
        if (const auto* str = type.get_if<core::StringNode>()) {
            if (str->form == core::StringForm::fixed_size || str->form == core::StringForm::magic_sequence) {
                return "[u8; " + std::to_string(type.size) + "]";
            }
            return "String";
        }
        if (type.is<core::PaddingNode>() || type.is<core::UnknownNode>()) {
            return "[u8; " + std::to_string(type.size) + "]";
        }
        if (type.is<core::SliceNode>()) {
            return type.size != 0 ? "[u8; " + std::to_string(type.size) + "]" : "Vec<u8>";
        }
        return "u8";
    }

    const TypeNode* root_;
    EmitOptions options_;
    std::string root_name_;
    std::ostringstream stream_;
    std::set<std::string> used_names_;
    std::map<const TypeNode*, std::string> struct_names_;
    std::map<const TypeNode*, std::string> enum_names_;
    std::vector<const TypeNode*> ordered_structs_;
    std::vector<const TypeNode*> ordered_enums_;
};

}  // namespace

core::Result<std::string> RustEmitter::generate(const core::TypeNode& root,
                                                const EmitOptions& options) const {
    RustGenerator generator(root, options);
    return generator.run();
}

core::Result<void> RustEmitter::write(const std::filesystem::path& path,
                                      const core::TypeNode& root,
                                      const EmitOptions& options) const {
    auto generated = generate(root, options);
    if (!generated) return generated.error();

    std::ofstream file(path);
    if (!file.is_open()) {
        return core::make_error(ErrorCode::io, "failed to open output file: " + path.string());
    }
    file << generated.value();
    if (!file.good()) {
        return core::make_error(ErrorCode::io, "write error writing to file: " + path.string());
    }
    return {};
}

}  // namespace typemorph::emit
