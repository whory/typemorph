// TypeMorph - Kaitai Struct 0.10 YAML emitter.
//
// The generated .ksy is a complete, structurally valid specification: meta,
// seq, nested types, global enums and (optionally) instances.  Every node in the
// TypeNode tree is visited, identifiers are sanitised into Kaitai's
// [a-z][a-z0-9_]*-with-hyphenated-keys style, strings are YAML-escaped and array
// repeat expressions reference the recovered length field by name.
#include <algorithm>
#include <cstddef>
#include <cstdint>
#include <fstream>
#include <map>
#include <optional>
#include <set>
#include <string>
#include <string_view>
#include <vector>

#include "typemorph/core/result.hpp"
#include "typemorph/core/types.hpp"
#include "typemorph/emitter/emit_options.hpp"
#include "typemorph/emitter/kaitai_emitter.hpp"

namespace typemorph::emit {
namespace {

using core::ErrorCode;
using core::TypeNode;
using core::TypePtr;

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
    collapsed.reserve(out.size());
    for (const char character : out) {
        if (character == '_' && (collapsed.empty() || collapsed.back() == '_')) continue;
        collapsed.push_back(character);
    }
    while (!collapsed.empty() && collapsed.back() == '_') collapsed.pop_back();
    if (collapsed.empty()) return std::string(fallback);
    if (collapsed.front() >= '0' && collapsed.front() <= '9') collapsed.insert(collapsed.begin(), 'x');
    return collapsed;
}

[[nodiscard]] bool is_reserved_identifier(std::string_view name) {
    static const std::vector<std::string_view> reserved = {
        "meta",  "seq",        "types",   "instances", "enums",  "doc",    "id",
        "type",  "size",       "repeat",  "repeat-expr", "value", "parent", "_root",
        "_io",   "true",       "false",   "null",      "bytes",  "str",    "u1",
        "u2",    "u4",         "u8",      "s1",        "s2",     "s4",     "s8",
        "f4",    "f8",         "if",      "process",   "io",     "contents",
        "terminator", "encoding", "eos",  "switch-on", "cases",  "pos",    "imports",
        "title", "application", "file-extension", "ks-version", "valid", "instances"};
    return std::find(reserved.begin(), reserved.end(), name) != reserved.end();
}

[[nodiscard]] std::string make_identifier(std::string_view raw, std::string_view fallback,
                                          std::set<std::string>& used) {
    std::string candidate = lower_snake(raw, fallback);
    if (is_reserved_identifier(candidate)) candidate += "_field";
    std::string unique = candidate;
    int suffix = 2;
    while (!used.insert(unique).second) {
        unique = candidate + "_" + std::to_string(suffix++);
    }
    return unique;
}

[[nodiscard]] std::string yaml_quote(std::string_view text) {
    std::string out = "'";
    for (const char character : text) {
        if (character == '\'') {
            out += "''";
        } else if (character == '\n') {
            out += " ";
        } else if (character == '\r') {
            continue;
        } else {
            out.push_back(character);
        }
    }
    out.push_back('\'');
    return out;
}

[[nodiscard]] std::string builtin_type(core::PrimitiveKind kind) {
    using core::PrimitiveKind;
    switch (kind) {
    case PrimitiveKind::u8:
    case PrimitiveKind::boolean:
    case PrimitiveKind::character: return "u1";
    case PrimitiveKind::u16: return "u2";
    case PrimitiveKind::u32: return "u4";
    case PrimitiveKind::u64: return "u8";
    case PrimitiveKind::i8: return "s1";
    case PrimitiveKind::i16: return "s2";
    case PrimitiveKind::i32: return "s4";
    case PrimitiveKind::i64: return "s8";
    case PrimitiveKind::f32: return "f4";
    case PrimitiveKind::f64: return "f8";
    }
    return "u1";
}

[[nodiscard]] bool is_valid_expression_identifier(std::string_view text) {
    if (text.empty()) return false;
    const auto valid_start = [](char character) {
        return (character >= 'a' && character <= 'z') || (character >= 'A' && character <= 'Z') ||
               character == '_';
    };
    const auto valid_body = [](char character) {
        return (character >= 'a' && character <= 'z') || (character >= 'A' && character <= 'Z') ||
               (character >= '0' && character <= '9') || character == '_';
    };
    if (!valid_start(text.front())) return false;
    for (const char character : text) {
        if (!valid_body(character)) return false;
    }
    return true;
}

class KaitaiGenerator {
public:
    KaitaiGenerator(const TypeNode& root, const EmitOptions& options)
        : root_(&root), options_(options) {
        format_id_ = lower_snake(
            options_.format_name.empty() ? std::string_view{"recovered"} : options_.format_name,
            "recovered");
        if (is_reserved_identifier(format_id_)) format_id_ += "_format";
        root_type_name_ = make_type_identifier(
            options_.root_type_name.empty() ? "root" : options_.root_type_name, 0);
        collect(&root, 0);
    }

    [[nodiscard]] core::Result<std::string> generate() {
        out_.clear();
        write_header_comment();
        write_meta();
        write_seq();
        write_types();
        write_enums();
        write_instances();
        return out_;
    }

private:
    [[nodiscard]] std::string indent(unsigned level) const {
        const unsigned step = options_.indent == 0 ? 2U : std::min(options_.indent, 8U);
        return std::string(static_cast<std::size_t>(level) * step, ' ');
    }

    void raw(std::string_view text) { out_ += text; }
    void line(std::string_view text) {
        out_ += text;
        out_.push_back('\n');
    }

    [[nodiscard]] std::string make_type_identifier(std::string_view raw, std::size_t index) {
        const std::string fallback = "type_" + std::to_string(index);
        return make_identifier(raw, fallback, used_type_names_);
    }

    void collect(const TypeNode* node, int depth) {
        if (node == nullptr || depth > kMaxDepth) return;
        if (node != root_) {
            if (const auto* struct_node = node->get_if<core::StructNode>()) {
                (void)struct_node;
                if (type_names_.find(node) == type_names_.end()) {
                    type_names_.emplace(node, make_type_identifier(node->name, type_names_.size()));
                    nested_order_.push_back(node);
                }
            } else if (const auto* enum_node = node->get_if<core::EnumNode>()) {
                (void)enum_node;
                if (enum_names_.find(node) == enum_names_.end()) {
                    std::string name = node->name.empty() ? "enum" : node->name;
                    enum_names_.emplace(node, make_identifier(name, "enum", used_enum_names_));
                }
                return;
            } else if (const auto* bitfield = node->get_if<core::BitfieldNode>()) {
                (void)bitfield;
                if (type_names_.find(node) == type_names_.end()) {
                    std::string name = node->name.empty() ? "flags" : node->name;
                    type_names_.emplace(node, make_type_identifier(name, type_names_.size()));
                    nested_order_.push_back(node);
                }
                return;
            }
        }
        if (const auto* struct_node = node->get_if<core::StructNode>()) {
            for (const auto& field : struct_node->fields) {
                if (field.type) collect(field.type.get(), depth + 1);
            }
        } else if (const auto* array_node = node->get_if<core::ArrayNode>()) {
            if (array_node->element) collect(array_node->element.get(), depth + 1);
        } else if (const auto* slice_node = node->get_if<core::SliceNode>()) {
            if (slice_node->element_type) collect(slice_node->element_type.get(), depth + 1);
        }
    }

    void write_header_comment() {
        line("# Generated by TypeMorph from recovered binary structure.");
        if (!options_.source_name.empty()) line("# source: " + options_.source_name);
        if (options_.file_size != 0) {
            line("# expected file size: " + std::to_string(options_.file_size) + " bytes");
        }
        line("# endianness: " + std::string(options_.endian == core::ByteOrder::little ? "little"
                                                                                       : "big"));
    }

    void write_meta() {
        line("meta:");
        line(indent(1) + "id: " + format_id_);
        line(indent(1) + "title: " + yaml_quote(options_.root_type_name.empty()
                                                    ? std::string("Recovered file")
                                                    : options_.root_type_name));
        line(indent(1) + "application: TypeMorph");
        line(indent(1) + "file-extension: bin");
        line(indent(1) + std::string("endian: ") +
             std::string(options_.endian == core::ByteOrder::little ? "le" : "be"));
        line(indent(1) + "encoding: UTF-8");
        line(indent(1) + "ks-version: '0.10'");
    }

    [[nodiscard]] std::vector<core::TypeField> root_fields() const {
        if (const auto* struct_node = root_->get_if<core::StructNode>()) {
            return struct_node->fields;
        }
        core::TypeField field;
        field.name = "data";
        field.type = std::make_shared<TypeNode>(*root_);
        field.offset = 0;
        field.confidence = root_->confidence;
        field.comment = root_->comment;
        return {field};
    }

    [[nodiscard]] std::string field_identifier(const core::TypeField& field,
                                               std::set<std::string>& used) const {
        return make_identifier(field.name, "field", used);
    }

    // Emits the attribute lines for one field at the given indentation level.
    // Returns false when the field cannot be represented (zero-sized opaque).
    bool write_attribute(const core::TypeField& field, unsigned level, std::set<std::string>& used) {
        if (!field.type) return false;
        const TypeNode& type = *field.type;
        const std::string id = field_identifier(field, used);
        const std::string pad = indent(level);

        if (const auto* primitive = type.get_if<core::PrimitiveNode>()) {
            line(pad + "- id: " + id);
            line(pad + "  type: " + builtin_type(primitive->kind));
            if (primitive->kind == core::PrimitiveKind::boolean) {
                line(pad + "  doc: 'boolean encoded as u1'");
            }
            write_doc(field, pad);
            return true;
        }
        if (const auto* enumeration = type.get_if<core::EnumNode>()) {
            line(pad + "- id: " + id);
            line(pad + "  type: " + builtin_type(enumeration->underlying));
            const auto found = enum_names_.find(&type);
            if (found != enum_names_.end()) line(pad + "  enum: " + found->second);
            write_doc(field, pad);
            return true;
        }
        if (const auto* structure = type.get_if<core::StructNode>()) {
            (void)structure;
            line(pad + "- id: " + id);
            const auto found = type_names_.find(&type);
            if (found == type_names_.end()) return false;
            line(pad + "  type: " + found->second);
            write_doc(field, pad);
            return true;
        }
        if (const auto* bitfield = type.get_if<core::BitfieldNode>()) {
            (void)bitfield;
            line(pad + "- id: " + id);
            const auto found = type_names_.find(&type);
            if (found == type_names_.end()) return false;
            line(pad + "  type: " + found->second);
            write_doc(field, pad);
            return true;
        }
        if (const auto* pointer = type.get_if<core::PointerNode>()) {
            line(pad + "- id: " + id);
            line(pad + "  type: " + std::string(pointer->width == 4 ? "u4" : "u8"));
            write_doc(field, pad);
            return true;
        }
        if (const auto* array = type.get_if<core::ArrayNode>()) {
            line(pad + "- id: " + id);
            write_array_element(array, pad);
            write_repeat(array, pad);
            write_doc(field, pad);
            return true;
        }
        if (const auto* slice = type.get_if<core::SliceNode>()) {
            line(pad + "- id: " + id);
            if (type.size != 0) {
                line(pad + "  size: " + std::to_string(type.size));
            } else {
                line(pad + "  size-eos: true");
            }
            (void)slice;
            write_doc(field, pad);
            return true;
        }
        if (const auto* str = type.get_if<core::StringNode>()) {
            line(pad + "- id: " + id);
            if (str->form == core::StringForm::magic_sequence && !str->literal_value.empty()) {
                line(pad + "  contents: " + yaml_quote(str->literal_value));
            } else if (str->form == core::StringForm::null_terminated) {
                line(pad + "  type: strz");
                line(pad + "  encoding: " + std::string(core::to_string(str->encoding)));
            } else if (str->form == core::StringForm::length_prefixed) {
                line(pad + "  type: str");
                if (!str->length_expression.empty()) {
                    line(pad + "  size: " + str->length_expression);
                } else {
                    line(pad + "  size: " + std::to_string(type.size));
                }
                line(pad + "  encoding: " + std::string(core::to_string(str->encoding)));
            } else {
                line(pad + "  type: str");
                line(pad + "  size: " + std::to_string(type.size));
                line(pad + "  encoding: " + std::string(core::to_string(str->encoding)));
            }
            write_doc(field, pad);
            return true;
        }
        if (type.is<core::UnknownNode>()) {
            if (type.size == 0) return false;
            line(pad + "- id: " + id);
            line(pad + "  size: " + std::to_string(type.size));
            write_doc(field, pad);
            return true;
        }
        if (type.is<core::PaddingNode>()) {
            if (type.size == 0) return false;
            line(pad + "- id: " + id);
            line(pad + "  size: " + std::to_string(type.size));
            if (options_.emit_comments) line(pad + "  doc: 'zero padding'");
            return true;
        }
        return false;
    }

    void write_array_element(const core::ArrayNode* array, const std::string& pad) {
        const TypeNode* element = array->element.get();
        if (element == nullptr) {
            const std::uint64_t stride = array->element_stride == 0 ? 1 : array->element_stride;
            line(pad + "  size: " + std::to_string(stride));
            return;
        }
        if (const auto* primitive = element->get_if<core::PrimitiveNode>()) {
            line(pad + "  type: " + builtin_type(primitive->kind));
            return;
        }
        if (const auto* enumeration = element->get_if<core::EnumNode>()) {
            line(pad + "  type: " + builtin_type(enumeration->underlying));
            const auto found = enum_names_.find(element);
            if (found != enum_names_.end()) line(pad + "  enum: " + found->second);
            return;
        }
        if (element->is<core::StructNode>()) {
            const auto found = type_names_.find(element);
            if (found != type_names_.end()) {
                line(pad + "  type: " + found->second);
            } else {
                line(pad + "  size: " + std::to_string(array->element_stride));
            }
            return;
        }
        if (const auto* pointer = element->get_if<core::PointerNode>()) {
            line(pad + "  type: " + std::string(pointer->width == 4 ? "u4" : "u8"));
            return;
        }
        const std::uint64_t stride = array->element_stride == 0 ? element->size : array->element_stride;
        line(pad + "  size: " + std::to_string(stride == 0 ? 1 : stride));
    }

    void write_repeat(const core::ArrayNode* array, const std::string& pad) {
        if (!array->count_expression.empty() &&
            is_valid_expression_identifier(array->count_expression)) {
            line(pad + "  repeat: expr");
            line(pad + "  repeat-expr: " + lower_snake(array->count_expression, "count"));
            return;
        }
        if (array->count.has_value()) {
            line(pad + "  repeat: expr");
            line(pad + "  repeat-expr: " + std::to_string(array->count.value()));
            return;
        }
        line(pad + "  repeat: eos");
    }

    void write_doc(const core::TypeField& field, const std::string& pad) {
        if (!options_.emit_comments) return;
        std::string doc = field.comment;
        if (doc.empty()) return;
        line(pad + "  doc: " + yaml_quote(doc));
    }

    void write_seq() {
        std::set<std::string> used;
        const auto fields = root_fields();
        // Attributes are emitted first into a temporary buffer so that an empty
        // sequence can be expressed as `seq: []` (valid YAML) rather than a
        // dangling bare sequence.
        std::string saved = std::move(out_);
        out_.clear();
        bool any = false;
        for (const auto& field : fields) {
            if (write_attribute(field, 1, used)) any = true;
        }
        if (!any) {
            out_ = std::move(saved);
            line("seq: []");
            return;
        }
        const std::string attributes = std::move(out_);
        out_ = std::move(saved);
        line("seq:");
        out_ += attributes;
    }

    void write_types() {
        if (nested_order_.empty()) return;
        line("types:");
        for (const TypeNode* type : nested_order_) {
            const auto& name = type_names_.at(type);
            line(indent(1) + name + ":");
            std::set<std::string> used;
            std::string saved = std::move(out_);
            out_.clear();
            bool any = false;
            if (const auto* structure = type->get_if<core::StructNode>()) {
                for (const auto& field : structure->fields) {
                    if (write_attribute(field, 3, used)) any = true;
                }
            } else if (const auto* bitfield = type->get_if<core::BitfieldNode>()) {
                for (const auto& member : bitfield->members) {
                    std::string mid = make_identifier(member.name, "flag", used);
                    line(indent(3) + "- id: " + mid);
                    line(indent(3) + "  type: b" + std::to_string(member.bit_width));
                    any = true;
                }
            }
            if (!any) {
                out_ = std::move(saved);
                line(indent(2) + "seq: []");
                continue;
            }
            const std::string attributes = std::move(out_);
            out_ = std::move(saved);
            line(indent(2) + "seq:");
            out_ += attributes;
        }
    }

    void write_enums() {
        if (enum_names_.empty()) return;
        line("enums:");
        for (const auto& [node, name] : enum_names_) {
            line(indent(1) + name + ":");
            const auto* enumeration = node->get_if<core::EnumNode>();
            if (enumeration == nullptr) continue;
            std::set<std::string> used;
            for (std::size_t i = 0; i < enumeration->variants.size(); ++i) {
                const auto& variant = enumeration->variants[i];
                const std::string variant_name =
                    make_identifier(variant.name, "value_" + std::to_string(i), used);
                line(indent(2) + std::to_string(variant.value) + ": " + variant_name);
            }
        }
    }

    void write_instances() {
        if (!options_.emit_instances) return;
        line("instances:");
        line(indent(1) + "file_size:");
        line(indent(2) + "value: _io.size");
        if (options_.emit_comments) {
            line(indent(2) + "doc: 'total size of the parsed file in bytes'");
        }
    }

    const TypeNode* root_ = nullptr;
    const EmitOptions& options_;
    std::string out_;
    std::string format_id_;
    std::string root_type_name_;
    std::map<const TypeNode*, std::string> type_names_;
    std::vector<const TypeNode*> nested_order_;
    std::map<const TypeNode*, std::string> enum_names_;
    std::set<std::string> used_type_names_;
    std::set<std::string> used_enum_names_;
};

}  // namespace

core::Result<std::string> KaitaiEmitter::generate(const core::TypeNode& root,
                                                  const EmitOptions& options) const {
    KaitaiGenerator generator(root, options);
    return generator.generate();
}

core::Result<void> KaitaiEmitter::write(const std::filesystem::path& path,
                                        const core::TypeNode& root,
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
        return core::make_error(ErrorCode::io, "failed to write Kaitai YAML", path.string());
    }
    return {};
}

}  // namespace typemorph::emit
