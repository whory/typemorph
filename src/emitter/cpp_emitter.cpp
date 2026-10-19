// TypeMorph - C++20 deserialization header emitter.
//
// The output is a self-contained header: a bounds-checked little/big-endian
// byte reader, one struct per recovered record (children emitted before
// parents), enum class definitions, array members (std::array for counts known
// at generation time, std::vector for counted arrays), padding members and a
// free parse() entry point for the root record.
#include <algorithm>
#include <cstddef>
#include <cstdint>
#include <fstream>
#include <map>
#include <set>
#include <string>
#include <string_view>
#include <utility>
#include <vector>

#include "typemorph/core/result.hpp"
#include "typemorph/core/types.hpp"
#include "typemorph/emitter/cpp_emitter.hpp"
#include "typemorph/emitter/emit_options.hpp"

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
    };
    return std::find(keywords.begin(), keywords.end(), name) != keywords.end();
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

[[nodiscard]] std::string fixed_width_type(core::PrimitiveKind kind) {
    using core::PrimitiveKind;
    switch (kind) {
    case PrimitiveKind::u8: return "std::uint8_t";
    case PrimitiveKind::u16: return "std::uint16_t";
    case PrimitiveKind::u32: return "std::uint32_t";
    case PrimitiveKind::u64: return "std::uint64_t";
    case PrimitiveKind::i8: return "std::int8_t";
    case PrimitiveKind::i16: return "std::int16_t";
    case PrimitiveKind::i32: return "std::int32_t";
    case PrimitiveKind::i64: return "std::int64_t";
    case PrimitiveKind::f32: return "float";
    case PrimitiveKind::f64: return "double";
    case PrimitiveKind::boolean: return "bool";
    case PrimitiveKind::character: return "char";
    }
    return "std::uint8_t";
}

[[nodiscard]] std::string enum_underlying_type(core::PrimitiveKind kind) {
    using core::PrimitiveKind;
    switch (kind) {
    case PrimitiveKind::i8:
    case PrimitiveKind::i16:
    case PrimitiveKind::i32:
    case PrimitiveKind::i64: return fixed_width_type(kind);
    case PrimitiveKind::f32: return "std::uint32_t";
    case PrimitiveKind::f64: return "std::uint64_t";
    default: return fixed_width_type(kind);
    }
}

class CppGenerator {
public:
    CppGenerator(const TypeNode& root, const EmitOptions& options)
        : root_(&root), options_(options) {
        namespace_name_ = lower_snake(
            options_.format_name.empty() ? std::string_view{"recovered"} : options_.format_name,
            "recovered");
        if (is_keyword(namespace_name_)) namespace_name_ += "_format";
        root_type_name_ = make_type_name(
            options_.root_type_name.empty() ? "RecoveredFile" : options_.root_type_name, "Root");
        collect(&root, 0);
    }

    [[nodiscard]] core::Result<std::string> generate() {
        out_.clear();
        write_prelude();
        write_enums();
        for (const TypeNode* type : definition_order_) write_struct(type);
        write_root();
        write_parse_function();
        line("}  // namespace " + namespace_name_);
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
        if (const auto* structure = node->get_if<core::StructNode>()) {
            for (const auto& field : structure->fields) {
                if (!field.type) continue;
                collect(field.type.get(), depth + 1);
                if (field.type->is<core::StructNode>() &&
                    std::find(definition_order_.begin(), definition_order_.end(),
                              field.type.get()) == definition_order_.end()) {
                    definition_order_.push_back(field.type.get());
                }
            }
            if (node != root_ &&
                std::find(definition_order_.begin(), definition_order_.end(), node) ==
                    definition_order_.end()) {
                definition_order_.push_back(node);
            }
        } else if (const auto* array = node->get_if<core::ArrayNode>()) {
            if (array->element) collect(array->element.get(), depth + 1);
        } else if (const auto* slice = node->get_if<core::SliceNode>()) {
            if (slice->element_type) collect(slice->element_type.get(), depth + 1);
        }
    }

    void write_prelude() {
        const std::uint64_t expected =
            options_.file_size != 0 ? options_.file_size : root_->size;
        line("#pragma once");
        line("");
        line("// Generated by TypeMorph from recovered binary structure.  Do not edit.");
        if (!options_.source_name.empty()) line("// source: " + options_.source_name);
        line("// endianness: " + std::string(options_.endian == core::ByteOrder::little ? "little"
                                                                                       : "big"));
        line("// recovered layout size: " + std::to_string(root_->size) + " bytes");
        line("");
        line("#include <array>");
        line("#include <bit>");
        line("#include <cstddef>");
        line("#include <cstdint>");
        line("#include <cstring>");
        line("#include <span>");
        line("#include <stdexcept>");
        line("#include <vector>");
        line("");
        line("namespace " + namespace_name_ + " {");
        line("");
        line("inline constexpr std::uint64_t kExpectedFileSize = " + std::to_string(expected) + ";");
        line("inline constexpr std::uint64_t kRecoveredSize = " + std::to_string(root_->size) + ";");
        line(std::string("inline constexpr bool kLittleEndian = ") +
             (options_.endian == core::ByteOrder::little ? "true;" : "false;"));
        line("");
        write_reader();
    }

    void write_reader() {
        line("namespace detail {");
        line("");
        line("class Reader {");
        line("public:");
        line(indent(1) + "explicit Reader(std::span<const std::uint8_t> bytes) noexcept");
        line(indent(2) + ": bytes_(bytes) {}");
        line("");
        line(indent(1) + "[[nodiscard]] std::size_t offset() const noexcept { return offset_; }");
        line(indent(1) + "[[nodiscard]] std::size_t remaining() const noexcept {");
        line(indent(2) + "return bytes_.size() - offset_;");
        line(indent(1) + "}");
        line(indent(1) + "[[nodiscard]] bool exhausted() const noexcept {");
        line(indent(2) + "return offset_ >= bytes_.size();");
        line(indent(1) + "}");
        line("");
        line(indent(1) + "void skip(std::size_t count) {");
        line(indent(2) + "require(count);");
        line(indent(2) + "offset_ += count;");
        line(indent(1) + "}");
        line("");
        line(indent(1) + "void read_bytes(std::uint8_t* destination, std::size_t count) {");
        line(indent(2) + "require(count);");
        line(indent(2) + "std::memcpy(destination, bytes_.data() + offset_, count);");
        line(indent(2) + "offset_ += count;");
        line(indent(1) + "}");
        line("");
        struct UnsignedReader {
            const char* name;
            const char* type;
            unsigned width;
        };
        const UnsignedReader readers[] = {
            {"read_u8", "std::uint8_t", 1U},
            {"read_u16", "std::uint16_t", 2U},
            {"read_u32", "std::uint32_t", 4U},
            {"read_u64", "std::uint64_t", 8U},
        };
        for (const auto& reader : readers) {
            line(indent(1) + "[[nodiscard]] " + reader.type + " " + reader.name + "() {");
            line(indent(2) + "return static_cast<" + reader.type + ">(read_unsigned(" +
                 std::to_string(reader.width) + "));");
            line(indent(1) + "}");
        }
        line(indent(1) + "[[nodiscard]] float read_f32() {");
        line(indent(2) + "return std::bit_cast<float>(static_cast<std::uint32_t>(read_unsigned(4)));");
        line(indent(1) + "}");
        line(indent(1) + "[[nodiscard]] double read_f64() {");
        line(indent(2) + "return std::bit_cast<double>(read_unsigned(8));");
        line(indent(1) + "}");
        line(indent(1) + "[[nodiscard]] bool read_bool() { return read_u8() != 0; }");
        line("");
        line("private:");
        line(indent(1) + "void require(std::size_t count) const {");
        line(indent(2) + "if (count > remaining()) {");
        line(indent(3) + "throw std::runtime_error(\"TypeMorph: read past end of buffer\");");
        line(indent(2) + "}");
        line(indent(1) + "}");
        line("");
        line(indent(1) + "[[nodiscard]] std::uint64_t read_unsigned(std::size_t width) {");
        line(indent(2) + "require(width);");
        line(indent(2) + "std::uint64_t value = 0;");
        line(indent(2) + "if (kLittleEndian) {");
        line(indent(3) + "for (std::size_t i = 0; i < width; ++i) {");
        line(indent(4) + "value |= static_cast<std::uint64_t>(bytes_[offset_ + i]) << (8U * i);");
        line(indent(3) + "}");
        line(indent(2) + "} else {");
        line(indent(3) + "for (std::size_t i = 0; i < width; ++i) {");
        line(indent(4) + "value = (value << 8U) | static_cast<std::uint64_t>(bytes_[offset_ + i]);");
        line(indent(3) + "}");
        line(indent(2) + "}");
        line(indent(2) + "offset_ += width;");
        line(indent(2) + "return value;");
        line(indent(1) + "}");
        line("");
        line(indent(1) + "std::span<const std::uint8_t> bytes_;");
        line(indent(1) + "std::size_t offset_ = 0;");
        line("};");
        line("");
        line("}  // namespace detail");
        line("");
    }

    void write_enums() {
        for (const auto& [node, name] : enum_names_) {
            const auto* enumeration = node->get_if<core::EnumNode>();
            if (enumeration == nullptr) continue;
            line("enum class " + name + " : " + enum_underlying_type(enumeration->underlying) + " {");
            std::set<std::string> used;
            for (std::size_t i = 0; i < enumeration->variants.size(); ++i) {
                const auto& variant = enumeration->variants[i];
                std::string variant_name = upper_snake(variant.name, "VALUE_" + std::to_string(i));
                if (is_keyword(variant_name)) variant_name += "_";
                std::string unique = variant_name;
                int suffix = 2;
                while (!used.insert(unique).second) {
                    unique = variant_name + "_" + std::to_string(suffix++);
                }
                line(indent(1) + unique + " = " + std::to_string(variant.value) + ",");
            }
            line("};");
            line("");
        }
    }

    [[nodiscard]] std::string cpp_type(const TypeNode& type) const {
        if (const auto* primitive = type.get_if<core::PrimitiveNode>()) {
            return fixed_width_type(primitive->kind);
        }
        if (type.is<core::EnumNode>()) {
            const auto found = enum_names_.find(&type);
            return found != enum_names_.end() ? found->second : std::string("std::uint8_t");
        }
        if (type.is<core::StructNode>()) {
            const auto found = type_names_.find(&type);
            return found != type_names_.end() ? found->second : std::string("std::uint8_t");
        }
        if (const auto* pointer = type.get_if<core::PointerNode>()) {
            return pointer->width == 4 ? "std::uint32_t" : "std::uint64_t";
        }
        if (const auto* str = type.get_if<core::StringNode>()) {
            if (str->form == core::StringForm::fixed_size || str->form == core::StringForm::magic_sequence) {
                return "std::array<char, " + std::to_string(type.size) + ">";
            }
            return "std::string";
        }
        return "std::uint8_t";
    }

    [[nodiscard]] std::string element_cpp_type(const TypeNode* element,
                                               std::uint64_t stride) const {
        if (element == nullptr) {
            return stride <= 1 ? std::string("std::uint8_t")
                               : "std::array<std::uint8_t, " + std::to_string(stride) + ">";
        }
        if (const auto* primitive = element->get_if<core::PrimitiveNode>()) {
            return fixed_width_type(primitive->kind);
        }
        if (element->is<core::EnumNode>()) {
            const auto found = enum_names_.find(element);
            return found != enum_names_.end() ? found->second : std::string("std::uint8_t");
        }
        if (element->is<core::StructNode>()) {
            const auto found = type_names_.find(element);
            return found != type_names_.end() ? found->second : std::string("std::uint8_t");
        }
        if (const auto* pointer = element->get_if<core::PointerNode>()) {
            return pointer->width == 4 ? "std::uint32_t" : "std::uint64_t";
        }
        return stride <= 1 ? std::string("std::uint8_t")
                           : "std::array<std::uint8_t, " + std::to_string(stride) + ">";
    }

    [[nodiscard]] std::string read_unsigned_call(std::uint8_t width) const {
        switch (width) {
        case 1: return "reader.read_u8()";
        case 2: return "reader.read_u16()";
        case 4: return "reader.read_u32()";
        default: return "reader.read_u64()";
        }
    }

    [[nodiscard]] std::string primitive_read_expression(const core::PrimitiveNode& primitive) const {
        const std::uint8_t width = core::primitive_size(primitive.kind);
        switch (primitive.kind) {
        case core::PrimitiveKind::f32: return "reader.read_f32()";
        case core::PrimitiveKind::f64: return "reader.read_f64()";
        case core::PrimitiveKind::boolean: return "reader.read_bool()";
        case core::PrimitiveKind::character: return "static_cast<char>(reader.read_u8())";
        case core::PrimitiveKind::i8: return "static_cast<std::int8_t>(reader.read_u8())";
        case core::PrimitiveKind::i16: return "static_cast<std::int16_t>(reader.read_u16())";
        case core::PrimitiveKind::i32: return "static_cast<std::int32_t>(reader.read_u32())";
        case core::PrimitiveKind::i64: return "static_cast<std::int64_t>(reader.read_u64())";
        default: return read_unsigned_call(width);
        }
    }

    [[nodiscard]] std::string element_read_expression(const TypeNode* element,
                                                      std::uint64_t stride) const {
        if (element == nullptr) return stride <= 1 ? std::string("reader.read_u8()") : std::string{};
        if (const auto* primitive = element->get_if<core::PrimitiveNode>()) {
            return primitive_read_expression(*primitive);
        }
        if (const auto* enumeration = element->get_if<core::EnumNode>()) {
            return "static_cast<" + cpp_type(*element) + ">(" +
                   read_unsigned_call(core::primitive_size(enumeration->underlying)) + ")";
        }
        if (element->is<core::StructNode>()) {
            return cpp_type(*element) + "::read(reader)";
        }
        if (const auto* pointer = element->get_if<core::PointerNode>()) {
            return pointer->width == 4 ? "reader.read_u32()" : "reader.read_u64()";
        }
        return {};
    }

    [[nodiscard]] std::map<std::string, std::string> assign_member_names(
        const std::vector<core::TypeField>& fields) {
        std::map<std::string, std::string> names;
        std::set<std::string> used;
        for (const auto& field : fields) {
            if (!field.type || field.type->size == 0) continue;
            names.emplace(field.name, make_member_name(field.name, "field", used));
        }
        return names;
    }

    void write_member_declaration(const core::TypeField& field, const std::string& name,
                                  const std::map<std::string, std::string>& names) {
        if (!field.type || field.type->size == 0) return;
        const TypeNode& type = *field.type;
        const std::string pad = indent(1);
        if (const auto* array = type.get_if<core::ArrayNode>()) {
            const std::uint64_t stride =
                array->element_stride == 0
                    ? (array->element ? std::max<std::uint64_t>(array->element->size, 1) : 1)
                    : array->element_stride;
            const std::string element_type = element_cpp_type(array->element.get(), stride);
            bool dynamic = !array->count_expression.empty();
            if (!dynamic && !array->count.has_value()) dynamic = true;
            std::string declaration;
            if (dynamic) {
                declaration = "std::vector<" + element_type + "> " + name + ";";
            } else {
                declaration = "std::array<" + element_type + ", " +
                              std::to_string(array->count.value()) + "> " + name + ";";
            }
            (void)names;
            line(pad + declaration);
            return;
        }
        if (type.is<core::PaddingNode>() || type.is<core::UnknownNode>()) {
            line(pad + "std::array<std::uint8_t, " + std::to_string(type.size) + "> " + name + ";");
            return;
        }
        if (type.is<core::SliceNode>()) {
            if (type.size != 0) {
                line(pad + "std::array<std::uint8_t, " + std::to_string(type.size) + "> " + name +
                     ";");
            } else {
                line(pad + "std::vector<std::uint8_t> " + name + ";");
            }
            return;
        }
        line(pad + cpp_type(type) + " " + name + ";");
    }

    void write_member_read(const core::TypeField& field, const std::string& name,
                           const std::map<std::string, std::string>& names) {
        if (!field.type || field.type->size == 0) return;
        const TypeNode& type = *field.type;
        const std::string pad = indent(2);
        const std::string target = "value." + name;

        if (const auto* primitive = type.get_if<core::PrimitiveNode>()) {
            line(pad + target + " = " + primitive_read_expression(*primitive) + ";");
            return;
        }
        if (const auto* enumeration = type.get_if<core::EnumNode>()) {
            line(pad + target + " = static_cast<" + cpp_type(type) + ">(" +
                 read_unsigned_call(core::primitive_size(enumeration->underlying)) + ");");
            return;
        }
        if (type.is<core::StructNode>()) {
            line(pad + target + " = " + cpp_type(type) + "::read(reader);");
            return;
        }
        if (const auto* pointer = type.get_if<core::PointerNode>()) {
            line(pad + target + " = " + (pointer->width == 4 ? "reader.read_u32()"
                                                             : "reader.read_u64()") +
                 ";");
            return;
        }
        if (const auto* array = type.get_if<core::ArrayNode>()) {
            const std::uint64_t stride =
                array->element_stride == 0
                    ? (array->element ? std::max<std::uint64_t>(array->element->size, 1) : 1)
                    : array->element_stride;
            const std::string expression = element_read_expression(array->element.get(), stride);
            const bool dynamic = !array->count_expression.empty() || !array->count.has_value();
            std::string count_reference;
            if (!array->count_expression.empty()) {
                const auto found = names.find(array->count_expression);
                if (found != names.end()) count_reference = "value." + found->second;
            }
            if (!count_reference.empty()) {
                line(pad + "{");
                line(pad + "    const std::size_t item_count = static_cast<std::size_t>(" +
                     count_reference + ");");
                line(pad + "    " + target + ".resize(item_count);");
                if (!expression.empty()) {
                    line(pad + "    for (auto& item : " + target + ") item = " + expression + ";");
                } else {
                    line(pad + "    for (auto& item : " + target + ") {");
                    line(pad + "        reader.read_bytes(item.data(), " + std::to_string(stride) +
                         ");");
                    line(pad + "    }");
                }
                line(pad + "}");
                return;
            }
            if (array->count.has_value() && !dynamic) {
                if (!expression.empty()) {
                    line(pad + "for (auto& item : " + target + ") item = " + expression + ";");
                } else {
                    line(pad + "for (auto& item : " + target + ") {");
                    line(pad + "    reader.read_bytes(item.data(), " + std::to_string(stride) + ");");
                    line(pad + "}");
                }
                return;
            }
            if (array->count.has_value()) {
                line(pad + target + ".resize(" + std::to_string(array->count.value()) + ");");
                if (!expression.empty()) {
                    line(pad + "for (auto& item : " + target + ") item = " + expression + ";");
                } else {
                    line(pad + "for (auto& item : " + target + ") {");
                    line(pad + "    reader.read_bytes(item.data(), " + std::to_string(stride) + ");");
                    line(pad + "}");
                }
                return;
            }
            // Unknown count: consume until the reader is exhausted.
            if (!expression.empty()) {
                line(pad + "while (!reader.exhausted()) " + target + ".push_back(" + expression +
                     ");");
            } else {
                line(pad + "while (!reader.exhausted()) {");
                line(pad + "    std::array<std::uint8_t, " + std::to_string(stride) + "> item{};");
                line(pad + "    reader.read_bytes(item.data(), " + std::to_string(stride) + ");");
                line(pad + "    " + target + ".push_back(item);");
                line(pad + "}");
            }
            return;
        }
        if (type.is<core::SliceNode>()) {
            if (type.size != 0) {
                line(pad + "reader.read_bytes(" + target + ".data(), " + std::to_string(type.size) +
                     ");");
            } else {
                line(pad + "while (!reader.exhausted()) " + target + ".push_back(reader.read_u8());");
            }
            return;
        }
        if (const auto* str = type.get_if<core::StringNode>()) {
            if (str->form == core::StringForm::fixed_size || str->form == core::StringForm::magic_sequence) {
                line(pad + "reader.read_bytes(reinterpret_cast<std::uint8_t*>(" + target + ".data()), " +
                     std::to_string(type.size) + ");");
            } else {
                line(pad + target + ".resize(" + std::to_string(type.size) + ");");
                line(pad + "reader.read_bytes(reinterpret_cast<std::uint8_t*>(" + target + ".data()), " +
                     target + ".size());");
            }
            return;
        }
        // Padding / unknown: skip the bytes.
        line(pad + "reader.skip(" + std::to_string(type.size) + ");");
    }

    void write_struct(const TypeNode* node) {
        const auto found = type_names_.find(node);
        if (found == type_names_.end()) return;
        const auto* structure = node->get_if<core::StructNode>();
        if (structure == nullptr) return;
        line("struct " + found->second + " {");
        const auto names = assign_member_names(structure->fields);
        for (const auto& field : structure->fields) {
            const auto name = names.find(field.name);
            if (name == names.end()) continue;
            write_member_declaration(field, name->second, names);
        }
        line("");
        line(indent(1) + "[[nodiscard]] static " + found->second +
             " read(detail::Reader& reader) {");
        line(indent(2) + found->second + " value{};");
        for (const auto& field : structure->fields) {
            const auto name = names.find(field.name);
            if (name == names.end()) continue;
            write_member_read(field, name->second, names);
        }
        line(indent(2) + "return value;");
        line(indent(1) + "}");
        line("};");
        line("");
    }

    void write_root() {
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
        line("struct " + root_type_name_ + " {");
        const auto names = assign_member_names(fields);
        for (const auto& field : fields) {
            const auto name = names.find(field.name);
            if (name == names.end()) continue;
            write_member_declaration(field, name->second, names);
        }
        line("");
        line(indent(1) + "[[nodiscard]] static " + root_type_name_ +
             " read(detail::Reader& reader) {");
        line(indent(2) + root_type_name_ + " value{};");
        for (const auto& field : fields) {
            const auto name = names.find(field.name);
            if (name == names.end()) continue;
            write_member_read(field, name->second, names);
        }
        line(indent(2) + "return value;");
        line(indent(1) + "}");
        line("};");
        line("");
    }

    void write_parse_function() {
        line("[[nodiscard]] inline " + root_type_name_ +
             " parse(std::span<const std::uint8_t> bytes) {");
        line(indent(1) + "detail::Reader reader(bytes);");
        line(indent(1) + "return " + root_type_name_ + "::read(reader);");
        line("}");
    }

    const TypeNode* root_ = nullptr;
    const EmitOptions& options_;
    std::string out_;
    std::string namespace_name_;
    std::string root_type_name_;
    std::map<const TypeNode*, std::string> type_names_;
    std::map<const TypeNode*, std::string> enum_names_;
    std::vector<const TypeNode*> definition_order_;
    std::set<std::string> used_type_names_;
};

}  // namespace

core::Result<std::string> CppEmitter::generate(const core::TypeNode& root,
                                               const EmitOptions& options) const {
    CppGenerator generator(root, options);
    return generator.generate();
}

core::Result<void> CppEmitter::write(const std::filesystem::path& path, const core::TypeNode& root,
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
        return core::make_error(ErrorCode::io, "failed to write C++ header", path.string());
    }
    return {};
}

}  // namespace typemorph::emit
