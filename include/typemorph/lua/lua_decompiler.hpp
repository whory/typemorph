// TypeMorph - Lua & LuaJIT Bytecode Decompiler and Disassembler
//
// Supports:
// - Standard Lua 5.1, 5.2, 5.3, 5.4 Bytecode (\x1bLua)
// - LuaJIT v2.0 and v2.1 Bytecode (\x1bLJ)
// - Reconstructs function prototypes, constants, upvalues, local variables,
//   and emits high-level Lua source code.
#pragma once

#include "typemorph/core/binary_view.hpp"
#include "typemorph/core/result.hpp"

#include <cstdint>
#include <string>
#include <string_view>
#include <vector>

namespace typemorph::lua {

enum class LuaFlavor {
    unknown,
    lua51,
    lua52,
    lua53,
    lua54,
    luajit20,
    luajit21
};

[[nodiscard]] constexpr const char* to_string(LuaFlavor flavor) noexcept {
    switch (flavor) {
    case LuaFlavor::lua51: return "Lua 5.1";
    case LuaFlavor::lua52: return "Lua 5.2";
    case LuaFlavor::lua53: return "Lua 5.3";
    case LuaFlavor::lua54: return "Lua 5.4";
    case LuaFlavor::luajit20: return "LuaJIT 2.0";
    case LuaFlavor::luajit21: return "LuaJIT 2.1";
    case LuaFlavor::unknown: return "Unknown Lua Bytecode";
    }
    return "Unknown";
}

struct LuaConstant {
    enum class Kind {
        nil_val,
        boolean,
        number,
        integer,
        string_val
    };

    Kind kind = Kind::nil_val;
    std::string string_value;
    double number_value = 0.0;
    std::int64_t integer_value = 0;
    bool bool_value = false;

    [[nodiscard]] std::string to_lua_literal() const;
};

struct LuaInstruction {
    std::uint32_t raw = 0;
    std::string opcode_name;
    std::uint32_t a = 0;
    std::int32_t b = 0;
    std::int32_t c = 0;
    std::int32_t bx = 0;
    std::int32_t sbx = 0;
    std::string comment;
};

struct LuaLocalVar {
    std::string name;
    std::uint32_t start_pc = 0;
    std::uint32_t end_pc = 0;
};

struct LuaFunction {
    std::uint32_t id = 0;
    std::string source_name;
    std::uint32_t line_defined = 0;
    std::uint32_t last_line_defined = 0;
    std::uint8_t num_params = 0;
    bool is_vararg = false;
    std::uint8_t max_stack_size = 0;

    std::vector<LuaInstruction> instructions;
    std::vector<LuaConstant> constants;
    std::vector<LuaLocalVar> locals;
    std::vector<std::string> upvalues;
    std::vector<LuaFunction> nested_functions;

    [[nodiscard]] std::string disassemble() const;
};

struct LuaDecompileReport {
    bool is_lua_bytecode = false;
    LuaFlavor flavor = LuaFlavor::unknown;
    std::uint8_t version_byte = 0;
    std::uint8_t format_version = 0;
    bool is_big_endian = false;
    std::size_t int_size = 4;
    std::size_t size_t_size = 8;
    std::size_t instruction_size = 4;
    std::size_t lua_number_size = 8;
    bool is_integral_number = false;

    LuaFunction root_function;
    std::size_t total_functions = 0;
    std::size_t total_instructions = 0;
    std::size_t total_constants = 0;

    std::string lua_source;
};

class LuaDecompiler {
public:
    LuaDecompiler() = default;

    [[nodiscard]] LuaDecompileReport decompile(const core::BinaryView& view) const;
    [[nodiscard]] static std::string to_lua_source(const LuaDecompileReport& report);
    [[nodiscard]] static std::string to_disassembly(const LuaDecompileReport& report);

private:
    [[nodiscard]] LuaDecompileReport decompile_lua51(const core::BinaryView& view) const;
    [[nodiscard]] LuaDecompileReport decompile_luajit(const core::BinaryView& view, bool is_v21) const;
};

}  // namespace typemorph::lua
