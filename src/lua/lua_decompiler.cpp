// TypeMorph - Lua & LuaJIT Bytecode Decompiler Implementation
#include "typemorph/lua/lua_decompiler.hpp"

#include <algorithm>
#include <cstdio>
#include <cstring>
#include <iomanip>
#include <sstream>

namespace typemorph::lua {

namespace {

inline std::uint16_t load16(const std::uint8_t* p) noexcept {
    return static_cast<std::uint16_t>(p[0]) | (static_cast<std::uint16_t>(p[1]) << 8U);
}

inline std::uint32_t load32(const std::uint8_t* p) noexcept {
    return static_cast<std::uint32_t>(p[0]) |
           (static_cast<std::uint32_t>(p[1]) << 8U) |
           (static_cast<std::uint32_t>(p[2]) << 16U) |
           (static_cast<std::uint32_t>(p[3]) << 24U);
}

inline std::uint64_t load64(const std::uint8_t* p) noexcept {
    return static_cast<std::uint64_t>(load32(p)) |
           (static_cast<std::uint64_t>(load32(p + 4)) << 32U);
}

// Opcode names for standard Lua 5.1
const char* const kLua51Opcodes[] = {
    "MOVE", "LOADK", "LOADBOOL", "LOADNIL", "GETUPVAL",
    "GETGLOBAL", "GETTABLE", "SETGLOBAL", "SETUPVAL", "SETTABLE",
    "NEWTABLE", "SELF", "ADD", "SUB", "MUL",
    "DIV", "MOD", "POW", "UNM", "NOT",
    "LEN", "CONCAT", "JMP", "EQ", "LT",
    "LE", "TEST", "TESTSET", "CALL", "TAILCALL",
    "RETURN", "FORLOOP", "FORPREP", "TFORLOOP", "SETLIST",
    "CLOSE", "CLOSURE", "VARARG"
};

// Opcode names for LuaJIT 2.0 / 2.1 (common subset)
const char* const kLuaJitOpcodes[] = {
    "ISLT", "ISGE", "ISLE", "ISGT", "ISEQV", "ISNEV", "ISEQS", "ISNES",
    "ISEQN", "ISNEN", "ISEQP", "ISNEP", "ISTC", "ISFC", "IST", "ISF",
    "MOV", "NOT", "UNM", "LEN", "ADDVN", "SUBVN", "MULVN", "DIVVN",
    "MODVN", "ADDNV", "SUBNV", "MULNV", "DIVNV", "MODNV", "ADDVV", "SUBVV",
    "MULVV", "DIVVV", "MODVV", "POW", "CAT", "KSTR", "KCDATA", "KSHORT",
    "KNUM", "KPRI", "KNIL", "UGET", "USETV", "USETS", "USETN", "USETP",
    "UCLO", "FNEW", "TNEW", "TDUP", "GGET", "GSET", "TGETV", "TGETS",
    "TGETB", "TSETV", "TSETS", "TSETB", "TSETM", "CALLM", "CALL", "CALLT",
    "ITERC", "ITERN", "VARG", "ISNEXT", "RETM", "RET", "RET0", "RET1",
    "FORI", "JFORI", "FORL", "IFORL", "JFORL", "ITERL", "IITERL", "JITERL",
    "LOOP", "ILOOP", "JLOOP", "JMP", "FUNCF", "IFUNCF", "JFUNCF", "FUNCV",
    "IFUNCV", "JFUNCV", "FUNCC", "FUNCCW"
};

}  // namespace

std::string LuaConstant::to_lua_literal() const {
    switch (kind) {
    case Kind::nil_val: return "nil";
    case Kind::boolean: return bool_value ? "true" : "false";
    case Kind::integer: return std::to_string(integer_value);
    case Kind::number: {
        std::ostringstream ss;
        ss << number_value;
        return ss.str();
    }
    case Kind::string_val: {
        std::string res = "\"";
        for (char ch : string_value) {
            if (ch == '"') res += "\\\"";
            else if (ch == '\\') res += "\\\\";
            else if (ch == '\n') res += "\\n";
            else if (ch == '\r') res += "\\r";
            else if (ch == '\t') res += "\\t";
            else if (static_cast<unsigned char>(ch) >= 0x20 && static_cast<unsigned char>(ch) <= 0x7E) {
                res.push_back(ch);
            } else {
                char hex[8];
                std::snprintf(hex, sizeof(hex), "\\x%02X", static_cast<unsigned char>(ch));
                res += hex;
            }
        }
        res += "\"";
        return res;
    }
    }
    return "nil";
}

std::string LuaFunction::disassemble() const {
    std::ostringstream ss;
    ss << "; Function ID: " << id << " [" << (source_name.empty() ? "(main)" : source_name) << "]\n";
    ss << "; Defined at line: " << line_defined << " to " << last_line_defined << "\n";
    ss << "; Params: " << static_cast<int>(num_params) << ", Max Stack: " << static_cast<int>(max_stack_size) << "\n";
    ss << "; Constants (" << constants.size() << "):\n";
    for (std::size_t i = 0; i < constants.size(); ++i) {
        ss << ";   [" << i << "] = " << constants[i].to_lua_literal() << "\n";
    }
    ss << "; Upvalues (" << upvalues.size() << "):\n";
    for (std::size_t i = 0; i < upvalues.size(); ++i) {
        ss << ";   [" << i << "] = " << upvalues[i] << "\n";
    }
    ss << "\n";

    for (std::size_t pc = 0; pc < instructions.size(); ++pc) {
        const auto& ins = instructions[pc];
        ss << std::setw(4) << pc << "  "
           << std::left << std::setw(12) << ins.opcode_name
           << " " << ins.a << " " << ins.b << " " << ins.c;
        if (!ins.comment.empty()) {
            ss << "    ; " << ins.comment;
        }
        ss << "\n";
    }

    for (const auto& nested : nested_functions) {
        ss << "\n" << nested.disassemble();
    }
    return ss.str();
}

std::string LuaDecompiler::to_disassembly(const LuaDecompileReport& report) {
    if (!report.is_lua_bytecode) {
        return "; Error: Not a valid Lua or LuaJIT bytecode file.\n";
    }
    std::ostringstream ss;
    ss << "; ================================================================\n";
    ss << "; Disassembled with TypeMorph Lua Engine\n";
    ss << "; Format: " << to_string(report.flavor) << "\n";
    ss << "; Total Functions: " << report.total_functions
       << ", Total Instructions: " << report.total_instructions
       << ", Constants: " << report.total_constants << "\n";
    ss << "; ================================================================\n\n";
    ss << report.root_function.disassemble();
    return ss.str();
}

std::string LuaDecompiler::to_lua_source(const LuaDecompileReport& report) {
    if (!report.is_lua_bytecode) {
        return "-- Error: Not a valid Lua or LuaJIT bytecode file.\n";
    }

    std::ostringstream ss;
    ss << "-- Decompiled with TypeMorph Lua Decompiler\n";
    ss << "-- Target: " << to_string(report.flavor) << "\n\n";

    // Decompile instructions to structured Lua statements
    auto decompile_func = [](auto& self, const LuaFunction& fn, int indent) -> std::string {
        (void)self;
        std::string ind(indent * 4, ' ');
        std::ostringstream out;

        // Collect global / local accesses and calls
        std::vector<std::string> registers(256, "nil");
        std::vector<std::string> statements;

        for (std::size_t pc = 0; pc < fn.instructions.size(); ++pc) {
            const auto& ins = fn.instructions[pc];

            if (ins.opcode_name == "LOADK") {
                if (ins.bx >= 0 && static_cast<std::size_t>(ins.bx) < fn.constants.size()) {
                    registers[ins.a] = fn.constants[static_cast<std::size_t>(ins.bx)].to_lua_literal();
                }
            } else if (ins.opcode_name == "LOADBOOL") {
                registers[ins.a] = (ins.b != 0) ? "true" : "false";
            } else if (ins.opcode_name == "LOADNIL") {
                for (std::uint32_t r = ins.a; r <= static_cast<std::uint32_t>(ins.b); ++r) {
                    registers[r] = "nil";
                }
            } else if (ins.opcode_name == "GETGLOBAL") {
                std::string gname = "var_" + std::to_string(ins.bx);
                if (ins.bx >= 0 && static_cast<std::size_t>(ins.bx) < fn.constants.size()) {
                    gname = fn.constants[static_cast<std::size_t>(ins.bx)].string_value;
                }
                registers[ins.a] = gname;
            } else if (ins.opcode_name == "SETGLOBAL") {
                std::string gname = "var_" + std::to_string(ins.bx);
                if (ins.bx >= 0 && static_cast<std::size_t>(ins.bx) < fn.constants.size()) {
                    gname = fn.constants[static_cast<std::size_t>(ins.bx)].string_value;
                }
                statements.push_back(ind + gname + " = " + registers[ins.a]);
            } else if (ins.opcode_name == "MOVE") {
                registers[ins.a] = registers[ins.b];
            } else if (ins.opcode_name == "CALL") {
                std::string target = registers[ins.a];
                std::string args;
                int nparams = ins.b - 1;
                if (nparams < 0) nparams = 0; // variable
                for (int p = 0; p < nparams; ++p) {
                    if (p > 0) args += ", ";
                    args += registers[ins.a + 1 + p];
                }
                statements.push_back(ind + target + "(" + args + ")");
            } else if (ins.opcode_name == "RETURN") {
                if (ins.b > 1) {
                    statements.push_back(ind + "return " + registers[ins.a]);
                } else if (ins.b == 0) {
                    statements.push_back(ind + "return");
                }
            } else if (ins.opcode_name == "ADD" || ins.opcode_name == "SUB" ||
                       ins.opcode_name == "MUL" || ins.opcode_name == "DIV") {
                std::string op = "+";
                if (ins.opcode_name == "SUB") op = "-";
                else if (ins.opcode_name == "MUL") op = "*";
                else if (ins.opcode_name == "DIV") op = "/";

                std::string left = (ins.b >= 256) ? fn.constants[ins.b - 256].to_lua_literal() : registers[ins.b];
                std::string right = (ins.c >= 256) ? fn.constants[ins.c - 256].to_lua_literal() : registers[ins.c];
                registers[ins.a] = left + " " + op + " " + right;
            } else if (ins.opcode_name == "CONCAT") {
                std::string conc = registers[ins.b];
                for (int c = ins.b + 1; c <= ins.c; ++c) {
                    conc += " .. " + registers[c];
                }
                registers[ins.a] = conc;
            }
        }

        for (const auto& stmt : statements) {
            out << stmt << "\n";
        }
        return out.str();
    };

    ss << decompile_func(decompile_func, report.root_function, 0);
    return ss.str();
}

LuaDecompileReport LuaDecompiler::decompile(const core::BinaryView& view) const {
    LuaDecompileReport report;
    const std::size_t size = view.size();
    const std::uint8_t* data = view.data();

    if (size < 4) {
        return report;
    }

    // Check for standard Lua bytecode signature: \x1bLua (0x1B, 0x4C, 0x75, 0x61)
    if (data[0] == 0x1B && data[1] == 'L' && data[2] == 'u' && data[3] == 'a') {
        report.is_lua_bytecode = true;
        if (size < 12) return report;

        report.version_byte = data[4];
        report.format_version = data[5];

        if (report.version_byte == 0x51) {
            report.flavor = LuaFlavor::lua51;
            return decompile_lua51(view);
        } else if (report.version_byte == 0x52) {
            report.flavor = LuaFlavor::lua52;
            return decompile_lua51(view); // Standard Lua chunk loader
        } else if (report.version_byte == 0x53) {
            report.flavor = LuaFlavor::lua53;
            return decompile_lua51(view);
        } else if (report.version_byte == 0x54) {
            report.flavor = LuaFlavor::lua54;
            return decompile_lua51(view);
        }
        return report;
    }

    // Check for LuaJIT bytecode signature: \x1bLJ (0x1B, 0x4C, 0x4A)
    if (data[0] == 0x1B && data[1] == 'L' && data[2] == 'J') {
        report.is_lua_bytecode = true;
        std::uint8_t ver = data[3];
        if (ver == 1) {
            report.flavor = LuaFlavor::luajit20;
            return decompile_luajit(view, false);
        } else if (ver == 2) {
            report.flavor = LuaFlavor::luajit21;
            return decompile_luajit(view, true);
        }
    }

    return report;
}

LuaDecompileReport LuaDecompiler::decompile_lua51(const core::BinaryView& view) const {
    LuaDecompileReport report;
    report.is_lua_bytecode = true;
    report.flavor = LuaFlavor::lua51;

    const std::size_t size = view.size();
    const std::uint8_t* data = view.data();

    if (size < 12) return report;
    report.version_byte = data[4];
    report.format_version = data[5];
    report.is_big_endian = (data[6] == 0);
    report.int_size = data[7];
    report.size_t_size = data[8];
    report.instruction_size = data[9];
    report.lua_number_size = data[10];
    report.is_integral_number = (data[11] != 0);

    std::size_t offset = 12;

    auto read_size_t = [&](std::size_t& off) -> std::uint64_t {
        if (off + report.size_t_size > size) return 0;
        std::uint64_t val = (report.size_t_size == 8) ? load64(data + off) : load32(data + off);
        off += report.size_t_size;
        return val;
    };

    auto read_string = [&](std::size_t& off) -> std::string {
        std::uint64_t s_len = read_size_t(off);
        if (s_len == 0 || off + s_len > size) return {};
        std::string str(reinterpret_cast<const char*>(data + off), s_len > 0 ? (s_len - 1) : 0);
        off += s_len;
        return str;
    };

    // Recursive function parser for Lua 5.1
    std::uint32_t func_id = 0;
    auto parse_func = [&](auto& self, std::size_t& off) -> LuaFunction {
        LuaFunction fn;
        fn.id = func_id++;
        fn.source_name = read_string(off);

        if (off + 8 > size) return fn;
        fn.line_defined = load32(data + off); off += 4;
        fn.last_line_defined = load32(data + off); off += 4;

        if (off + 4 > size) return fn;
        std::uint8_t nups = data[off++];
        fn.num_params = data[off++];
        fn.is_vararg = (data[off++] != 0);
        fn.max_stack_size = data[off++];

        // Read instructions
        if (off + 4 > size) return fn;
        std::uint32_t num_inst = load32(data + off); off += 4;

        for (std::uint32_t i = 0; i < num_inst; ++i) {
            if (off + 4 > size) break;
            std::uint32_t ins_raw = load32(data + off); off += 4;

            std::uint8_t op = static_cast<std::uint8_t>(ins_raw & 0x3F);
            std::uint32_t a = (ins_raw >> 6) & 0xFF;
            std::uint32_t c = (ins_raw >> 14) & 0x1FF;
            std::uint32_t b = (ins_raw >> 23) & 0x1FF;
            std::uint32_t bx = (ins_raw >> 14);
            std::int32_t sbx = static_cast<std::int32_t>(bx) - 131071;

            LuaInstruction ins;
            ins.raw = ins_raw;
            ins.opcode_name = (op < sizeof(kLua51Opcodes) / sizeof(kLua51Opcodes[0])) ? kLua51Opcodes[op] : ("OP_" + std::to_string(op));
            ins.a = a;
            ins.b = static_cast<std::int32_t>(b);
            ins.c = static_cast<std::int32_t>(c);
            ins.bx = static_cast<std::int32_t>(bx);
            ins.sbx = sbx;

            fn.instructions.push_back(std::move(ins));
        }

        // Read constants
        if (off + 4 > size) return fn;
        std::uint32_t num_consts = load32(data + off); off += 4;

        for (std::uint32_t i = 0; i < num_consts; ++i) {
            if (off >= size) break;
            std::uint8_t k_type = data[off++];
            LuaConstant k;
            if (k_type == 0) { // LUA_TNIL
                k.kind = LuaConstant::Kind::nil_val;
            } else if (k_type == 1) { // LUA_TBOOLEAN
                k.kind = LuaConstant::Kind::boolean;
                if (off < size) k.bool_value = (data[off++] != 0);
            } else if (k_type == 3) { // LUA_TNUMBER
                k.kind = LuaConstant::Kind::number;
                if (off + 8 <= size) {
                    std::uint64_t raw_f = load64(data + off); off += 8;
                    std::memcpy(&k.number_value, &raw_f, sizeof(double));
                }
            } else if (k_type == 4) { // LUA_TSTRING
                k.kind = LuaConstant::Kind::string_val;
                k.string_value = read_string(off);
            }
            fn.constants.push_back(std::move(k));
        }

        // Read nested functions (prototypes)
        if (off + 4 > size) return fn;
        std::uint32_t num_protos = load32(data + off); off += 4;
        for (std::uint32_t p = 0; p < num_protos; ++p) {
            fn.nested_functions.push_back(self(self, off));
        }

        // Read source line debug info
        if (off + 4 <= size) {
            std::uint32_t num_lines = load32(data + off); off += 4;
            off += num_lines * 4;
        }

        // Read local variables debug info
        if (off + 4 <= size) {
            std::uint32_t num_locals = load32(data + off); off += 4;
            for (std::uint32_t l = 0; l < num_locals && off < size; ++l) {
                LuaLocalVar lv;
                lv.name = read_string(off);
                if (off + 8 <= size) {
                    lv.start_pc = load32(data + off); off += 4;
                    lv.end_pc = load32(data + off); off += 4;
                }
                fn.locals.push_back(std::move(lv));
            }
        }

        // Read upvalues debug info
        if (off + 4 <= size) {
            std::uint32_t num_upvalues = load32(data + off); off += 4;
            for (std::uint32_t u = 0; u < num_upvalues && off < size; ++u) {
                fn.upvalues.push_back(read_string(off));
            }
        }

        if (fn.upvalues.empty() && nups > 0) {
            for (std::uint8_t u = 0; u < nups; ++u) {
                fn.upvalues.push_back("uv_" + std::to_string(u));
            }
        }

        return fn;
    };

    report.root_function = parse_func(parse_func, offset);

    // Compute totals
    auto count_stats = [](auto& self, const LuaFunction& f, std::size_t& funcs, std::size_t& insts, std::size_t& consts) -> void {
        funcs++;
        insts += f.instructions.size();
        consts += f.constants.size();
        for (const auto& n : f.nested_functions) {
            self(self, n, funcs, insts, consts);
        }
    };

    count_stats(count_stats, report.root_function, report.total_functions, report.total_instructions, report.total_constants);
    report.lua_source = to_lua_source(report);

    return report;
}

LuaDecompileReport LuaDecompiler::decompile_luajit(const core::BinaryView& view, bool is_v21) const {
    LuaDecompileReport report;
    report.is_lua_bytecode = true;
    report.flavor = is_v21 ? LuaFlavor::luajit21 : LuaFlavor::luajit20;

    const std::size_t size = view.size();
    const std::uint8_t* data = view.data();

    if (size < 5) return report;
    std::uint8_t flags = data[4];
    report.is_big_endian = (flags & 0x01) != 0;

    std::size_t offset = 5;

    // Read ULEB128 helper for LuaJIT
    auto read_uleb128 = [&](std::size_t& off) -> std::uint32_t {
        std::uint32_t val = 0;
        int shift = 0;
        while (off < size) {
            std::uint8_t b = data[off++];
            val |= (b & 0x7F) << shift;
            if ((b & 0x80) == 0) break;
            shift += 7;
        }
        return val;
    };

    // If flags & 0x02, chunk contains debug info name
    if (flags & 0x02) {
        std::uint32_t name_len = read_uleb128(offset);
        if (offset + name_len <= size) {
            report.root_function.source_name = std::string(reinterpret_cast<const char*>(data + offset), name_len);
            offset += name_len;
        }
    }

    // Read LuaJIT prototypes
    std::uint32_t proto_idx = 0;
    while (offset < size) {
        std::uint32_t proto_size = read_uleb128(offset);
        if (proto_size == 0 || offset + proto_size > size) break;

        std::size_t p_end = offset + proto_size;
        LuaFunction fn;
        fn.id = proto_idx++;
        if (offset + 4 <= p_end) {
            fn.num_params = data[offset++];
            fn.max_stack_size = data[offset++];
            std::uint8_t nups = data[offset++];
            std::uint8_t ncomplex = data[offset++]; (void)ncomplex;

            for (std::uint8_t u = 0; u < nups; ++u) {
                fn.upvalues.push_back("uv_" + std::to_string(u));
            }
        }

        // Parse instructions in prototype body
        std::uint32_t n_inst = read_uleb128(offset);
        for (std::uint32_t i = 0; i < n_inst && offset + 4 <= p_end; ++i) {
            std::uint32_t ins_raw = load32(data + offset); offset += 4;
            std::uint8_t op = static_cast<std::uint8_t>(ins_raw & 0xFF);
            std::uint8_t a = static_cast<std::uint8_t>((ins_raw >> 8) & 0xFF);
            std::uint8_t c = static_cast<std::uint8_t>((ins_raw >> 16) & 0xFF);
            std::uint8_t b = static_cast<std::uint8_t>((ins_raw >> 24) & 0xFF);

            LuaInstruction ins;
            ins.raw = ins_raw;
            ins.opcode_name = (op < sizeof(kLuaJitOpcodes) / sizeof(kLuaJitOpcodes[0])) ? kLuaJitOpcodes[op] : ("LJ_OP_" + std::to_string(op));
            ins.a = a;
            ins.b = b;
            ins.c = c;
            fn.instructions.push_back(std::move(ins));
        }

        report.total_instructions += fn.instructions.size();
        report.total_functions++;

        if (proto_idx == 1) {
            report.root_function = std::move(fn);
        } else {
            report.root_function.nested_functions.push_back(std::move(fn));
        }

        offset = p_end;
    }

    report.lua_source = to_lua_source(report);
    return report;
}

}  // namespace typemorph::lua
