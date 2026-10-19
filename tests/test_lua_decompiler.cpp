// TypeMorph - Lua & LuaJIT Decompiler Unit Tests
#include "typemorph/lua/lua_decompiler.hpp"
#include "test_framework.hpp"

#include <vector>

namespace typemorph::lua {

TEST_CASE("lua_decompiler: non-lua file rejection") {
    const std::vector<std::uint8_t> dummy = {0x7F, 'E', 'L', 'F', 0x02, 0x01, 0x01, 0x00};
    auto view = core::BinaryView::from_external(dummy, "dummy.elf");

    LuaDecompiler decompiler;
    auto rep = decompiler.decompile(view);

    CHECK(!rep.is_lua_bytecode);
    CHECK(rep.flavor == LuaFlavor::unknown);

    auto src = LuaDecompiler::to_lua_source(rep);
    CHECK(src.find("Error") != std::string::npos);

    auto dis = LuaDecompiler::to_disassembly(rep);
    CHECK(dis.find("Error") != std::string::npos);
}

TEST_CASE("lua_decompiler: synthetic Lua 5.1 bytecode chunk parsing") {
    // Construct a valid Lua 5.1 header + minimal main function
    std::vector<std::uint8_t> chunk = {
        0x1B, 'L', 'u', 'a', // Signature
        0x51,                // Version 5.1
        0x00,                // Format 0 (official)
        0x01,                // Little endian
        0x04,                // sizeof(int)
        0x08,                // sizeof(size_t)
        0x04,                // sizeof(Instruction)
        0x08,                // sizeof(lua_Number)
        0x00                 // Integral flag: float
    };

    // Append function header:
    // source name: len = 6 ("@test\0")
    std::uint64_t s_len = 6;
    for (int i = 0; i < 8; ++i) chunk.push_back(static_cast<std::uint8_t>((s_len >> (i * 8)) & 0xFF));
    chunk.push_back('@'); chunk.push_back('t'); chunk.push_back('e'); chunk.push_back('s'); chunk.push_back('t'); chunk.push_back('\0');

    // line_defined = 0 (4 bytes), last_line_defined = 0 (4 bytes)
    for (int i = 0; i < 8; ++i) chunk.push_back(0);
    // nups = 0, num_params = 0, is_vararg = 2 (VARARG_ISVARARG), max_stack_size = 2
    chunk.push_back(0); chunk.push_back(0); chunk.push_back(2); chunk.push_back(2);

    // Instructions: count = 2 (4 bytes)
    std::uint32_t num_inst = 2;
    for (int i = 0; i < 4; ++i) chunk.push_back(static_cast<std::uint8_t>((num_inst >> (i * 8)) & 0xFF));

    // Instruction 1: GETGLOBAL (opcode 5, a = 0, bx = 0)
    // op(6 bits)=5, a(8 bits)=0, bx(18 bits)=0 -> 0x00000005
    std::uint32_t ins1 = 5;
    for (int i = 0; i < 4; ++i) chunk.push_back(static_cast<std::uint8_t>((ins1 >> (i * 8)) & 0xFF));

    // Instruction 2: RETURN (opcode 30, a = 0, b = 1, c = 0)
    // op(6 bits)=30, a(8 bits)=0, c(9 bits)=0, b(9 bits)=1 -> 30 | (1 << 23)
    std::uint32_t ins2 = 30 | (1U << 23U);
    for (int i = 0; i < 4; ++i) chunk.push_back(static_cast<std::uint8_t>((ins2 >> (i * 8)) & 0xFF));

    // Constants: count = 1 (4 bytes)
    std::uint32_t num_consts = 1;
    for (int i = 0; i < 4; ++i) chunk.push_back(static_cast<std::uint8_t>((num_consts >> (i * 8)) & 0xFF));
    // Constant 0: type = 4 (String), len = 6 ("print\0")
    chunk.push_back(4); // LUA_TSTRING
    std::uint64_t c_len = 6;
    for (int i = 0; i < 8; ++i) chunk.push_back(static_cast<std::uint8_t>((c_len >> (i * 8)) & 0xFF));
    chunk.push_back('p'); chunk.push_back('r'); chunk.push_back('i'); chunk.push_back('n'); chunk.push_back('t'); chunk.push_back('\0');

    // Nested prototypes: count = 0 (4 bytes)
    for (int i = 0; i < 4; ++i) chunk.push_back(0);

    // Debug line info: count = 0 (4 bytes)
    for (int i = 0; i < 4; ++i) chunk.push_back(0);
    // Debug locals: count = 0 (4 bytes)
    for (int i = 0; i < 4; ++i) chunk.push_back(0);
    // Debug upvalues: count = 0 (4 bytes)
    for (int i = 0; i < 4; ++i) chunk.push_back(0);

    auto view = core::BinaryView::from_external(chunk, "test.luac");
    LuaDecompiler decompiler;
    auto rep = decompiler.decompile(view);

    CHECK(rep.is_lua_bytecode);
    CHECK(rep.flavor == LuaFlavor::lua51);
    CHECK(rep.total_functions == 1);
    CHECK(rep.total_instructions == 2);
    CHECK(rep.total_constants == 1);
    CHECK(rep.root_function.source_name == "@test");

    auto disasm = LuaDecompiler::to_disassembly(rep);
    CHECK(disasm.find("GETGLOBAL") != std::string::npos);
    CHECK(disasm.find("RETURN") != std::string::npos);
    CHECK(disasm.find("\"print\"") != std::string::npos);
}

TEST_CASE("lua_decompiler: synthetic LuaJIT 2.0 bytecode chunk parsing") {
    // Construct minimal LuaJIT 2.0 header: \x1bLJ\x01\x00
    std::vector<std::uint8_t> chunk = {
        0x1B, 'L', 'J',
        0x01, // ver = 1 (LuaJIT 2.0)
        0x00  // flags: little endian, no debug name
    };

    // Prototype 1 (main chunk): ULEB128 size = 8
    chunk.push_back(8);
    chunk.push_back(0); // num_params = 0
    chunk.push_back(2); // max_stack = 2
    chunk.push_back(0); // nups = 0
    chunk.push_back(0); // ncomplex = 0

    // Number of instructions = 1
    chunk.push_back(1);
    // Instruction: RET0 (opcode 70 = 0x46)
    chunk.push_back(70); chunk.push_back(0); chunk.push_back(0); chunk.push_back(0);

    auto view = core::BinaryView::from_external(chunk, "test.lj");
    LuaDecompiler decompiler;
    auto rep = decompiler.decompile(view);

    CHECK(rep.is_lua_bytecode);
    CHECK(rep.flavor == LuaFlavor::luajit20);
    CHECK(rep.total_functions >= 1);
}

}  // namespace typemorph::lua
