// TypeMorph - Calling Convention & Function Signature Classifier tests.
#include "test_framework.hpp"

#include "typemorph/abi/calling_convention.hpp"

#include <cstdint>
#include <string>
#include <vector>

using namespace typemorph::abi;
using namespace typemorph::core;

TEST_CASE("abi: x86 stdcall recovery") {
    // push ebp; mov ebp, esp; sub esp, 16; xor eax, eax; leave; ret 12
    const std::vector<std::uint8_t> code = {
        0x55,
        0x89, 0xE5,
        0x83, 0xEC, 0x10,
        0x31, 0xC0,
        0xC9,
        0xC2, 0x0C, 0x00
    };

    AbiClassifier classifier;
    auto sig = classifier.analyze_function_bytes(code, 0x00401000, 32, ImageFormat::pe);

    CHECK_EQ(sig.convention, CallingConvention::x86_stdcall);
    CHECK_EQ(sig.return_kind, ReturnKind::integer);
    CHECK_EQ(sig.return_type_hint, std::string("int32_t"));
    CHECK_EQ(sig.stack_frame_size, std::uint32_t{16});
    CHECK_EQ(sig.stack_purge_bytes, std::uint32_t{12});
    REQUIRE_EQ(sig.arguments.size(), std::size_t{3});
    CHECK_EQ(sig.arguments[0].name, std::string("arg0"));
    CHECK_EQ(sig.arguments[1].name, std::string("arg1"));
    CHECK_EQ(sig.arguments[2].name, std::string("arg2"));
    CHECK(sig.prototype.find("__stdcall") != std::string::npos);
}

TEST_CASE("abi: x86 thiscall recovery") {
    // push ebp; mov ebp, esp; mov eax, [ecx]; leave; ret 8
    const std::vector<std::uint8_t> code = {
        0x55,
        0x89, 0xE5,
        0x8B, 0x01,       // mov eax, [ecx]
        0xC9,
        0xC2, 0x08, 0x00  // ret 8
    };

    AbiClassifier classifier;
    auto sig = classifier.analyze_function_bytes(code, 0x00401020, 32, ImageFormat::pe);

    CHECK_EQ(sig.convention, CallingConvention::x86_thiscall);
    CHECK_EQ(sig.stack_purge_bytes, std::uint32_t{8});
    REQUIRE_EQ(sig.arguments.size(), std::size_t{3});
    CHECK_EQ(sig.arguments[0].name, std::string("this_ptr"));
    CHECK_EQ(sig.arguments[0].location, std::string("ecx"));
    CHECK_EQ(sig.arguments[0].type_hint, std::string("void*"));
    CHECK_EQ(sig.arguments[1].name, std::string("arg1"));
    CHECK_EQ(sig.arguments[2].name, std::string("arg2"));
    CHECK(sig.prototype.find("__thiscall") != std::string::npos);
}

TEST_CASE("abi: x86 fastcall recovery") {
    // push ebp; mov ebp, esp; mov eax, ecx; test edx, edx; leave; ret 4
    const std::vector<std::uint8_t> code = {
        0x55,
        0x89, 0xE5,
        0x89, 0xC8,       // mov eax, ecx
        0x85, 0xD2,       // test edx, edx
        0xC9,
        0xC2, 0x04, 0x00  // ret 4
    };

    AbiClassifier classifier;
    auto sig = classifier.analyze_function_bytes(code, 0x00401040, 32, ImageFormat::pe);

    CHECK_EQ(sig.convention, CallingConvention::x86_fastcall);
    CHECK_EQ(sig.stack_purge_bytes, std::uint32_t{4});
    REQUIRE_EQ(sig.arguments.size(), std::size_t{3}); // ecx, edx + 1 stack arg
    CHECK_EQ(sig.arguments[0].location, std::string("ecx"));
    CHECK_EQ(sig.arguments[1].location, std::string("edx"));
    CHECK(sig.prototype.find("__fastcall") != std::string::npos);
}

TEST_CASE("abi: x86 cdecl recovery") {
    // push ebp; mov ebp, esp; mov eax, [ebp+8]; add eax, [ebp+12]; leave; ret
    const std::vector<std::uint8_t> code = {
        0x55,
        0x89, 0xE5,
        0x8B, 0x45, 0x08, // mov eax, [ebp+8]
        0x03, 0x45, 0x0C, // add eax, [ebp+12]
        0xC9,
        0xC3              // ret
    };

    AbiClassifier classifier;
    auto sig = classifier.analyze_function_bytes(code, 0x00401060, 32, ImageFormat::pe);

    CHECK_EQ(sig.convention, CallingConvention::x86_cdecl);
    CHECK_EQ(sig.stack_purge_bytes, std::uint32_t{0});
    REQUIRE_EQ(sig.arguments.size(), std::size_t{2});
    CHECK(sig.prototype.find("__cdecl") != std::string::npos);
}

TEST_CASE("abi: x64 Windows calling convention recovery") {
    // mov [rsp+8], rcx; mov [rsp+16], rdx; sub rsp, 40; xor eax, eax; add rsp, 40; ret
    const std::vector<std::uint8_t> code = {
        0x48, 0x89, 0x4C, 0x24, 0x08, // mov [rsp+8], rcx
        0x48, 0x89, 0x54, 0x24, 0x10, // mov [rsp+16], rdx
        0x48, 0x83, 0xEC, 0x28,       // sub rsp, 40 (0x28)
        0x31, 0xC0,                   // xor eax, eax
        0x48, 0x83, 0xC4, 0x28,       // add rsp, 40
        0xC3                          // ret
    };

    AbiClassifier classifier;
    auto sig = classifier.analyze_function_bytes(code, 0x140001000, 64, ImageFormat::pe);

    CHECK_EQ(sig.convention, CallingConvention::x64_windows);
    CHECK_EQ(sig.stack_frame_size, std::uint32_t{40});
    REQUIRE_EQ(sig.arguments.size(), std::size_t{2});
    CHECK_EQ(sig.arguments[0].name, std::string("rcx"));
    CHECK_EQ(sig.arguments[1].name, std::string("rdx"));
    CHECK(sig.prototype.find("__win64") != std::string::npos);
}

TEST_CASE("abi: x64 System V calling convention recovery") {
    // endbr64; push rbp; mov rbp, rsp; test rdi, rdi; mov rax, rsi; pop rbp; ret
    const std::vector<std::uint8_t> code = {
        0xF3, 0x0F, 0x1E, 0xFA,       // endbr64
        0x55,
        0x48, 0x89, 0xE5,             // mov rbp, rsp
        0x48, 0x85, 0xFF,             // test rdi, rdi
        0x48, 0x89, 0xF0,             // mov rax, rsi
        0x5D,
        0xC3                          // ret
    };

    AbiClassifier classifier;
    auto sig = classifier.analyze_function_bytes(code, 0x00400500, 64, ImageFormat::elf);

    CHECK_EQ(sig.convention, CallingConvention::x64_sysv);
    REQUIRE_EQ(sig.arguments.size(), std::size_t{2});
    CHECK_EQ(sig.arguments[0].name, std::string("rdi"));
    CHECK_EQ(sig.arguments[1].name, std::string("rsi"));
    CHECK(sig.prototype.find("__sysv") != std::string::npos);
}

TEST_CASE("abi: return type inference (bool and double)") {
    // sete al; ret
    const std::vector<std::uint8_t> code_bool = {
        0x0F, 0x94, 0xC0, // sete al
        0xC3
    };
    AbiClassifier classifier;
    auto sig_bool = classifier.analyze_function_bytes(code_bool, 0x00401080, 32, ImageFormat::pe);
    CHECK_EQ(sig_bool.return_kind, ReturnKind::boolean_type);
    CHECK_EQ(sig_bool.return_type_hint, std::string("bool"));

    // movsd xmm0, [0x403000]; ret
    const std::vector<std::uint8_t> code_float = {
        0xF2, 0x0F, 0x10, 0x05, 0x00, 0x30, 0x40, 0x00,
        0xC3
    };
    auto sig_float = classifier.analyze_function_bytes(code_float, 0x00401090, 32, ImageFormat::pe);
    CHECK_EQ(sig_float.return_kind, ReturnKind::floating_point);
    CHECK_EQ(sig_float.return_type_hint, std::string("double"));
}
