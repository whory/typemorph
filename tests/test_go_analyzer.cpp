// TypeMorph - Golang pclntab & Symbol Metadata Reconstructor tests.
#include "test_framework.hpp"

#include "typemorph/go/go_analyzer.hpp"

#include <cstdint>
#include <cstring>
#include <string>
#include <vector>

using namespace typemorph::golang;
using namespace typemorph::core;

TEST_CASE("go: extract package names from symbols") {
    CHECK_EQ(GoAnalyzer::extract_package("main.main"), std::string("main"));
    CHECK_EQ(GoAnalyzer::extract_package("main.init"), std::string("main"));
    CHECK_EQ(GoAnalyzer::extract_package("net/http.Get"), std::string("net/http"));
    CHECK_EQ(GoAnalyzer::extract_package("net/http.(*Server).Serve"), std::string("net/http"));
    CHECK_EQ(GoAnalyzer::extract_package("github.com/gin-gonic/gin.Default"), std::string("github.com/gin-gonic/gin"));
    CHECK_EQ(GoAnalyzer::extract_package("runtime.mallocgc"), std::string("runtime"));
}

TEST_CASE("go: synthetic pclntab recovery (Go 1.2 - 1.15 format)") {
    // Construct a synthetic 64-bit pclntab buffer:
    // Header:
    // [0..3]: magic 0xFFFFFFFB
    // [4..5]: 0, 0
    // [6]: quantum = 1
    // [7]: ptr_size = 8
    // [8..15]: nfunc = 2
    // Functab at offset 16 (2 * 16 = 32 bytes):
    //   Entry 0: (func_va=0x401000, data_off=48)
    //   Entry 1: (func_va=0x401050, data_off=64)
    // Data at offset 48 (func 0):
    //   [48..55]: entry_va = 0x401000
    //   [56..59]: name_off = 80 (relative to pclntab start)
    // Data at offset 64 (func 1):
    //   [64..71]: entry_va = 0x401050
    //   [72..75]: name_off = 96
    // Strings:
    //   Offset 80: "main.init\0"
    //   Offset 96: "main.main\0"

    std::vector<std::uint8_t> buffer(256, 0x00);

    // Magic 0xFFFFFFFB
    *reinterpret_cast<std::uint32_t*>(&buffer[0]) = 0xFFFFFFFB;
    buffer[6] = 1; // quantum
    buffer[7] = 8; // ptr_size

    // nfunc = 2
    *reinterpret_cast<std::uint64_t*>(&buffer[8]) = 2;

    // Functab
    *reinterpret_cast<std::uint64_t*>(&buffer[16]) = 0x401000;
    *reinterpret_cast<std::uint64_t*>(&buffer[24]) = 48;

    *reinterpret_cast<std::uint64_t*>(&buffer[32]) = 0x401050;
    *reinterpret_cast<std::uint64_t*>(&buffer[40]) = 64;

    // Func 0 data
    *reinterpret_cast<std::uint64_t*>(&buffer[48]) = 0x401000;
    *reinterpret_cast<std::int32_t*>(&buffer[56]) = 80;

    // Func 1 data
    *reinterpret_cast<std::uint64_t*>(&buffer[64]) = 0x401050;
    *reinterpret_cast<std::int32_t*>(&buffer[72]) = 96;

    // Strings
    const char* str0 = "main.init";
    const char* str1 = "main.main";
    std::memcpy(&buffer[80], str0, std::strlen(str0) + 1);
    std::memcpy(&buffer[96], str1, std::strlen(str1) + 1);

    BinaryView view = BinaryView::from_owned(std::move(buffer));
    GoAnalyzer analyzer;
    auto rep = analyzer.analyze_view(view);

    REQUIRE(rep.detected);
    CHECK_EQ(rep.ptr_size, std::uint16_t{8});
    CHECK(rep.version == GoPclnVersion::go12);
    REQUIRE_EQ(rep.functions.size(), std::size_t{2});

    CHECK_EQ(rep.functions[0].name, std::string("main.init"));
    CHECK_EQ(rep.functions[0].entry_va, std::uint64_t{0x401000});
    CHECK_EQ(rep.functions[0].package_name, std::string("main"));

    CHECK_EQ(rep.functions[1].name, std::string("main.main"));
    CHECK_EQ(rep.functions[1].entry_va, std::uint64_t{0x401050});
    CHECK_EQ(rep.functions[1].package_name, std::string("main"));

    CHECK_EQ(rep.user_functions, std::size_t{2});
    CHECK_EQ(rep.runtime_functions, std::size_t{0});
}
