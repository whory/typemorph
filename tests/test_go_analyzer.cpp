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

TEST_CASE("go: to_golang_source generates valid Go source code") {
    GoAnalysisReport report;
    report.detected = true;
    report.version = GoPclnVersion::go118;
    report.ptr_size = 8;
    report.function_count = 1;

    // Interface
    GoInterfaceType iface;
    iface.name = "Greeter";
    iface.type_va = 0x480000;
    iface.methods.push_back({"Greet", "func()", 0x401020});
    report.interfaces.push_back(iface);

    // Struct
    GoStructType st;
    st.name = "UserSession";
    st.size = 24;
    st.type_va = 0x481000;
    st.fields.push_back({"Token", "string", "json:\"token\"", 0x0});
    st.fields.push_back({"Expires", "int64", "", 0x10});
    report.structs.push_back(st);

    // itab
    GoITab itab;
    itab.itab_va = 0x490000;
    itab.interface_name = "Greeter";
    itab.concrete_type_name = "UserSession";
    itab.methods.push_back({"Greet", "func()", 0x401020});
    report.itabs.push_back(itab);

    // User function
    GoFunction fn;
    fn.name = "main.runServer";
    fn.package_name = "main";
    fn.entry_va = 0x401000;
    fn.frame_size = 32;
    fn.args_size = 8;
    report.functions.push_back(fn);

    std::string go_code = GoAnalyzer::to_golang_source(report);

    CHECK(go_code.find("package main") != std::string::npos);
    CHECK(go_code.find("type Greeter interface {") != std::string::npos);
    CHECK(go_code.find("Greet()") != std::string::npos);
    CHECK(go_code.find("type UserSession struct {") != std::string::npos);
    CHECK(go_code.find("Token string `json:\"token\"` // +0x0") != std::string::npos);
    CHECK(go_code.find("Expires int64 // +0x10") != std::string::npos);
    CHECK(go_code.find("func (recv *UserSession) Greet()") != std::string::npos);
    CHECK(go_code.find("func main.runServer()") != std::string::npos);
}

TEST_CASE("go: synthetic runtime type descriptors and itab recovery") {
    // Construct synthetic 64-bit ELF image with .rodata and .data containing Go itab & struct
    std::vector<std::uint8_t> buffer(4096, 0x00);

    // Section 1: .text (executable, VA 0x401000, file offset 0x100, size 0x100)
    // Section 2: .rodata (read-only, VA 0x402000, file offset 0x200, size 0x400)
    // Section 3: .data (read-write, VA 0x403000, file offset 0x600, size 0x400)

    // In .rodata (file offset 0x200, VA 0x402000):
    // Type name strings at types_base = 0x200:
    // Offset 0x10 (0x210): tag=0x00, len=7, "Greeter"
    buffer[0x210] = 0x00;
    buffer[0x211] = 7;
    std::memcpy(&buffer[0x212], "Greeter", 7);

    // Offset 0x20 (0x220): tag=0x00, len=11, "UserSession"
    buffer[0x220] = 0x00;
    buffer[0x221] = 11;
    std::memcpy(&buffer[0x222], "UserSession", 11);

    // Offset 0x30 (0x230): tag=0x00, len=5, "Token"
    buffer[0x230] = 0x00;
    buffer[0x231] = 5;
    std::memcpy(&buffer[0x232], "Token", 5);

    // Interface _type at 0x250 (VA 0x402050):
    // kind at 0x250 + 23 = 20 (kKindInterface)
    buffer[0x250 + 23] = 20;
    // str offset at 0x250 + 40 = 0x10 ("Greeter")
    *reinterpret_cast<std::int32_t*>(&buffer[0x250 + 40]) = 0x10;

    // Struct _type at 0x280 (VA 0x402080):
    // size at 0x280 = 16
    *reinterpret_cast<std::uint64_t*>(&buffer[0x280]) = 16;
    // align at 0x280 + 21 = 8
    buffer[0x280 + 21] = 8;
    // kind at 0x280 + 23 = 25 (kKindStruct)
    buffer[0x280 + 23] = 25;
    // str offset at 0x280 + 40 = 0x20 ("UserSession")
    *reinterpret_cast<std::int32_t*>(&buffer[0x280 + 40]) = 0x20;
    // fields slice at 0x280 + 56 (VA 0x4020B8):
    // ptr to fields = 0x4020E0 (file offset 0x2E0)
    *reinterpret_cast<std::uint64_t*>(&buffer[0x280 + 56]) = 0x4020E0;
    // len = 1
    *reinterpret_cast<std::uint64_t*>(&buffer[0x280 + 64]) = 1;
    // cap = 1
    *reinterpret_cast<std::uint64_t*>(&buffer[0x280 + 72]) = 1;

    // Field 0 at 0x2E0 (VA 0x4020E0, 24 bytes):
    // name offset = 0x30 ("Token")
    *reinterpret_cast<std::int32_t*>(&buffer[0x2E0]) = 0x30;
    // offset in struct at 0x2E0 + 16 = 0
    *reinterpret_cast<std::uint64_t*>(&buffer[0x2E0 + 16]) = 0;

    // In .data (file offset 0x600, VA 0x403000):
    // itab at 0x600 (VA 0x403000):
    // inter = 0x402050
    *reinterpret_cast<std::uint64_t*>(&buffer[0x600]) = 0x402050;
    // _type = 0x402080
    *reinterpret_cast<std::uint64_t*>(&buffer[0x608]) = 0x402080;
    // hash = 0x12345678
    *reinterpret_cast<std::uint32_t*>(&buffer[0x610]) = 0x12345678;
    // fun[0] = 0x401050 (points into executable .text section)
    *reinterpret_cast<std::uint64_t*>(&buffer[0x618]) = 0x401050;

    ImageParts parts;
    parts.format = ImageFormat::elf;
    parts.bits = 64;
    parts.endian = ByteOrder::little;
    parts.image_base = 0x400000;
    parts.entry_point = 0x401000;
    parts.sections.push_back({".text", 0x401000, 0x100, 0x100, 0x100, SectionFlag::executable});
    parts.sections.push_back({".rodata", 0x402000, 0x400, 0x200, 0x400, SectionFlag::read_only});
    parts.sections.push_back({".data", 0x403000, 0x400, 0x600, 0x400, SectionFlag::writable});

    auto view = BinaryView::from_external(buffer, "synthetic.go.bin");
    auto image = ExecutableImage::from_parts(view, std::move(parts));

    GoAnalyzer analyzer;
    GoAnalysisReport report;
    report.detected = true;
    report.ptr_size = 8;
    analyzer.recover_types(image, report);

    REQUIRE_EQ(report.itabs.size(), std::size_t{1});
    CHECK_EQ(report.itabs[0].interface_name, std::string("Greeter"));
    CHECK_EQ(report.itabs[0].concrete_type_name, std::string("UserSession"));
    REQUIRE_EQ(report.itabs[0].methods.size(), std::size_t{1});
    CHECK_EQ(report.itabs[0].methods[0].fn_va, std::uint64_t{0x401050});

    REQUIRE_EQ(report.structs.size(), std::size_t{1});
    CHECK_EQ(report.structs[0].name, std::string("UserSession"));
    CHECK_EQ(report.structs[0].size, std::uint64_t{16});
    REQUIRE_EQ(report.structs[0].fields.size(), std::size_t{1});
    CHECK_EQ(report.structs[0].fields[0].name, std::string("Token"));
    CHECK_EQ(report.structs[0].fields[0].offset, std::uint64_t{0});
}

