// TypeMorph - .NET / C# Metadata & Code Reconstructor tests.
#include "test_framework.hpp"

#include "typemorph/dotnet/dotnet_analyzer.hpp"

#include <cstdint>
#include <cstring>
#include <string>
#include <vector>

using namespace typemorph::dotnet;
using namespace typemorph::core;

TEST_CASE("dotnet: C# source code generation from reconstructed report") {
    DotNetReport report;
    report.is_dotnet = true;
    report.runtime_version = "v4.0.30319";
    report.type_count = 2;
    report.method_count = 2;
    report.field_count = 2;

    // Type 1: App.Core.IAuthService (interface)
    DotNetType iface;
    iface.name = "IAuthService";
    iface.namespace_name = "App.Core";
    iface.full_name = "App.Core.IAuthService";
    iface.is_public = true;
    iface.is_interface = true;

    DotNetMethod m1;
    m1.name = "Login";
    m1.return_type = "bool";
    m1.is_public = true;
    m1.parameters.push_back({"username", "string", 1});
    m1.parameters.push_back({"password", "string", 2});
    iface.methods.push_back(m1);

    // Type 2: App.Core.Session (class)
    DotNetType cls;
    cls.name = "Session";
    cls.namespace_name = "App.Core";
    cls.full_name = "App.Core.Session";
    cls.base_type = "Object";
    cls.is_public = true;

    DotNetField f1;
    f1.name = "m_token";
    f1.type_name = "string";
    f1.is_private = true;
    f1.is_readonly = true;
    cls.fields.push_back(f1);

    DotNetField f2;
    f2.name = "ExpiresAt";
    f2.type_name = "int";
    f2.is_public = true;
    cls.fields.push_back(f2);

    DotNetMethod m2;
    m2.name = "GetToken";
    m2.return_type = "string";
    m2.is_public = true;
    m2.rva = 0x2050;
    cls.methods.push_back(m2);

    report.types.push_back(iface);
    report.types.push_back(cls);

    std::string cs = DotNetAnalyzer::to_csharp(report);

    CHECK(cs.find("using System;") != std::string::npos);
    CHECK(cs.find("namespace App.Core {") != std::string::npos);
    CHECK(cs.find("public interface IAuthService {") != std::string::npos);
    CHECK(cs.find("bool Login(string username, string password);") != std::string::npos);
    CHECK(cs.find("public class Session {") != std::string::npos);
    CHECK(cs.find("private readonly string m_token;") != std::string::npos);
    CHECK(cs.find("public int ExpiresAt;") != std::string::npos);
    CHECK(cs.find("public string GetToken()") != std::string::npos);
    CHECK(cs.find("IL RVA: 0x2050") != std::string::npos);
}

TEST_CASE("dotnet: synthetic PE with BSJB metadata root recovery") {
    // Build a minimal synthetic PE32 image containing COM descriptor & BSJB metadata
    std::vector<std::uint8_t> buffer(4096, 0x00);

    // 1. DOS Header
    buffer[0] = 'M';
    buffer[1] = 'Z';
    // e_lfanew at 0x3C = 0x80
    *reinterpret_cast<std::uint32_t*>(&buffer[0x3C]) = 0x80;

    // 2. PE Signature at 0x80
    buffer[0x80] = 'P';
    buffer[0x81] = 'E';
    buffer[0x82] = 0;
    buffer[0x83] = 0;

    // COFF Header (20 bytes) at 0x84
    *reinterpret_cast<std::uint16_t*>(&buffer[0x84]) = 0x014C; // Machine: i386
    *reinterpret_cast<std::uint16_t*>(&buffer[0x86]) = 1;      // NumberOfSections: 1
    *reinterpret_cast<std::uint16_t*>(&buffer[0x94]) = 224;    // SizeOfOptionalHeader = 224

    // Optional Header at 0x98 (224 bytes, PE32)
    *reinterpret_cast<std::uint16_t*>(&buffer[0x98]) = 0x10B; // PE32 magic
    *reinterpret_cast<std::uint32_t*>(&buffer[0x98 + 16]) = 0x1000; // AddressOfEntryPoint
    *reinterpret_cast<std::uint32_t*>(&buffer[0x98 + 28]) = 0x00400000; // ImageBase
    *reinterpret_cast<std::uint32_t*>(&buffer[0x98 + 32]) = 0x1000; // SectionAlignment
    *reinterpret_cast<std::uint32_t*>(&buffer[0x98 + 36]) = 0x200;  // FileAlignment
    *reinterpret_cast<std::uint32_t*>(&buffer[0x98 + 68]) = 16;     // NumberOfRvaAndSizes

    // Data Directories start at 0x98 + 96 = 0xF8
    // Entry 14 is COM_DESCRIPTOR (.NET) at 0xF8 + 14 * 8 = 0x168
    // RVA = 0x1000, Size = 72
    *reinterpret_cast<std::uint32_t*>(&buffer[0x168]) = 0x1000;
    *reinterpret_cast<std::uint32_t*>(&buffer[0x16C]) = 72;

    // Section table at 0x98 + 224 = 0x178 (40 bytes per entry)
    std::memcpy(&buffer[0x178], ".text\0\0\0", 8);
    *reinterpret_cast<std::uint32_t*>(&buffer[0x178 + 8]) = 0x1000;  // VirtualSize
    *reinterpret_cast<std::uint32_t*>(&buffer[0x178 + 12]) = 0x1000; // VirtualAddress
    *reinterpret_cast<std::uint32_t*>(&buffer[0x178 + 16]) = 0x800;  // SizeOfRawData
    *reinterpret_cast<std::uint32_t*>(&buffer[0x178 + 20]) = 0x200;  // PointerToRawData
    *reinterpret_cast<std::uint32_t*>(&buffer[0x178 + 36]) = 0x60000020; // Characteristics (RX)

    // Raw section data starts at 0x200 (corresponds to RVA 0x1000)
    // 3. IMAGE_COR20_HEADER at offset 0x200 (72 bytes)
    *reinterpret_cast<std::uint32_t*>(&buffer[0x200]) = 72; // cb
    *reinterpret_cast<std::uint16_t*>(&buffer[0x204]) = 2;  // MajorRuntimeVersion
    *reinterpret_cast<std::uint16_t*>(&buffer[0x206]) = 5;  // MinorRuntimeVersion
    // Metadata directory: RVA = 0x1100, Size = 512
    *reinterpret_cast<std::uint32_t*>(&buffer[0x208]) = 0x1100;
    *reinterpret_cast<std::uint32_t*>(&buffer[0x20C]) = 512;
    *reinterpret_cast<std::uint32_t*>(&buffer[0x214]) = 0x06000001; // EntryPointToken

    // 4. BSJB Metadata root at RVA 0x1100 -> Raw offset 0x300
    const std::size_t bsjb_off = 0x300;
    *reinterpret_cast<std::uint32_t*>(&buffer[bsjb_off]) = 0x424A5342; // "BSJB"
    *reinterpret_cast<std::uint16_t*>(&buffer[bsjb_off + 4]) = 1;      // MajorVersion
    *reinterpret_cast<std::uint16_t*>(&buffer[bsjb_off + 6]) = 1;      // MinorVersion
    *reinterpret_cast<std::uint32_t*>(&buffer[bsjb_off + 8]) = 0;      // Reserved
    // Version length = 12
    const std::string ver_str = "v4.0.30319";
    *reinterpret_cast<std::uint32_t*>(&buffer[bsjb_off + 12]) = static_cast<std::uint32_t>(ver_str.size() + 1);
    std::memcpy(&buffer[bsjb_off + 16], ver_str.c_str(), ver_str.size() + 1);

    auto view = BinaryView::from_external(buffer, "synthetic.net.dll");
    DotNetAnalyzer analyzer;
    auto rep = analyzer.analyze_view(view);

    CHECK(rep.is_dotnet);
    CHECK_EQ(rep.runtime_version, std::string("v4.0.30319"));
    CHECK_EQ(rep.cli_header_rva, std::uint32_t{0x1000});
    CHECK_EQ(rep.metadata_rva, std::uint32_t{0x1100});
    CHECK_EQ(rep.entry_point_token, std::uint32_t{0x06000001});
}
