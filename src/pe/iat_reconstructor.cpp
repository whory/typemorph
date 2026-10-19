// TypeMorph - PE IAT Reconstruction & Import Table Fixer Engine.
#include "typemorph/pe/iat_reconstructor.hpp"

#include <algorithm>
#include <cctype>
#include <cstring>
#include <iomanip>
#include <sstream>
#include <unordered_map>

namespace typemorph::pe {

namespace {

inline std::uint16_t read_u16(const std::uint8_t* p) noexcept {
    return static_cast<std::uint16_t>(p[0]) |
           (static_cast<std::uint16_t>(p[1]) << 8U);
}

inline std::uint32_t read_u32(const std::uint8_t* p) noexcept {
    return static_cast<std::uint32_t>(p[0]) |
           (static_cast<std::uint32_t>(p[1]) << 8U) |
           (static_cast<std::uint32_t>(p[2]) << 16U) |
           (static_cast<std::uint32_t>(p[3]) << 24U);
}

inline std::uint64_t read_u64(const std::uint8_t* p) noexcept {
    return static_cast<std::uint64_t>(read_u32(p)) |
           (static_cast<std::uint64_t>(read_u32(p + 4)) << 32U);
}

inline void write_u16(std::uint8_t* p, std::uint16_t val) noexcept {
    p[0] = static_cast<std::uint8_t>(val & 0xFFU);
    p[1] = static_cast<std::uint8_t>((val >> 8U) & 0xFFU);
}

inline void write_u32(std::uint8_t* p, std::uint32_t val) noexcept {
    p[0] = static_cast<std::uint8_t>(val & 0xFFU);
    p[1] = static_cast<std::uint8_t>((val >> 8U) & 0xFFU);
    p[2] = static_cast<std::uint8_t>((val >> 16U) & 0xFFU);
    p[3] = static_cast<std::uint8_t>((val >> 24U) & 0xFFU);
}

inline void write_u64(std::uint8_t* p, std::uint64_t val) noexcept {
    write_u32(p, static_cast<std::uint32_t>(val & 0xFFFFFFFFU));
    write_u32(p + 4, static_cast<std::uint32_t>((val >> 32U) & 0xFFFFFFFFU));
}

inline std::string to_lower_str(std::string_view s) {
    std::string out;
    out.reserve(s.size());
    for (char c : s) out.push_back(static_cast<char>(std::tolower(static_cast<unsigned char>(c))));
    return out;
}

// ---------------------------------------------------------------------------
// Standard Windows System API database & module dispatching
// ---------------------------------------------------------------------------

struct WinApiEntry {
    const char* module;
    const char* name;
    std::uint16_t ordinal;
    std::uint64_t default_rva_x86;
    std::uint64_t default_rva_x64;
};

// Standard base addresses often seen in typical Windows installations / dump environments
constexpr std::uint64_t kBaseKernel32_x64 = 0x7FFF00000000ULL + 0x20000000ULL;
constexpr std::uint64_t kBaseNtdll_x64    = 0x7FFF00000000ULL + 0x30000000ULL;
constexpr std::uint64_t kBaseUser32_x64   = 0x7FFF00000000ULL + 0x40000000ULL;
constexpr std::uint64_t kBaseAdvapi32_x64 = 0x7FFF00000000ULL + 0x50000000ULL;
constexpr std::uint64_t kBaseWs2_32_x64   = 0x7FFF00000000ULL + 0x60000000ULL;

constexpr std::uint64_t kBaseKernel32_x86 = 0x75000000ULL;
constexpr std::uint64_t kBaseNtdll_x86    = 0x77000000ULL;
constexpr std::uint64_t kBaseUser32_x86   = 0x76000000ULL;
constexpr std::uint64_t kBaseAdvapi32_x86 = 0x74000000ULL;
constexpr std::uint64_t kBaseWs2_32_x86   = 0x71AB0000ULL;

static const WinApiEntry kStandardApis[] = {
    // KERNEL32.DLL
    {"KERNEL32.dll", "GetProcAddress", 0, 0x15340, 0x1F220},
    {"KERNEL32.dll", "GetModuleHandleA", 0, 0x15400, 0x1F300},
    {"KERNEL32.dll", "GetModuleHandleW", 0, 0x15450, 0x1F350},
    {"KERNEL32.dll", "LoadLibraryA", 0, 0x15600, 0x1F500},
    {"KERNEL32.dll", "LoadLibraryW", 0, 0x15650, 0x1F550},
    {"KERNEL32.dll", "ExitProcess", 0, 0x16000, 0x20000},
    {"KERNEL32.dll", "VirtualAlloc", 0, 0x16100, 0x20100},
    {"KERNEL32.dll", "VirtualProtect", 0, 0x16200, 0x20200},
    {"KERNEL32.dll", "VirtualFree", 0, 0x16300, 0x20300},
    {"KERNEL32.dll", "CreateFileA", 0, 0x17000, 0x21000},
    {"KERNEL32.dll", "CreateFileW", 0, 0x17080, 0x21080},
    {"KERNEL32.dll", "ReadFile", 0, 0x17100, 0x21100},
    {"KERNEL32.dll", "WriteFile", 0, 0x17150, 0x21150},
    {"KERNEL32.dll", "CloseHandle", 0, 0x17200, 0x21200},
    {"KERNEL32.dll", "GetLastError", 0, 0x17300, 0x21300},
    {"KERNEL32.dll", "SetLastError", 0, 0x17350, 0x21350},
    {"KERNEL32.dll", "Sleep", 0, 0x18000, 0x22000},
    {"KERNEL32.dll", "GetCurrentProcess", 0, 0x18100, 0x22100},
    {"KERNEL32.dll", "GetCurrentThreadId", 0, 0x18200, 0x22200},
    {"KERNEL32.dll", "GetCurrentProcessId", 0, 0x18250, 0x22250},
    {"KERNEL32.dll", "GetCommandLineA", 0, 0x18300, 0x22300},
    {"KERNEL32.dll", "GetCommandLineW", 0, 0x18350, 0x22350},
    {"KERNEL32.dll", "GetStdHandle", 0, 0x18400, 0x22400},
    {"KERNEL32.dll", "SetUnhandledExceptionFilter", 0, 0x18500, 0x22500},
    {"KERNEL32.dll", "UnhandledExceptionFilter", 0, 0x18550, 0x22550},
    {"KERNEL32.dll", "TerminateProcess", 0, 0x18600, 0x22600},
    {"KERNEL32.dll", "QueryPerformanceCounter", 0, 0x18700, 0x22700},
    {"KERNEL32.dll", "GetSystemTimeAsFileTime", 0, 0x18800, 0x22800},
    {"KERNEL32.dll", "InitializeCriticalSection", 0, 0x18900, 0x22900},
    {"KERNEL32.dll", "EnterCriticalSection", 0, 0x18950, 0x22950},
    {"KERNEL32.dll", "LeaveCriticalSection", 0, 0x189A0, 0x229A0},
    {"KERNEL32.dll", "DeleteCriticalSection", 0, 0x18A00, 0x22A00},
    {"KERNEL32.dll", "TlsAlloc", 0, 0x19000, 0x23000},
    {"KERNEL32.dll", "TlsGetValue", 0, 0x19050, 0x23050},
    {"KERNEL32.dll", "TlsSetValue", 0, 0x190A0, 0x230A0},
    {"KERNEL32.dll", "TlsFree", 0, 0x19100, 0x23100},
    {"KERNEL32.dll", "MultiByteToWideChar", 0, 0x19200, 0x23200},
    {"KERNEL32.dll", "WideCharToMultiByte", 0, 0x19250, 0x23250},
    {"KERNEL32.dll", "IsDebuggerPresent", 0, 0x19300, 0x23300},
    {"KERNEL32.dll", "CheckRemoteDebuggerPresent", 0, 0x19350, 0x23350},
    {"KERNEL32.dll", "OutputDebugStringA", 0, 0x19400, 0x23400},
    {"KERNEL32.dll", "OutputDebugStringW", 0, 0x19450, 0x23450},

    // NTDLL.DLL
    {"ntdll.dll", "NtQueryInformationProcess", 0, 0x11000, 0x1A000},
    {"ntdll.dll", "NtSetInformationThread", 0, 0x11200, 0x1A200},
    {"ntdll.dll", "RtlInitUnicodeString", 0, 0x12000, 0x1B000},
    {"ntdll.dll", "RtlAllocateHeap", 0, 0x12500, 0x1B500},
    {"ntdll.dll", "RtlFreeHeap", 0, 0x12600, 0x1B600},
    {"ntdll.dll", "NtClose", 0, 0x13000, 0x1C000},
    {"ntdll.dll", "LdrLoadDll", 0, 0x14000, 0x1D000},
    {"ntdll.dll", "LdrGetProcedureAddress", 0, 0x14100, 0x1D100},

    // USER32.DLL
    {"USER32.dll", "MessageBoxA", 0, 0x21000, 0x31000},
    {"USER32.dll", "MessageBoxW", 0, 0x21050, 0x31050},
    {"USER32.dll", "CreateWindowExA", 0, 0x22000, 0x32000},
    {"USER32.dll", "CreateWindowExW", 0, 0x22050, 0x32050},
    {"USER32.dll", "DefWindowProcA", 0, 0x23000, 0x33000},
    {"USER32.dll", "DefWindowProcW", 0, 0x23050, 0x33050},
    {"USER32.dll", "ShowWindow", 0, 0x24000, 0x34000},
    {"USER32.dll", "UpdateWindow", 0, 0x24100, 0x34100},
    {"USER32.dll", "GetMessageA", 0, 0x25000, 0x35000},
    {"USER32.dll", "GetMessageW", 0, 0x25050, 0x35050},
    {"USER32.dll", "TranslateMessage", 0, 0x25100, 0x35100},
    {"USER32.dll", "DispatchMessageA", 0, 0x25200, 0x35200},
    {"USER32.dll", "DispatchMessageW", 0, 0x25250, 0x35250},
    {"USER32.dll", "PostQuitMessage", 0, 0x25300, 0x35300},

    // ADVAPI32.DLL
    {"ADVAPI32.dll", "RegOpenKeyExA", 0, 0x31000, 0x41000},
    {"ADVAPI32.dll", "RegOpenKeyExW", 0, 0x31050, 0x41050},
    {"ADVAPI32.dll", "RegQueryValueExA", 0, 0x31100, 0x41100},
    {"ADVAPI32.dll", "RegQueryValueExW", 0, 0x31150, 0x41150},
    {"ADVAPI32.dll", "RegCloseKey", 0, 0x31200, 0x41200},
    {"ADVAPI32.dll", "OpenProcessToken", 0, 0x32000, 0x42000},
    {"ADVAPI32.dll", "GetTokenInformation", 0, 0x32100, 0x42100},

    // WS2_32.DLL
    {"WS2_32.dll", "WSAStartup", 115, 0x1100, 0x2100},
    {"WS2_32.dll", "WSACleanup", 116, 0x1150, 0x2150},
    {"WS2_32.dll", "socket", 23, 0x1200, 0x2200},
    {"WS2_32.dll", "connect", 4, 0x1250, 0x2250},
    {"WS2_32.dll", "send", 19, 0x1300, 0x2300},
    {"WS2_32.dll", "recv", 16, 0x1350, 0x2350},
    {"WS2_32.dll", "closesocket", 3, 0x1400, 0x2400}
};

struct PeHeaderMeta {
    std::uint32_t pe_offset = 0;
    std::uint16_t machine = 0;
    std::uint16_t num_sections = 0;
    std::uint16_t optional_header_size = 0;
    std::uint16_t magic = 0;
    bool pe32plus = false;
    std::uint64_t image_base = 0;
    std::uint32_t entry_point_rva = 0;
    std::uint32_t section_alignment = 0x1000;
    std::uint32_t file_alignment = 0x200;
    std::uint32_t size_of_image = 0;
    std::uint32_t size_of_headers = 0;
    std::uint32_t num_rva_and_sizes = 0;
    std::uint64_t data_directory_offset = 0;
    std::uint32_t import_dir_rva = 0;
    std::uint32_t import_dir_size = 0;
    std::uint32_t iat_dir_rva = 0;
    std::uint32_t iat_dir_size = 0;
    std::uint64_t section_headers_offset = 0;
};

std::optional<PeHeaderMeta> parse_pe_meta(const core::BinaryView& view) {
    if (view.size() < 64) return std::nullopt;
    const std::uint8_t* data = view.data();
    if (data[0] != 'M' || data[1] != 'Z') return std::nullopt;

    const std::uint32_t pe_offset = read_u32(data + 0x3C);
    if (pe_offset + 24 > view.size()) return std::nullopt;
    if (data[pe_offset] != 'P' || data[pe_offset + 1] != 'E' ||
        data[pe_offset + 2] != 0 || data[pe_offset + 3] != 0) {
        return std::nullopt;
    }

    PeHeaderMeta meta;
    meta.pe_offset = pe_offset;
    meta.machine = read_u16(data + pe_offset + 4);
    meta.num_sections = read_u16(data + pe_offset + 6);
    meta.optional_header_size = read_u16(data + pe_offset + 20);

    const std::uint64_t opt_offset = static_cast<std::uint64_t>(pe_offset) + 24U;
    if (opt_offset + meta.optional_header_size > view.size() || meta.optional_header_size < 68) {
        return std::nullopt;
    }

    meta.magic = read_u16(data + opt_offset);
    if (meta.magic != 0x10B && meta.magic != 0x20B) return std::nullopt;
    meta.pe32plus = (meta.magic == 0x20B);

    meta.entry_point_rva = read_u32(data + opt_offset + 16);
    meta.image_base = meta.pe32plus ? read_u64(data + opt_offset + 24)
                                    : read_u32(data + opt_offset + 28);
    meta.section_alignment = read_u32(data + opt_offset + (meta.pe32plus ? 32 : 32));
    meta.file_alignment = read_u32(data + opt_offset + (meta.pe32plus ? 36 : 36));
    meta.size_of_image = read_u32(data + opt_offset + (meta.pe32plus ? 56 : 56));
    meta.size_of_headers = read_u32(data + opt_offset + (meta.pe32plus ? 60 : 60));

    const std::uint64_t num_dir_off = opt_offset + (meta.pe32plus ? 108 : 92);
    if (num_dir_off + 4 <= view.size()) {
        meta.num_rva_and_sizes = read_u32(data + num_dir_off);
    }
    meta.data_directory_offset = opt_offset + (meta.pe32plus ? 112 : 96);
    if (meta.num_rva_and_sizes > 1 && meta.data_directory_offset + 16 <= view.size()) {
        // Index 1 = IMAGE_DIRECTORY_ENTRY_IMPORT
        meta.import_dir_rva = read_u32(data + meta.data_directory_offset + 8);
        meta.import_dir_size = read_u32(data + meta.data_directory_offset + 12);
    }
    if (meta.num_rva_and_sizes > 12 && meta.data_directory_offset + 12 * 8 + 8 <= view.size()) {
        // Index 12 = IMAGE_DIRECTORY_ENTRY_IAT
        meta.iat_dir_rva = read_u32(data + meta.data_directory_offset + 12 * 8);
        meta.iat_dir_size = read_u32(data + meta.data_directory_offset + 12 * 8 + 4);
    }

    meta.section_headers_offset = opt_offset + meta.optional_header_size;
    return meta;
}

struct PeSectionRecord {
    std::string name;
    std::uint32_t virtual_size = 0;
    std::uint32_t virtual_address = 0;
    std::uint32_t raw_size = 0;
    std::uint32_t raw_offset = 0;
    std::uint32_t characteristics = 0;
};

std::vector<PeSectionRecord> parse_sections(const core::BinaryView& view, const PeHeaderMeta& meta) {
    std::vector<PeSectionRecord> sections;
    if (meta.section_headers_offset + meta.num_sections * 40U > view.size()) return sections;

    const std::uint8_t* data = view.data();
    for (std::uint16_t i = 0; i < meta.num_sections; ++i) {
        const std::uint64_t base = meta.section_headers_offset + static_cast<std::uint64_t>(i) * 40U;
        char name_buf[9] = {0};
        std::memcpy(name_buf, data + base, 8);
        PeSectionRecord sec;
        sec.name = std::string(name_buf);
        sec.virtual_size = read_u32(data + base + 8);
        sec.virtual_address = read_u32(data + base + 12);
        sec.raw_size = read_u32(data + base + 16);
        sec.raw_offset = read_u32(data + base + 20);
        sec.characteristics = read_u32(data + base + 36);
        sections.push_back(std::move(sec));
    }
    return sections;
}

std::optional<std::uint64_t> rva_to_file_offset(std::uint32_t rva,
                                                const std::vector<PeSectionRecord>& sections,
                                                std::uint64_t file_size,
                                                std::uint32_t size_of_headers) {
    if (rva < size_of_headers && rva < file_size) return static_cast<std::uint64_t>(rva);
    for (const auto& sec : sections) {
        if (rva >= sec.virtual_address) {
            const std::uint32_t delta = rva - sec.virtual_address;
            if (delta < sec.raw_size && sec.raw_offset + delta < file_size) {
                return static_cast<std::uint64_t>(sec.raw_offset) + delta;
            }
        }
    }
    return std::nullopt;
}

std::optional<std::uint32_t> file_offset_to_rva(std::uint64_t offset,
                                                const std::vector<PeSectionRecord>& sections) {
    for (const auto& sec : sections) {
        if (offset >= sec.raw_offset && offset < sec.raw_offset + sec.raw_size) {
            return sec.virtual_address + static_cast<std::uint32_t>(offset - sec.raw_offset);
        }
    }
    return std::nullopt;
}

// ---------------------------------------------------------------------------
// Thunk Tracing (JMP [mem], JMP imm, PUSH imm; RET)
// ---------------------------------------------------------------------------

struct TraceResult {
    std::uint64_t target_va = 0;
    ThunkResolutionType type = ThunkResolutionType::direct_va;
    std::string comment;
};

TraceResult trace_thunk(std::uint64_t initial_target,
                        const core::BinaryView& view,
                        const PeHeaderMeta& meta,
                        const std::vector<PeSectionRecord>& sections,
                        std::size_t max_depth) {
    std::uint64_t current = initial_target;
    TraceResult res;
    res.target_va = initial_target;
    res.type = ThunkResolutionType::direct_va;

    for (std::size_t depth = 0; depth < max_depth; ++depth) {
        if (current < meta.image_base) break;
        const std::uint64_t rva_64 = current - meta.image_base;
        if (rva_64 > 0xFFFFFFFFULL) break;
        const std::uint32_t rva = static_cast<std::uint32_t>(rva_64);

        auto off_opt = rva_to_file_offset(rva, sections, view.size(), meta.size_of_headers);
        if (!off_opt) break;
        const std::uint64_t off = *off_opt;
        if (off + 16 > view.size()) break;

        const std::uint8_t* p = view.data() + off;

        // Pattern 1: FF 25 xx xx xx xx -> JMP [rip + disp32] (x64) or JMP [abs32] (x86)
        if (p[0] == 0xFF && p[1] == 0x25) {
            res.type = ThunkResolutionType::jmp_thunk;
            if (meta.pe32plus) {
                // x64: relative to next instruction (off + 6)
                const std::int32_t disp = static_cast<std::int32_t>(read_u32(p + 2));
                const std::uint64_t target_ptr_va = current + 6U + static_cast<std::uint64_t>(static_cast<std::int64_t>(disp));
                if (target_ptr_va >= meta.image_base) {
                    const std::uint32_t ptr_rva = static_cast<std::uint32_t>(target_ptr_va - meta.image_base);
                    auto ptr_off = rva_to_file_offset(ptr_rva, sections, view.size(), meta.size_of_headers);
                    if (ptr_off && *ptr_off + 8 <= view.size()) {
                        const std::uint64_t next_va = read_u64(view.data() + *ptr_off);
                        if (next_va != 0 && next_va != current) {
                            res.comment = "traced JMP [RIP+disp]";
                            current = next_va;
                            res.target_va = current;
                            continue;
                        }
                    }
                }
            } else {
                // x86: absolute address
                const std::uint32_t target_ptr_va = read_u32(p + 2);
                if (target_ptr_va >= meta.image_base) {
                    const std::uint32_t ptr_rva = static_cast<std::uint32_t>(target_ptr_va - meta.image_base);
                    auto ptr_off = rva_to_file_offset(ptr_rva, sections, view.size(), meta.size_of_headers);
                    if (ptr_off && *ptr_off + 4 <= view.size()) {
                        const std::uint64_t next_va = read_u32(view.data() + *ptr_off);
                        if (next_va != 0 && next_va != current) {
                            res.comment = "traced JMP [abs32]";
                            current = next_va;
                            res.target_va = current;
                            continue;
                        }
                    }
                }
            }
            break;
        }

        // Pattern 2: E9 xx xx xx xx -> JMP rel32
        if (p[0] == 0xE9) {
            res.type = ThunkResolutionType::jmp_thunk;
            const std::int32_t rel = static_cast<std::int32_t>(read_u32(p + 1));
            const std::uint64_t next_va = current + 5U + static_cast<std::uint64_t>(static_cast<std::int64_t>(rel));
            if (next_va != 0 && next_va != current) {
                res.comment = "traced JMP rel32";
                current = next_va;
                res.target_va = current;
                continue;
            }
            break;
        }

        // Pattern 3: 68 xx xx xx xx C3 -> PUSH imm32; RET (VMP / Themida redirection stub)
        if (p[0] == 0x68 && p[5] == 0xC3) {
            res.type = ThunkResolutionType::push_ret_thunk;
            const std::uint32_t imm = read_u32(p + 1);
            current = imm;
            res.target_va = current;
            res.comment = "traced PUSH imm32; RET stub";
            continue;
        }

        // Pattern 4: 48 B8 xx xx xx xx xx xx xx xx 50 C3 -> MOV RAX, imm64; PUSH RAX; RET
        if (p[0] == 0x48 && p[1] == 0xB8 && p[10] == 0x50 && p[11] == 0xC3) {
            res.type = ThunkResolutionType::push_ret_thunk;
            const std::uint64_t imm64 = read_u64(p + 2);
            current = imm64;
            res.target_va = current;
            res.comment = "traced MOV RAX, imm64; PUSH RAX; RET stub";
            continue;
        }

        // Pattern 5: 48 B8 xx xx xx xx xx xx xx xx FF E0 -> MOV RAX, imm64; JMP RAX
        if (p[0] == 0x48 && p[1] == 0xB8 && p[10] == 0xFF && p[11] == 0xE0) {
            res.type = ThunkResolutionType::jmp_thunk;
            const std::uint64_t imm64 = read_u64(p + 2);
            current = imm64;
            res.target_va = current;
            res.comment = "traced MOV RAX, imm64; JMP RAX stub";
            continue;
        }

        // Pattern 6: B8 xx xx xx xx FF E0 -> MOV EAX, imm32; JMP EAX
        if (p[0] == 0xB8 && p[5] == 0xFF && p[6] == 0xE0) {
            res.type = ThunkResolutionType::jmp_thunk;
            const std::uint32_t imm32 = read_u32(p + 1);
            current = imm32;
            res.target_va = current;
            res.comment = "traced MOV EAX, imm32; JMP EAX stub";
            continue;
        }

        // No more redirection patterns matched
        break;
    }

    return res;
}

}  // namespace

// ---------------------------------------------------------------------------
// Public API implementations
// ---------------------------------------------------------------------------

std::optional<std::pair<std::string, std::string>> IatReconstructor::resolve_api_by_address(
    std::uint64_t address, std::uint16_t bits) {
    if (address == 0) return std::nullopt;

    for (const auto& entry : kStandardApis) {
        if (bits == 64) {
            std::uint64_t base = 0;
            std::string_view mod = entry.module;
            if (mod.find("KERNEL32") != std::string_view::npos) base = kBaseKernel32_x64;
            else if (mod.find("ntdll") != std::string_view::npos) base = kBaseNtdll_x64;
            else if (mod.find("USER32") != std::string_view::npos) base = kBaseUser32_x64;
            else if (mod.find("ADVAPI32") != std::string_view::npos) base = kBaseAdvapi32_x64;
            else if (mod.find("WS2_32") != std::string_view::npos) base = kBaseWs2_32_x64;

            if (base != 0 && (address == base + entry.default_rva_x64 || address == entry.default_rva_x64)) {
                return std::make_pair(std::string(entry.module), std::string(entry.name));
            }
        } else {
            std::uint64_t base = 0;
            std::string_view mod = entry.module;
            if (mod.find("KERNEL32") != std::string_view::npos) base = kBaseKernel32_x86;
            else if (mod.find("ntdll") != std::string_view::npos) base = kBaseNtdll_x86;
            else if (mod.find("USER32") != std::string_view::npos) base = kBaseUser32_x86;
            else if (mod.find("ADVAPI32") != std::string_view::npos) base = kBaseAdvapi32_x86;
            else if (mod.find("WS2_32") != std::string_view::npos) base = kBaseWs2_32_x86;

            if (base != 0 && (address == base + entry.default_rva_x86 || address == entry.default_rva_x86)) {
                return std::make_pair(std::string(entry.module), std::string(entry.name));
            }
        }
    }
    return std::nullopt;
}

bool IatReconstructor::is_known_winapi(std::string_view module_name, std::string_view func_name) {
    const std::string lower_mod = to_lower_str(module_name);
    for (const auto& entry : kStandardApis) {
        if (to_lower_str(entry.module) == lower_mod && entry.name == func_name) {
            return true;
        }
    }
    return false;
}

IatReconstructionReport IatReconstructor::analyze(const core::BinaryView& view) const {
    IatReconstructionReport report;
    auto meta_opt = parse_pe_meta(view);
    if (!meta_opt) {
        return report;
    }
    const auto& meta = *meta_opt;
    report.bits = meta.pe32plus ? 64 : 32;
    report.image_base = meta.image_base != 0 ? meta.image_base : options_.default_image_base;
    report.entry_point = meta.entry_point_rva != 0 ? report.image_base + meta.entry_point_rva : 0;
    report.original_import_rva = meta.import_dir_rva;
    report.original_import_size = meta.import_dir_size;

    const auto sections = parse_sections(view, meta);
    const std::size_t ptr_size = (report.bits == 64) ? 8 : 4;

    // Helper map to group resolved functions by module
    std::unordered_map<std::string, ImportedModule> module_map;

    // 1. First parse standard import table if present and valid
    if (meta.import_dir_rva != 0 && meta.import_dir_size >= 20) {
        auto imp_off_opt = rva_to_file_offset(meta.import_dir_rva, sections, view.size(), meta.size_of_headers);
        if (imp_off_opt && *imp_off_opt + 20 <= view.size()) {
            std::uint64_t curr_desc_off = *imp_off_opt;
            bool descriptors_valid = true;
            while (curr_desc_off + 20 <= view.size()) {
                const std::uint8_t* desc = view.data() + curr_desc_off;
                const std::uint32_t orig_first_thunk = read_u32(desc);
                const std::uint32_t time_stamp = read_u32(desc + 4);
                const std::uint32_t forwarder = read_u32(desc + 8);
                const std::uint32_t name_rva = read_u32(desc + 12);
                const std::uint32_t first_thunk = read_u32(desc + 16);

                if (orig_first_thunk == 0 && time_stamp == 0 && forwarder == 0 &&
                    name_rva == 0 && first_thunk == 0) {
                    // Null descriptor marks end
                    break;
                }

                auto name_off = rva_to_file_offset(name_rva, sections, view.size(), meta.size_of_headers);
                if (!name_off || *name_off >= view.size()) {
                    descriptors_valid = false;
                    break;
                }
                const char* mod_name_raw = reinterpret_cast<const char*>(view.data() + *name_off);
                std::size_t max_len = static_cast<std::size_t>(view.size() - *name_off);
                std::size_t len = 0;
                while (len < max_len && len < 256 && mod_name_raw[len] != '\0') ++len;
                if (len == 0) {
                    descriptors_valid = false;
                    break;
                }
                std::string mod_name(mod_name_raw, len);

                ImportedModule& mod = module_map[to_lower_str(mod_name)];
                if (mod.module_name.empty()) mod.module_name = mod_name;
                mod.first_thunk_rva = first_thunk;
                mod.original_first_thunk_rva = orig_first_thunk;

                // Traverse Thunk table (IAT or INT)
                const std::uint32_t thunk_table_rva = (first_thunk != 0) ? first_thunk : orig_first_thunk;
                auto thunk_off = rva_to_file_offset(thunk_table_rva, sections, view.size(), meta.size_of_headers);
                if (thunk_off) {
                    std::uint64_t curr_thunk_off = *thunk_off;
                    std::uint32_t curr_iat_rva = thunk_table_rva;
                    while (curr_thunk_off + ptr_size <= view.size()) {
                        const std::uint64_t raw_val = (report.bits == 64)
                            ? read_u64(view.data() + curr_thunk_off)
                            : read_u32(view.data() + curr_thunk_off);
                        if (raw_val == 0) break;

                        ImportedFunction fn;
                        fn.iat_rva = curr_iat_rva;
                        fn.iat_va = report.image_base + curr_iat_rva;
                        fn.target_va = raw_val;
                        fn.resolved_target_va = raw_val;

                        // Check ordinal flag
                        const std::uint64_t ord_flag = (report.bits == 64) ? 0x8000000000000000ULL : 0x80000000ULL;
                        if ((raw_val & ord_flag) != 0) {
                            fn.ordinal = static_cast<std::uint16_t>(raw_val & 0xFFFFU);
                            fn.valid = true;
                            fn.comment = "imported by ordinal " + std::to_string(fn.ordinal);
                        } else if (raw_val < view.size() || raw_val < meta.size_of_image) {
                            // Possible hint/name RVA
                            auto hint_off = rva_to_file_offset(static_cast<std::uint32_t>(raw_val), sections, view.size(), meta.size_of_headers);
                            if (hint_off && *hint_off + 2 < view.size()) {
                                fn.ordinal = read_u16(view.data() + *hint_off);
                                const char* fn_str = reinterpret_cast<const char*>(view.data() + *hint_off + 2);
                                std::size_t fn_len = 0;
                                while (*hint_off + 2 + fn_len < view.size() && fn_len < 128 && fn_str[fn_len] != '\0') {
                                    ++fn_len;
                                }
                                if (fn_len > 0) {
                                    fn.name.assign(fn_str, fn_len);
                                    fn.valid = true;
                                }
                            }
                        }

                        // If not resolved by hint/name, try database lookup
                        if (!fn.valid) {
                            auto resolved = resolve_api_by_address(raw_val, report.bits);
                            if (resolved) {
                                fn.name = resolved->second;
                                fn.valid = true;
                                fn.comment = "resolved from API database (" + resolved->first + ")";
                            }
                        }

                        mod.functions.push_back(std::move(fn));
                        curr_thunk_off += ptr_size;
                        curr_iat_rva += static_cast<std::uint32_t>(ptr_size);
                    }
                }

                curr_desc_off += 20;
            }
            if (descriptors_valid && !module_map.empty()) {
                report.original_import_valid = true;
            }
        }
    }

    // 2. Scan sections for IAT thunk tables (pointer runs) if packed, stripped, or requested
    for (const auto& sec : sections) {
        if (sec.raw_size < ptr_size * 2) continue;
        if (sec.raw_offset + sec.raw_size > view.size()) continue;

        const std::uint8_t* sec_data = view.data() + sec.raw_offset;
        const std::size_t max_entries = sec.raw_size / ptr_size;

        std::size_t consecutive = 0;
        std::uint64_t run_start_offset = 0;
        std::size_t resolved_in_run = 0;

        for (std::size_t idx = 0; idx < max_entries; ++idx) {
            const std::uint64_t curr_offset = sec.raw_offset + idx * ptr_size;
            const std::uint64_t val = (report.bits == 64)
                ? read_u64(sec_data + idx * ptr_size)
                : read_u32(sec_data + idx * ptr_size);

            bool is_candidate = false;
            std::optional<std::pair<std::string, std::string>> api_match;
            TraceResult trace_res;

            if (val != 0) {
                // Check if val points outside current module or into known DLL / stub
                if (options_.trace_redirections) {
                    trace_res = trace_thunk(val, view, meta, sections, options_.max_trace_depth);
                } else {
                    trace_res.target_va = val;
                    trace_res.type = ThunkResolutionType::direct_va;
                }

                api_match = resolve_api_by_address(trace_res.target_va, report.bits);
                if (api_match) {
                    is_candidate = true;
                    ++resolved_in_run;
                } else if (val > 0x10000 && val != 0xFFFFFFFFULL) {
                    // General plausible pointer
                    is_candidate = true;
                }
            }

            if (is_candidate) {
                if (consecutive == 0) run_start_offset = curr_offset;
                ++consecutive;
            } else {
                if (consecutive >= 3 && resolved_in_run > 0) {
                    IatSearchRange range;
                    range.start_va = report.image_base + *file_offset_to_rva(run_start_offset, sections);
                    range.end_va = range.start_va + consecutive * ptr_size;
                    range.size = consecutive * ptr_size;
                    range.section_name = sec.name;
                    range.candidate_pointer_count = consecutive;
                    range.resolved_api_count = resolved_in_run;
                    report.discovered_ranges.push_back(range);
                }
                consecutive = 0;
                resolved_in_run = 0;
            }
        }

        if (consecutive >= 3 && resolved_in_run > 0) {
            IatSearchRange range;
            range.start_va = report.image_base + *file_offset_to_rva(run_start_offset, sections);
            range.end_va = range.start_va + consecutive * ptr_size;
            range.size = consecutive * ptr_size;
            range.section_name = sec.name;
            range.candidate_pointer_count = consecutive;
            range.resolved_api_count = resolved_in_run;
            report.discovered_ranges.push_back(range);
        }
    }

    // 3. Populate discovered ranges into modules if original imports were empty / broken
    if (module_map.empty() && !report.discovered_ranges.empty()) {
        for (const auto& range : report.discovered_ranges) {
            const std::uint32_t start_rva = static_cast<std::uint32_t>(range.start_va - report.image_base);
            auto off_opt = rva_to_file_offset(start_rva, sections, view.size(), meta.size_of_headers);
            if (!off_opt) continue;

            const std::size_t num_ptrs = range.candidate_pointer_count;
            for (std::size_t i = 0; i < num_ptrs; ++i) {
                const std::uint64_t ptr_off = *off_opt + i * ptr_size;
                if (ptr_off + ptr_size > view.size()) break;

                const std::uint64_t val = (report.bits == 64)
                    ? read_u64(view.data() + ptr_off)
                    : read_u32(view.data() + ptr_off);
                if (val == 0) continue;

                TraceResult tr = options_.trace_redirections
                    ? trace_thunk(val, view, meta, sections, options_.max_trace_depth)
                    : TraceResult{val, ThunkResolutionType::direct_va, ""};

                auto api = resolve_api_by_address(tr.target_va, report.bits);
                std::string mod_name = api ? api->first : "KERNEL32.dll";
                std::string fn_name = api ? api->second : ("sub_" + std::to_string(val));

                ImportedModule& mod = module_map[to_lower_str(mod_name)];
                if (mod.module_name.empty()) {
                    mod.module_name = mod_name;
                    mod.first_thunk_rva = start_rva;
                }

                ImportedFunction fn;
                fn.name = fn_name;
                fn.iat_rva = start_rva + static_cast<std::uint32_t>(i * ptr_size);
                fn.iat_va = report.image_base + fn.iat_rva;
                fn.target_va = val;
                fn.resolved_target_va = tr.target_va;
                fn.resolution_type = tr.type;
                fn.valid = (api.has_value());
                fn.comment = tr.comment;
                if (tr.type != ThunkResolutionType::direct_va) {
                    ++report.redirected_thunks;
                }
                mod.functions.push_back(std::move(fn));
            }
        }
    }

    // Assemble final modules list
    report.modules.reserve(module_map.size());
    for (auto& [_, mod] : module_map) {
        report.total_functions += mod.functions.size();
        report.resolved_functions += mod.valid_count();
        report.modules.push_back(std::move(mod));
    }

    report.success = !report.modules.empty();
    return report;
}

core::Result<std::vector<std::uint8_t>> IatReconstructor::rebuild_pe(
    const core::BinaryView& view,
    IatReconstructionReport* out_report) const {
    auto report = analyze(view);
    if (!report.success || report.modules.empty()) {
        if (out_report) *out_report = report;
        return core::make_error(core::ErrorCode::parse_error,
                                "cannot rebuild PE: no valid import modules could be resolved");
    }

    auto meta_opt = parse_pe_meta(view);
    if (!meta_opt) {
        if (out_report) *out_report = report;
        return core::make_error(core::ErrorCode::parse_error, "invalid PE binary structure");
    }
    const auto& meta = *meta_opt;
    const auto sections = parse_sections(view, meta);

    // Calculate alignment helpers
    const std::uint32_t sec_align = meta.section_alignment != 0 ? meta.section_alignment : 0x1000;
    const std::uint32_t file_align = meta.file_alignment != 0 ? meta.file_alignment : 0x200;
    const auto align_up = [](std::uint32_t val, std::uint32_t align) {
        return (val + align - 1) & ~(align - 1);
    };

    // Determine new section RVA and file offset
    std::uint32_t max_virtual_end = meta.size_of_headers;
    std::uint32_t max_file_end = meta.size_of_headers;
    for (const auto& sec : sections) {
        const std::uint32_t v_end = sec.virtual_address + align_up(sec.virtual_size, sec_align);
        if (v_end > max_virtual_end) max_virtual_end = v_end;
        const std::uint32_t f_end = sec.raw_offset + sec.raw_size;
        if (f_end > max_file_end) max_file_end = f_end;
    }

    const std::uint32_t new_sec_rva = align_up(max_virtual_end, sec_align);
    const std::uint32_t new_sec_file_offset = align_up(max_file_end, file_align);

    // Reconstruct import tables buffer:
    // Layout in new section:
    // 1. IMAGE_IMPORT_DESCRIPTOR array: (num_modules + 1) * 20 bytes
    // 2. OriginalFirstThunk arrays (INT)
    // 3. FirstThunk arrays (IAT)
    // 4. IMAGE_IMPORT_BY_NAME and DLL name strings
    const std::size_t num_modules = report.modules.size();
    const std::size_t desc_table_size = (num_modules + 1) * 20;

    std::vector<std::uint8_t> new_sec_payload;
    new_sec_payload.resize(desc_table_size, 0x00);

    const std::size_t ptr_size = (report.bits == 64) ? 8 : 4;

    struct ModuleOffsets {
        std::uint32_t name_rva = 0;
        std::uint32_t int_rva = 0;
        std::uint32_t iat_rva = 0;
    };
    std::vector<ModuleOffsets> mod_offsets(num_modules);

    // Build INT & IAT & Strings
    for (std::size_t m = 0; m < num_modules; ++m) {
        const auto& mod = report.modules[m];
        mod_offsets[m].int_rva = new_sec_rva + static_cast<std::uint32_t>(new_sec_payload.size());

        // Allocate space for INT thunks ((num_funcs + 1) * ptr_size)
        const std::size_t thunks_bytes = (mod.functions.size() + 1) * ptr_size;
        const std::size_t int_payload_start = new_sec_payload.size();
        new_sec_payload.resize(new_sec_payload.size() + thunks_bytes, 0x00);

        // Allocate space for IAT thunks ((num_funcs + 1) * ptr_size)
        mod_offsets[m].iat_rva = new_sec_rva + static_cast<std::uint32_t>(new_sec_payload.size());
        const std::size_t iat_payload_start = new_sec_payload.size();
        new_sec_payload.resize(new_sec_payload.size() + thunks_bytes, 0x00);

        // Add DLL name string
        mod_offsets[m].name_rva = new_sec_rva + static_cast<std::uint32_t>(new_sec_payload.size());
        for (char c : mod.module_name) new_sec_payload.push_back(static_cast<std::uint8_t>(c));
        new_sec_payload.push_back(0x00);
        if (new_sec_payload.size() % 2 != 0) new_sec_payload.push_back(0x00);

        // Add IMAGE_IMPORT_BY_NAME structures and write thunks
        for (std::size_t f = 0; f < mod.functions.size(); ++f) {
            const auto& fn = mod.functions[f];
            std::uint64_t thunk_val = 0;

            if (fn.ordinal != 0 && fn.name.empty()) {
                // By ordinal
                const std::uint64_t ord_flag = (report.bits == 64) ? 0x8000000000000000ULL : 0x80000000ULL;
                thunk_val = ord_flag | fn.ordinal;
            } else {
                // By name
                const std::uint32_t ibn_rva = new_sec_rva + static_cast<std::uint32_t>(new_sec_payload.size());
                thunk_val = ibn_rva;

                // Hint (2 bytes)
                new_sec_payload.push_back(static_cast<std::uint8_t>(fn.ordinal & 0xFFU));
                new_sec_payload.push_back(static_cast<std::uint8_t>((fn.ordinal >> 8U) & 0xFFU));
                for (char c : fn.name) new_sec_payload.push_back(static_cast<std::uint8_t>(c));
                new_sec_payload.push_back(0x00);
                if (new_sec_payload.size() % 2 != 0) new_sec_payload.push_back(0x00);
            }

            // Write to INT
            std::uint8_t* int_ptr = new_sec_payload.data() + int_payload_start + f * ptr_size;
            if (report.bits == 64) write_u64(int_ptr, thunk_val);
            else write_u32(int_ptr, static_cast<std::uint32_t>(thunk_val));

            // Write to IAT (initial pointer matches thunk_val or resolved address)
            std::uint8_t* iat_ptr = new_sec_payload.data() + iat_payload_start + f * ptr_size;
            if (report.bits == 64) write_u64(iat_ptr, thunk_val);
            else write_u32(iat_ptr, static_cast<std::uint32_t>(thunk_val));
        }
    }

    // Now fill the IMAGE_IMPORT_DESCRIPTOR descriptors at index 0
    for (std::size_t m = 0; m < num_modules; ++m) {
        std::uint8_t* desc = new_sec_payload.data() + m * 20;
        write_u32(desc + 0, mod_offsets[m].int_rva);   // OriginalFirstThunk (INT)
        write_u32(desc + 4, 0);                         // TimeDateStamp
        write_u32(desc + 8, 0);                         // ForwarderChain
        write_u32(desc + 12, mod_offsets[m].name_rva); // Name RVA
        write_u32(desc + 16, mod_offsets[m].iat_rva);  // FirstThunk (IAT)
    }

    // Align new section payload
    const std::uint32_t new_sec_virtual_size = static_cast<std::uint32_t>(new_sec_payload.size());
    const std::uint32_t new_sec_raw_size = align_up(new_sec_virtual_size, file_align);
    new_sec_payload.resize(new_sec_raw_size, 0x00);

    // Create rebuilt PE file buffer
    std::vector<std::uint8_t> output(view.data(), view.data() + view.size());
    if (output.size() < new_sec_file_offset) {
        output.resize(new_sec_file_offset, 0x00);
    }
    output.insert(output.end(), new_sec_payload.begin(), new_sec_payload.end());

    // Update PE headers in output
    const std::uint64_t pe_off = meta.pe_offset;
    const std::uint64_t opt_off = pe_off + 24U;

    // 1. Increment NumberOfSections
    const std::uint16_t new_num_sections = meta.num_sections + 1;
    write_u16(output.data() + pe_off + 6, new_num_sections);

    // 2. Append new section header
    const std::uint64_t new_sec_hdr_off = meta.section_headers_offset + meta.num_sections * 40U;
    if (new_sec_hdr_off + 40U > meta.size_of_headers) {
        // Space exceeded in headers
        if (out_report) *out_report = report;
        return core::make_error(core::ErrorCode::out_of_range,
                                "insufficient header slack to append new section header");
    }

    std::uint8_t* hdr = output.data() + new_sec_hdr_off;
    std::memset(hdr, 0, 40);
    const std::string sec_name = options_.new_section_name.empty() ? ".typem" : options_.new_section_name;
    std::memcpy(hdr, sec_name.c_str(), std::min<std::size_t>(sec_name.size(), 8));
    write_u32(hdr + 8, new_sec_virtual_size);
    write_u32(hdr + 12, new_sec_rva);
    write_u32(hdr + 16, new_sec_raw_size);
    write_u32(hdr + 20, new_sec_file_offset);
    // Characteristics: IMAGE_SCN_MEM_READ | IMAGE_SCN_MEM_WRITE | IMAGE_SCN_CNT_INITIALIZED_DATA
    constexpr std::uint32_t kSecFlags = 0x40000000U | 0x80000000U | 0x00000040U;
    write_u32(hdr + 36, kSecFlags);

    // 3. Update SizeOfImage in OptionalHeader
    const std::uint32_t new_size_of_image = new_sec_rva + align_up(new_sec_virtual_size, sec_align);
    write_u32(output.data() + opt_off + (meta.pe32plus ? 56 : 56), new_size_of_image);

    // 4. Update Import Table Data Directory (Index 1)
    write_u32(output.data() + meta.data_directory_offset + 8, new_sec_rva);
    write_u32(output.data() + meta.data_directory_offset + 12, static_cast<std::uint32_t>(desc_table_size));

    // Update report
    report.binary_patched = true;
    report.new_import_rva = new_sec_rva;
    report.new_import_size = static_cast<std::uint32_t>(desc_table_size);
    report.new_section_name = sec_name;
    report.patched_binary_size = output.size();

    if (out_report) *out_report = report;
    return output;
}

std::string IatReconstructor::to_text_summary(const IatReconstructionReport& rep) {
    std::ostringstream ss;
    char hex_buf[32];

    ss << "TypeMorph IAT Reconstruction & Import Table Fixer\n";
    ss << "=================================================\n";
    std::snprintf(hex_buf, sizeof(hex_buf), "0x%llx", static_cast<unsigned long long>(rep.image_base));
    ss << "Target Architecture : PE" << rep.bits << " (Image Base: " << hex_buf << ")\n";

    std::snprintf(hex_buf, sizeof(hex_buf), "0x%llx", static_cast<unsigned long long>(rep.entry_point));
    ss << "Entry Point Address : " << hex_buf << "\n";

    ss << "Original Import Dir : "
       << (rep.original_import_valid ? "Valid" : (rep.original_import_rva != 0 ? "Corrupted / Hooked" : "Stripped / None"))
       << " (RVA: 0x" << std::hex << rep.original_import_rva << ", Size: 0x" << rep.original_import_size << std::dec << ")\n\n";

    if (!rep.discovered_ranges.empty()) {
        ss << "Discovered Candidate IAT Ranges (" << rep.discovered_ranges.size() << "):\n";
        for (const auto& rng : rep.discovered_ranges) {
            std::snprintf(hex_buf, sizeof(hex_buf), "0x%llx - 0x%llx",
                          static_cast<unsigned long long>(rng.start_va),
                          static_cast<unsigned long long>(rng.end_va));
            ss << "  [" << rng.section_name << "] " << hex_buf
               << " (" << rng.size << "B, " << rng.candidate_pointer_count << " pointers, "
               << rng.resolved_api_count << " APIs resolved)\n";
        }
        ss << "\n";
    }

    ss << "Reconstructed Import Modules (" << rep.modules.size() << " modules, "
       << rep.resolved_functions << "/" << rep.total_functions << " APIs resolved):\n";

    for (const auto& mod : rep.modules) {
        ss << "  Module: " << mod.module_name << " (" << mod.valid_count() << "/" << mod.functions.size() << " valid)\n";
        for (const auto& fn : mod.functions) {
            std::snprintf(hex_buf, sizeof(hex_buf), "0x%llx", static_cast<unsigned long long>(fn.iat_va));
            ss << "    [" << hex_buf << "] ";
            if (!fn.name.empty()) {
                ss << fn.name;
            } else {
                ss << "Ordinal #" << fn.ordinal;
            }
            if (fn.resolution_type != ThunkResolutionType::direct_va) {
                ss << " [" << to_string(fn.resolution_type) << "]";
            }
            if (!fn.comment.empty()) {
                ss << " (" << fn.comment << ")";
            }
            ss << "\n";
        }
    }

    if (rep.binary_patched) {
        ss << "\nBinary Rebuilding & Import Injection:\n";
        ss << "  Status          : PE patched successfully\n";
        ss << "  New Section     : " << rep.new_section_name << "\n";
        ss << "  New Import RVA  : 0x" << std::hex << rep.new_import_rva << std::dec << "\n";
        ss << "  New Import Size : 0x" << std::hex << rep.new_import_size << std::dec << " bytes\n";
        ss << "  Patched File Size: " << rep.patched_binary_size << " bytes\n";
    }

    return ss.str();
}

}  // namespace typemorph::pe
