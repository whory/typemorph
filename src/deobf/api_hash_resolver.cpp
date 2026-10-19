// TypeMorph - API Hashing resolver implementation.
#include "typemorph/deobf/api_hash_resolver.hpp"

#include <algorithm>
#include <cstring>

namespace typemorph::deobf {

std::uint32_t ApiHashResolver::compute_ror13(std::string_view name) {
    std::uint32_t hash = 0;
    for (char c : name) {
        hash = (hash >> 13) | (hash << 19);
        hash += static_cast<std::uint8_t>(c);
    }
    return hash;
}

std::uint32_t ApiHashResolver::compute_djb2(std::string_view name) {
    std::uint32_t hash = 5381;
    for (char c : name) {
        hash = ((hash << 5) + hash) + static_cast<std::uint8_t>(c);
    }
    return hash;
}

std::uint32_t ApiHashResolver::compute_sdbm(std::string_view name) {
    std::uint32_t hash = 0;
    for (char c : name) {
        hash = static_cast<std::uint8_t>(c) + (hash << 6) + (hash << 16) - hash;
    }
    return hash;
}

std::uint32_t ApiHashResolver::compute_fnv1a(std::string_view name) {
    std::uint32_t hash = 0x811C9DC5u;
    for (char c : name) {
        hash ^= static_cast<std::uint8_t>(c);
        hash *= 0x01000193u;
    }
    return hash;
}

std::uint32_t ApiHashResolver::compute_crc32(std::string_view name) {
    std::uint32_t crc = 0xFFFFFFFFu;
    for (char c : name) {
        crc ^= static_cast<std::uint8_t>(c);
        for (int k = 0; k < 8; ++k) {
            crc = (crc >> 1) ^ (0xEDB88320u & (-(static_cast<std::int32_t>(crc & 1))));
        }
    }
    return ~crc;
}

ApiHashResolver::ApiHashResolver() {
    init_database();
}

void ApiHashResolver::init_database() {
    struct RawApi {
        const char* module;
        const char* name;
    };

    static const RawApi kApis[] = {
        // Memory management
        {"KERNEL32.DLL", "VirtualAlloc"},
        {"KERNEL32.DLL", "VirtualAllocEx"},
        {"KERNEL32.DLL", "VirtualProtect"},
        {"KERNEL32.DLL", "VirtualProtectEx"},
        {"KERNEL32.DLL", "VirtualFree"},
        {"KERNEL32.DLL", "VirtualFreeEx"},
        {"KERNEL32.DLL", "VirtualQuery"},
        {"KERNEL32.DLL", "VirtualQueryEx"},
        {"KERNEL32.DLL", "HeapAlloc"},
        {"KERNEL32.DLL", "HeapCreate"},
        {"KERNEL32.DLL", "HeapFree"},
        {"KERNEL32.DLL", "HeapDestroy"},
        {"KERNEL32.DLL", "GlobalAlloc"},
        {"KERNEL32.DLL", "LocalAlloc"},

        // Execution & Process creation
        {"KERNEL32.DLL", "CreateThread"},
        {"KERNEL32.DLL", "CreateRemoteThread"},
        {"KERNEL32.DLL", "CreateRemoteThreadEx"},
        {"KERNEL32.DLL", "OpenProcess"},
        {"KERNEL32.DLL", "CreateProcessA"},
        {"KERNEL32.DLL", "CreateProcessW"},
        {"KERNEL32.DLL", "ExitProcess"},
        {"KERNEL32.DLL", "TerminateProcess"},
        {"KERNEL32.DLL", "WriteProcessMemory"},
        {"KERNEL32.DLL", "ReadProcessMemory"},
        {"KERNEL32.DLL", "QueueUserAPC"},
        {"KERNEL32.DLL", "SetThreadContext"},
        {"KERNEL32.DLL", "GetThreadContext"},
        {"KERNEL32.DLL", "ResumeThread"},
        {"KERNEL32.DLL", "SuspendThread"},

        // Module & Symbol resolution
        {"KERNEL32.DLL", "LoadLibraryA"},
        {"KERNEL32.DLL", "LoadLibraryW"},
        {"KERNEL32.DLL", "LoadLibraryExA"},
        {"KERNEL32.DLL", "LoadLibraryExW"},
        {"KERNEL32.DLL", "GetProcAddress"},
        {"KERNEL32.DLL", "GetModuleHandleA"},
        {"KERNEL32.DLL", "GetModuleHandleW"},
        {"KERNEL32.DLL", "GetModuleHandleExA"},
        {"KERNEL32.DLL", "GetModuleFileNameA"},
        {"KERNEL32.DLL", "GetModuleFileNameW"},
        {"KERNEL32.DLL", "FreeLibrary"},

        // File and filesystem
        {"KERNEL32.DLL", "CreateFileA"},
        {"KERNEL32.DLL", "CreateFileW"},
        {"KERNEL32.DLL", "ReadFile"},
        {"KERNEL32.DLL", "WriteFile"},
        {"KERNEL32.DLL", "DeleteFileA"},
        {"KERNEL32.DLL", "DeleteFileW"},
        {"KERNEL32.DLL", "CloseHandle"},
        {"KERNEL32.DLL", "GetTempPathA"},
        {"KERNEL32.DLL", "GetTempPathW"},
        {"KERNEL32.DLL", "GetWindowsDirectoryA"},
        {"KERNEL32.DLL", "GetSystemDirectoryA"},

        // Sync & Timing & Anti-Debug
        {"KERNEL32.DLL", "Sleep"},
        {"KERNEL32.DLL", "WaitForSingleObject"},
        {"KERNEL32.DLL", "WaitForMultipleObjects"},
        {"KERNEL32.DLL", "CreateMutexA"},
        {"KERNEL32.DLL", "CreateMutexW"},
        {"KERNEL32.DLL", "OpenMutexA"},
        {"KERNEL32.DLL", "IsDebuggerPresent"},
        {"KERNEL32.DLL", "CheckRemoteDebuggerPresent"},
        {"KERNEL32.DLL", "SetUnhandledExceptionFilter"},
        {"KERNEL32.DLL", "GetTickCount"},
        {"KERNEL32.DLL", "QueryPerformanceCounter"},

        // NTDLL internals
        {"NTDLL.DLL", "NtAllocateVirtualMemory"},
        {"NTDLL.DLL", "NtProtectVirtualMemory"},
        {"NTDLL.DLL", "NtFreeVirtualMemory"},
        {"NTDLL.DLL", "NtWriteVirtualMemory"},
        {"NTDLL.DLL", "NtReadVirtualMemory"},
        {"NTDLL.DLL", "NtCreateThreadEx"},
        {"NTDLL.DLL", "NtQueueApcThread"},
        {"NTDLL.DLL", "NtOpenProcess"},
        {"NTDLL.DLL", "NtQueryInformationProcess"},
        {"NTDLL.DLL", "NtSetInformationThread"},
        {"NTDLL.DLL", "RtlCreateUserThread"},
        {"NTDLL.DLL", "LdrLoadDll"},
        {"NTDLL.DLL", "LdrGetProcedureAddress"},
        {"NTDLL.DLL", "NtClose"},
        {"NTDLL.DLL", "NtDelayExecution"},

        // USER32 GUI & input
        {"USER32.DLL", "MessageBoxA"},
        {"USER32.DLL", "MessageBoxW"},
        {"USER32.DLL", "ShowWindow"},
        {"USER32.DLL", "GetForegroundWindow"},
        {"USER32.DLL", "GetAsyncKeyState"},
        {"USER32.DLL", "GetKeyState"},
        {"USER32.DLL", "SetWindowsHookExA"},
        {"USER32.DLL", "CallNextHookEx"},
        {"USER32.DLL", "FindWindowA"},
        {"USER32.DLL", "FindWindowW"},
        {"USER32.DLL", "EnumWindows"},

        // ADVAPI32 Registry & Tokens & Services
        {"ADVAPI32.DLL", "RegOpenKeyExA"},
        {"ADVAPI32.DLL", "RegOpenKeyExW"},
        {"ADVAPI32.DLL", "RegQueryValueExA"},
        {"ADVAPI32.DLL", "RegQueryValueExW"},
        {"ADVAPI32.DLL", "RegSetValueExA"},
        {"ADVAPI32.DLL", "RegSetValueExW"},
        {"ADVAPI32.DLL", "RegCloseKey"},
        {"ADVAPI32.DLL", "RegCreateKeyExA"},
        {"ADVAPI32.DLL", "OpenProcessToken"},
        {"ADVAPI32.DLL", "AdjustTokenPrivileges"},
        {"ADVAPI32.DLL", "LookupPrivilegeValueA"},
        {"ADVAPI32.DLL", "CreateServiceA"},
        {"ADVAPI32.DLL", "StartServiceA"},
        {"ADVAPI32.DLL", "OpenSCManagerA"},

        // Network / WS2_32
        {"WS2_32.DLL", "WSAStartup"},
        {"WS2_32.DLL", "WSACleanup"},
        {"WS2_32.DLL", "socket"},
        {"WS2_32.DLL", "connect"},
        {"WS2_32.DLL", "send"},
        {"WS2_32.DLL", "recv"},
        {"WS2_32.DLL", "bind"},
        {"WS2_32.DLL", "listen"},
        {"WS2_32.DLL", "accept"},
        {"WS2_32.DLL", "closesocket"},
        {"WS2_32.DLL", "htons"},
        {"WS2_32.DLL", "inet_addr"},
        {"WS2_32.DLL", "gethostbyname"},

        // WinInet / URLMon
        {"WININET.DLL", "InternetOpenA"},
        {"WININET.DLL", "InternetOpenW"},
        {"WININET.DLL", "InternetOpenUrlA"},
        {"WININET.DLL", "InternetOpenUrlW"},
        {"WININET.DLL", "InternetReadFile"},
        {"WININET.DLL", "HttpOpenRequestA"},
        {"WININET.DLL", "HttpSendRequestA"},
        {"WININET.DLL", "InternetConnectA"},
        {"URLMON.DLL", "URLDownloadToFileA"},
        {"URLMON.DLL", "URLDownloadToFileW"},

        // POSIX / Linux syscalls & libc
        {"LIBC.SO", "mmap"},
        {"LIBC.SO", "mprotect"},
        {"LIBC.SO", "munmap"},
        {"LIBC.SO", "fork"},
        {"LIBC.SO", "execve"},
        {"LIBC.SO", "ptrace"},
        {"LIBDL.SO", "dlopen"},
        {"LIBDL.SO", "dlsym"},
        {"LIBDL.SO", "dlclose"},
    };

    database_.clear();
    database_.reserve(sizeof(kApis) / sizeof(kApis[0]));

    for (const auto& item : kApis) {
        ApiEntry entry;
        entry.module_name = item.module;
        entry.api_name = item.name;
        entry.ror13_hash = compute_ror13(item.name);
        entry.djb2_hash = compute_djb2(item.name);
        entry.sdbm_hash = compute_sdbm(item.name);
        entry.fnv1a_hash = compute_fnv1a(item.name);
        entry.crc32_hash = compute_crc32(item.name);
        database_.push_back(std::move(entry));
    }
}

std::vector<ApiHashMatch> ApiHashResolver::resolve(std::uint32_t hash_value) const {
    std::vector<ApiHashMatch> matches;
    if (hash_value == 0 || hash_value == 0xFFFFFFFFu) return matches;

    for (const auto& entry : database_) {
        if (entry.ror13_hash == hash_value) {
            matches.push_back({0, hash_value, HashAlgorithm::ror13, entry.module_name, entry.api_name, 0.98, "ROR13"});
        }
        if (entry.djb2_hash == hash_value) {
            matches.push_back({0, hash_value, HashAlgorithm::djb2, entry.module_name, entry.api_name, 0.98, "DJB2"});
        }
        if (entry.sdbm_hash == hash_value) {
            matches.push_back({0, hash_value, HashAlgorithm::sdbm, entry.module_name, entry.api_name, 0.98, "SDBM"});
        }
        if (entry.fnv1a_hash == hash_value) {
            matches.push_back({0, hash_value, HashAlgorithm::fnv1a32, entry.module_name, entry.api_name, 0.98, "FNV-1a 32"});
        }
        if (entry.crc32_hash == hash_value) {
            matches.push_back({0, hash_value, HashAlgorithm::crc32, entry.module_name, entry.api_name, 0.95, "CRC32"});
        }
    }
    return matches;
}

std::vector<ApiHashMatch> ApiHashResolver::scan(const core::BinaryView& view, double min_confidence) const {
    std::vector<ApiHashMatch> matches;
    if (!view.valid() || view.size() < 4) return matches;

    const auto bytes = view.bytes();
    for (std::size_t offset = 0; offset + 4 <= bytes.size(); ++offset) {
        // Read 32-bit little-endian value
        const std::uint32_t val_le = static_cast<std::uint32_t>(bytes[offset]) |
                                    (static_cast<std::uint32_t>(bytes[offset + 1]) << 8) |
                                    (static_cast<std::uint32_t>(bytes[offset + 2]) << 16) |
                                    (static_cast<std::uint32_t>(bytes[offset + 3]) << 24);

        if (val_le == 0 || val_le == 0xFFFFFFFFu) continue;

        auto resolved = resolve(val_le);
        for (auto& match : resolved) {
            if (match.confidence >= min_confidence) {
                match.offset = offset;
                matches.push_back(std::move(match));
            }
        }
    }

    return matches;
}

}  // namespace typemorph::deobf
