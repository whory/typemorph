#include "typemorph/core/binary_view.hpp"

#include <algorithm>
#include <limits>
#include <system_error>
#include <utility>

#ifdef _WIN32
#include <Windows.h>
#else
#include <fcntl.h>
#include <sys/mman.h>
#include <sys/stat.h>
#include <unistd.h>
#endif

namespace typemorph::core {
namespace {

std::string path_to_utf8(const std::filesystem::path& path) {
#ifdef _WIN32
    const auto utf8 = path.u8string();
    return std::string(utf8.begin(), utf8.end());
#else
    return path.string();
#endif
}

#ifdef _WIN32
std::string windows_error_message(DWORD code) {
    return std::error_code(static_cast<int>(code), std::system_category()).message();
}
#endif

}  // namespace

BinaryView::Storage::~Storage() {
#ifdef _WIN32
    if (mapped) {
        if (data != nullptr) ::UnmapViewOfFile(data);
        if (mapping != nullptr) ::CloseHandle(static_cast<HANDLE>(mapping));
    } else if (mapping != nullptr) {
        ::CloseHandle(static_cast<HANDLE>(mapping));
    }
    if (file != nullptr) ::CloseHandle(static_cast<HANDLE>(file));
#else
    if (mapped && data != nullptr && size != 0) {
        ::munmap(const_cast<std::uint8_t*>(data), size);
    }
    if (fd >= 0) ::close(fd);
#endif
}

Result<BinaryView> BinaryView::open(const std::filesystem::path& path) {
    std::error_code fs_error;
    const bool exists = std::filesystem::exists(path, fs_error);
    if (!exists || fs_error) {
        return make_error(ErrorCode::io, "cannot open binary file",
                          path_to_utf8(path) + (fs_error ? " (" + fs_error.message() + ")" : ""));
    }

    auto storage = std::make_shared<Storage>();
    storage->name = path_to_utf8(path);

#ifdef _WIN32
    const HANDLE file = ::CreateFileW(path.c_str(), GENERIC_READ, FILE_SHARE_READ | FILE_SHARE_WRITE,
                                      nullptr, OPEN_EXISTING, FILE_ATTRIBUTE_NORMAL, nullptr);
    if (file == INVALID_HANDLE_VALUE) {
        return make_error(ErrorCode::io, "CreateFileW failed: " +
                                             windows_error_message(::GetLastError()),
                          storage->name);
    }
    storage->file = file;

    LARGE_INTEGER file_size{};
    if (!::GetFileSizeEx(file, &file_size)) {
        return make_error(ErrorCode::io, "GetFileSizeEx failed: " +
                                             windows_error_message(::GetLastError()),
                          storage->name);
    }
    if (file_size.QuadPart < 0 ||
        static_cast<std::uint64_t>(file_size.QuadPart) > std::numeric_limits<std::size_t>::max()) {
        return make_error(ErrorCode::io, "file is too large to address", storage->name);
    }
    storage->size = static_cast<std::size_t>(file_size.QuadPart);

    if (storage->size != 0) {
        const HANDLE mapping = ::CreateFileMappingW(file, nullptr, PAGE_READONLY, 0, 0, nullptr);
        if (mapping == nullptr) {
            return make_error(ErrorCode::io, "CreateFileMappingW failed: " +
                                                 windows_error_message(::GetLastError()),
                              storage->name);
        }
        storage->mapping = mapping;
        const void* address = ::MapViewOfFile(mapping, FILE_MAP_READ, 0, 0, 0);
        if (address == nullptr) {
            return make_error(ErrorCode::io, "MapViewOfFile failed: " +
                                                 windows_error_message(::GetLastError()),
                              storage->name);
        }
        storage->data = static_cast<const std::uint8_t*>(address);
        storage->mapped = true;
    }
#else
    const int fd = ::open(path.c_str(), O_RDONLY | O_CLOEXEC);
    if (fd < 0) {
        return make_error(ErrorCode::io, "open failed", storage->name);
    }
    storage->fd = fd;
    struct stat info {};
    if (::fstat(fd, &info) != 0 || info.st_size < 0) {
        return make_error(ErrorCode::io, "fstat failed", storage->name);
    }
    if (static_cast<std::uint64_t>(info.st_size) > std::numeric_limits<std::size_t>::max()) {
        return make_error(ErrorCode::io, "file is too large to address", storage->name);
    }
    storage->size = static_cast<std::size_t>(info.st_size);
    if (storage->size != 0) {
        void* address = ::mmap(nullptr, storage->size, PROT_READ, MAP_PRIVATE, fd, 0);
        if (address == MAP_FAILED) {
            return make_error(ErrorCode::io, "mmap failed", storage->name);
        }
        storage->data = static_cast<const std::uint8_t*>(address);
        storage->mapped = true;
    }
#endif

    BinaryView view;
    view.storage_ = std::move(storage);
    view.view_ = std::span<const std::uint8_t>(view.storage_->data, view.storage_->size);
    return view;
}

BinaryView BinaryView::from_owned(std::vector<std::uint8_t> bytes, std::string name) {
    auto storage = std::make_shared<Storage>();
    storage->name = std::move(name);
    storage->owned = std::move(bytes);
    storage->data = storage->owned.data();
    storage->size = storage->owned.size();

    BinaryView view;
    view.storage_ = std::move(storage);
    view.view_ = std::span<const std::uint8_t>(view.storage_->data, view.storage_->size);
    return view;
}

BinaryView BinaryView::from_external(std::span<const std::uint8_t> bytes, std::string name) {
    auto storage = std::make_shared<Storage>();
    storage->name = std::move(name);
    storage->data = bytes.data();
    storage->size = bytes.size();

    BinaryView view;
    view.storage_ = std::move(storage);
    view.view_ = bytes;
    return view;
}

const std::string& BinaryView::name() const noexcept {
    static const std::string empty;
    return storage_ ? storage_->name : empty;
}

}  // namespace typemorph::core
