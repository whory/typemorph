// TypeMorph - monadic error handling for the core and all engines.
//
// The project targets C++20, so std::expected is not available on every
// supported compiler.  Result<T, Error> provides the subset we need (monadic
// map/and_then, value_or, explicit bool) with deterministic error propagation.
#pragma once

#include <functional>
#include <stdexcept>
#include <string>
#include <string_view>
#include <type_traits>
#include <utility>
#include <variant>

namespace typemorph::core {

enum class ErrorCode : std::uint8_t {
    none = 0,
    io,
    out_of_range,
    invalid_argument,
    parse_error,
    unsupported,
    not_found,
    invalid_state,
    runtime_error,
    interrupted,
};

[[nodiscard]] constexpr std::string_view to_string(ErrorCode code) noexcept {
    switch (code) {
    case ErrorCode::none: return "none";
    case ErrorCode::io: return "io";
    case ErrorCode::out_of_range: return "out_of_range";
    case ErrorCode::invalid_argument: return "invalid_argument";
    case ErrorCode::parse_error: return "parse_error";
    case ErrorCode::unsupported: return "unsupported";
    case ErrorCode::not_found: return "not_found";
    case ErrorCode::invalid_state: return "invalid_state";
    case ErrorCode::runtime_error: return "runtime_error";
    case ErrorCode::interrupted: return "interrupted";
    }
    return "unknown";
}

struct Error {
    ErrorCode code = ErrorCode::runtime_error;
    std::string message;
    std::string context;

    [[nodiscard]] std::string to_string() const {
        std::string out;
        out.reserve(message.size() + context.size() + 32);
        out += '[';
        out += typemorph::core::to_string(code);
        out += "] ";
        out += message;
        if (!context.empty()) {
            out += " (";
            out += context;
            out += ')';
        }
        return out;
    }
};

[[nodiscard]] inline Error make_error(ErrorCode code, std::string message, std::string context = {}) {
    return Error{code, std::move(message), std::move(context)};
}

class BadResultAccess : public std::runtime_error {
public:
    explicit BadResultAccess(const Error& error)
        : std::runtime_error("attempted to access a failed Result: " + error.to_string()) {}
};

template <class T>
class Result {
    static_assert(!std::is_reference_v<T>, "Result<T> does not support reference types");
    static_assert(!std::is_void_v<T>, "use Result<void>");

public:
    using value_type = T;

    Result(T value) : storage_(std::in_place_index<0>, std::move(value)) {}
    Result(Error error) : storage_(std::in_place_index<1>, std::move(error)) {}

    [[nodiscard]] bool has_value() const noexcept { return storage_.index() == 0; }
    [[nodiscard]] explicit operator bool() const noexcept { return has_value(); }

    T& value() & {
        if (!has_value()) throw BadResultAccess(std::get<1>(storage_));
        return std::get<0>(storage_);
    }
    const T& value() const& {
        if (!has_value()) throw BadResultAccess(std::get<1>(storage_));
        return std::get<0>(storage_);
    }
    T&& value() && {
        if (!has_value()) throw BadResultAccess(std::get<1>(storage_));
        return std::move(std::get<0>(storage_));
    }

    T& operator*() & { return value(); }
    const T& operator*() const& { return value(); }
    T&& operator*() && { return std::move(*this).value(); }
    T* operator->() { return &value(); }
    const T* operator->() const { return &value(); }

    Error& error() & {
        if (has_value()) throw BadResultAccess(Error{ErrorCode::invalid_state, "result is a value"});
        return std::get<1>(storage_);
    }
    const Error& error() const& {
        if (has_value()) throw BadResultAccess(Error{ErrorCode::invalid_state, "result is a value"});
        return std::get<1>(storage_);
    }
    Error&& error() && {
        if (has_value()) throw BadResultAccess(Error{ErrorCode::invalid_state, "result is a value"});
        return std::move(std::get<1>(storage_));
    }

    template <class U>
    [[nodiscard]] T value_or(U&& fallback) const& {
        return has_value() ? std::get<0>(storage_) : static_cast<T>(std::forward<U>(fallback));
    }

    template <class F>
    [[nodiscard]] auto map(F&& fn) const& -> Result<std::invoke_result_t<F, const T&>> {
        using U = std::invoke_result_t<F, const T&>;
        if (has_value()) return Result<U>(std::invoke(std::forward<F>(fn), std::get<0>(storage_)));
        return Result<U>(std::get<1>(storage_));
    }

    template <class F>
    [[nodiscard]] auto map(F&& fn) && -> Result<std::invoke_result_t<F, T&&>> {
        using U = std::invoke_result_t<F, T&&>;
        if (has_value()) {
            return Result<U>(std::invoke(std::forward<F>(fn), std::move(std::get<0>(storage_))));
        }
        return Result<U>(std::get<1>(storage_));
    }

    template <class F>
    [[nodiscard]] auto and_then(F&& fn) const& -> std::invoke_result_t<F, const T&> {
        using R = std::invoke_result_t<F, const T&>;
        if (has_value()) return std::invoke(std::forward<F>(fn), std::get<0>(storage_));
        return R(std::get<1>(storage_));
    }

    template <class F>
    [[nodiscard]] auto and_then(F&& fn) && -> std::invoke_result_t<F, T&&> {
        using R = std::invoke_result_t<F, T&&>;
        if (has_value()) return std::invoke(std::forward<F>(fn), std::move(std::get<0>(storage_)));
        return R(std::get<1>(storage_));
    }

private:
    std::variant<T, Error> storage_;
};

template <>
class Result<void> {
public:
    using value_type = void;

    Result() noexcept = default;
    Result(Error error) : storage_(std::move(error)) {}

    [[nodiscard]] bool has_value() const noexcept { return storage_.index() == 0; }
    [[nodiscard]] explicit operator bool() const noexcept { return has_value(); }

    void value() const {
        if (!has_value()) throw BadResultAccess(std::get<1>(storage_));
    }

    Error& error() & {
        if (has_value()) throw BadResultAccess(Error{ErrorCode::invalid_state, "result is a value"});
        return std::get<1>(storage_);
    }
    const Error& error() const& {
        if (has_value()) throw BadResultAccess(Error{ErrorCode::invalid_state, "result is a value"});
        return std::get<1>(storage_);
    }
    Error&& error() && {
        if (has_value()) throw BadResultAccess(Error{ErrorCode::invalid_state, "result is a value"});
        return std::move(std::get<1>(storage_));
    }

    template <class F>
    [[nodiscard]] auto and_then(F&& fn) const -> std::invoke_result_t<F> {
        using R = std::invoke_result_t<F>;
        if (has_value()) return std::invoke(std::forward<F>(fn));
        return R(std::get<1>(storage_));
    }

private:
    std::variant<std::monostate, Error> storage_{};
};

template <class T>
using ResultOr = Result<T>;

}  // namespace typemorph::core
