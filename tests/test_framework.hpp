// TypeMorph - tiny self-contained test harness.
//
// Catch2 is used when available, but the test suite must remain runnable in a
// completely offline build.  The subset below (registration, REQUIRE/CHECK,
// CHECK_EQ, CHECK_NEAR, filtering) is intentionally small and deterministic.
#pragma once

#include <cmath>
#include <exception>
#include <functional>
#include <iostream>
#include <sstream>
#include <string>
#include <string_view>
#include <utility>
#include <vector>

namespace tmtest {

struct TestFailure : std::runtime_error {
    using std::runtime_error::runtime_error;
};

struct TestCase {
    std::string name;
    void (*fn)() = nullptr;
};

inline std::vector<TestCase>& registry() {
    static std::vector<TestCase> tests;
    return tests;
}

struct Registrar {
    Registrar(std::string name, void (*fn)()) { registry().push_back(TestCase{std::move(name), fn}); }
};

inline void fail(const char* expression, const char* file, int line, const std::string& detail = {}) {
    std::ostringstream message;
    message << file << ':' << line << ": check failed: " << expression;
    if (!detail.empty()) message << " [" << detail << ']';
    throw TestFailure(message.str());
}

inline void fail_fatal(const char* expression, const char* file, int line,
                       const std::string& detail = {}) {
    fail(expression, file, line, detail);
}

inline int run_all(int argc, char** argv) {
    std::string filter;
    for (int i = 1; i < argc; ++i) {
        const std::string_view arg = argv[i];
        if (arg == "--filter" && i + 1 < argc) {
            filter = argv[++i];
        } else if (arg.rfind("--filter=", 0) == 0) {
            filter = std::string(arg.substr(9));
        }
    }

    std::size_t executed = 0;
    std::size_t failed = 0;
    for (const auto& test : registry()) {
        if (!filter.empty() && test.name.find(filter) == std::string::npos) continue;
        ++executed;
        try {
            test.fn();
            std::cout << "[  PASS  ] " << test.name << '\n';
        } catch (const TestFailure& failure) {
            ++failed;
            std::cout << "[  FAIL  ] " << test.name << "\n           " << failure.what() << '\n';
        } catch (const std::exception& error) {
            ++failed;
            std::cout << "[  FAIL  ] " << test.name << "\n           unexpected exception: " << error.what()
                      << '\n';
        } catch (...) {
            ++failed;
            std::cout << "[  FAIL  ] " << test.name << "\n           unknown exception\n";
        }
    }

    std::cout << "\n" << (executed - failed) << '/' << executed << " tests passed";
    if (failed != 0) std::cout << ", " << failed << " failed";
    std::cout << '\n';
    return failed == 0 && executed != 0 ? 0 : 1;
}

}  // namespace tmtest

#define TM_CONCAT_INNER(a, b) a##b
#define TM_CONCAT(a, b) TM_CONCAT_INNER(a, b)

#define TM_TEST_CASE_IMPL(name, id)                                                       \
    static void TM_CONCAT(tm_test_impl_, id)();                                           \
    static const tmtest::Registrar TM_CONCAT(tm_test_reg_, id)(                           \
        name, &TM_CONCAT(tm_test_impl_, id));                                             \
    static void TM_CONCAT(tm_test_impl_, id)()

#define TEST_CASE(name) TM_TEST_CASE_IMPL(name, __COUNTER__)

#define CHECK(expression)                                                          \
    do {                                                                           \
        if (!(expression))                                                         \
            tmtest::fail(#expression, __FILE__, __LINE__);                         \
    } while (false)

#define REQUIRE(expression)                                                        \
    do {                                                                           \
        if (!(expression))                                                         \
            tmtest::fail_fatal(#expression, __FILE__, __LINE__);                   \
    } while (false)

#define CHECK_EQ(actual, expected)                                                 \
    do {                                                                           \
        /* Copy, not bind: expressions like f()[0] may reference a temporary. */   \
        const auto tm_a = (actual);                                                \
        const auto tm_b = (expected);                                              \
        if (!(tm_a == tm_b)) {                                                     \
            std::ostringstream tm_msg;                                             \
            tm_msg << "actual=" << tm_a << " expected=" << tm_b;                   \
            tmtest::fail(#actual " == " #expected, __FILE__, __LINE__, tm_msg.str()); \
        }                                                                          \
    } while (false)

#define REQUIRE_EQ(actual, expected) CHECK_EQ(actual, expected)

#define CHECK_NEAR(actual, expected, tolerance)                                    \
    do {                                                                           \
        const double tm_a = static_cast<double>(actual);                           \
        const double tm_b = static_cast<double>(expected);                         \
        const double tm_t = static_cast<double>(tolerance);                        \
        if (std::fabs(tm_a - tm_b) > tm_t) {                                       \
            std::ostringstream tm_msg;                                             \
            tm_msg << "actual=" << tm_a << " expected=" << tm_b                    \
                   << " tolerance=" << tm_t;                                       \
            tmtest::fail(#actual " ~= " #expected, __FILE__, __LINE__, tm_msg.str()); \
        }                                                                          \
    } while (false)
