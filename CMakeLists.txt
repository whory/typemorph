cmake_minimum_required(VERSION 3.25)

project(
    TypeMorph
    VERSION 0.7.0
    DESCRIPTION "Binary structure inference, code reconstruction & semantic recovery framework"
    HOMEPAGE_URL "https://github.com/typemorph/typemorph"
    LANGUAGES CXX
)

set(CMAKE_CXX_STANDARD 20)
set(CMAKE_CXX_STANDARD_REQUIRED ON)
set(CMAKE_CXX_EXTENSIONS OFF)
set(CMAKE_EXPORT_COMPILE_COMMANDS ON)

option(TYPEMORPH_BUILD_TESTS "Build unit and integration tests" ON)
option(TYPEMORPH_FETCH_DEPS "Fetch optional third-party dependencies with FetchContent" OFF)
option(TYPEMORPH_WARNINGS_AS_ERRORS "Treat compiler warnings as errors" OFF)

include(cmake/Dependencies.cmake)

# CONFIGURE_DEPENDS lets engine owners add translation units without racing on
# the CMakeLists file.  A fresh configure is still required after removing one.
file(GLOB_RECURSE TYPEMORPH_CORE_SOURCES CONFIGURE_DEPENDS "${PROJECT_SOURCE_DIR}/src/core/*.cpp")
file(GLOB_RECURSE TYPEMORPH_DERUST_SOURCES CONFIGURE_DEPENDS "${PROJECT_SOURCE_DIR}/src/derust/*.cpp")
file(GLOB_RECURSE TYPEMORPH_INFER_SOURCES CONFIGURE_DEPENDS "${PROJECT_SOURCE_DIR}/src/infer/*.cpp")
file(GLOB_RECURSE TYPEMORPH_EMITTER_SOURCES CONFIGURE_DEPENDS "${PROJECT_SOURCE_DIR}/src/emitter/*.cpp")
file(GLOB_RECURSE TYPEMORPH_TUI_SOURCES CONFIGURE_DEPENDS "${PROJECT_SOURCE_DIR}/src/tui/*.cpp")
file(GLOB_RECURSE TYPEMORPH_CLI_SOURCES CONFIGURE_DEPENDS "${PROJECT_SOURCE_DIR}/src/cli/*.cpp")
file(GLOB_RECURSE TYPEMORPH_DEOBF_SOURCES CONFIGURE_DEPENDS "${PROJECT_SOURCE_DIR}/src/deobf/*.cpp")
file(GLOB_RECURSE TYPEMORPH_CRYPTO_SOURCES CONFIGURE_DEPENDS "${PROJECT_SOURCE_DIR}/src/crypto/*.cpp")
file(GLOB_RECURSE TYPEMORPH_DIFF_SOURCES CONFIGURE_DEPENDS "${PROJECT_SOURCE_DIR}/src/diff/*.cpp")
file(GLOB_RECURSE TYPEMORPH_SECURITY_SOURCES CONFIGURE_DEPENDS "${PROJECT_SOURCE_DIR}/src/security/*.cpp")
file(GLOB_RECURSE TYPEMORPH_RTTI_SOURCES CONFIGURE_DEPENDS "${PROJECT_SOURCE_DIR}/src/rtti/*.cpp")
file(GLOB_RECURSE TYPEMORPH_GO_SOURCES CONFIGURE_DEPENDS "${PROJECT_SOURCE_DIR}/src/go/*.cpp")
file(GLOB_RECURSE TYPEMORPH_PE_SOURCES CONFIGURE_DEPENDS "${PROJECT_SOURCE_DIR}/src/pe/*.cpp")
file(GLOB_RECURSE TYPEMORPH_ABI_SOURCES CONFIGURE_DEPENDS "${PROJECT_SOURCE_DIR}/src/abi/*.cpp")
file(GLOB_RECURSE TYPEMORPH_DOTNET_SOURCES CONFIGURE_DEPENDS "${PROJECT_SOURCE_DIR}/src/dotnet/*.cpp")
file(GLOB_RECURSE TYPEMORPH_DECOMPILE_SOURCES CONFIGURE_DEPENDS "${PROJECT_SOURCE_DIR}/src/decompile/*.cpp")
file(GLOB_RECURSE TYPEMORPH_DETECT_SOURCES CONFIGURE_DEPENDS "${PROJECT_SOURCE_DIR}/src/detect/*.cpp")
file(GLOB_RECURSE TYPEMORPH_LUA_SOURCES CONFIGURE_DEPENDS "${PROJECT_SOURCE_DIR}/src/lua/*.cpp")
file(GLOB_RECURSE TYPEMORPH_DELPHI_SOURCES CONFIGURE_DEPENDS "${PROJECT_SOURCE_DIR}/src/delphi/*.cpp")
file(GLOB_RECURSE TYPEMORPH_DEX_SOURCES CONFIGURE_DEPENDS "${PROJECT_SOURCE_DIR}/src/dex/*.cpp")
file(GLOB_RECURSE TYPEMORPH_VB_SOURCES CONFIGURE_DEPENDS "${PROJECT_SOURCE_DIR}/src/vb/*.cpp")
file(GLOB_RECURSE TYPEMORPH_AUTOIT_SOURCES CONFIGURE_DEPENDS "${PROJECT_SOURCE_DIR}/src/autoit/*.cpp")
file(GLOB_RECURSE TYPEMORPH_UNPACK_SOURCES CONFIGURE_DEPENDS "${PROJECT_SOURCE_DIR}/src/unpack/*.cpp")
file(GLOB_RECURSE TYPEMORPH_VM_SOURCES CONFIGURE_DEPENDS "${PROJECT_SOURCE_DIR}/src/vm/*.cpp")
file(GLOB_RECURSE TYPEMORPH_GUI_SOURCES CONFIGURE_DEPENDS "${PROJECT_SOURCE_DIR}/src/gui/*.cpp")

add_library(
    typemorph_core STATIC
    ${TYPEMORPH_CORE_SOURCES}
    ${TYPEMORPH_DERUST_SOURCES}
    ${TYPEMORPH_INFER_SOURCES}
    ${TYPEMORPH_EMITTER_SOURCES}
    ${TYPEMORPH_TUI_SOURCES}
    ${TYPEMORPH_CLI_SOURCES}
    ${TYPEMORPH_DEOBF_SOURCES}
    ${TYPEMORPH_CRYPTO_SOURCES}
    ${TYPEMORPH_DIFF_SOURCES}
    ${TYPEMORPH_SECURITY_SOURCES}
    ${TYPEMORPH_RTTI_SOURCES}
    ${TYPEMORPH_GO_SOURCES}
    ${TYPEMORPH_PE_SOURCES}
    ${TYPEMORPH_ABI_SOURCES}
    ${TYPEMORPH_DOTNET_SOURCES}
    ${TYPEMORPH_DECOMPILE_SOURCES}
    ${TYPEMORPH_DETECT_SOURCES}
    ${TYPEMORPH_LUA_SOURCES}
    ${TYPEMORPH_DELPHI_SOURCES}
    ${TYPEMORPH_DEX_SOURCES}
    ${TYPEMORPH_VB_SOURCES}
    ${TYPEMORPH_AUTOIT_SOURCES}
    ${TYPEMORPH_UNPACK_SOURCES}
    ${TYPEMORPH_VM_SOURCES}
)

add_library(TypeMorph::Core ALIAS typemorph_core)

target_include_directories(
    typemorph_core
    PUBLIC
        "$<BUILD_INTERFACE:${PROJECT_SOURCE_DIR}/include>"
        "$<INSTALL_INTERFACE:include>"
)

target_compile_features(typemorph_core PUBLIC cxx_std_20)
target_compile_definitions(
    typemorph_core
    PUBLIC TYPEMORPH_VERSION="${PROJECT_VERSION}"
    PRIVATE TYPEMORPH_BUILDING_LIBRARY=1
)

if(WIN32)
    target_compile_definitions(typemorph_core PRIVATE NOMINMAX WIN32_LEAN_AND_MEAN UNICODE _UNICODE)
endif()

if(MSVC)
    target_compile_options(
        typemorph_core
        PRIVATE /W4 /permissive- /Zc:__cplusplus /utf-8 /EHsc /MP
    )
    if(TYPEMORPH_WARNINGS_AS_ERRORS)
        target_compile_options(typemorph_core PRIVATE /WX)
    endif()
else()
    target_compile_options(
        typemorph_core
        PRIVATE -Wall -Wextra -Wpedantic -Wshadow -Wconversion -Wsign-conversion
    )
    if(TYPEMORPH_WARNINGS_AS_ERRORS)
        target_compile_options(typemorph_core PRIVATE -Werror)
    endif()
endif()

if(TYPEMORPH_HAVE_FTXUI)
    target_link_libraries(typemorph_core PUBLIC ftxui::component)
    target_compile_definitions(typemorph_core PUBLIC TYPEMORPH_HAVE_FTXUI=1)
endif()
if(TYPEMORPH_HAVE_LIEF)
    target_link_libraries(typemorph_core PUBLIC LIEF::LIEF)
    target_compile_definitions(typemorph_core PUBLIC TYPEMORPH_HAVE_LIEF=1)
endif()
if(TYPEMORPH_HAVE_NLOHMANN_JSON)
    target_compile_definitions(typemorph_core PUBLIC TYPEMORPH_HAVE_NLOHMANN_JSON=1)
endif()

add_executable(typemorph src/main.cpp)
target_link_libraries(typemorph PRIVATE typemorph_core)
target_compile_features(typemorph PRIVATE cxx_std_20)

if(WIN32)
    add_library(typemorph_gui STATIC ${TYPEMORPH_GUI_SOURCES})
    target_link_libraries(typemorph_gui PUBLIC typemorph_core)
    target_compile_features(typemorph_gui PUBLIC cxx_std_20)
    target_compile_definitions(typemorph_gui PRIVATE NOMINMAX WIN32_LEAN_AND_MEAN UNICODE _UNICODE)
    target_link_libraries(typemorph PRIVATE typemorph_gui)
    if(MSVC)
        target_link_options(typemorph PRIVATE /DELAYLOAD:comctl32.dll /DELAYLOAD:comdlg32.dll /DELAYLOAD:user32.dll /DELAYLOAD:gdi32.dll delayimp.lib)
    endif()
endif()

if(MSVC)
    target_compile_options(typemorph PRIVATE /W4 /permissive- /Zc:__cplusplus /utf-8 /EHsc)
endif()

if(TYPEMORPH_BUILD_TESTS)
    enable_testing()
    file(GLOB TYPEMORPH_TEST_SOURCES CONFIGURE_DEPENDS "${PROJECT_SOURCE_DIR}/tests/test_*.cpp")
    add_executable(typemorph_tests tests/main.cpp ${TYPEMORPH_TEST_SOURCES})
    target_link_libraries(typemorph_tests PRIVATE typemorph_core)
    if(WIN32)
        target_link_libraries(typemorph_tests PRIVATE typemorph_gui)
        if(MSVC)
            target_link_options(typemorph_tests PRIVATE /DELAYLOAD:comctl32.dll /DELAYLOAD:comdlg32.dll /DELAYLOAD:user32.dll /DELAYLOAD:gdi32.dll delayimp.lib)
        endif()
    endif()
    target_compile_definitions(
        typemorph_tests
        PRIVATE TYPEMORPH_TEST_FIXTURES="${PROJECT_SOURCE_DIR}/tests/fixtures"
    )
    if(MSVC)
        target_compile_options(typemorph_tests PRIVATE /W4 /permissive- /Zc:__cplusplus /utf-8 /EHsc /bigobj)
    else()
        target_compile_options(typemorph_tests PRIVATE -Wall -Wextra -Wpedantic)
    endif()
    add_test(NAME typemorph.unit COMMAND typemorph_tests)
endif()

install(TARGETS typemorph typemorph_core RUNTIME DESTINATION bin ARCHIVE DESTINATION lib)
install(DIRECTORY include/ DESTINATION include)

message(STATUS "TypeMorph ${PROJECT_VERSION}: ${CMAKE_CXX_COMPILER_ID} ${CMAKE_CXX_COMPILER_VERSION}")
message(STATUS "  optional deps: FTXUI=${TYPEMORPH_HAVE_FTXUI} LIEF=${TYPEMORPH_HAVE_LIEF} JSON=${TYPEMORPH_HAVE_NLOHMANN_JSON}")
message(STATUS "  tests=${TYPEMORPH_BUILD_TESTS} fetch-deps=${TYPEMORPH_FETCH_DEPS}")
