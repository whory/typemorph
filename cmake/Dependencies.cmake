# Optional dependency discovery.
#
# TypeMorph's analysis core is dependency-free by design, which makes it
# buildable in air-gapped RE labs and in CI without a package manager.  The
# built-in parser, JSON, TUI and test harness are always compiled.  The
# canonical libraries are still discovered (and can be linked by downstream
# consumers) when they are installed:
#
#   FTXUI          optional rich terminal frontend for downstream apps
#   LIEF           optional executable parser interoperability
#   nlohmann_json  optional JSON interoperability
#   CLI11          optional argument parser interoperability
#   yaml-cpp       optional YAML interoperability
#   Catch2         optional test framework interoperability
#
# Set TYPEMORPH_FETCH_DEPS=ON on a networked machine to acquire them with
# FetchContent.  Pinned tags keep builds reproducible.

set(TYPEMORPH_HAVE_FTXUI OFF)
set(TYPEMORPH_HAVE_LIEF OFF)
set(TYPEMORPH_HAVE_NLOHMANN_JSON OFF)
set(TYPEMORPH_HAVE_CLI11 OFF)
set(TYPEMORPH_HAVE_YAML_CPP OFF)
set(TYPEMORPH_HAVE_CATCH2 OFF)

if(TYPEMORPH_FETCH_DEPS)
    include(FetchContent)

    FetchContent_Declare(
        ftxui
        GIT_REPOSITORY https://github.com/ArthurSonzogni/FTXUI.git
        GIT_TAG v5.0.0
        GIT_SHALLOW TRUE
    )
    FetchContent_Declare(
        lief
        GIT_REPOSITORY https://github.com/lief-project/LIEF.git
        GIT_TAG 0.15.1
        GIT_SHALLOW TRUE
    )
    FetchContent_Declare(
        nlohmann_json
        GIT_REPOSITORY https://github.com/nlohmann/json.git
        GIT_TAG v3.11.3
        GIT_SHALLOW TRUE
    )
    FetchContent_Declare(
        cli11
        GIT_REPOSITORY https://github.com/CLIUtils/CLI11.git
        GIT_TAG v2.4.1
        GIT_SHALLOW TRUE
    )
    FetchContent_Declare(
        yaml-cpp
        GIT_REPOSITORY https://github.com/jbeder/yaml-cpp.git
        GIT_TAG 0.8.0
        GIT_SHALLOW TRUE
    )
    FetchContent_Declare(
        catch2
        GIT_REPOSITORY https://github.com/catchorg/Catch2.git
        GIT_TAG v3.5.2
        GIT_SHALLOW TRUE
    )

    FetchContent_MakeAvailable(ftxui lief nlohmann_json cli11 yaml-cpp catch2)
    set(TYPEMORPH_HAVE_FTXUI ON)
    set(TYPEMORPH_HAVE_LIEF ON)
    set(TYPEMORPH_HAVE_NLOHMANN_JSON ON)
    set(TYPEMORPH_HAVE_CLI11 ON)
    set(TYPEMORPH_HAVE_YAML_CPP ON)
    set(TYPEMORPH_HAVE_CATCH2 ON)
else()
    find_package(ftxui CONFIG QUIET)
    if(ftxui_FOUND)
        set(TYPEMORPH_HAVE_FTXUI ON)
    endif()

    find_package(LIEF CONFIG QUIET)
    if(LIEF_FOUND)
        set(TYPEMORPH_HAVE_LIEF ON)
    endif()

    find_package(nlohmann_json CONFIG QUIET)
    if(nlohmann_json_FOUND)
        set(TYPEMORPH_HAVE_NLOHMANN_JSON ON)
    endif()

    find_package(CLI11 CONFIG QUIET)
    if(CLI11_FOUND)
        set(TYPEMORPH_HAVE_CLI11 ON)
    endif()

    find_package(yaml-cpp CONFIG QUIET)
    if(yaml-cpp_FOUND)
        set(TYPEMORPH_HAVE_YAML_CPP ON)
    endif()

    find_package(Catch2 3 CONFIG QUIET)
    if(Catch2_FOUND)
        set(TYPEMORPH_HAVE_CATCH2 ON)
    endif()
endif()
