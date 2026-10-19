// TypeMorph - UNIX-style CLI, JSON stream and JSON-RPC dispatcher.
#pragma once

#include <iosfwd>
#include <span>
#include <string>
#include <string_view>
#include <vector>

namespace typemorph::cli {

struct AppConfig {
    std::string program_name = "typemorph";
    std::string version = "0.1.0";
};

class Application {
public:
    Application(std::ostream& out, std::ostream& err, AppConfig config = {});

    // `args` excludes argv[0].
    int run(std::span<const std::string_view> args);
    int run(const std::vector<std::string>& args);

private:
    std::ostream& out_;
    std::ostream& err_;
    AppConfig config_;
};

int run_cli(int argc, char** argv);

}  // namespace typemorph::cli
