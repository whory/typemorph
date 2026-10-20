// TypeMorph - Standalone Native Desktop GUI Application 
//
// Pure C++20 Win32 native implementation:
// - Left pane: Hierarchical Explorer TreeView (Assemblies, Delphi Forms, DEX Packages, Functions, Strings, Classes, Handlers)
// - Center pane: Multi-language Decompiler & Disassembly Editor (C#, C, Rust, Dalvik, Pascal, VB, Lua)
// - Right/Bottom pane: Diagnostic Inspector, Token List, Log, Security & VM Profiler
// - Comprehensive Menu: File, Decompile, Deobfuscate, Analysis, Tools, View, Help
#pragma once

#ifdef _WIN32

#include "typemorph/core/binary_view.hpp"
#include "typemorph/core/entropy.hpp"
#include "typemorph/dotnet/dotnet_analyzer.hpp"
#include "typemorph/dotnet/dotnet_deobf.hpp"
#include "typemorph/delphi/delphi_analyzer.hpp"
#include "typemorph/dex/dex_analyzer.hpp"
#include "typemorph/vb/vb_analyzer.hpp"
#include "typemorph/autoit/autoit_decompiler.hpp"
#include "typemorph/lua/lua_decompiler.hpp"
#include "typemorph/unpack/vfs_extractor.hpp"
#include "typemorph/unpack/universal_unpacker.hpp"
#include "typemorph/vm/vm_analyzer.hpp"
#include "typemorph/decompile/c_decompiler.hpp"
#include "typemorph/derust/rust_source.hpp"
#include "typemorph/go/go_analyzer.hpp"
#include "typemorph/detect/detect_engine.hpp"
#include "typemorph/pe/iat_reconstructor.hpp"
#include "typemorph/pe/rich_header.hpp"
#include "typemorph/dump/dump_fixer.hpp"
#include "typemorph/crypto/crypto_scanner.hpp"
#include "typemorph/crypto/aes_recovery.hpp"
#include "typemorph/deobf/strings.hpp"
#include "typemorph/deobf/unxorer.hpp"
#include "typemorph/deobf/api_hash_resolver.hpp"
#include "typemorph/deobf/opaque_predicates.hpp"
#include "typemorph/deobf/cff_reconstructor.hpp"
#include "typemorph/deobf/devirtualizer.hpp"
#include "typemorph/rtti/rtti_analyzer.hpp"
#include "typemorph/security/security_analyzer.hpp"
#include "typemorph/abi/calling_convention.hpp"

#include <memory>
#include <string>
#include <vector>

namespace typemorph::gui {

enum class DecompilerMode {
    csharp,
    c_source,
    rust_source,
    go_source,
    dex_java,
    delphi_pascal,
    vb_source,
    autoit_script,
    lua_source,
    vm_profile,
    unpack_summary,
    vfs_summary,
    raw_disasm
};

struct TreeItemInfo {
    std::string title;
    std::string category;
    std::uint64_t va = 0;
    std::size_t size = 0;
    std::string content;
    std::string status_info;
};

class StudioApp {
public:
    StudioApp() = default;
    ~StudioApp() = default;

    int run(const std::string& initial_file = "");

    void open_file(const std::string& path);
    void deobfuscate_current();
    void set_mode(DecompilerMode mode);

    // Analysis & Protection
    void run_detection();
    void run_vm_analysis();
    void run_unpack();
    void run_vfs_extract();
    void run_iat_fix();
    void run_memdump_fix();
    void run_checksec();
    void run_rich_header();
    void run_abi_classifier();

    // Forensics & Cryptography
    void run_crypto_scanner();
    void run_aes_recovery();
    void run_entropy_analysis();
    void run_string_revealer();

    // Deobfuscation & Advanced Reversing
    void run_unxorer();
    void run_apihash_scan();
    void run_opaque_predicates();
    void run_cff_reconstruction();
    void run_classinformer();
    void run_sigmaker();

    // Binary Structure & Subroutine Inspection
    void run_infer();
    void run_dumpsubs();
    void run_applycalletype();
    void save_decompiled_output();

    void populate_tree(const core::BinaryView& view);

private:
    std::string current_file_;
    DecompilerMode mode_ = DecompilerMode::csharp;

    dotnet::DotNetReport dotnet_report_;
    dotnet::DotNetDeobfReport dotnet_deobf_report_;
    delphi::DelphiReport delphi_report_;
    dex::DexReport dex_report_;
    vb::VbReport vb_report_;
    autoit::AutoItReport autoit_report_;
    lua::LuaDecompileReport lua_report_;
    golang::GoAnalysisReport go_report_;
    unpack::VfsContainerReport vfs_report_;
    unpack::UnpackTarget unpack_target_;
    vm::VmProfileReport vm_report_;
    detect::DetectionReport detect_result_;
    decompile::DecompileReport c_report_;
    abi::AbiReport abi_report_;

    std::vector<std::unique_ptr<TreeItemInfo>> tree_items_;

    bool is_deobfuscated_ = false;
};

// Global entry point for launching the native desktop Studio GUI
int run_native_studio(int argc, char** argv);

}  // namespace typemorph::gui

#endif  // _WIN32

