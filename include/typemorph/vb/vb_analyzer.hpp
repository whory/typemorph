// TypeMorph - Visual Basic 5.0/6.0 Native & P-Code Analyzer (VB Decompiler engine)
//
// Extracts and reconstructs:
// - VB Header (VB5! magic, project info, runtime version: MSVBVM50 / MSVBVM60)
// - Forms, Modules, and UserControls hierarchy
// - Control definitions (CommandButton, TextBox, Label, Timer, etc.)
// - Event procedures mapping (Form_Load, Command1_Click, Timer1_Timer)
// - Native subroutines and P-Code opcodes (LitVarStr, LitI4, Branch, HardType, etc.)
// - Visual Basic source code reconstruction (.frm / .bas)
#pragma once

#include "typemorph/core/binary_view.hpp"

#include <cstdint>
#include <string>
#include <vector>

namespace typemorph::vb {

using core::BinaryView;

struct VbControl {
    std::string name;
    std::string type; // "CommandButton", "TextBox", "Label", "Timer", etc.
    std::vector<std::pair<std::string, std::string>> properties;
};

struct VbEvent {
    std::string object_name; // e.g. "Command1"
    std::string event_name;  // e.g. "Click"
    std::string full_name;   // e.g. "Command1_Click"
    std::uint64_t code_rva = 0;
    std::uint64_t code_va  = 0;
    bool is_pcode = false;
};

struct VbModule {
    std::string name;
    std::string kind; // "Form", "Module", "Class"
    std::vector<VbControl> controls;
    std::vector<VbEvent> events;
    std::vector<std::string> subroutines;
};

struct VbReport {
    bool is_vb = false;
    bool is_pcode = false; // true = P-Code, false = Native Code
    std::string runtime_version; // "MSVBVM60.DLL" (VB6) or "MSVBVM50.DLL" (VB5)
    std::string project_title;
    std::string app_name;
    std::uint64_t vb_header_offset = 0;
    std::vector<VbModule> modules;
    std::vector<VbEvent> events;
    std::vector<std::string> strings;
};

class VbAnalyzer {
public:
    static bool is_vb(const BinaryView& view);
    static VbReport analyze(const BinaryView& view);
    static std::string format_report(const VbReport& report);
    static std::string to_vb_source(const VbReport& report);
};

} // namespace typemorph::vb
