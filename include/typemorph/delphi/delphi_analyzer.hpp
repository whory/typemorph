// TypeMorph - Delphi / C++Builder VCL & Form Rescuer (IDR / DeDe engine)
//
// Extracts and reconstructs:
// - VCL DFM Form resources (binary TPF0/TPF1 and text)
// - Form components (TButton, TEdit, TTimer, etc.), properties, and child hierarchies
// - VMT (Virtual Method Table) with negative offset tables (vmtClassName, vmtParent, vmtMethodTable)
// - Event handler mappings (e.g. OnClick = Button1Click -> VA 0x00452A10)
// - Delphi compiler version identification (Delphi 2 - 12 Athens)
// - Pascal unit stub generation (.pas)
#pragma once

#include "typemorph/core/binary_view.hpp"

#include <cstdint>
#include <string>
#include <vector>

namespace typemorph::delphi {

using core::BinaryView;

struct DfmProperty {
    std::string name;
    std::string type; // string, integer, boolean, float, binary, ident
    std::string value;
};

struct DfmEvent {
    std::string event_name;   // e.g. "OnClick"
    std::string handler_name; // e.g. "Button1Click"
    std::uint64_t handler_rva = 0;
    std::uint64_t handler_va  = 0;
};

struct DfmComponent {
    std::string type_name;      // e.g. "TButton", "TEdit"
    std::string component_name; // e.g. "ButtonSubmit", "EditSerial"
    std::vector<DfmProperty> properties;
    std::vector<DfmEvent> events;
    std::vector<DfmComponent> children;
};

struct DfmForm {
    std::string form_name;
    std::string class_name;
    DfmComponent root_component;
    std::string text_representation;
    std::size_t raw_size = 0;
    bool is_binary_tpf = false;
};

struct DelphiMethod {
    std::string name;
    std::uint64_t address = 0;
    std::string kind; // "virtual", "dynamic", "published"
    int index = 0;
};

struct DelphiClass {
    std::string class_name;
    std::string parent_name;
    std::uint64_t vmt_address = 0;
    std::uint32_t instance_size = 0;
    std::vector<DelphiMethod> methods;
    std::vector<std::string> published_fields;
};

struct DelphiReport {
    bool is_delphi = false;
    std::string compiler_version; // e.g. "Borland Delphi 7.0", "Embarcadero Delphi 11 Alexandria"
    std::vector<DfmForm> forms;
    std::vector<DelphiClass> classes;
    std::vector<DfmEvent> mapped_events;
    std::vector<std::string> packages;
    std::vector<std::string> strings;
};

class DelphiAnalyzer {
public:
    static bool is_delphi(const BinaryView& view);
    static DelphiReport analyze(const BinaryView& view);
    static std::string format_report(const DelphiReport& report);
    static std::string to_pascal_source(const DelphiReport& report);
    static std::string decompile_dfm_binary(std::span<const std::uint8_t> data);
};

} // namespace typemorph::delphi
