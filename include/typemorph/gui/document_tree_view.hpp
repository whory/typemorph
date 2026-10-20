// TypeMorph - Native C++ port of dnSpy DocumentTreeView Architecture
// (DocumentTreeView.cs, AssemblyDocumentNodeImpl.cs, NamespaceNodeImpl.cs, TypeNodeImpl.cs, MethodNodeImpl.cs)
#pragma once

#ifdef _WIN32
#ifndef WIN32_LEAN_AND_MEAN
#define WIN32_LEAN_AND_MEAN
#endif
#ifndef NOMINMAX
#define NOMINMAX
#endif

#include <windows.h>
#include <commctrl.h>
#include <string>
#include <vector>
#include <memory>
#include <functional>
#include <cstdint>

namespace typemorph::gui {

enum class DocumentNodeType {
    Root,
    Assembly,
    Module,
    ReferencesFolder,
    AssemblyReference,
    ResourcesFolder,
    Resource,
    Namespace,
    TypeClass,
    TypeInterface,
    TypeStruct,
    TypeEnum,
    Method,
    Constructor,
    Property,
    Field,
    Event,
    BaseTypesFolder,
    DerivedTypesFolder,
    // Native Extensions
    DelphiForm,
    DelphiEvent,
    DexPackage,
    DexClass,
    NativeSubroutine,
    VmEntry,
    Unknown
};

class DocumentTreeNodeData {
public:
    virtual ~DocumentTreeNodeData() = default;

    [[nodiscard]] virtual DocumentNodeType node_type() const = 0;
    [[nodiscard]] virtual std::string text() const = 0;
    [[nodiscard]] virtual std::string tooltip() const { return text(); }
    [[nodiscard]] virtual std::string decompiled_code() const { return ""; }
    [[nodiscard]] virtual std::uint64_t rva_or_va() const { return 0; }
    [[nodiscard]] virtual bool has_children() const { return !children_.empty(); }

    void add_child(std::shared_ptr<DocumentTreeNodeData> child) {
        if (child) children_.push_back(std::move(child));
    }

    [[nodiscard]] const std::vector<std::shared_ptr<DocumentTreeNodeData>>& children() const {
        return children_;
    }

private:
    std::vector<std::shared_ptr<DocumentTreeNodeData>> children_;
};

// Node Implementations
class AssemblyDocumentNode : public DocumentTreeNodeData {
public:
    explicit AssemblyDocumentNode(std::string name, std::string full_path)
        : name_(std::move(name)), path_(std::move(full_path)) {}

    [[nodiscard]] DocumentNodeType node_type() const override { return DocumentNodeType::Assembly; }
    [[nodiscard]] std::string text() const override { return name_; }
    [[nodiscard]] std::string tooltip() const override { return path_; }

private:
    std::string name_;
    std::string path_;
};

class NamespaceNode : public DocumentTreeNodeData {
public:
    explicit NamespaceNode(std::string ns_name) : ns_name_(std::move(ns_name)) {}

    [[nodiscard]] DocumentNodeType node_type() const override { return DocumentNodeType::Namespace; }
    [[nodiscard]] std::string text() const override { return ns_name_.empty() ? "-" : ns_name_; }

private:
    std::string ns_name_;
};

class TypeDocumentNode : public DocumentTreeNodeData {
public:
    TypeDocumentNode(std::string name, std::string full_name, std::string code, DocumentNodeType type = DocumentNodeType::TypeClass)
        : name_(std::move(name)), full_name_(std::move(full_name)), code_(std::move(code)), type_(type) {}

    [[nodiscard]] DocumentNodeType node_type() const override { return type_; }
    [[nodiscard]] std::string text() const override { return name_; }
    [[nodiscard]] std::string tooltip() const override { return full_name_; }
    [[nodiscard]] std::string decompiled_code() const override { return code_; }

private:
    std::string name_;
    std::string full_name_;
    std::string code_;
    DocumentNodeType type_;
};

class MethodDocumentNode : public DocumentTreeNodeData {
public:
    MethodDocumentNode(std::string name, std::string signature, std::string code, std::uint64_t rva = 0)
        : name_(std::move(name)), signature_(std::move(signature)), code_(std::move(code)), rva_(rva) {}

    [[nodiscard]] DocumentNodeType node_type() const override {
        return (name_ == ".ctor" || name_ == ".cctor") ? DocumentNodeType::Constructor : DocumentNodeType::Method;
    }
    [[nodiscard]] std::string text() const override { return signature_.empty() ? name_ : signature_; }
    [[nodiscard]] std::string tooltip() const override { return signature_; }
    [[nodiscard]] std::string decompiled_code() const override { return code_; }
    [[nodiscard]] std::uint64_t rva_or_va() const override { return rva_; }

private:
    std::string name_;
    std::string signature_;
    std::string code_;
    std::uint64_t rva_ = 0;
};

// C++ Port of dnSpy DocumentTreeView
class DocumentTreeView {
public:
    DocumentTreeView() = default;
    ~DocumentTreeView();

    void create(HWND hwnd_parent, int id, RECT bounds);
    void set_bounds(int x, int y, int width, int height);

    void clear();
    void set_root_node(std::shared_ptr<DocumentTreeNodeData> root);

    using NodeSelectedHandler = std::function<void(std::shared_ptr<DocumentTreeNodeData>)>;
    void set_on_node_selected(NodeSelectedHandler handler) {
        on_node_selected_ = std::move(handler);
    }

    [[nodiscard]] HWND hwnd() const { return hwnd_tree_; }

    void on_selection_changed(LPARAM lparam);

private:
    void insert_node_recursive(HTREEITEM h_parent, const std::shared_ptr<DocumentTreeNodeData>& node_data);

    HWND hwnd_parent_ = nullptr;
    HWND hwnd_tree_ = nullptr;
    int id_ = 0;
    HFONT font_ = nullptr;
    HIMAGELIST himl_ = nullptr;

    std::shared_ptr<DocumentTreeNodeData> root_node_;
    std::vector<std::shared_ptr<DocumentTreeNodeData>> node_registry_;
    NodeSelectedHandler on_node_selected_;
};

} // namespace typemorph::gui
#endif // _WIN32
