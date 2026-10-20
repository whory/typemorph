// TypeMorph - Native C++ port of dnSpy Search Architecture (SearchControl.xaml.cs, SearchService.cs)
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
#include <functional>
#include <cstdint>

namespace typemorph::gui {

enum class SymbolSearchType {
    All,
    Type,
    Method,
    Field,
    Property,
    Event,
    Assembly,
    StringLiteral
};

struct SearchResultItem {
    SymbolSearchType type = SymbolSearchType::All;
    std::string name;
    std::string container;
    std::uint64_t rva_or_va = 0;
    std::string display_text;
    std::string decompiled_snippet;
};

// C++ Port of dnSpy SearchWindow and SearchService
class SearchWindow {
public:
    SearchWindow() = default;
    ~SearchWindow();

    void show(HWND hwnd_parent);
    void set_results(std::vector<SearchResultItem> results);

    using OnNavigateHandler = std::function<void(const SearchResultItem&)>;
    void set_on_navigate(OnNavigateHandler handler) {
        on_navigate_ = std::move(handler);
    }

    using OnSearchQueryHandler = std::function<std::vector<SearchResultItem>(const std::string& query, SymbolSearchType filter)>;
    void set_search_provider(OnSearchQueryHandler provider) {
        search_provider_ = std::move(provider);
    }

private:
    static LRESULT CALLBACK DialogProc(HWND hwnd, UINT msg, WPARAM wParam, LPARAM lParam);
    void update_search();

    HWND hwnd_dlg_ = nullptr;
    HWND hwnd_query_ = nullptr;
    HWND hwnd_filter_ = nullptr;
    HWND hwnd_list_ = nullptr;
    HWND hwnd_status_ = nullptr;

    std::vector<SearchResultItem> current_results_;
    OnNavigateHandler on_navigate_;
    OnSearchQueryHandler search_provider_;
};

} // namespace typemorph::gui
#endif // _WIN32
