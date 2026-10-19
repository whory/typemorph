// TypeMorph - PointerGraph unit tests.
//
// Synthetic buffers exercise 32/64-bit extraction, node/edge construction,
// cycle detection, bounded scanning and executable VA -> file-offset lookup.
#include "test_framework.hpp"

#include <algorithm>
#include <cstdint>
#include <set>
#include <vector>

#include "typemorph/core/binary_view.hpp"
#include "typemorph/core/executable.hpp"
#include "typemorph/infer/pointer_graph.hpp"

namespace {

using typemorph::core::BinaryView;
using typemorph::core::ByteOrder;
using typemorph::core::ExecutableImage;
using typemorph::core::ImageFormat;
using typemorph::core::ImageParts;
using typemorph::core::Section;
using typemorph::core::SectionFlag;
using typemorph::infer::PointerGraph;
using typemorph::infer::PointerGraphOptions;

void put_u32(std::vector<std::uint8_t>& bytes, std::size_t offset, std::uint32_t value) {
    for (std::size_t i = 0; i < 4; ++i) {
        bytes[offset + i] = static_cast<std::uint8_t>((value >> (8U * i)) & 0xFFU);
    }
}

void put_u64(std::vector<std::uint8_t>& bytes, std::size_t offset, std::uint64_t value) {
    for (std::size_t i = 0; i < 8; ++i) {
        bytes[offset + i] = static_cast<std::uint8_t>((value >> (8U * i)) & 0xFFU);
    }
}

std::set<std::uint64_t> node_offsets(const PointerGraph& graph) {
    std::set<std::uint64_t> offsets;
    for (const auto& node : graph.nodes()) offsets.insert(node.offset);
    return offsets;
}

}  // namespace

TEST_CASE("pointer graph: 64-bit file offsets form a cycle") {
    std::vector<std::uint8_t> bytes(64, 0);
    put_u64(bytes, 0x10, 0x20);  // 0x10 -> 0x20
    put_u64(bytes, 0x20, 0x10);  // 0x20 -> 0x10
    put_u64(bytes, 0x30, 0x10);  // 0x30 -> 0x10
    const BinaryView view = BinaryView::from_owned(bytes, "ptrs");

    const auto built = PointerGraph::build(view);
    REQUIRE(built.has_value());
    const PointerGraph& graph = built.value();

    REQUIRE_EQ(graph.edges().size(), 3U);
    const std::set<std::uint64_t> offsets = node_offsets(graph);
    CHECK(offsets.count(0x10) == 1);
    CHECK(offsets.count(0x20) == 1);
    CHECK(offsets.count(0x30) == 1);

    const auto from_source = graph.edges_from(0x10);
    REQUIRE_EQ(from_source.size(), 1U);
    const auto& edge = graph.edges()[from_source.front()];
    CHECK_EQ(edge.source_offset, 0x10ULL);
    REQUIRE(edge.target_offset.has_value());
    CHECK_EQ(edge.target_offset.value(), 0x20ULL);
    CHECK_EQ(edge.width, 8);
    CHECK(edge.confidence > 0.0);

    REQUIRE_EQ(graph.edges_to(0x10).size(), 2U);

    const auto cycles = graph.cycles();
    REQUIRE(!cycles.empty());
    bool found = false;
    for (const auto& cycle : cycles) {
        std::set<std::uint64_t> cycle_offsets;
        for (const std::size_t index : cycle) {
            REQUIRE(index < graph.nodes().size());
            cycle_offsets.insert(graph.nodes()[index].offset);
        }
        if (cycle_offsets.count(0x10) == 1 && cycle_offsets.count(0x20) == 1) found = true;
        CHECK(cycle.size() >= 2);
    }
    CHECK(found);
}

TEST_CASE("pointer graph: 32-bit pointers and option bounds") {
    std::vector<std::uint8_t> bytes(32, 0);
    put_u32(bytes, 0x08, 0x10);  // 0x08 -> 0x10
    put_u32(bytes, 0x10, 0x08);  // 0x10 -> 0x08
    const BinaryView view = BinaryView::from_owned(bytes, "ptrs32");

    PointerGraphOptions options;
    options.max_pointer_width = 4;
    const auto built = PointerGraph::build(view, nullptr, options);
    REQUIRE(built.has_value());
    const PointerGraph& graph = built.value();
    REQUIRE_EQ(graph.edges().size(), 2U);
    for (const auto& edge : graph.edges()) {
        CHECK_EQ(static_cast<int>(edge.width), 4);
    }
    CHECK(!graph.cycles().empty());

    // Bounded scanning stops before the second pointer, so no cycle exists.
    PointerGraphOptions bounded;
    bounded.max_pointer_width = 4;
    bounded.max_scan_bytes = 0x10;
    const auto bounded_graph = PointerGraph::build(view, nullptr, bounded);
    REQUIRE(bounded_graph.has_value());
    CHECK(bounded_graph.value().cycles().empty());
}

TEST_CASE("pointer graph: executable virtual addresses are translated") {
    std::vector<std::uint8_t> bytes(0x400, 0);
    put_u64(bytes, 0x210, 0x1000);  // VA inside .text
    const BinaryView view = BinaryView::from_owned(bytes, "image");

    ImageParts parts;
    parts.format = ImageFormat::pe;
    parts.bits = 64;
    parts.endian = ByteOrder::little;
    parts.image_base = 0x1000;
    Section text;
    text.name = ".text";
    text.virtual_address = 0x1000;
    text.virtual_size = 0x100;
    text.file_offset = 0x200;
    text.file_size = 0x100;
    text.flags = SectionFlag::readable | SectionFlag::executable;
    Section data;
    data.name = ".data";
    data.virtual_address = 0x2000;
    data.virtual_size = 0x100;
    data.file_offset = 0x300;
    data.file_size = 0x100;
    data.flags = SectionFlag::readable | SectionFlag::writable;
    parts.sections = {text, data};
    const ExecutableImage image = ExecutableImage::from_parts(view, parts);

    const auto built = PointerGraph::build(view, &image);
    REQUIRE(built.has_value());
    const PointerGraph& graph = built.value();
    REQUIRE_EQ(graph.edges().size(), 1U);
    const auto& edge = graph.edges().front();
    CHECK_EQ(edge.source_offset, 0x210ULL);
    REQUIRE(edge.target_offset.has_value());
    CHECK_EQ(edge.target_offset.value(), 0x200ULL);
    REQUIRE(edge.target_address.has_value());
    CHECK_EQ(edge.target_address.value(), 0x1000ULL);
    CHECK(edge.target_section == ".text");
    CHECK(edge.confidence >= 0.9);

    const auto source = graph.edges_from(0x210);
    REQUIRE_EQ(source.size(), 1U);
    bool source_in_text = false;
    for (const auto& node : graph.nodes()) {
        if (node.offset == 0x210) {
            source_in_text = node.section == ".text" && node.executable;
        }
    }
    CHECK(source_in_text);

    // A value outside the image is not treated as a pointer.
    std::vector<std::uint8_t> other_bytes(0x400, 0);
    put_u64(other_bytes, 0x210, 0xDEADBEEFULL);
    const BinaryView other_view = BinaryView::from_owned(other_bytes, "image2");
    const auto other_graph = PointerGraph::build(other_view, &image);
    REQUIRE(other_graph.has_value());
    CHECK(other_graph.value().edges().empty());
}

TEST_CASE("pointer graph: invalid views fail cleanly") {
    const auto built = PointerGraph::build(BinaryView{});
    REQUIRE(!built.has_value());
    CHECK_EQ(static_cast<int>(built.error().code),
             static_cast<int>(typemorph::core::ErrorCode::invalid_argument));

    const BinaryView empty = BinaryView::from_owned(std::vector<std::uint8_t>{}, "empty");
    const auto empty_graph = PointerGraph::build(empty);
    REQUIRE(empty_graph.has_value());
    CHECK(empty_graph.value().edges().empty());
    CHECK(empty_graph.value().nodes().empty());
    CHECK(empty_graph.value().cycles().empty());
}
