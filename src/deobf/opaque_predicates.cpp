// TypeMorph - Opaque Predicates Detector implementation.
#include "typemorph/deobf/opaque_predicates.hpp"

namespace typemorph::deobf {

std::vector<OpaquePredicateMatch> OpaquePredicateDetector::scan(const core::BinaryView& view) const {
    std::vector<OpaquePredicateMatch> matches;
    if (!view.valid() || view.size() < 3) return matches;

    const auto bytes = view.bytes();
    for (std::size_t i = 0; i + 3 <= bytes.size(); ++i) {
        const std::uint8_t b0 = bytes[i];
        const std::uint8_t b1 = bytes[i + 1];

        // 1. Invariant carry flag: CLC (F8) or STC (F9)
        if (b0 == 0xF8 || b0 == 0xF9) {
            const bool is_clc = (b0 == 0xF8);
            const std::string flag_op = is_clc ? "clc" : "stc";

            // Followed by short jump JC (72) or JNC (73)
            if (b1 == 0x72 || b1 == 0x73) {
                const bool is_jc = (b1 == 0x72);
                // For CLC: CF=0. JC is false, JNC is true.
                // For STC: CF=1. JC is true, JNC is false.
                const PredicateOutcome outcome = (is_clc ? (!is_jc) : is_jc)
                                                     ? PredicateOutcome::always_true
                                                     : PredicateOutcome::always_false;
                const std::string jmp_op = is_jc ? "jc" : "jnc";

                matches.push_back({
                    i,
                    3,
                    outcome,
                    "carry_flag_invariant",
                    flag_op + "; " + jmp_op + " <disp8>",
                    "Flag CF statically set by " + flag_op + " makes branch invariant",
                    0.99
                });
                i += 2;
                continue;
            }

            // Followed by near jump JC (0F 82) or JNC (0F 83)
            if (i + 5 <= bytes.size() && b1 == 0x0F && (bytes[i + 2] == 0x82 || bytes[i + 2] == 0x83)) {
                const bool is_jc = (bytes[i + 2] == 0x82);
                const PredicateOutcome outcome = (is_clc ? (!is_jc) : is_jc)
                                                     ? PredicateOutcome::always_true
                                                     : PredicateOutcome::always_false;
                const std::string jmp_op = is_jc ? "jc" : "jnc";

                matches.push_back({
                    i,
                    7,
                    outcome,
                    "carry_flag_invariant",
                    flag_op + "; " + jmp_op + " <disp32>",
                    "Flag CF statically set by " + flag_op + " makes branch invariant",
                    0.99
                });
                i += 6;
                continue;
            }
        }

        // 2. Self operations that force ZF=1:
        // XOR r, r: 31 C0/DB/C9/D2/ED/F6/FF or 33 C0/DB/C9/D2/ED/F6/FF
        // SUB r, r: 29 C0/DB/C9/D2/ED/F6/FF or 2B C0/DB/C9/D2/ED/F6/FF
        // CMP r, r: 39 C0/DB/C9/D2/ED/F6/FF or 3B C0/DB/C9/D2/ED/F6/FF
        bool is_self_zero = false;
        std::string op_name;
        if ((b0 == 0x31 || b0 == 0x33) && ((b1 & 0xC0) == 0xC0) && (((b1 >> 3) & 7) == (b1 & 7))) {
            is_self_zero = true;
            op_name = "xor reg, reg";
        } else if ((b0 == 0x29 || b0 == 0x2B) && ((b1 & 0xC0) == 0xC0) && (((b1 >> 3) & 7) == (b1 & 7))) {
            is_self_zero = true;
            op_name = "sub reg, reg";
        } else if ((b0 == 0x39 || b0 == 0x3B) && ((b1 & 0xC0) == 0xC0) && (((b1 >> 3) & 7) == (b1 & 7))) {
            is_self_zero = true;
            op_name = "cmp reg, reg";
        }

        if (is_self_zero) {
            const std::uint8_t jmp_byte = bytes[i + 2];
            // Followed by short JZ/JE (74) or JNZ/JNE (75)
            if (i + 3 <= bytes.size() && (jmp_byte == 0x74 || jmp_byte == 0x75)) {
                const bool is_jz = (jmp_byte == 0x74);
                // ZF is 1, so JZ is always true, JNZ is always false
                const PredicateOutcome outcome = is_jz ? PredicateOutcome::always_true : PredicateOutcome::always_false;
                const std::string jmp_op = is_jz ? "jz" : "jnz";

                matches.push_back({
                    i,
                    4,
                    outcome,
                    "self_register_zero_flag",
                    op_name + "; " + jmp_op + " <disp8>",
                    "Zero flag ZF is guaranteed set by " + op_name,
                    0.98
                });
                i += 3;
                continue;
            }

            // Followed by near JZ/JE (0F 84) or JNZ/JNE (0F 85)
            if (i + 7 <= bytes.size() && jmp_byte == 0x0F && (bytes[i + 3] == 0x84 || bytes[i + 3] == 0x85)) {
                const bool is_jz = (bytes[i + 3] == 0x84);
                const PredicateOutcome outcome = is_jz ? PredicateOutcome::always_true : PredicateOutcome::always_false;
                const std::string jmp_op = is_jz ? "jz" : "jnz";

                matches.push_back({
                    i,
                    8,
                    outcome,
                    "self_register_zero_flag",
                    op_name + "; " + jmp_op + " <disp32>",
                    "Zero flag ZF is guaranteed set by " + op_name,
                    0.98
                });
                i += 7;
                continue;
            }
        }
    }

    return matches;
}

}  // namespace typemorph::deobf
