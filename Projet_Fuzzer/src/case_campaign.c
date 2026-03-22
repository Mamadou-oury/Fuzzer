#include "case_builder.h"
#include "case_internal.h"

/*
 * V3 fuzz-case construction.
 *
 * Phase A (25%): mostly valid cases + size boundaries.
 * Phase B (25%): links/multi-entry cases + special paths.
 * Phase C (20%): header mutations, usually with valid checksums.
 * Phase D (18%): TAR container structural mutations.
 * Phase E (12%): aggressive combinations (header + structure).
 */
void build_case(struct fuzz_case *fcase,
                unsigned int index,
                unsigned long run_nonce,
                unsigned int total_cases) {
    struct case_material m;
    const unsigned int phase_a_end = (total_cases * 25U) / 100U;
    const unsigned int phase_b_end = (total_cases * 50U) / 100U;
    const unsigned int phase_c_end = (total_cases * 70U) / 100U;
    const unsigned int phase_d_end = (total_cases * 88U) / 100U;
    unsigned int mix;

    init_case(fcase);

    mix = mix_index(index, run_nonce);
    prepare_case_material(&m, index, run_nonce, mix);

    if (index < phase_a_end) {
        build_phase_a(fcase, &m, index, mix);
        return;
    }

    if (index < phase_b_end) {
        build_phase_b(fcase, &m, index, run_nonce, mix);
        return;
    }

    if (index < phase_c_end) {
        build_phase_c(fcase, &m, index, run_nonce, mix);
        return;
    }

    if (index < phase_d_end) {
        build_phase_d(fcase, &m, mix);
        return;
    }

    build_phase_e(fcase, &m, mix);
}
