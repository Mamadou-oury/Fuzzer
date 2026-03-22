#include "case_internal.h"

/* Boundary payload sizes used to hit common parser edge conditions. */
static const size_t g_boundary_sizes[] = {
    0U, 1U, 2U, 3U, 7U, 15U, 31U, 63U,
    127U, 255U, 511U, 512U, 513U, 1024U, 2048U, 4096U
};

/*
 * Phase A: mostly valid archives with controlled size boundaries.
 * This keeps baseline coverage while still probing parser limits.
 */
void build_phase_a(struct fuzz_case *fcase,
                   const struct case_material *m,
                   unsigned int index,
                   unsigned int mix) {
    const char *n0 = m->n0;
    const char *n1 = m->n1;
    const char *n2 = m->n2;
    size_t s = g_boundary_sizes[index % (sizeof(g_boundary_sizes) / sizeof(g_boundary_sizes[0]))];

    if (mix % 6U == 0U) {
        set_directory_entry(&fcase->entries[0], n0);
    } else {
        char tf = (mix % 11U == 0U) ? '\0' : '0';
        set_regular_entry(&fcase->entries[0], n0, (unsigned long)s, s, tf);
    }

    /* Occasionally add a second regular entry. */
    if (mix % 9U == 0U) {
        fcase->entry_count = 2U;
        set_regular_entry(&fcase->entries[1], n1,
                          (unsigned long)(mix % 41U),
                          (size_t)(mix % 41U),
                          '0');
    }

    /* Rarer 3-entry baseline used to exercise multi-header processing. */
    if (mix % 29U == 0U) {
        fcase->entry_count = 3U;
        set_regular_entry(&fcase->entries[1], n1, 64UL, 64U, '0');
        set_regular_entry(&fcase->entries[2], n2, 0UL, 0U, '0');
    }
}
