#include "case_internal.h"

/*
 * Phase D: container-level TAR mutations.
 * Focus is on EOF markers, padding, garbage bytes, and truncations.
 */
void build_phase_d(struct fuzz_case *fcase,
                   const struct case_material *m,
                   unsigned int mix) {
    const char *n0 = m->n0;
    const char *n1 = m->n1;
    unsigned int scenario = mix % 22U;

    set_regular_entry(&fcase->entries[0], n0, 33UL, 33U, '0');

    switch (scenario) {
        case 0:
            fcase->archive_mutation = AM_SKIP_LAST_PADDING;
            break;
        case 1:
            fcase->eof_blocks_override = 1;
            break;
        case 2:
            fcase->eof_blocks_override = 0;
            break;
        case 3:
            fcase->eof_blocks_override = 3;
            break;
        case 4:
            fcase->eof_blocks_override = 4;
            break;
        case 5:
            fcase->archive_mutation = AM_LEADING_GARBAGE;
            fcase->leading_garbage_size = 1U;
            break;
        case 6:
            fcase->archive_mutation = AM_LEADING_GARBAGE;
            fcase->leading_garbage_size = 37U;
            break;
        case 7:
            fcase->archive_mutation = AM_TRAILING_GARBAGE;
            fcase->trailing_garbage_size = 1U;
            break;
        case 8:
            fcase->archive_mutation = AM_TRAILING_GARBAGE;
            fcase->trailing_garbage_size = 37U;
            break;
        case 9:
            fcase->archive_mutation = AM_TRUNCATE_1;
            break;
        case 10:
            fcase->archive_mutation = AM_TRUNCATE_BLOCK;
            break;
        case 11:
            set_regular_entry(&fcase->entries[0], n0, 64UL, 64U, '0');
            fcase->archive_mutation = AM_TRUNCATE_MID_HEADER;
            break;
        case 12:
            set_regular_entry(&fcase->entries[0], n0, 128UL, 128U, '0');
            fcase->archive_mutation = AM_TRUNCATE_MID_PAYLOAD;
            break;
        case 13:
            set_regular_entry(&fcase->entries[0], n0, 33UL, 33U, '0');
            fcase->archive_mutation = AM_TRUNCATE_MID_PADDING;
            break;
        case 14:
            fcase->entry_count = 2U;
            set_regular_entry(&fcase->entries[0], n0, 19UL, 19U, '0');
            set_regular_entry(&fcase->entries[1], n1, 17UL, 17U, '0');
            fcase->archive_mutation = AM_SKIP_LAST_PADDING;
            break;
        case 15:
            fcase->entry_count = 2U;
            set_regular_entry(&fcase->entries[0], n0, 24UL, 24U, '0');
            set_regular_entry(&fcase->entries[1], n1, 9UL, 9U, '0');
            fcase->eof_blocks_override = 0;
            break;
        case 16:
            fcase->entry_count = 2U;
            set_regular_entry(&fcase->entries[0], n0, 24UL, 24U, '0');
            set_regular_entry(&fcase->entries[1], n1, 9UL, 9U, '0');
            fcase->eof_blocks_override = 3;
            break;
        case 17:
            set_regular_entry(&fcase->entries[0], n0, 4096UL, 1U, '0');
            fcase->archive_mutation = AM_TRUNCATE_1;
            break;
        case 18:
            set_directory_entry(&fcase->entries[0], n0);
            fcase->entries[0].declared_size = 8UL;
            fcase->entries[0].payload_size = 8U;
            fcase->archive_mutation = AM_OMIT_EOF_1;
            break;
        case 19:
            set_symlink_entry(&fcase->entries[0], n0, n1);
            fcase->archive_mutation = AM_LEADING_GARBAGE;
            fcase->leading_garbage_size = 19U;
            break;
        case 20:
            set_regular_entry(&fcase->entries[0], n0, 48UL, 48U, '0');
            fcase->archive_mutation = AM_TRUNCATE_1;
            fcase->cut_tail_bytes = 7U;
            break;
        case 21:
            set_regular_entry(&fcase->entries[0], n0, 48UL, 48U, '0');
            fcase->archive_mutation = AM_TRAILING_GARBAGE;
            fcase->trailing_garbage_size = 257U;
            break;
        default:
            break;
    }
}
