#include "case_internal.h"

/*
 * Phase C: targeted header-field mutations.
 * Most scenarios keep the surrounding archive shape plausible.
 */
void build_phase_c(struct fuzz_case *fcase,
                   const struct case_material *m,
                   unsigned int index,
                   unsigned long run_nonce,
                   unsigned int mix) {
    const char *n0 = m->n0;
    const char *n1 = m->n1;
    char long_name[100];
    unsigned int scenario = mix % 40U;

    set_regular_entry(&fcase->entries[0], n0, 32UL, 32U, '0');

    /* Add a second entry in a subset of cases for parser state interactions. */
    if (mix % 5U == 0U) {
        fcase->entry_count = 2U;
        set_regular_entry(&fcase->entries[1], n1, 16UL, 16U, '0');
    }

    switch (scenario) {
        case 0:
            fcase->entries[0].mutation = MUT_SIZE_NON_OCTAL;
            break;
        case 1:
            fcase->entries[0].mutation = MUT_SIZE_NO_NUL;
            break;
        case 2:
            fcase->entries[0].mutation = MUT_MODE_NON_OCTAL;
            break;
        case 3:
            fcase->entries[0].mutation = MUT_UID_NON_OCTAL;
            break;
        case 4:
            fcase->entries[0].mutation = MUT_GID_NON_OCTAL;
            break;
        case 5:
            fcase->entries[0].mutation = MUT_MTIME_NON_OCTAL;
            break;
        case 6:
            fcase->entries[0].mutation = MUT_MAGIC_ZERO;
            break;
        case 7:
            fcase->entries[0].mutation = MUT_MAGIC_GARBAGE;
            break;
        case 8:
            fcase->entries[0].mutation = MUT_VERSION_GARBAGE;
            break;
        case 9:
            make_near_limit_name(long_name, sizeof(long_name), run_nonce, index);
            set_regular_entry(&fcase->entries[0], long_name, 64UL, 64U, '0');
            fcase->entries[0].mutation = MUT_NAME_NO_NUL;
            break;
        case 10:
            set_symlink_entry(&fcase->entries[0], n0, n1);
            fcase->entries[0].mutation = MUT_LINKNAME_NO_NUL;
            break;
        case 11:
            fcase->entries[0].uid = 077777777UL;
            fcase->entries[0].gid = 077777777UL;
            break;
        case 12:
            fcase->entries[0].declared_size = 077777777777UL;
            fcase->entries[0].payload_size = 0U;
            break;
        case 13:
            fcase->entries[0].mutation = MUT_SIZE_SPACES;
            break;
        case 14:
            fcase->entries[0].mutation = MUT_MODE_SPACES;
            break;
        case 15:
            fcase->entries[0].mutation = MUT_UID_SPACES;
            break;
        case 16:
            fcase->entries[0].mutation = MUT_GID_SPACES;
            break;
        case 17:
            fcase->entries[0].mutation = MUT_MTIME_SPACES;
            break;
        case 18:
            fcase->entries[0].mutation = MUT_SIZE_PLUS;
            break;
        case 19:
            fcase->entries[0].mutation = MUT_SIZE_MINUS;
            break;
        case 20:
            fcase->entries[0].mutation = MUT_SIZE_OVERFLOW;
            break;
        case 21:
            fcase->entries[0].mutation = MUT_SIZE_NUL_MIXED;
            break;
        case 22:
            fcase->entries[0].mutation = MUT_MODE_PLUS;
            break;
        case 23:
            fcase->entries[0].mutation = MUT_MODE_MINUS;
            break;
        case 24:
            fcase->entries[0].mutation = MUT_MODE_OVERFLOW;
            break;
        case 25:
            fcase->entries[0].mutation = MUT_UID_PLUS;
            break;
        case 26:
            fcase->entries[0].mutation = MUT_UID_MINUS;
            break;
        case 27:
            fcase->entries[0].mutation = MUT_UID_OVERFLOW;
            break;
        case 28:
            fcase->entries[0].mutation = MUT_GID_PLUS;
            break;
        case 29:
            fcase->entries[0].mutation = MUT_GID_MINUS;
            break;
        case 30:
            fcase->entries[0].mutation = MUT_GID_OVERFLOW;
            break;
        case 31:
            fcase->entries[0].mutation = MUT_MTIME_PLUS;
            break;
        case 32:
            fcase->entries[0].mutation = MUT_MTIME_MINUS;
            break;
        case 33:
            fcase->entries[0].mutation = MUT_MTIME_OVERFLOW;
            break;
        case 34:
            set_regular_entry(&fcase->entries[0], n0, 0UL, 511U, '0');
            fcase->entries[0].mutation = MUT_SIZE_PLUS;
            break;
        case 35:
            set_regular_entry(&fcase->entries[0], n0, 1UL, 0U, '0');
            fcase->entries[0].mutation = MUT_SIZE_MINUS;
            break;
        case 36:
            set_regular_entry(&fcase->entries[0], n0, 077777777777UL, 3U, '0');
            fcase->entries[0].mutation = MUT_SIZE_NUL_MIXED;
            break;
        case 37:
            set_regular_entry(&fcase->entries[0], n0, 512UL, 513U, '0');
            fcase->entries[0].mutation = MUT_SIZE_OVERFLOW;
            break;
        case 38:
            set_regular_entry(&fcase->entries[0], n0, 513UL, 1U, '0');
            fcase->entries[0].mutation = MUT_UID_OVERFLOW;
            break;
        case 39:
            set_regular_entry(&fcase->entries[0], n0, 2048UL, 7U, '0');
            fcase->entries[0].mutation = MUT_GID_OVERFLOW;
            break;
        default:
            break;
    }
}
