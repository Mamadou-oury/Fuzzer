#include "case_internal.h"
#include "common.h"

void build_phase_e(struct fuzz_case *fcase,
                   const struct case_material *m,
                   unsigned int mix) {
    const char *n0 = m->n0;
    const char *n1 = m->n1;
    const char *n2 = m->n2;
    const char *n0_child = m->n0_child;
    const char *path_slash_end = m->path_slash_end;
    const char *path_long_pref = m->path_long_pref;
    unsigned int scenario;
    static const unsigned char tf_unknown_low[] = {'8', '9', 'A', 'B', '?', 'x'};
    static const unsigned char tf_unknown_high[] = {0x01, 0x1f, 0x7f, 0x80, 0x90, 0xff};

    /*
     * Phase E distribution:
     * - 68.75% historical aggressive scenarios (0..15)
     * - 12.5% typeflag campaign (#2) (16..27)
     * - 12.5% cross-field campaign (#4) (28..39)
     * - 6.25% non-ASCII campaign (#7) (40..47)
     */
    if ((mix & 0xfU) <= 1U) {
        scenario = 16U + ((mix >> 4U) % 12U);
    } else if ((mix & 0xfU) <= 3U) {
        scenario = 28U + ((mix >> 4U) % 12U);
    } else if ((mix & 0xfU) == 4U) {
        scenario = 40U + ((mix >> 4U) % 8U);
    } else {
        scenario = mix % 16U;
    }

    switch (scenario) {
        case 0:
            set_regular_entry(&fcase->entries[0], n0, 64UL, 64U, '0');
            fcase->entries[0].mutation = MUT_BAD_CHECKSUM;
            break;
        case 1:
            set_regular_entry(&fcase->entries[0], n0, 0UL, 0U, '0');
            fcase->entries[0].mutation = MUT_TYPEFLAG_HIGHBIT;
            break;
        case 2:
            set_hardlink_entry(&fcase->entries[0], n0, n1);
            fcase->entries[0].mutation = MUT_BAD_CHECKSUM;
            break;
        case 3:
            set_symlink_entry(&fcase->entries[0], n0, n1);
            fcase->entries[0].mutation = MUT_LINKNAME_NO_NUL;
            fcase->archive_mutation = AM_TRAILING_GARBAGE;
            fcase->trailing_garbage_size = 23U;
            break;
        case 4:
            set_regular_entry(&fcase->entries[0], n0, 0UL, 128U, '0');
            fcase->entries[0].mutation = MUT_SIZE_NON_OCTAL;
            fcase->archive_mutation = AM_TRUNCATE_BLOCK;
            break;
        case 5:
            set_regular_entry(&fcase->entries[0], n0, 1024UL, 1U, '0');
            fcase->entries[0].mutation = MUT_MODE_NON_OCTAL;
            fcase->archive_mutation = AM_SKIP_LAST_PADDING;
            break;
        case 6:
            set_regular_entry(&fcase->entries[0], n0, 32UL, 32U, '0');
            fcase->entries[0].mutation = MUT_MAGIC_ZERO;
            fcase->archive_mutation = AM_OMIT_EOF_2;
            break;
        case 7:
            set_regular_entry(&fcase->entries[0], n0, 32UL, 32U, '0');
            fcase->entries[0].mutation = MUT_VERSION_GARBAGE;
            fcase->archive_mutation = AM_TRAILING_GARBAGE;
            fcase->trailing_garbage_size = 7U;
            break;
        case 8:
            set_directory_entry(&fcase->entries[0], n0);
            fcase->entries[0].declared_size = 16UL;
            fcase->entries[0].payload_size = 16U;
            fcase->archive_mutation = AM_SKIP_LAST_PADDING;
            break;
        case 9:
            set_regular_entry(&fcase->entries[0], n0, 0UL, 33U, '0');
            fcase->archive_mutation = AM_SKIP_LAST_PADDING;
            break;
        case 10:
            fcase->entry_count = 2U;
            set_regular_entry(&fcase->entries[0], n0, 24UL, 24U, '0');
            set_regular_entry(&fcase->entries[1], n1, 24UL, 24U, '0');
            fcase->entries[1].mutation = MUT_BAD_CHECKSUM;
            fcase->archive_mutation = AM_OMIT_EOF_1;
            break;
        case 11:
            set_regular_entry(&fcase->entries[0], n0, 077777777777UL, 2U, '0');
            fcase->archive_mutation = AM_TRUNCATE_1;
            break;
        case 12:
            set_regular_entry(&fcase->entries[0], n0, 64UL, 64U, '0');
            fcase->entries[0].mutation = MUT_CHKSUM_SPACES;
            break;
        case 13:
            set_regular_entry(&fcase->entries[0], n0, 0UL, 0U, '0');
            fcase->entries[0].mutation = MUT_TYPEFLAG_ODD;
            fcase->archive_mutation = AM_OMIT_EOF_2;
            break;
        case 14:
            fcase->entry_count = 2U;
            set_regular_entry(&fcase->entries[0], n0, 512UL, 512U, '0');
            set_regular_entry(&fcase->entries[1], n1, 1UL, 0U, '0');
            fcase->entries[1].mutation = MUT_SIZE_NON_OCTAL;
            fcase->archive_mutation = AM_SKIP_LAST_PADDING;
            break;
        case 15:
            set_hardlink_entry(&fcase->entries[0], n0, n1);
            fcase->entries[0].mutation = MUT_TYPEFLAG_ODD;
            fcase->archive_mutation = AM_TRAILING_GARBAGE;
            fcase->trailing_garbage_size = 64U;
            break;
        case 16:
            /* Regular-file typeflag in old style: '\0'. */
            set_regular_entry(&fcase->entries[0], n0, 23UL, 23U, '\0');
            break;
        case 17:
            /* Explicit regular-file typeflag '0'. */
            set_regular_entry(&fcase->entries[0], n0, 31UL, 31U, '0');
            break;
        case 18:
            /* Hardlink typeflag ('1') with an existing target. */
            fcase->entry_count = 2U;
            set_regular_entry(&fcase->entries[0], n1, 12UL, 12U, '0');
            set_hardlink_entry(&fcase->entries[1], n0, n1);
            break;
        case 19:
            /* Symlink typeflag ('2') with size/payload mismatch. */
            set_symlink_entry(&fcase->entries[0], n0, n1);
            fcase->entries[0].declared_size = 17UL;
            fcase->entries[0].payload_size = 17U;
            break;
        case 20:
            /* Char-device typeflag ('3'). */
            set_regular_entry(&fcase->entries[0], n0, 0UL, 0U, '3');
            break;
        case 21:
            /* Block-device typeflag ('4'). */
            set_regular_entry(&fcase->entries[0], n0, 0UL, 9U, '4');
            break;
        case 22:
            /* Directory typeflag ('5') with non-zero size. */
            set_directory_entry(&fcase->entries[0], n0);
            fcase->entries[0].declared_size = 19UL;
            fcase->entries[0].payload_size = 19U;
            break;
        case 23:
            /* FIFO typeflag ('6') with unexpected payload. */
            set_regular_entry(&fcase->entries[0], n0, 13UL, 13U, '6');
            break;
        case 24:
            /* Contiguous-file typeflag ('7'). */
            set_regular_entry(&fcase->entries[0], n0, 27UL, 27U, '7');
            break;
        case 25:
            /* Unknown printable-ASCII typeflag. */
            set_regular_entry(&fcase->entries[0], n0, 15UL, 15U,
                              (char)tf_unknown_low[(mix >> 5U) % (sizeof(tf_unknown_low) / sizeof(tf_unknown_low[0]))]);
            break;
        case 26:
            /* Unknown control/high-bit typeflag. */
            set_regular_entry(&fcase->entries[0], n0, 15UL, 15U,
                              (char)tf_unknown_high[(mix >> 5U) % (sizeof(tf_unknown_high) / sizeof(tf_unknown_high[0]))]);
            break;
        case 27:
            /* Mixed typeflags in one archive (dir + file + unknown). */
            fcase->entry_count = 3U;
            set_directory_entry(&fcase->entries[0], n0);
            set_regular_entry(&fcase->entries[1], n0_child, 11UL, 11U, '\0');
            set_regular_entry(&fcase->entries[2], n1, 7UL, 7U,
                              (char)tf_unknown_low[(mix >> 7U) % (sizeof(tf_unknown_low) / sizeof(tf_unknown_low[0]))]);
            break;
        case 28:
            /* Directory with payload + inconsistent linkname. */
            set_directory_entry(&fcase->entries[0], n0);
            copy_cstr(fcase->entries[0].linkname, sizeof(fcase->entries[0].linkname), n1);
            fcase->entries[0].declared_size = 33UL;
            fcase->entries[0].payload_size = 33U;
            break;
        case 29:
            /* Symlink with non-zero payload. */
            set_symlink_entry(&fcase->entries[0], n0, n1);
            fcase->entries[0].declared_size = 64UL;
            fcase->entries[0].payload_size = 64U;
            break;
        case 30:
            /* Hardlink with non-zero size/payload. */
            set_hardlink_entry(&fcase->entries[0], n0, n1);
            fcase->entries[0].declared_size = 48UL;
            fcase->entries[0].payload_size = 48U;
            break;
        case 31:
            /* Regular file with linkname set (out-of-context field). */
            set_regular_entry(&fcase->entries[0], n0, 24UL, 24U, '0');
            copy_cstr(fcase->entries[0].linkname, sizeof(fcase->entries[0].linkname), n1);
            break;
        case 32:
            /* Char device with payload and very large declared size. */
            set_regular_entry(&fcase->entries[0], n0, 077777777777UL, 7U, '3');
            break;
        case 33:
            /* Block device with unexpected payload + truncated archive end. */
            set_regular_entry(&fcase->entries[0], n0, 27UL, 27U, '4');
            fcase->archive_mutation = AM_TRUNCATE_1;
            break;
        case 34:
            /* FIFO with payload + checksum forced to spaces. */
            set_regular_entry(&fcase->entries[0], n0, 19UL, 19U, '6');
            fcase->entries[0].mutation = MUT_CHKSUM_SPACES;
            break;
        case 35:
            /* Directory-like name (trailing slash) but regular typeflag. */
            set_regular_entry(&fcase->entries[0], path_slash_end, 29UL, 29U, '0');
            break;
        case 36:
            /* Long prefix/name entry combined with symlink + payload. */
            set_symlink_entry(&fcase->entries[0], "placeholder_sl", n1);
            set_path_with_prefix(&fcase->entries[0], path_long_pref);
            fcase->entries[0].declared_size = 23UL;
            fcase->entries[0].payload_size = 23U;
            break;
        case 37:
            /* Multi-entry case with incompatible types and contradictory sizes. */
            fcase->entry_count = 3U;
            set_symlink_entry(&fcase->entries[0], n0, n1);
            fcase->entries[0].declared_size = 9UL;
            fcase->entries[0].payload_size = 9U;
            set_hardlink_entry(&fcase->entries[1], n1, n2);
            fcase->entries[1].declared_size = 11UL;
            fcase->entries[1].payload_size = 11U;
            set_directory_entry(&fcase->entries[2], n2);
            fcase->entries[2].declared_size = 13UL;
            fcase->entries[2].payload_size = 13U;
            break;
        case 38:
            /* Regular file with prefix set but empty name. */
            set_regular_entry(&fcase->entries[0], "placeholder.txt", 17UL, 17U, '0');
            set_path_with_prefix(&fcase->entries[0], path_long_pref);
            fcase->entries[0].name[0] = '\0';
            break;
        case 39:
            /* Global inconsistency: non-octal mode + directory type + payload. */
            set_directory_entry(&fcase->entries[0], n0);
            fcase->entries[0].declared_size = 41UL;
            fcase->entries[0].payload_size = 41U;
            fcase->entries[0].mutation = MUT_MODE_NON_OCTAL;
            break;
        case 40:
            /* Name with non-ASCII bytes (NUL-terminated). */
            set_regular_entry(&fcase->entries[0], n0, 23UL, 23U, '0');
            fcase->entries[0].mutation = MUT_NAME_HIGHBIT;
            break;
        case 41:
            /* Non-ASCII linkname on a symlink entry. */
            set_symlink_entry(&fcase->entries[0], n0, n1);
            fcase->entries[0].mutation = MUT_LINKNAME_HIGHBIT;
            break;
        case 42:
            /* Magic field filled with non-ASCII bytes. */
            set_regular_entry(&fcase->entries[0], n0, 31UL, 31U, '0');
            fcase->entries[0].mutation = MUT_MAGIC_HIGHBIT;
            break;
        case 43:
            /* Version field filled with non-ASCII bytes. */
            set_regular_entry(&fcase->entries[0], n0, 17UL, 17U, '0');
            fcase->entries[0].mutation = MUT_VERSION_HIGHBIT;
            break;
        case 44:
            /* Non-ASCII uname field. */
            set_regular_entry(&fcase->entries[0], n0, 19UL, 19U, '0');
            fcase->entries[0].mutation = MUT_UNAME_HIGHBIT;
            break;
        case 45:
            /* Non-ASCII gname field. */
            set_regular_entry(&fcase->entries[0], n0, 19UL, 19U, '0');
            fcase->entries[0].mutation = MUT_GNAME_HIGHBIT;
            break;
        case 46:
            /* Size field filled with non-ASCII bytes. */
            set_regular_entry(&fcase->entries[0], n0, 512UL, 9U, '0');
            fcase->entries[0].mutation = MUT_SIZE_HIGHBIT;
            break;
        case 47:
            /* Multi-entry non-ASCII + structural combination. */
            fcase->entry_count = 2U;
            set_regular_entry(&fcase->entries[0], n0, 13UL, 13U, '0');
            fcase->entries[0].mutation = MUT_NAME_HIGHBIT;
            set_regular_entry(&fcase->entries[1], n1, 13UL, 13U, '0');
            fcase->entries[1].mutation = MUT_GNAME_HIGHBIT;
            fcase->archive_mutation = AM_TRAILING_GARBAGE;
            fcase->trailing_garbage_size = 9U;
            break;
        default:
            break;
    }
}
