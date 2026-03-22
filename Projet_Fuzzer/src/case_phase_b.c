#include "case_internal.h"

void build_phase_b(struct fuzz_case *fcase,
                   const struct case_material *m,
                   unsigned int index,
                   unsigned long run_nonce,
                   unsigned int mix) {
    const char *n0 = m->n0;
    const char *n1 = m->n1;
    const char *n2 = m->n2;
    const char *path_dot = m->path_dot;
    const char *path_slash2 = m->path_slash2;
    const char *path_dotseg = m->path_dotseg;
    const char *path_slash_end = m->path_slash_end;
    const char *n0_child = m->n0_child;
    const char *n1_child = m->n1_child;
    const char *n0_grandchild = m->n0_grandchild;
    const char *path_rel_parent = m->path_rel_parent;
    const char *path_abs_nowrite = m->path_abs_nowrite;
    const char *path_long_pref = m->path_long_pref;
    char dir_name[100];
    char nested_name[100];
    unsigned int scenario;

    /*
     * Rebalancing:
     * - 87.5% core multi-entry/conflict cases (0..25)
     * - 12.5% path/prefix cases (#1) (26..33)
     */
    if ((mix & 0x7U) == 0U) {
        scenario = 26U + ((mix >> 3U) % 8U);
    } else {
        scenario = mix % 26U;
    }

    switch (scenario) {
        case 0:
            fcase->entry_count = 2U;
            set_regular_entry(&fcase->entries[0], n0, 16UL, 16U, '0');
            set_symlink_entry(&fcase->entries[1], n1, n0);
            break;
        case 1:
            fcase->entry_count = 2U;
            set_regular_entry(&fcase->entries[0], n0, 16UL, 16U, '0');
            set_hardlink_entry(&fcase->entries[1], n1, n0);
            break;
        case 2:
            set_symlink_entry(&fcase->entries[0], n0, n1);
            break;
        case 3:
            set_hardlink_entry(&fcase->entries[0], n0, n1);
            break;
        case 4:
            fcase->entry_count = 2U;
            make_nested_names(dir_name, sizeof(dir_name),
                              nested_name, sizeof(nested_name),
                              run_nonce, index, 0U);
            set_directory_entry(&fcase->entries[0], dir_name);
            set_regular_entry(&fcase->entries[1], nested_name, 24UL, 24U, '0');
            break;
        case 5:
            fcase->entry_count = 2U;
            set_regular_entry(&fcase->entries[0], n0, 8UL, 8U, '0');
            set_regular_entry(&fcase->entries[1], n0, 64UL, 64U, '0');
            break;
        case 6:
            fcase->entry_count = 2U;
            set_regular_entry(&fcase->entries[0], n0, 12UL, 12U, '0');
            set_directory_entry(&fcase->entries[1], n0);
            break;
        case 7:
            fcase->entry_count = 3U;
            set_regular_entry(&fcase->entries[0], n0, 20UL, 20U, '0');
            set_hardlink_entry(&fcase->entries[1], n1, n0);
            set_symlink_entry(&fcase->entries[2], n2, n1);
            break;
        case 8:
            set_regular_entry(&fcase->entries[0], path_dot, 32UL, 32U, '0');
            break;
        case 9:
            fcase->entry_count = 2U;
            set_directory_entry(&fcase->entries[0], n0);
            set_regular_entry(&fcase->entries[1], path_slash2, 19UL, 19U, '0');
            break;
        case 10:
            fcase->entry_count = 2U;
            set_directory_entry(&fcase->entries[0], n0);
            set_regular_entry(&fcase->entries[1], path_dotseg, 19UL, 19U, '0');
            break;
        case 11:
            set_regular_entry(&fcase->entries[0], path_slash_end, 11UL, 11U, '0');
            break;
        case 12:
            /* Numeric edge: payload present, declared size empty/space-filled. */
            set_regular_entry(&fcase->entries[0], n0, 0UL, 40U, '0');
            fcase->entries[0].mutation = MUT_SIZE_SPACES;
            break;
        case 13:
            /* Atypical typeflag while keeping the archive otherwise plausible. */
            set_regular_entry(&fcase->entries[0], n0, 32UL, 32U, '0');
            fcase->entries[0].mutation = MUT_TYPEFLAG_ODD;
            break;
        case 14:
            /* Reverse conflict: directory then file with the same name. */
            fcase->entry_count = 2U;
            set_directory_entry(&fcase->entries[0], n0);
            set_regular_entry(&fcase->entries[1], n0, 18UL, 18U, '0');
            break;
        case 15:
            /* Symlink then file on the same path. */
            fcase->entry_count = 2U;
            set_symlink_entry(&fcase->entries[0], n0, n1);
            set_regular_entry(&fcase->entries[1], n0, 21UL, 21U, '0');
            break;
        case 16:
            /* File then symlink on the same path. */
            fcase->entry_count = 2U;
            set_regular_entry(&fcase->entries[0], n0, 21UL, 21U, '0');
            set_symlink_entry(&fcase->entries[1], n0, n1);
            break;
        case 17:
            /* Hardlink to a target that appears later in the stream. */
            fcase->entry_count = 2U;
            set_hardlink_entry(&fcase->entries[0], n0, n1);
            set_regular_entry(&fcase->entries[1], n1, 13UL, 13U, '0');
            break;
        case 18:
            /* Symlink chain: n0 -> n1 -> n2, then create n2. */
            fcase->entry_count = 3U;
            set_symlink_entry(&fcase->entries[0], n0, n1);
            set_symlink_entry(&fcase->entries[1], n1, n2);
            set_regular_entry(&fcase->entries[2], n2, 17UL, 17U, '0');
            break;
        case 19:
            /* Parent is a file, then attempt to create a child under it. */
            fcase->entry_count = 2U;
            set_regular_entry(&fcase->entries[0], n0, 10UL, 10U, '0');
            set_regular_entry(&fcase->entries[1], n0_child, 9UL, 9U, '0');
            break;
        case 20:
            /* Child entry appears before its parent directory. */
            fcase->entry_count = 2U;
            set_regular_entry(&fcase->entries[0], n1_child, 15UL, 15U, '0');
            set_directory_entry(&fcase->entries[1], n1);
            break;
        case 21:
            /* Duplicate directory entry followed by nested file. */
            fcase->entry_count = 3U;
            set_directory_entry(&fcase->entries[0], n0);
            set_directory_entry(&fcase->entries[1], n0);
            set_regular_entry(&fcase->entries[2], n0_child, 14UL, 14U, '0');
            break;
        case 22:
            /* Repeated overwrites of the same path (file/dir/file). */
            fcase->entry_count = 3U;
            set_regular_entry(&fcase->entries[0], n0, 11UL, 11U, '0');
            set_directory_entry(&fcase->entries[1], n0);
            set_regular_entry(&fcase->entries[2], n0, 3UL, 3U, '0');
            break;
        case 23:
            /* Hardlink cycle with no initial real file. */
            fcase->entry_count = 2U;
            set_hardlink_entry(&fcase->entries[0], n0, n1);
            set_hardlink_entry(&fcase->entries[1], n1, n0);
            break;
        case 24:
            /* Multi-level collisions with deep paths. */
            fcase->entry_count = 3U;
            set_directory_entry(&fcase->entries[0], n0);
            set_regular_entry(&fcase->entries[1], n0_grandchild, 22UL, 22U, '0');
            set_regular_entry(&fcase->entries[2], n0_child, 7UL, 7U, '0');
            break;
        case 25:
            /* Target file + symlink + hardlink in cascade. */
            fcase->entry_count = 3U;
            set_regular_entry(&fcase->entries[0], n0, 12UL, 12U, '0');
            set_symlink_entry(&fcase->entries[1], n1, n0);
            set_hardlink_entry(&fcase->entries[2], n2, n1);
            break;
        case 26:
            /* Path with relative parent segment (path normalization). */
            set_regular_entry(&fcase->entries[0], path_rel_parent, 23UL, 23U, '0');
            break;
        case 27:
            /* Absolute path toward an intentionally non-writable area. */
            set_regular_entry(&fcase->entries[0], path_abs_nowrite, 5UL, 5U, '0');
            break;
        case 28:
            /* Long path encoded through valid ustar (prefix,name). */
            set_regular_entry(&fcase->entries[0], "placeholder.txt", 29UL, 29U, '0');
            set_path_with_prefix(&fcase->entries[0], path_long_pref);
            break;
        case 29:
            /* Long directory via prefix, then a regular child file. */
            fcase->entry_count = 2U;
            set_directory_entry(&fcase->entries[0], "placeholder_dir");
            set_path_with_prefix(&fcase->entries[0], path_long_pref);
            set_regular_entry(&fcase->entries[1], n0, 11UL, 11U, '0');
            break;
        case 30:
            /* Prefix + hardlink targeting a short local name. */
            fcase->entry_count = 2U;
            set_regular_entry(&fcase->entries[0], n0, 17UL, 17U, '0');
            set_hardlink_entry(&fcase->entries[1], "placeholder_hl", n0);
            set_path_with_prefix(&fcase->entries[1], path_long_pref);
            break;
        case 31:
            /* Prefix + symlink to a relative target with ../ */
            set_symlink_entry(&fcase->entries[0], "placeholder_sl", "../target");
            set_path_with_prefix(&fcase->entries[0], path_long_pref);
            break;
        case 32:
            /* Double normalization: ./ + // + /./ in the same case. */
            fcase->entry_count = 2U;
            set_regular_entry(&fcase->entries[0], path_dot, 10UL, 10U, '0');
            set_regular_entry(&fcase->entries[1], path_slash2, 10UL, 10U, '0');
            break;
        case 33:
            /* Parent entry followed by long child path encoded via prefix. */
            fcase->entry_count = 2U;
            set_directory_entry(&fcase->entries[0], n0);
            set_regular_entry(&fcase->entries[1], "placeholder.txt", 16UL, 16U, '0');
            set_path_with_prefix(&fcase->entries[1], path_long_pref);
            break;
        default:
            break;
    }
}
