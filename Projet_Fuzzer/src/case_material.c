#define _POSIX_C_SOURCE 200809L

#include <stdio.h>
#include <string.h>

#include "case_internal.h"
#include "common.h"

/*
 * Initialize an entry with safe baseline values.
 * Campaign phases then specialize these fields.
 */
static void init_entry_defaults(struct fuzz_entry *entry) {
    memset(entry, 0, sizeof(*entry));
    entry->typeflag = '0';
    entry->mode = 0644UL;
    entry->uid = 1000UL;
    entry->gid = 1000UL;
    entry->declared_size = 0UL;
    entry->payload_size = 0U;
    entry->mutation = MUT_NONE;
}

/*
 * Helpers to quickly build common entry types.
 */
void set_regular_entry(struct fuzz_entry *entry,
                       const char *name,
                       unsigned long declared_size,
                       size_t payload_size,
                       char typeflag) {
    init_entry_defaults(entry);
    copy_cstr(entry->name, sizeof(entry->name), name);
    entry->typeflag = typeflag;
    entry->mode = 0644UL;
    entry->declared_size = declared_size;
    entry->payload_size = payload_size;
}

void set_directory_entry(struct fuzz_entry *entry, const char *name) {
    init_entry_defaults(entry);
    copy_cstr(entry->name, sizeof(entry->name), name);
    entry->typeflag = '5';
    entry->mode = 0755UL;
    entry->declared_size = 0UL;
    entry->payload_size = 0U;
}

void set_symlink_entry(struct fuzz_entry *entry, const char *name, const char *target) {
    init_entry_defaults(entry);
    copy_cstr(entry->name, sizeof(entry->name), name);
    copy_cstr(entry->linkname, sizeof(entry->linkname), target);
    entry->typeflag = '2';
    entry->mode = 0777UL;
    entry->declared_size = 0UL;
    entry->payload_size = 0U;
}

void set_hardlink_entry(struct fuzz_entry *entry, const char *name, const char *target) {
    init_entry_defaults(entry);
    copy_cstr(entry->name, sizeof(entry->name), name);
    copy_cstr(entry->linkname, sizeof(entry->linkname), target);
    entry->typeflag = '1';
    entry->mode = 0644UL;
    entry->declared_size = 0UL;
    entry->payload_size = 0U;
}

/*
 * Generate stable and unique names (no collisions across cases).
 */
static void make_name(char *dst,
                      size_t dst_size,
                      unsigned long run_nonce,
                      unsigned int case_index,
                      unsigned int entry_index,
                      const char *tag) {
    (void)snprintf(dst, dst_size, "fz_%lu_%u_%u_%s",
                   run_nonce, case_index, entry_index, tag);
}

/*
 * Generate a (directory, child file) pair for nested path tests.
 */
void make_nested_names(char *dir_name,
                       size_t dir_size,
                       char *file_name,
                       size_t file_size,
                       unsigned long run_nonce,
                       unsigned int case_index,
                       unsigned int entry_index) {
    int n;

    (void)snprintf(dir_name, dir_size, "fz_%lu_%u_%u_dir",
                   run_nonce, case_index, entry_index);

    /*
     * Safely append "dir_name/in_file" into file_name.
     * Remaining capacity is checked to avoid silent truncation.
     */
    n = snprintf(file_name, file_size, "%s", dir_name);
    if (n < 0 || (size_t)n >= file_size) {
        file_name[file_size - 1U] = '\0';
        return;
    }

    if ((size_t)n + sizeof("/in_file") - 1U < file_size) {
        (void)snprintf(file_name + n, file_size - (size_t)n, "/in_file");
    } else {
        file_name[file_size - 1U] = '\0';
    }
}

/*
 * Generate a name close to the TAR name field limit (99 usable chars).
 */
void make_near_limit_name(char *dst,
                          size_t dst_size,
                          unsigned long run_nonce,
                          unsigned int case_index) {
    int prefix_len;
    size_t i;

    prefix_len = snprintf(dst, dst_size, "fz_%lu_%u_", run_nonce, case_index);
    if (prefix_len < 0) {
        dst[0] = '\0';
        return;
    }
    if ((size_t)prefix_len >= dst_size) {
        dst[dst_size - 1U] = '\0';
        return;
    }

    for (i = (size_t)prefix_len; i + 1U < dst_size; i++) {
        dst[i] = (char)('a' + (char)((i + case_index) % 26U));
    }
    dst[dst_size - 1U] = '\0';
}

/*
 * Build "base + suffix" into dst, with guaranteed NUL termination.
 */
static void append_suffix(char *dst, size_t dst_size, const char *base, const char *suffix) {
    size_t n;
    copy_cstr(dst, dst_size, base);
    n = strlen(dst);
    if (n + 1U < dst_size) {
        copy_cstr(dst + n, dst_size - n, suffix);
    }
}

/*
 * Convert a potentially long path into TAR (prefix, name) fields.
 * POSIX ustar rule: prefix <= 154 chars, name <= 99 chars.
 */
void set_path_with_prefix(struct fuzz_entry *entry, const char *full_path) {
    size_t len = strlen(full_path);

    memset(entry->prefix, 0, sizeof(entry->prefix));
    if (len <= sizeof(entry->name) - 1U) {
        copy_cstr(entry->name, sizeof(entry->name), full_path);
        return;
    }

    {
        size_t i;
        for (i = len; i > 0U; i--) {
            if (full_path[i] != '/') {
                continue;
            }
            if (i <= sizeof(entry->prefix) - 1U &&
                (len - i - 1U) <= sizeof(entry->name) - 1U) {
                size_t p_len = i;
                size_t n_len = len - i - 1U;
                if (p_len > 0U) {
                    memcpy(entry->prefix, full_path, p_len);
                }
                entry->prefix[p_len] = '\0';
                if (n_len > 0U) {
                    memcpy(entry->name, full_path + i + 1U, n_len);
                }
                entry->name[n_len] = '\0';
                return;
            }
        }
    }

    /*
     * Robust fallback: keep the end of the path in name.
     * Prefix remains empty if no valid split can be found.
     */
    copy_cstr(entry->name, sizeof(entry->name),
              full_path + (len - (sizeof(entry->name) - 1U)));
}

void init_case(struct fuzz_case *fcase) {
    size_t i;
    memset(fcase, 0, sizeof(*fcase));
    fcase->entry_count = 1U;
    fcase->archive_mutation = AM_NONE;
    fcase->eof_blocks_override = -1;
    fcase->leading_garbage_size = 0U;
    fcase->trailing_garbage_size = 0U;
    fcase->cut_tail_bytes = 0U;
    for (i = 0; i < MAX_ENTRIES_PER_CASE; i++) {
        init_entry_defaults(&fcase->entries[i]);
    }
}

/*
 * Small deterministic mixer to vary scenarios without targeting a specific bug.
 */
unsigned int mix_index(unsigned int index, unsigned long run_nonce) {
    unsigned int x = index ^ (unsigned int)run_nonce;
    x ^= x >> 16;
    x *= 0x7feb352dU;
    x ^= x >> 15;
    x *= 0x846ca68bU;
    x ^= x >> 16;
    return x;
}

void prepare_case_material(struct case_material *m,
                           unsigned int index,
                           unsigned long run_nonce,
                           unsigned int mix) {
    copy_cstr(m->path_dot, sizeof(m->path_dot), "./");

    make_name(m->n0, sizeof(m->n0), run_nonce, index, 0U, "file");
    make_name(m->n1, sizeof(m->n1), run_nonce, index, 1U, "file");
    make_name(m->n2, sizeof(m->n2), run_nonce, index, 2U, "file");

    append_suffix(m->path_dot, sizeof(m->path_dot), m->path_dot, m->n0);
    append_suffix(m->path_slash2, sizeof(m->path_slash2), m->n0, "//inner");
    append_suffix(m->path_dotseg, sizeof(m->path_dotseg), m->n0, "/./inner");
    append_suffix(m->path_slash_end, sizeof(m->path_slash_end), m->n0, "/");
    append_suffix(m->n0_child, sizeof(m->n0_child), m->n0, "/child");
    append_suffix(m->n1_child, sizeof(m->n1_child), m->n1, "/child");
    append_suffix(m->n0_grandchild, sizeof(m->n0_grandchild), m->n0_child, "/grandchild");

    copy_cstr(m->path_rel_parent, sizeof(m->path_rel_parent), m->n0);
    append_suffix(m->path_rel_parent, sizeof(m->path_rel_parent), m->path_rel_parent, "/../");
    append_suffix(m->path_rel_parent, sizeof(m->path_rel_parent), m->path_rel_parent, m->n1);

    (void)snprintf(m->path_abs_nowrite, sizeof(m->path_abs_nowrite),
                   "/this/path/should/not/be/writable/fz_%lu_%u_abs", run_nonce, index);
    (void)snprintf(m->path_long_pref, sizeof(m->path_long_pref),
                   "fz_%lu_%u_deep/seg_alpha/seg_beta/seg_gamma/seg_delta/"
                   "seg_epsilon/seg_zeta/seg_eta/seg_theta/leaf_file_%u.txt",
                   run_nonce, index, (unsigned int)(mix % 10000U));
}
