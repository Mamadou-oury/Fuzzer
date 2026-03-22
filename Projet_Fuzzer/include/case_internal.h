#ifndef CASE_INTERNAL_H
#define CASE_INTERNAL_H

#include <stddef.h>

#include "fuzzer_types.h"

struct case_material {
    char n0[100];
    char n1[100];
    char n2[100];
    char path_dot[100];
    char path_slash2[100];
    char path_dotseg[100];
    char path_slash_end[100];
    char n0_child[100];
    char n1_child[100];
    char n0_grandchild[100];
    char path_rel_parent[160];
    char path_abs_nowrite[220];
    char path_long_pref[300];
};

void init_case(struct fuzz_case *fcase);
unsigned int mix_index(unsigned int index, unsigned long run_nonce);

void set_regular_entry(struct fuzz_entry *entry,
                       const char *name,
                       unsigned long declared_size,
                       size_t payload_size,
                       char typeflag);
void set_directory_entry(struct fuzz_entry *entry, const char *name);
void set_symlink_entry(struct fuzz_entry *entry,
                       const char *name,
                       const char *target);
void set_hardlink_entry(struct fuzz_entry *entry,
                        const char *name,
                        const char *target);

void make_nested_names(char *dir_name,
                       size_t dir_size,
                       char *file_name,
                       size_t file_size,
                       unsigned long run_nonce,
                       unsigned int case_index,
                       unsigned int entry_index);
void make_near_limit_name(char *dst,
                          size_t dst_size,
                          unsigned long run_nonce,
                          unsigned int case_index);
void set_path_with_prefix(struct fuzz_entry *entry, const char *full_path);

void prepare_case_material(struct case_material *m,
                           unsigned int index,
                           unsigned long run_nonce,
                           unsigned int mix);

void build_phase_a(struct fuzz_case *fcase,
                   const struct case_material *m,
                   unsigned int index,
                   unsigned int mix);
void build_phase_b(struct fuzz_case *fcase,
                   const struct case_material *m,
                   unsigned int index,
                   unsigned long run_nonce,
                   unsigned int mix);
void build_phase_c(struct fuzz_case *fcase,
                   const struct case_material *m,
                   unsigned int index,
                   unsigned long run_nonce,
                   unsigned int mix);
void build_phase_d(struct fuzz_case *fcase,
                   const struct case_material *m,
                   unsigned int mix);
void build_phase_e(struct fuzz_case *fcase,
                   const struct case_material *m,
                   unsigned int mix);

#endif /* CASE_INTERNAL_H */
