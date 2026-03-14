#define _POSIX_C_SOURCE 200809L

#include <errno.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#include "case_builder.h"
#include "common.h"

/*
 * Initialise une entree avec des valeurs "saines" de depart.
 * Les campagnes viennent ensuite specialiser ces champs.
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
 * Helpers pour construire rapidement des entrees frequentes.
 */
static void set_regular_entry(struct fuzz_entry *entry,
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

static void set_directory_entry(struct fuzz_entry *entry, const char *name) {
    init_entry_defaults(entry);
    copy_cstr(entry->name, sizeof(entry->name), name);
    entry->typeflag = '5';
    entry->mode = 0755UL;
    entry->declared_size = 0UL;
    entry->payload_size = 0U;
}

static void set_symlink_entry(struct fuzz_entry *entry, const char *name, const char *target) {
    init_entry_defaults(entry);
    copy_cstr(entry->name, sizeof(entry->name), name);
    copy_cstr(entry->linkname, sizeof(entry->linkname), target);
    entry->typeflag = '2';
    entry->mode = 0777UL;
    entry->declared_size = 0UL;
    entry->payload_size = 0U;
}

static void set_hardlink_entry(struct fuzz_entry *entry, const char *name, const char *target) {
    init_entry_defaults(entry);
    copy_cstr(entry->name, sizeof(entry->name), name);
    copy_cstr(entry->linkname, sizeof(entry->linkname), target);
    entry->typeflag = '1';
    entry->mode = 0644UL;
    entry->declared_size = 0UL;
    entry->payload_size = 0U;
}

/*
 * Generation de noms stables et uniques (pas de collisions entre cas).
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
 * Genere un couple (dossier, fichier dedie) pour tester les chemins imbriques.
 */
static void make_nested_names(char *dir_name,
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
     * Concatene de facon sure "dir_name/in_file" dans file_name.
     * On verifie la place restante pour eviter la troncature silencieuse.
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
 * Genere un nom proche de la limite du champ name (99 caracteres utiles).
 */
static void make_near_limit_name(char *dst,
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
 * Construit "base + suffix" dans dst, avec terminaison '\0' garantie.
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
 * Convertit un chemin potentiellement long en couple TAR (prefix, name).
 * Regle POSIX ustar: prefix <= 154 chars, name <= 99 chars.
 */
static void set_path_with_prefix(struct fuzz_entry *entry, const char *full_path) {
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
     * Fallback robuste: conserve la fin du chemin dans name.
     * Le prefix reste vide si aucune decomposition valide n'est trouvee.
     */
    copy_cstr(entry->name, sizeof(entry->name),
              full_path + (len - (sizeof(entry->name) - 1U)));
}
static void init_case(struct fuzz_case *fcase) {
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
 * Petit melange deterministe pour varier les scenarios sans hardcoder un bug cible.
 */
static unsigned int mix_index(unsigned int index, unsigned long run_nonce) {
    unsigned int x = index ^ (unsigned int)run_nonce;
    x ^= x >> 16;
    x *= 0x7feb352dU;
    x ^= x >> 15;
    x *= 0x846ca68bU;
    x ^= x >> 16;
    return x;
}

/*
 * Nombre de cas configurable via FUZZ_CASES (par defaut MAX_CASES).
 * Bornes de securite pour rester dans un temps de run raisonnable.
 */
unsigned int resolve_case_count(void) {
    const char *raw = getenv("FUZZ_CASES");
    char *end = NULL;
    unsigned long parsed;

    if (raw == NULL || raw[0] == '\0') {
        return MAX_CASES;
    }

    errno = 0;
    parsed = strtoul(raw, &end, 10);
    if (errno != 0 || end == raw || *end != '\0') {
        return MAX_CASES;
    }

    if (parsed < 64UL) {
        return 64U;
    }
    if (parsed > 20000UL) {
        return 20000U;
    }
    return (unsigned int)parsed;
}

/*
 * Construction V3 des cas de fuzzing.
 *
 * Campagne A (30%): cas majoritairement valides + bornes de taille.
 * Campagne B (25%): liens/multi-entrees + chemins speciaux.
 * Campagne C (20%): mutations de header avec checksum generalement valide.
 * Campagne D (15%): mutations structurelles de conteneur TAR.
 * Campagne E (10%): combinaisons agressives (header + structure).
 */
void build_case(struct fuzz_case *fcase,
                unsigned int index,
                unsigned long run_nonce,
                unsigned int total_cases) {
    static const size_t boundary_sizes[] = {
        0U, 1U, 2U, 3U, 7U, 15U, 31U, 63U,
        127U, 255U, 511U, 512U, 513U, 1024U, 2048U, 4096U
    };

    const unsigned int phase_a_end = (total_cases * 25U) / 100U;
    const unsigned int phase_b_end = (total_cases * 50U) / 100U;
    const unsigned int phase_c_end = (total_cases * 70U) / 100U;
    const unsigned int phase_d_end = (total_cases * 88U) / 100U;
    unsigned int mix = mix_index(index, run_nonce);

    char n0[100], n1[100], n2[100];
    char dir_name[100], nested_name[100];
    char long_name[100];
    char path_dot[100], path_slash2[100], path_dotseg[100], path_slash_end[100];
    char n0_child[100], n1_child[100], n0_grandchild[100];
    char path_rel_parent[160], path_abs_nowrite[220], path_long_pref[300];

    init_case(fcase);
    make_name(n0, sizeof(n0), run_nonce, index, 0U, "file");
    make_name(n1, sizeof(n1), run_nonce, index, 1U, "file");
    make_name(n2, sizeof(n2), run_nonce, index, 2U, "file");

    copy_cstr(path_dot, sizeof(path_dot), "./");
    append_suffix(path_dot, sizeof(path_dot), path_dot, n0);
    append_suffix(path_slash2, sizeof(path_slash2), n0, "//inner");
    append_suffix(path_dotseg, sizeof(path_dotseg), n0, "/./inner");
    append_suffix(path_slash_end, sizeof(path_slash_end), n0, "/");
    append_suffix(n0_child, sizeof(n0_child), n0, "/child");
    append_suffix(n1_child, sizeof(n1_child), n1, "/child");
    append_suffix(n0_grandchild, sizeof(n0_grandchild), n0_child, "/grandchild");
    copy_cstr(path_rel_parent, sizeof(path_rel_parent), n0);
    append_suffix(path_rel_parent, sizeof(path_rel_parent), path_rel_parent, "/../");
    append_suffix(path_rel_parent, sizeof(path_rel_parent), path_rel_parent, n1);
    (void)snprintf(path_abs_nowrite, sizeof(path_abs_nowrite),
                   "/this/path/should/not/be/writable/fz_%lu_%u_abs", run_nonce, index);
    (void)snprintf(path_long_pref, sizeof(path_long_pref),
                   "fz_%lu_%u_deep/seg_alpha/seg_beta/seg_gamma/seg_delta/"
                   "seg_epsilon/seg_zeta/seg_eta/seg_theta/leaf_file_%u.txt",
                   run_nonce, index, (unsigned int)(mix % 10000U));

    if (index < phase_a_end) {
        size_t s = boundary_sizes[index % (sizeof(boundary_sizes) / sizeof(boundary_sizes[0]))];

        if (mix % 6U == 0U) {
            set_directory_entry(&fcase->entries[0], n0);
        } else {
            char tf = (mix % 11U == 0U) ? '\0' : '0';
            set_regular_entry(&fcase->entries[0], n0, (unsigned long)s, s, tf);
        }

        if (mix % 9U == 0U) {
            fcase->entry_count = 2U;
            set_regular_entry(&fcase->entries[1], n1,
                              (unsigned long)(mix % 41U),
                              (size_t)(mix % 41U),
                              '0');
        }

        if (mix % 29U == 0U) {
            fcase->entry_count = 3U;
            set_regular_entry(&fcase->entries[1], n1, 64UL, 64U, '0');
            set_regular_entry(&fcase->entries[2], n2, 0UL, 0U, '0');
        }
        return;
    }

    if (index < phase_b_end) {
        unsigned int scenario;

        /*
         * Reequilibrage:
         * - 87.5% de cas "coeur" multi-entrees/conflits (0..25)
         * - 12.5% de cas chemins/prefix (#1) (26..33)
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
                /* Numeric edge: payload present, taille declaree vide/espace. */
                set_regular_entry(&fcase->entries[0], n0, 0UL, 40U, '0');
                fcase->entries[0].mutation = MUT_SIZE_SPACES;
                break;
            case 13:
                /* Typeflag atypique mais archive sinon plausible. */
                set_regular_entry(&fcase->entries[0], n0, 32UL, 32U, '0');
                fcase->entries[0].mutation = MUT_TYPEFLAG_ODD;
                break;
            case 14:
                /* Conflit inverse: dossier puis fichier sur le meme nom. */
                fcase->entry_count = 2U;
                set_directory_entry(&fcase->entries[0], n0);
                set_regular_entry(&fcase->entries[1], n0, 18UL, 18U, '0');
                break;
            case 15:
                /* Symlink puis fichier sur le meme nom. */
                fcase->entry_count = 2U;
                set_symlink_entry(&fcase->entries[0], n0, n1);
                set_regular_entry(&fcase->entries[1], n0, 21UL, 21U, '0');
                break;
            case 16:
                /* Fichier puis symlink sur le meme nom. */
                fcase->entry_count = 2U;
                set_regular_entry(&fcase->entries[0], n0, 21UL, 21U, '0');
                set_symlink_entry(&fcase->entries[1], n0, n1);
                break;
            case 17:
                /* Lien dur vers une cible future dans le flux. */
                fcase->entry_count = 2U;
                set_hardlink_entry(&fcase->entries[0], n0, n1);
                set_regular_entry(&fcase->entries[1], n1, 13UL, 13U, '0');
                break;
            case 18:
                /* Chaine de symlinks: n0 -> n1 -> n2 puis creation de n2. */
                fcase->entry_count = 3U;
                set_symlink_entry(&fcase->entries[0], n0, n1);
                set_symlink_entry(&fcase->entries[1], n1, n2);
                set_regular_entry(&fcase->entries[2], n2, 17UL, 17U, '0');
                break;
            case 19:
                /* Parent fichier, puis tentative de creation d'un enfant. */
                fcase->entry_count = 2U;
                set_regular_entry(&fcase->entries[0], n0, 10UL, 10U, '0');
                set_regular_entry(&fcase->entries[1], n0_child, 9UL, 9U, '0');
                break;
            case 20:
                /* Enfant avant parent dossier. */
                fcase->entry_count = 2U;
                set_regular_entry(&fcase->entries[0], n1_child, 15UL, 15U, '0');
                set_directory_entry(&fcase->entries[1], n1);
                break;
            case 21:
                /* Doublon de dossier puis fichier imbrique. */
                fcase->entry_count = 3U;
                set_directory_entry(&fcase->entries[0], n0);
                set_directory_entry(&fcase->entries[1], n0);
                set_regular_entry(&fcase->entries[2], n0_child, 14UL, 14U, '0');
                break;
            case 22:
                /* Ecrasements successifs du meme nom (fichier/dossier/fichier). */
                fcase->entry_count = 3U;
                set_regular_entry(&fcase->entries[0], n0, 11UL, 11U, '0');
                set_directory_entry(&fcase->entries[1], n0);
                set_regular_entry(&fcase->entries[2], n0, 3UL, 3U, '0');
                break;
            case 23:
                /* Cycle de liens durs sans fichier reel initial. */
                fcase->entry_count = 2U;
                set_hardlink_entry(&fcase->entries[0], n0, n1);
                set_hardlink_entry(&fcase->entries[1], n1, n0);
                break;
            case 24:
                /* Collisions multi-niveaux avec chemin profond. */
                fcase->entry_count = 3U;
                set_directory_entry(&fcase->entries[0], n0);
                set_regular_entry(&fcase->entries[1], n0_grandchild, 22UL, 22U, '0');
                set_regular_entry(&fcase->entries[2], n0_child, 7UL, 7U, '0');
                break;
            case 25:
                /* Fichier cible + symlink + hardlink en cascade. */
                fcase->entry_count = 3U;
                set_regular_entry(&fcase->entries[0], n0, 12UL, 12U, '0');
                set_symlink_entry(&fcase->entries[1], n1, n0);
                set_hardlink_entry(&fcase->entries[2], n2, n1);
                break;
            case 26:
                /* Chemin avec parent relatif (normalisation de chemin). */
                set_regular_entry(&fcase->entries[0], path_rel_parent, 23UL, 23U, '0');
                break;
            case 27:
                /* Chemin absolu vers une zone volontairement non ecrivable. */
                set_regular_entry(&fcase->entries[0], path_abs_nowrite, 5UL, 5U, '0');
                break;
            case 28:
                /* Long chemin encode via (prefix,name) ustar valide. */
                set_regular_entry(&fcase->entries[0], "placeholder.txt", 29UL, 29U, '0');
                set_path_with_prefix(&fcase->entries[0], path_long_pref);
                break;
            case 29:
                /* Dossier long via prefix puis fichier enfant classique. */
                fcase->entry_count = 2U;
                set_directory_entry(&fcase->entries[0], "placeholder_dir");
                set_path_with_prefix(&fcase->entries[0], path_long_pref);
                set_regular_entry(&fcase->entries[1], n0, 11UL, 11U, '0');
                break;
            case 30:
                /* Prefix + hardlink qui cible un nom court local. */
                fcase->entry_count = 2U;
                set_regular_entry(&fcase->entries[0], n0, 17UL, 17U, '0');
                set_hardlink_entry(&fcase->entries[1], "placeholder_hl", n0);
                set_path_with_prefix(&fcase->entries[1], path_long_pref);
                break;
            case 31:
                /* Prefix + symlink vers une cible relative avec ../ */
                set_symlink_entry(&fcase->entries[0], "placeholder_sl", "../target");
                set_path_with_prefix(&fcase->entries[0], path_long_pref);
                break;
            case 32:
                /* Double normalisation: ./ + // + /./ dans le meme cas. */
                fcase->entry_count = 2U;
                set_regular_entry(&fcase->entries[0], path_dot, 10UL, 10U, '0');
                set_regular_entry(&fcase->entries[1], path_slash2, 10UL, 10U, '0');
                break;
            case 33:
                /* Sequence parent puis enfant long encode via prefix. */
                fcase->entry_count = 2U;
                set_directory_entry(&fcase->entries[0], n0);
                set_regular_entry(&fcase->entries[1], "placeholder.txt", 16UL, 16U, '0');
                set_path_with_prefix(&fcase->entries[1], path_long_pref);
                break;
            default:
                break;
        }
        return;
    }

    if (index < phase_c_end) {
        unsigned int scenario = mix % 40U;
        set_regular_entry(&fcase->entries[0], n0, 32UL, 32U, '0');

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
        return;
    }

    if (index < phase_d_end) {
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
        return;
    }

    {
        unsigned int scenario;
        static const unsigned char tf_unknown_low[] = {'8', '9', 'A', 'B', '?', 'x'};
        static const unsigned char tf_unknown_high[] = {0x01, 0x1f, 0x7f, 0x80, 0x90, 0xff};

        /*
         * Repartition de phase E:
         * - 68.75% scenarios agressifs historiques (0..15)
         * - 12.5% campagne typeflag (#2) (16..27)
         * - 12.5% campagne cross-field (#4) (28..39)
         * - 6.25% campagne non-ASCII (#7) (40..47)
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
                /* Typeflag regular file en style ancien: '\0'. */
                set_regular_entry(&fcase->entries[0], n0, 23UL, 23U, '\0');
                break;
            case 17:
                /* Typeflag regular file explicite '0'. */
                set_regular_entry(&fcase->entries[0], n0, 31UL, 31U, '0');
                break;
            case 18:
                /* Typeflag hardlink ('1') avec cible existante. */
                fcase->entry_count = 2U;
                set_regular_entry(&fcase->entries[0], n1, 12UL, 12U, '0');
                set_hardlink_entry(&fcase->entries[1], n0, n1);
                break;
            case 19:
                /* Typeflag symlink ('2') avec incoherence taille/payload. */
                set_symlink_entry(&fcase->entries[0], n0, n1);
                fcase->entries[0].declared_size = 17UL;
                fcase->entries[0].payload_size = 17U;
                break;
            case 20:
                /* Typeflag char device ('3'). */
                set_regular_entry(&fcase->entries[0], n0, 0UL, 0U, '3');
                break;
            case 21:
                /* Typeflag block device ('4'). */
                set_regular_entry(&fcase->entries[0], n0, 0UL, 9U, '4');
                break;
            case 22:
                /* Typeflag directory ('5') avec taille non nulle. */
                set_directory_entry(&fcase->entries[0], n0);
                fcase->entries[0].declared_size = 19UL;
                fcase->entries[0].payload_size = 19U;
                break;
            case 23:
                /* Typeflag FIFO ('6') avec payload inattendu. */
                set_regular_entry(&fcase->entries[0], n0, 13UL, 13U, '6');
                break;
            case 24:
                /* Typeflag contiguous file ('7'). */
                set_regular_entry(&fcase->entries[0], n0, 27UL, 27U, '7');
                break;
            case 25:
                /* Typeflag inconnu ASCII imprimable. */
                set_regular_entry(&fcase->entries[0], n0, 15UL, 15U,
                                  (char)tf_unknown_low[(mix >> 5U) % (sizeof(tf_unknown_low) / sizeof(tf_unknown_low[0]))]);
                break;
            case 26:
                /* Typeflag inconnu controle/high-bit. */
                set_regular_entry(&fcase->entries[0], n0, 15UL, 15U,
                                  (char)tf_unknown_high[(mix >> 5U) % (sizeof(tf_unknown_high) / sizeof(tf_unknown_high[0]))]);
                break;
            case 27:
                /* Mix de typeflags dans une meme archive (dir + file + inconnu). */
                fcase->entry_count = 3U;
                set_directory_entry(&fcase->entries[0], n0);
                set_regular_entry(&fcase->entries[1], n0_child, 11UL, 11U, '\0');
                set_regular_entry(&fcase->entries[2], n1, 7UL, 7U,
                                  (char)tf_unknown_low[(mix >> 7U) % (sizeof(tf_unknown_low) / sizeof(tf_unknown_low[0]))]);
                break;
            case 28:
                /* Dossier avec payload + linkname incoherent. */
                set_directory_entry(&fcase->entries[0], n0);
                copy_cstr(fcase->entries[0].linkname, sizeof(fcase->entries[0].linkname), n1);
                fcase->entries[0].declared_size = 33UL;
                fcase->entries[0].payload_size = 33U;
                break;
            case 29:
                /* Symlink avec payload non nul. */
                set_symlink_entry(&fcase->entries[0], n0, n1);
                fcase->entries[0].declared_size = 64UL;
                fcase->entries[0].payload_size = 64U;
                break;
            case 30:
                /* Hardlink avec taille/payload non nuls. */
                set_hardlink_entry(&fcase->entries[0], n0, n1);
                fcase->entries[0].declared_size = 48UL;
                fcase->entries[0].payload_size = 48U;
                break;
            case 31:
                /* Fichier regulier avec linkname renseigne (champ hors contexte). */
                set_regular_entry(&fcase->entries[0], n0, 24UL, 24U, '0');
                copy_cstr(fcase->entries[0].linkname, sizeof(fcase->entries[0].linkname), n1);
                break;
            case 32:
                /* Char device avec donnees et taille extremement grande. */
                set_regular_entry(&fcase->entries[0], n0, 077777777777UL, 7U, '3');
                break;
            case 33:
                /* Block device avec payload inattendu + fin d'archive tronquee. */
                set_regular_entry(&fcase->entries[0], n0, 27UL, 27U, '4');
                fcase->archive_mutation = AM_TRUNCATE_1;
                break;
            case 34:
                /* FIFO avec payload + checksum force en espaces. */
                set_regular_entry(&fcase->entries[0], n0, 19UL, 19U, '6');
                fcase->entries[0].mutation = MUT_CHKSUM_SPACES;
                break;
            case 35:
                /* Nom de dossier (slash final) mais type regulier. */
                set_regular_entry(&fcase->entries[0], path_slash_end, 29UL, 29U, '0');
                break;
            case 36:
                /* Entree longue prefix/name combinee a un symlink avec payload. */
                set_symlink_entry(&fcase->entries[0], "placeholder_sl", n1);
                set_path_with_prefix(&fcase->entries[0], path_long_pref);
                fcase->entries[0].declared_size = 23UL;
                fcase->entries[0].payload_size = 23U;
                break;
            case 37:
                /* Multi-entrees avec types incompatibles et tailles contradictoires. */
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
                /* Fichier regulier avec prefix mais name vide. */
                set_regular_entry(&fcase->entries[0], "placeholder.txt", 17UL, 17U, '0');
                set_path_with_prefix(&fcase->entries[0], path_long_pref);
                fcase->entries[0].name[0] = '\0';
                break;
            case 39:
                /* Incoherence globale: mode non octal + type directory + payload. */
                set_directory_entry(&fcase->entries[0], n0);
                fcase->entries[0].declared_size = 41UL;
                fcase->entries[0].payload_size = 41U;
                fcase->entries[0].mutation = MUT_MODE_NON_OCTAL;
                break;
            case 40:
                /* Nom avec octets non-ASCII (termine par NUL). */
                set_regular_entry(&fcase->entries[0], n0, 23UL, 23U, '0');
                fcase->entries[0].mutation = MUT_NAME_HIGHBIT;
                break;
            case 41:
                /* Linkname non-ASCII sur symlink. */
                set_symlink_entry(&fcase->entries[0], n0, n1);
                fcase->entries[0].mutation = MUT_LINKNAME_HIGHBIT;
                break;
            case 42:
                /* Champ magic en octets non-ASCII. */
                set_regular_entry(&fcase->entries[0], n0, 31UL, 31U, '0');
                fcase->entries[0].mutation = MUT_MAGIC_HIGHBIT;
                break;
            case 43:
                /* Champ version en octets non-ASCII. */
                set_regular_entry(&fcase->entries[0], n0, 17UL, 17U, '0');
                fcase->entries[0].mutation = MUT_VERSION_HIGHBIT;
                break;
            case 44:
                /* uname non-ASCII. */
                set_regular_entry(&fcase->entries[0], n0, 19UL, 19U, '0');
                fcase->entries[0].mutation = MUT_UNAME_HIGHBIT;
                break;
            case 45:
                /* gname non-ASCII. */
                set_regular_entry(&fcase->entries[0], n0, 19UL, 19U, '0');
                fcase->entries[0].mutation = MUT_GNAME_HIGHBIT;
                break;
            case 46:
                /* Champ size rempli de non-ASCII. */
                set_regular_entry(&fcase->entries[0], n0, 512UL, 9U, '0');
                fcase->entries[0].mutation = MUT_SIZE_HIGHBIT;
                break;
            case 47:
                /* Multi-entrees combinee non-ASCII + structure. */
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
}
