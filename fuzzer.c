#define _POSIX_C_SOURCE 200809L

#include <errno.h>
#include <limits.h>
#include <dirent.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/stat.h>
#include <sys/types.h>
#include <time.h>
#include <unistd.h>

/*
 * Vue d'ensemble (version V3)
 * ---------------------------
 * 1) Le fuzzer genere des archives TAR via plusieurs campagnes ciblees.
 * 2) Chaque archive est soumise a l'extracteur passe en argument.
 * 3) Si le message "*** The program has crashed ***" apparait, l'archive est
 *    sauvegardee sous success_XXXX.tar et le fichier "crashing" est cree.
 * 4) Les artefacts extraits sont nettoyes apres chaque cas pour garder
 *    le repertoire de travail exploitable.
 *
 * Objectif: augmenter la couverture tout en restant "generation-based":
 * on construit des archives depuis la structure TAR, au lieu de muter
 * un fichier de base existant.
 */

/* Constantes du format et de la campagne de fuzzing. */
#define BLOCK_SIZE 512U
#define MAX_CASES 1024U
#define ARCHIVE_NAME "archive.tar"
#define CRASH_MARKER "crashing"
#define MAX_ENTRIES_PER_CASE 3U

/*
 * Mutations de structure d'archive (niveau "container", pas seulement header).
 */
enum archive_mutation {
    AM_NONE = 0,
    AM_OMIT_EOF_1,
    AM_OMIT_EOF_2,
    AM_EOF_3,
    AM_EOF_4,
    AM_LEADING_GARBAGE,
    AM_TRAILING_GARBAGE,
    AM_SKIP_LAST_PADDING,
    AM_TRUNCATE_1,
    AM_TRUNCATE_BLOCK,
    AM_TRUNCATE_MID_HEADER,
    AM_TRUNCATE_MID_PAYLOAD,
    AM_TRUNCATE_MID_PADDING
};

/*
 * Header POSIX TAR (512 octets).
 * Cette structure est la base de generation des entrees d'archives.
 */
struct tar_t {
    char name[100];
    char mode[8];
    char uid[8];
    char gid[8];
    char size[12];
    char mtime[12];
    char chksum[8];
    char typeflag;
    char linkname[100];
    char magic[6];
    char version[2];
    char uname[32];
    char gname[32];
    char devmajor[8];
    char devminor[8];
    char prefix[155];
    char padding[12];
};

/*
 * Mutations de header appliquees de maniere ciblee.
 * Certaines conservent un checksum valide, d'autres le corrompent volontairement.
 */
enum header_mutation {
    MUT_NONE = 0,
    MUT_BAD_CHECKSUM,
    MUT_SIZE_NON_OCTAL,
    MUT_SIZE_NO_NUL,
    MUT_SIZE_SPACES,
    MUT_SIZE_PLUS,
    MUT_SIZE_MINUS,
    MUT_SIZE_OVERFLOW,
    MUT_SIZE_NUL_MIXED,
    MUT_MODE_NON_OCTAL,
    MUT_MODE_SPACES,
    MUT_MODE_PLUS,
    MUT_MODE_MINUS,
    MUT_MODE_OVERFLOW,
    MUT_UID_NON_OCTAL,
    MUT_UID_SPACES,
    MUT_UID_PLUS,
    MUT_UID_MINUS,
    MUT_UID_OVERFLOW,
    MUT_GID_NON_OCTAL,
    MUT_GID_SPACES,
    MUT_GID_PLUS,
    MUT_GID_MINUS,
    MUT_GID_OVERFLOW,
    MUT_MTIME_NON_OCTAL,
    MUT_MTIME_SPACES,
    MUT_MTIME_PLUS,
    MUT_MTIME_MINUS,
    MUT_MTIME_OVERFLOW,
    MUT_MAGIC_ZERO,
    MUT_MAGIC_GARBAGE,
    MUT_MAGIC_HIGHBIT,
    MUT_VERSION_GARBAGE,
    MUT_VERSION_HIGHBIT,
    MUT_NAME_NO_NUL,
    MUT_NAME_HIGHBIT,
    MUT_LINKNAME_NO_NUL,
    MUT_LINKNAME_HIGHBIT,
    MUT_UNAME_HIGHBIT,
    MUT_GNAME_HIGHBIT,
    MUT_SIZE_HIGHBIT,
    MUT_TYPEFLAG_HIGHBIT,
    MUT_TYPEFLAG_ODD,
    MUT_CHKSUM_SPACES
};

/*
 * Description d'une entree TAR a ecrire.
 * declared_size: valeur ecrite dans le header
 * payload_size: octets reellement ecrits apres le header
 */
struct fuzz_entry {
    char name[100];
    char prefix[155];
    char linkname[100];
    char typeflag;
    unsigned long mode;
    unsigned long uid;
    unsigned long gid;
    unsigned long declared_size;
    size_t payload_size;
    enum header_mutation mutation;
};

/*
 * Une archive generee pour un test.
 * On supporte 1 a 3 entrees pour tester les parseurs multi-headers.
 * archive_mutation + (eof/leading/trailing/cut_tail) permettent de casser la
 * structure globale du conteneur TAR.
 */
struct fuzz_case {
    size_t entry_count;
    struct fuzz_entry entries[MAX_ENTRIES_PER_CASE];
    enum archive_mutation archive_mutation;
    int eof_blocks_override;
    size_t leading_garbage_size;
    size_t trailing_garbage_size;
    size_t cut_tail_bytes;
};

/*
 * Copie sure d'une chaine vers un buffer fixe (toujours termine par '\0').
 */
static void copy_cstr(char *dst, size_t dst_size, const char *src) {
    size_t n;
    if (dst_size == 0U) {
        return;
    }
    n = strlen(src);
    if (n >= dst_size) {
        n = dst_size - 1U;
    }
    if (n > 0U) {
        memcpy(dst, src, n);
    }
    dst[n] = '\0';
}

/*
 * Remplit un champ avec un motif alphabetique (sans forcement inserer '\0').
 * Utile pour des mutations de champs non termines.
 */
static void fill_field_pattern(char *field, size_t len, unsigned int seed, char base) {
    size_t i;
    for (i = 0; i < len; i++) {
        field[i] = (char)(base + (char)((seed + i) % 26U));
    }
}

/*
 * Remplit un champ avec des octets non-ASCII (bit de poids fort a 1).
 */
static void fill_field_highbit(char *field, size_t len, unsigned int seed) {
    size_t i;
    for (i = 0; i < len; i++) {
        field[i] = (char)(0x80U | ((seed + (unsigned int)i) & 0x3fU));
    }
}

/*
 * Encode un entier dans un champ octal ASCII TAR.
 * Exemple: 420 decimal devient "0000644" pour un champ mode.
 */
static void write_octal_field(char *field, size_t field_size, unsigned long value) {
    if (field_size == 0U) {
        return;
    }
    memset(field, 0, field_size);
    (void)snprintf(field, field_size, "%0*lo", (int)(field_size - 1U), value);
}

/*
 * Calcule le checksum TAR:
 * - chksum est temporairement rempli d'espaces
 * - on somme les 512 octets du header
 * - on reencode la somme en octal ASCII
 */
static unsigned int calculate_checksum(struct tar_t *entry) {
    unsigned int check = 0U;
    unsigned char *raw = (unsigned char *)entry;
    size_t i;

    memset(entry->chksum, ' ', sizeof(entry->chksum));
    for (i = 0; i < BLOCK_SIZE; i++) {
        check += raw[i];
    }

    (void)snprintf(entry->chksum, sizeof(entry->chksum), "%06o0", check);
    entry->chksum[6] = '\0';
    entry->chksum[7] = ' ';
    return check;
}

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

/*
 * Applique les mutations qui doivent intervenir AVANT le checksum.
 * Le checksum calcule ensuite "valide" la mutation (sauf si on le casse apres).
 */
static void apply_pre_checksum_mutation(struct tar_t *header,
                                        enum header_mutation mutation,
                                        unsigned int seed) {
    static const unsigned char odd_typeflags[] = {0x00, 0x01, 0x7f, 0x80, 0x90, 'A', 'Z', '3', '6'};

    switch (mutation) {
        case MUT_SIZE_NON_OCTAL:
            memset(header->size, '9', sizeof(header->size) - 1U);
            header->size[sizeof(header->size) - 1U] = '\0';
            break;
        case MUT_SIZE_NO_NUL:
            memset(header->size, '7', sizeof(header->size));
            break;
        case MUT_SIZE_SPACES:
            memset(header->size, ' ', sizeof(header->size));
            break;
        case MUT_SIZE_PLUS:
            memcpy(header->size, "+0000007777", 10U);
            header->size[10] = '\0';
            header->size[11] = ' ';
            break;
        case MUT_SIZE_MINUS:
            memcpy(header->size, "-0000000001", 11U);
            header->size[11] = '\0';
            break;
        case MUT_SIZE_OVERFLOW:
            memset(header->size, '7', sizeof(header->size));
            break;
        case MUT_SIZE_NUL_MIXED:
            memset(header->size, ' ', sizeof(header->size));
            memcpy(header->size, "000000", 6U);
            header->size[6] = '\0';
            header->size[7] = '7';
            header->size[8] = '7';
            header->size[9] = '\0';
            header->size[10] = '0';
            header->size[11] = ' ';
            break;
        case MUT_MODE_NON_OCTAL:
            memset(header->mode, '9', sizeof(header->mode) - 1U);
            header->mode[sizeof(header->mode) - 1U] = '\0';
            break;
        case MUT_MODE_SPACES:
            memset(header->mode, ' ', sizeof(header->mode));
            break;
        case MUT_MODE_PLUS:
            memcpy(header->mode, "+00644", 6U);
            header->mode[6] = '\0';
            header->mode[7] = ' ';
            break;
        case MUT_MODE_MINUS:
            memcpy(header->mode, "-000644", 7U);
            header->mode[7] = '\0';
            break;
        case MUT_MODE_OVERFLOW:
            memset(header->mode, '7', sizeof(header->mode));
            break;
        case MUT_UID_NON_OCTAL:
            memcpy(header->uid, "-000001", 7U);
            header->uid[7] = '\0';
            break;
        case MUT_UID_SPACES:
            memset(header->uid, ' ', sizeof(header->uid));
            break;
        case MUT_UID_PLUS:
            memcpy(header->uid, "+001234", 7U);
            header->uid[7] = '\0';
            break;
        case MUT_UID_MINUS:
            memcpy(header->uid, "-001234", 7U);
            header->uid[7] = '\0';
            break;
        case MUT_UID_OVERFLOW:
            memset(header->uid, '7', sizeof(header->uid));
            break;
        case MUT_GID_NON_OCTAL:
            memset(header->gid, 'x', sizeof(header->gid) - 1U);
            header->gid[sizeof(header->gid) - 1U] = '\0';
            break;
        case MUT_GID_SPACES:
            memset(header->gid, ' ', sizeof(header->gid));
            break;
        case MUT_GID_PLUS:
            memcpy(header->gid, "+007777", 7U);
            header->gid[7] = '\0';
            break;
        case MUT_GID_MINUS:
            memcpy(header->gid, "-007777", 7U);
            header->gid[7] = '\0';
            break;
        case MUT_GID_OVERFLOW:
            memset(header->gid, '7', sizeof(header->gid));
            break;
        case MUT_MTIME_NON_OCTAL:
            memset(header->mtime, 'z', sizeof(header->mtime) - 1U);
            header->mtime[sizeof(header->mtime) - 1U] = '\0';
            break;
        case MUT_MTIME_SPACES:
            memset(header->mtime, ' ', sizeof(header->mtime));
            break;
        case MUT_MTIME_PLUS:
            memcpy(header->mtime, "+0000001234", 11U);
            header->mtime[11] = '\0';
            break;
        case MUT_MTIME_MINUS:
            memcpy(header->mtime, "-0000000001", 11U);
            header->mtime[11] = '\0';
            break;
        case MUT_MTIME_OVERFLOW:
            memset(header->mtime, '7', sizeof(header->mtime));
            break;
        case MUT_SIZE_HIGHBIT:
            fill_field_highbit(header->size, sizeof(header->size), seed);
            break;
        case MUT_MAGIC_ZERO:
            memset(header->magic, 0, sizeof(header->magic));
            break;
        case MUT_MAGIC_GARBAGE:
            memcpy(header->magic, "abcde", 5U);
            header->magic[5] = '\0';
            break;
        case MUT_MAGIC_HIGHBIT:
            fill_field_highbit(header->magic, sizeof(header->magic), seed);
            break;
        case MUT_VERSION_GARBAGE:
            header->version[0] = '9';
            header->version[1] = '9';
            break;
        case MUT_VERSION_HIGHBIT:
            fill_field_highbit(header->version, sizeof(header->version), seed);
            break;
        case MUT_NAME_NO_NUL:
            fill_field_pattern(header->name, sizeof(header->name), seed, 'a');
            break;
        case MUT_NAME_HIGHBIT:
            fill_field_highbit(header->name, sizeof(header->name) - 1U, seed);
            header->name[sizeof(header->name) - 1U] = '\0';
            break;
        case MUT_LINKNAME_NO_NUL:
            fill_field_pattern(header->linkname, sizeof(header->linkname), seed, 'k');
            break;
        case MUT_LINKNAME_HIGHBIT:
            fill_field_highbit(header->linkname, sizeof(header->linkname) - 1U, seed);
            header->linkname[sizeof(header->linkname) - 1U] = '\0';
            break;
        case MUT_UNAME_HIGHBIT:
            fill_field_highbit(header->uname, sizeof(header->uname) - 1U, seed);
            header->uname[sizeof(header->uname) - 1U] = '\0';
            break;
        case MUT_GNAME_HIGHBIT:
            fill_field_highbit(header->gname, sizeof(header->gname) - 1U, seed);
            header->gname[sizeof(header->gname) - 1U] = '\0';
            break;
        case MUT_TYPEFLAG_HIGHBIT:
            header->typeflag = (char)0x90;
            break;
        case MUT_TYPEFLAG_ODD:
            header->typeflag = (char)odd_typeflags[seed % (sizeof(odd_typeflags) / sizeof(odd_typeflags[0]))];
            break;
        case MUT_NONE:
        case MUT_BAD_CHECKSUM:
        case MUT_CHKSUM_SPACES:
            break;
    }
}

/*
 * Applique les mutations qui doivent intervenir APRES le checksum.
 */
static void apply_post_checksum_mutation(struct tar_t *header,
                                         enum header_mutation mutation) {
    if (mutation == MUT_BAD_CHECKSUM) {
        header->chksum[0] = (header->chksum[0] == '0') ? '1' : '0';
    } else if (mutation == MUT_CHKSUM_SPACES) {
        memset(header->chksum, ' ', sizeof(header->chksum));
    }
}

/*
 * Construit le header final d'une entree.
 */
static void init_header(struct tar_t *header,
                        const struct fuzz_entry *entry,
                        unsigned int seed) {
    memset(header, 0, sizeof(*header));

    copy_cstr(header->name, sizeof(header->name), entry->name);
    write_octal_field(header->mode, sizeof(header->mode), entry->mode);
    write_octal_field(header->uid, sizeof(header->uid), entry->uid);
    write_octal_field(header->gid, sizeof(header->gid), entry->gid);
    write_octal_field(header->size, sizeof(header->size), entry->declared_size);
    write_octal_field(header->mtime, sizeof(header->mtime), (unsigned long)time(NULL));
    header->typeflag = entry->typeflag;
    copy_cstr(header->linkname, sizeof(header->linkname), entry->linkname);
    copy_cstr(header->prefix, sizeof(header->prefix), entry->prefix);

    memcpy(header->magic, "ustar", 5U);
    header->magic[5] = '\0';
    memcpy(header->version, "00", 2U);
    copy_cstr(header->uname, sizeof(header->uname), "student");
    copy_cstr(header->gname, sizeof(header->gname), "student");

    apply_pre_checksum_mutation(header, entry->mutation, seed);
    (void)calculate_checksum(header);
    apply_post_checksum_mutation(header, entry->mutation);
}

/*
 * Taille de padding pour aligner les donnees sur 512 octets.
 */
static size_t block_padding(size_t payload_size) {
    return (BLOCK_SIZE - (payload_size % BLOCK_SIZE)) % BLOCK_SIZE;
}

/*
 * Remplit un payload avec un motif deterministe pour ce cas.
 */
static void fill_payload(unsigned char *data, size_t len, unsigned int seed) {
    size_t i;
    for (i = 0; i < len; i++) {
        data[i] = (unsigned char)((seed + i) & 0xffU);
    }
}

/*
 * Ecrit une entree complete (header + payload + padding optionnel).
 * Si write_padding == 0, on saute volontairement l'alignement 512 octets.
 */
struct entry_layout {
    long header_start;
    long payload_start;
    long payload_end;
    long padding_start;
    long padding_end;
};

static int write_entry(FILE *out,
                       const struct fuzz_entry *entry,
                       unsigned int seed,
                       int write_padding,
                       struct entry_layout *layout) {
    struct tar_t header;
    size_t pad_size = block_padding(entry->payload_size);
    long pos;

    if (layout != NULL) {
        layout->header_start = -1L;
        layout->payload_start = -1L;
        layout->payload_end = -1L;
        layout->padding_start = -1L;
        layout->padding_end = -1L;
    }

    init_header(&header, entry, seed);

    pos = ftell(out);
    if (pos < 0L) {
        return -1;
    }
    if (layout != NULL) {
        layout->header_start = pos;
    }

    if (fwrite(&header, 1U, sizeof(header), out) != sizeof(header)) {
        return -1;
    }

    pos = ftell(out);
    if (pos < 0L) {
        return -1;
    }
    if (layout != NULL) {
        layout->payload_start = pos;
    }

    if (entry->payload_size > 0U) {
        unsigned char *payload = malloc(entry->payload_size);
        if (payload == NULL) {
            return -1;
        }
        fill_payload(payload, entry->payload_size, seed);
        if (fwrite(payload, 1U, entry->payload_size, out) != entry->payload_size) {
            free(payload);
            return -1;
        }
        free(payload);
    }

    pos = ftell(out);
    if (pos < 0L) {
        return -1;
    }
    if (layout != NULL) {
        layout->payload_end = pos;
        layout->padding_start = pos;
    }

    if (write_padding && pad_size > 0U) {
        unsigned char pad[BLOCK_SIZE] = {0};
        if (fwrite(pad, 1U, pad_size, out) != pad_size) {
            return -1;
        }
    }

    pos = ftell(out);
    if (pos < 0L) {
        return -1;
    }
    if (layout != NULL) {
        layout->padding_end = pos;
    }

    return 0;
}

/*
 * Ecrit l'archive complete:
 * - N entrees (1..3)
 * - fin TAR configurable (0/1/2 blocs zero)
 * - garbage optionnel apres la fin
 * - troncature optionnelle de la fin de fichier
 */
static int write_archive(const char *path, const struct fuzz_case *fcase, unsigned int seed) {
    FILE *out;
    size_t i;
    int eof_blocks_to_write = 2;
    int skip_padding_on_last = (fcase->archive_mutation == AM_SKIP_LAST_PADDING);
    struct entry_layout layout[MAX_ENTRIES_PER_CASE];
    long truncate_pos = -1L;
    long end_pos;

    out = fopen(path, "wb");
    if (out == NULL) {
        fprintf(stderr, "fopen(%s): %s\n", path, strerror(errno));
        return -1;
    }

    if (fcase->leading_garbage_size > 0U ||
        fcase->archive_mutation == AM_LEADING_GARBAGE) {
        unsigned char extra[64];
        size_t left = fcase->leading_garbage_size;
        if (left == 0U) {
            left = 17U;
        }
        memset(extra, 0x4c, sizeof(extra));
        while (left > 0U) {
            size_t chunk = (left < sizeof(extra)) ? left : sizeof(extra);
            if (fwrite(extra, 1U, chunk, out) != chunk) {
                fclose(out);
                return -1;
            }
            left -= chunk;
        }
    }

    for (i = 0; i < fcase->entry_count; i++) {
        int write_padding = 1;
        if (skip_padding_on_last && i + 1U == fcase->entry_count) {
            write_padding = 0;
        }

        if (write_entry(out,
                        &fcase->entries[i],
                        seed + (unsigned int)(i * 997U),
                        write_padding,
                        &layout[i]) != 0) {
            fclose(out);
            return -1;
        }
    }

    if (fcase->eof_blocks_override >= 0) {
        eof_blocks_to_write = fcase->eof_blocks_override;
    } else if (fcase->archive_mutation == AM_OMIT_EOF_1) {
        eof_blocks_to_write = 1;
    } else if (fcase->archive_mutation == AM_OMIT_EOF_2) {
        eof_blocks_to_write = 0;
    } else if (fcase->archive_mutation == AM_EOF_3) {
        eof_blocks_to_write = 3;
    } else if (fcase->archive_mutation == AM_EOF_4) {
        eof_blocks_to_write = 4;
    }

    if (eof_blocks_to_write > 0) {
        unsigned char zeros[BLOCK_SIZE] = {0};
        int b;
        for (b = 0; b < eof_blocks_to_write; b++) {
            if (fwrite(zeros, 1U, BLOCK_SIZE, out) != BLOCK_SIZE) {
                fclose(out);
                return -1;
            }
        }
    }

    if (fcase->trailing_garbage_size > 0U ||
        fcase->archive_mutation == AM_TRAILING_GARBAGE) {
        unsigned char extra[64];
        size_t left = fcase->trailing_garbage_size;
        if (left == 0U) {
            left = 13U;
        }
        memset(extra, 0x41, sizeof(extra));
        while (left > 0U) {
            size_t chunk = (left < sizeof(extra)) ? left : sizeof(extra);
            if (fwrite(extra, 1U, chunk, out) != chunk) {
                fclose(out);
                return -1;
            }
            left -= chunk;
        }
    }

    end_pos = ftell(out);
    if (end_pos < 0L) {
        fclose(out);
        return -1;
    }

    if (fcase->archive_mutation == AM_TRUNCATE_MID_HEADER &&
        fcase->entry_count > 0U &&
        layout[0].header_start >= 0L) {
        truncate_pos = layout[0].header_start + (long)(BLOCK_SIZE / 2U);
    } else if (fcase->archive_mutation == AM_TRUNCATE_MID_PAYLOAD) {
        for (i = 0; i < fcase->entry_count; i++) {
            long span = layout[i].payload_end - layout[i].payload_start;
            if (layout[i].payload_start >= 0L && layout[i].payload_end > layout[i].payload_start && span > 1L) {
                truncate_pos = layout[i].payload_start + (span / 2L);
                break;
            }
        }
    } else if (fcase->archive_mutation == AM_TRUNCATE_MID_PADDING) {
        for (i = 0; i < fcase->entry_count; i++) {
            long span = layout[i].padding_end - layout[i].padding_start;
            if (layout[i].padding_start >= 0L && layout[i].padding_end > layout[i].padding_start && span > 1L) {
                truncate_pos = layout[i].padding_start + (span / 2L);
                break;
            }
        }
    }

    if (truncate_pos > 0L && truncate_pos < end_pos) {
        int fd = fileno(out);
        if (fd < 0 || ftruncate(fd, (off_t)truncate_pos) != 0) {
            fclose(out);
            return -1;
        }
        end_pos = truncate_pos;
    }

    if (fcase->archive_mutation == AM_TRUNCATE_1 ||
        fcase->archive_mutation == AM_TRUNCATE_BLOCK ||
        fcase->cut_tail_bytes > 0U) {
        size_t cut = fcase->cut_tail_bytes;
        if (cut == 0U) {
            cut = (fcase->archive_mutation == AM_TRUNCATE_1) ? 1U : BLOCK_SIZE;
        }
        if (end_pos > 0L && cut > 0U && (unsigned long)end_pos > cut) {
            int fd = fileno(out);
            if (fd < 0 || ftruncate(fd, (off_t)((unsigned long)end_pos - cut)) != 0) {
                fclose(out);
                return -1;
            }
            end_pos = (long)((unsigned long)end_pos - cut);
        }
    }

    if (fclose(out) != 0) {
        return -1;
    }
    return 0;
}

/*
 * Lance l'extracteur et detecte le message de crash.
 * Retour: -1 erreur, 0 pas de crash, 1 crash detecte.
 */
static int run_extractor_and_detect_crash(const char *extractor_path, const char *archive_path) {
    char cmd[1024];
    FILE *fp;
    char line[256];
    int crashed = 0;

    if (snprintf(cmd, sizeof(cmd), "\"%s\" \"%s\" 2>&1",
                 extractor_path, archive_path) >= (int)sizeof(cmd)) {
        return -1;
    }

    fp = popen(cmd, "r");
    if (fp == NULL) {
        return -1;
    }

    while (fgets(line, sizeof(line), fp) != NULL) {
        if (strstr(line, "*** The program has crashed ***") != NULL) {
            crashed = 1;
            break;
        }
    }

    if (pclose(fp) == -1) {
        return -1;
    }
    return crashed;
}

/*
 * Copie binaire d'un fichier (pour sauvegarder les cas crashants).
 */
static int copy_file(const char *src, const char *dst) {
    FILE *in;
    FILE *out;
    unsigned char buf[4096];
    size_t nread;

    in = fopen(src, "rb");
    if (in == NULL) {
        return -1;
    }
    out = fopen(dst, "wb");
    if (out == NULL) {
        fclose(in);
        return -1;
    }

    while ((nread = fread(buf, 1U, sizeof(buf), in)) > 0U) {
        if (fwrite(buf, 1U, nread, out) != nread) {
            fclose(in);
            fclose(out);
            return -1;
        }
    }

    if (ferror(in) != 0 || fclose(in) != 0 || fclose(out) != 0) {
        return -1;
    }
    return 0;
}

/*
 * Cree le fichier "crashing" des qu'un crash est trouve.
 */
static int mark_crashing(void) {
    FILE *marker = fopen(CRASH_MARKER, "w");
    if (marker == NULL) {
        return -1;
    }
    if (fputs("1\n", marker) == EOF) {
        fclose(marker);
        return -1;
    }
    return fclose(marker);
}

/*
 * Supprime recursivement les parents (s'ils sont vides) d'un chemin imbrique.
 * Ex: "a/b/c" -> tente rmdir("a/b"), puis rmdir("a").
 */
static void cleanup_parent_dirs(const char *path) {
    char tmp[256];
    char *slash;

    copy_cstr(tmp, sizeof(tmp), path);
    while ((slash = strrchr(tmp, '/')) != NULL) {
        *slash = '\0';
        if (tmp[0] == '\0') {
            break;
        }
        if (rmdir(tmp) != 0) {
            break;
        }
    }
}

/*
 * Supprime un artefact potentiel (fichier, lien, fifo, dossier vide).
 */
static void cleanup_path(const char *path) {
    if (path[0] == '\0') {
        return;
    }

    /*
     * Garde-fous: ne jamais supprimer en dehors du dossier courant.
     * On ignore les chemins absolus et ceux contenant "..".
     */
    if (path[0] == '/' || strstr(path, "..") != NULL) {
        return;
    }

    if (unlink(path) != 0) {
        if (errno == EISDIR || errno == EPERM || errno == EACCES) {
            (void)rmdir(path);
        }
    }

    cleanup_parent_dirs(path);
}

/*
 * Suppression recursive robuste d'un chemin relatif.
 * Utilise pour les residues de cas (ex: dossiers vides restants).
 */
static int remove_tree_recursive(const char *path) {
    struct stat st;

    if (path == NULL || path[0] == '\0') {
        return -1;
    }
    if (path[0] == '/' || strstr(path, "..") != NULL) {
        return -1;
    }

    if (lstat(path, &st) != 0) {
        return -1;
    }

    if (S_ISDIR(st.st_mode)) {
        DIR *dir = opendir(path);
        struct dirent *ent;

        if (dir == NULL) {
            return -1;
        }

        while ((ent = readdir(dir)) != NULL) {
            char child[PATH_MAX];

            if (strcmp(ent->d_name, ".") == 0 || strcmp(ent->d_name, "..") == 0) {
                continue;
            }

            if (snprintf(child, sizeof(child), "%s/%s", path, ent->d_name) >= (int)sizeof(child)) {
                (void)closedir(dir);
                return -1;
            }

            (void)remove_tree_recursive(child);
        }

        (void)closedir(dir);
        return rmdir(path);
    }

    return unlink(path);
}

/*
 * Nettoyage de securite: supprime tout objet commencant par
 * "fz_<run_nonce>_" dans le dossier courant.
 * On balaye tout le namespace du run pour eviter les residues inter-cas.
 */
static void cleanup_run_prefix(unsigned long run_nonce) {
    char prefix[64];
    DIR *dir;
    struct dirent *ent;
    size_t prefix_len;

    if (snprintf(prefix, sizeof(prefix), "fz_%lu_", run_nonce) >= (int)sizeof(prefix)) {
        return;
    }
    prefix_len = strlen(prefix);

    dir = opendir(".");
    if (dir == NULL) {
        return;
    }

    while ((ent = readdir(dir)) != NULL) {
        const char *name = ent->d_name;
        if (name[0] == '.') {
            continue;
        }
        if (strncmp(name, prefix, prefix_len) == 0) {
            (void)remove_tree_recursive(name);
        }
    }

    (void)closedir(dir);
}

/*
 * Nettoie les objets extraits correspondant aux noms du cas courant.
 * Cela evite que le dossier se remplisse entre les iterations.
 */
static void cleanup_case_artifacts(const struct fuzz_case *fcase) {
    size_t i;
    for (i = 0; i < fcase->entry_count; i++) {
        cleanup_path(fcase->entries[i].name);
    }
}

/*
 * Initialise un cas vide.
 */
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
static unsigned int resolve_case_count(void) {
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
static void build_case(struct fuzz_case *fcase,
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

int main(int argc, char **argv) {
    char extractor_path[PATH_MAX];
    unsigned long run_nonce;
    unsigned int success_count = 0U;
    unsigned int total_cases;
    unsigned int i;

    if (argc != 2) {
        fprintf(stderr, "Usage: %s <path-to-extractor>\n", argv[0]);
        return 1;
    }

    if (realpath(argv[1], extractor_path) == NULL) {
        fprintf(stderr, "Invalid extractor path (%s): %s\n", argv[1], strerror(errno));
        return 1;
    }

    total_cases = resolve_case_count();
    run_nonce = ((unsigned long)time(NULL)) ^ ((unsigned long)getpid());

    for (i = 0U; i < total_cases; i++) {
        struct fuzz_case fcase;
        int crash;

        build_case(&fcase, i, run_nonce, total_cases);

        if (write_archive(ARCHIVE_NAME, &fcase, i) != 0) {
            fprintf(stderr, "Failed to write archive for case %u\n", i);
            continue;
        }

        crash = run_extractor_and_detect_crash(extractor_path, ARCHIVE_NAME);
        if (crash < 0) {
            fprintf(stderr, "Failed to run extractor at case %u\n", i);
            cleanup_case_artifacts(&fcase);
            cleanup_run_prefix(run_nonce);
            continue;
        }

        if (crash == 1) {
            char out_name[64];
            (void)snprintf(out_name, sizeof(out_name), "success_%04u.tar", success_count);
            if (copy_file(ARCHIVE_NAME, out_name) == 0) {
                success_count++;
                (void)mark_crashing();
            }
        }

        cleanup_case_artifacts(&fcase);
        cleanup_run_prefix(run_nonce);
    }

    printf("Done. Tested %u cases, saved %u crashing archives.\n", total_cases, success_count);
    return 0;
}
