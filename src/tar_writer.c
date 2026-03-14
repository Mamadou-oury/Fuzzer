#define _POSIX_C_SOURCE 200809L

#include <errno.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/types.h>
#include <time.h>
#include <unistd.h>

#include "common.h"
#include "tar_writer.h"

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
int write_archive(const char *path, const struct fuzz_case *fcase, unsigned int seed) {
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
