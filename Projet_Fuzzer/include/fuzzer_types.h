#ifndef FUZZER_TYPES_H
#define FUZZER_TYPES_H

#include <stddef.h>

/* Format and fuzzing campaign constants. */
#define BLOCK_SIZE 512U
#define MAX_CASES 1024U
#define ARCHIVE_NAME "archive.tar"
#define CRASH_MARKER "crashing"
#define MAX_ENTRIES_PER_CASE 3U

/*
 * Archive-structure mutations (container-level, not only header-level).
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
 * POSIX TAR header (512 bytes).
 * This structure is the base used to generate archive entries.
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
 * Targeted header mutations.
 * Some keep a valid checksum, others intentionally corrupt it.
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
 * Description of one TAR entry to write.
 * declared_size: value written in the header
 * payload_size: bytes effectively written after the header
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
 * One generated archive for a test case.
 * We support 1 to 3 entries to exercise multi-header parsers.
 * archive_mutation + (eof/leading/trailing/cut_tail) allow breaking
 * the global TAR container structure.
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

#endif /* FUZZER_TYPES_H */
