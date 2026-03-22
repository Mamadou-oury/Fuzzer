#define _POSIX_C_SOURCE 200809L

#include <dirent.h>
#include <errno.h>
#include <limits.h>
#include <stdio.h>
#include <string.h>
#include <sys/stat.h>
#include <sys/types.h>
#include <unistd.h>

#include "common.h"
#include "runtime.h"

/*
 * Run extractor_path archive_path and detect crash by stdout banner.
 * Returns: 1 crash found, 0 no crash, -1 execution error.
 */
int run_extractor_and_detect_crash(const char *extractor_path, const char *archive_path) {
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

/* Binary file copy helper for saving crashing archives. */
int copy_file(const char *src, const char *dst) {
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

/* Create/update the required "crashing" marker file. */
int mark_crashing(void) {
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

/* Remove empty parent directories of a relative path. */
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

/* Remove one path safely, then prune empty parent directories. */
static void cleanup_path(const char *path) {
    if (path[0] == '\0') {
        return;
    }

    /*
     * Safety guardrails: never delete outside the current directory.
     * Ignore absolute paths and any path containing "..".
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

/* Recursively delete a relative file tree rooted at path. */
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

/* Remove all top-level entries starting with "fz_<run_nonce>_". */
void cleanup_run_prefix(unsigned long run_nonce) {
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

/* Best-effort cleanup of entry names emitted in one fuzz case. */
void cleanup_case_artifacts(const struct fuzz_case *fcase) {
    size_t i;
    for (i = 0; i < fcase->entry_count; i++) {
        cleanup_path(fcase->entries[i].name);
    }
}
