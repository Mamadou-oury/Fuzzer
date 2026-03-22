#define _POSIX_C_SOURCE 200809L

#include <errno.h>
#include <limits.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <time.h>
#include <unistd.h>

#include "case_builder.h"
#include "tar_writer.h"
#include "runtime.h"

/*
 * Main fuzzing loop:
 * 1) build one case
 * 2) write archive.tar
 * 3) run extractor and detect crash marker
 * 4) save crashing inputs as success_XXXX.tar
 * 5) clean extracted side effects before next iteration
 */
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

    /* FUZZ_CASES-aware case count with safety bounds. */
    total_cases = resolve_case_count();
    run_nonce = ((unsigned long)time(NULL)) ^ ((unsigned long)getpid());

    for (i = 0U; i < total_cases; i++) {
        struct fuzz_case fcase;
        int crash;

        /* Build one generation-based test case. */
        build_case(&fcase, i, run_nonce, total_cases);

        /* Materialize the generated case into archive.tar. */
        if (write_archive(ARCHIVE_NAME, &fcase, i) != 0) {
            fprintf(stderr, "Failed to write archive for case %u\n", i);
            continue;
        }

        /* Execute extractor and look for the exact crash banner. */
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
                /* Marker required by the project statement. */
                (void)mark_crashing();
            }
        }

        /* Remove files/directories possibly created by this extractor run. */
        cleanup_case_artifacts(&fcase);
        cleanup_run_prefix(run_nonce);
    }

    printf("Done. Tested %u cases, saved %u crashing archives.\n", total_cases, success_count);
    return 0;
}
