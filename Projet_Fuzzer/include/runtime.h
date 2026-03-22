#ifndef RUNTIME_H
#define RUNTIME_H

#include "fuzzer_types.h"

int run_extractor_and_detect_crash(const char *extractor_path, const char *archive_path);
int copy_file(const char *src, const char *dst);
int mark_crashing(void);
void cleanup_run_prefix(unsigned long run_nonce);
void cleanup_case_artifacts(const struct fuzz_case *fcase);

#endif /* RUNTIME_H */
