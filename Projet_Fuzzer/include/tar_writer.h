#ifndef TAR_WRITER_H
#define TAR_WRITER_H

#include "fuzzer_types.h"

int write_archive(const char *path, const struct fuzz_case *fcase, unsigned int seed);

#endif /* TAR_WRITER_H */
