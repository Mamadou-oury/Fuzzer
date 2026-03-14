#ifndef CASE_BUILDER_H
#define CASE_BUILDER_H

#include "fuzzer_types.h"

unsigned int resolve_case_count(void);
void build_case(struct fuzz_case *fcase,
                unsigned int index,
                unsigned long run_nonce,
                unsigned int total_cases);

#endif /* CASE_BUILDER_H */
