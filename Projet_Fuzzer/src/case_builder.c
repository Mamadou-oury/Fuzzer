#define _POSIX_C_SOURCE 200809L

#include <errno.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#include "case_builder.h"
#include "common.h"

/*
 * Number of cases configurable through FUZZ_CASES (default: MAX_CASES).
 * Safety bounds keep execution time reasonable.
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
