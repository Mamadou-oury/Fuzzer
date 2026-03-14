#define _POSIX_C_SOURCE 200809L

#include <string.h>

#include "common.h"

void copy_cstr(char *dst, size_t dst_size, const char *src) {
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
