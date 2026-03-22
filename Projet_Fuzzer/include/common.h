#ifndef COMMON_H
#define COMMON_H

#include <stddef.h>

/* Safe string copy into a fixed-size buffer (always NUL-terminated). */
void copy_cstr(char *dst, size_t dst_size, const char *src);

#endif /* COMMON_H */
