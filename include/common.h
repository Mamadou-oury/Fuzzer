#ifndef COMMON_H
#define COMMON_H

#include <stddef.h>

/* Copie sure d'une chaine vers un buffer fixe (toujours termine par '\0'). */
void copy_cstr(char *dst, size_t dst_size, const char *src);

#endif /* COMMON_H */
