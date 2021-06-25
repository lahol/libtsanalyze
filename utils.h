#pragma once

#include <stdlib.h>

void *util_alloc(size_t size);
void *util_alloc0(size_t size);
void *util_realloc(void *ptr, size_t size);
void util_free(void *ptr);
