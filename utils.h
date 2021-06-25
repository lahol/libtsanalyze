#pragma once

#include <stdlib.h>
#include <memory.h>

void *util_alloc(size_t size)
{
    void *ptr = malloc(size);
    if (ptr == NULL) {
        exit(1);
    }
    return ptr;
}

void *util_alloc0(size_t size)
{
    void *ptr = util_alloc(size);
    memset(ptr, 0, size);
    return ptr;
}

void util_free(void *ptr)
{
    free(ptr);
}
