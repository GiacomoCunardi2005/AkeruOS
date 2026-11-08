#ifndef AKERU_NIKON_V11_MEMDUMP_MAP_H
#define AKERU_NIKON_V11_MEMDUMP_MAP_H
#include "nikon_v11_memdump_held.h"
#include "ram_dump.h"

/* Experimental: one owner, zero-initialized persistent session; no inferred map. */
struct akeru_memdump_map {
    struct akeru_memdump_held held;
    void *file;
    uint32_t start, length, completed;
};
int akeru_memdump_map_run(struct akeru_memdump_map *, const struct akeru_dump_region *, uint32_t);
#endif
