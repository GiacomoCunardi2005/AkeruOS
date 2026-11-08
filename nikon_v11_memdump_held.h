#ifndef AKERU_NIKON_V11_MEMDUMP_HELD_H
#define AKERU_NIKON_V11_MEMDUMP_HELD_H

#include <stdint.h>

/* Offline prototype: caller must own and synchronize this context and handle. */
struct akeru_memdump_held {
    volatile uintptr_t owner;
    void * volatile handle;
    volatile uint32_t phase;
};

uint32_t akeru_memdump_held_route(struct akeru_memdump_held *ctx,
    uintptr_t current, const char *name, const void *data, uint32_t length,
    uint32_t selector);

int akeru_memdump_held_attach(struct akeru_memdump_held *ctx, void *handle);
int akeru_memdump_held_detach(struct akeru_memdump_held *ctx);
uint32_t akeru_memdump_held_route_current(struct akeru_memdump_held *ctx,
    const char *name, const void *data, uint32_t length, uint32_t selector);

#endif
