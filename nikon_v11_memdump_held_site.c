#include "nikon_v11_memdump_held.h"

/* Offline prototype: lives in the Resource payload, whose ownership/writability is a lab hypothesis. */
struct akeru_memdump_held akeru_held_ctx __attribute__((section(".data.akeru_held"))) = {0, 0, 0};

/* Target of the two patched 0x12BD5C call sites inside V1.1 0x16ED40. */
uint32_t akeru_memdump_held_site(const char *name, const void *data,
                                 uint32_t length, uint32_t selector)
{
    return akeru_memdump_held_route_current(&akeru_held_ctx, name, data, length, selector);
}
