#include "nikon_v11_memdump_map.h"

struct akeru_memdump_map akeru_map_session __attribute__((section(".data.akeru_map_session"))) = {0};

uint32_t akeru_memdump_held_site(const char *name, const void *data,
                                 uint32_t length, uint32_t selector)
{
    return akeru_memdump_held_route_current(&akeru_map_session.held, name, data, length, selector);
}
