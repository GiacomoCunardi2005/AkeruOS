#include "nikon_v11_memdump_map.h"
#include <stddef.h>

extern uint32_t nikon_v11_save_original(const char *, const void *, uint32_t, uint32_t);
extern uint32_t nikon_v11_write_original(void *, const void *, uint32_t, uint32_t, uint32_t *);
extern uint32_t nikon_v11_open_new_original(const char *, uint32_t, void **);
extern uint32_t nikon_v11_close_original(void **);
extern void nikon_v11_memdump_original(void);

uint32_t akeru_memdump_held_route(struct akeru_memdump_held *held,
    uintptr_t current, const char *name, const void *data, uint32_t length, uint32_t selector)
{
    static const char expected[] = "B:\\MEMDUMP.BIN";
    struct akeru_memdump_map *session = (struct akeru_memdump_map *)held;
    uint32_t count = 0, status, phase, wanted = length;
    const uint8_t *error;
    unsigned i;
    if (!held || !held->owner || held->owner != current)
        return nikon_v11_save_original(name, data, length, selector);
    phase = held->phase;
    held->phase = 3;
    if (!held->handle || !name || selector != 1 || phase > 1)
        return 1;
    for (i = 0; i < sizeof(expected); ++i)
        if (name[i] != expected[i]) return 1;
    if ((phase == 0 && (!data || length != 256)) ||
        (phase == 1 && ((uintptr_t)data != 0x100u || length != 0x104064cu))) return 1;
    if (phase == 1) {
        data = (const void *)(uintptr_t)session->start;
        wanted = session->length;
    }
    status = nikon_v11_write_original(held->handle, data, wanted, selector, &count);
    if (status) return status;
    error = (const uint8_t *)held->handle + 12;
    if (count != wanted || error[0] || error[1] || error[2] || error[3]) return 1;
    held->phase = phase + 1;
    return 0;
}

int akeru_memdump_map_run(struct akeru_memdump_map *session,
    const struct akeru_dump_region *regions, uint32_t count)
{
    static const char hex[] = "0123456789ABCDEF";
    static const char path_template[] = "B:\\00000000.BIN";
    char path[sizeof(path_template)];
    uint32_t i, j, end = 0;
    if (!session || !regions || !count || count > AKERU_DUMP_MAX_REGIONS ||
        session->file || session->held.owner || session->held.handle || session->completed)
        return -1;
    for (i = 0; i < count; ++i) {
        uint32_t base = regions[i].address, n = regions[i].length;
        if (!n || base >= 0x0fe00000u || n > 0x0fe00000u - base || (i && base < end))
            return -1;
        end = base + n;
    }
    for (i = 0; i < count; ++i) {
        uint32_t status, phase;
        for (j = 0; j < sizeof(path); ++j) path[j] = path_template[j];
        for (j = 0; j < 8; ++j) path[3 + j] = hex[(regions[i].address >> (28 - 4*j)) & 15];
        session->start = regions[i].address;
        session->length = regions[i].length;
        if (nikon_v11_open_new_original(path, 3, &session->file) != 0 || !session->file)
            return -1;
        if (akeru_memdump_held_attach(&session->held, session->file) != 0) {
            (void)nikon_v11_close_original(&session->file);
            return -1;
        }
        nikon_v11_memdump_original();
        phase = session->held.phase;
        if (akeru_memdump_held_detach(&session->held) != 0) return -1;
        status = nikon_v11_close_original(&session->file);
        if (phase != 2 || status != 0 || session->file != NULL) return -1;
        ++session->completed;
    }
    return 0;
}
