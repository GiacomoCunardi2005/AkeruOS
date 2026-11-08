#include "nikon_v11_memdump_held.h"
#include <stddef.h>

extern uint32_t nikon_v11_save_original(const char *, const void *, uint32_t, uint32_t);
extern uint32_t nikon_v11_write_original(void *, const void *, uint32_t, uint32_t, uint32_t *);

uint32_t akeru_memdump_held_route(struct akeru_memdump_held *ctx,
    uintptr_t current, const char *name, const void *data, uint32_t length,
    uint32_t selector)
{
    static const char expected[] = "B:\\MEMDUMP.BIN";
    uint32_t count = 0, status, phase;
    const uint8_t *error;
    unsigned i;
    if (ctx == NULL || ctx->owner == 0u || ctx->owner != current)
        return nikon_v11_save_original(name, data, length, selector);
    phase = ctx->phase;
    ctx->phase = 3u;
    if (ctx->handle == NULL || name == NULL || selector != 1u || phase > 1u)
        return 1u;
    for (i = 0; i < sizeof(expected); ++i)
        if (name[i] != expected[i])
            return 1u;
    if ((phase == 0u && (data == NULL || length != 256u)) ||
        (phase == 1u && ((uintptr_t)data != 0x100u || length != 0x104064cu)))
        return 1u;
    status = nikon_v11_write_original(ctx->handle, data, length, selector, &count);
    if (status != 0u)
        return status;
    error = (const uint8_t *)ctx->handle + 12;
    if (error[0] || error[1] || error[2] || error[3] || count != length)
        return 1u;
    ctx->phase = phase + 1u;
    return 0u;
}
