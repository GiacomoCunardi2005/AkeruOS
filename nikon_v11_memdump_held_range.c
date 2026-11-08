#include "nikon_v11_memdump_held.h"
#include <stddef.h>

/* v6: la seconda scrittura del diagnostico Nikon (0x16ED40) viene sostituita da un intervallo scelto.
 * L'intervallo e' ristretto alla fascia [0x0F600000, 0x0F700000): la riserva alta MMIO (da 0x0FE00000) resta esclusa. */
#define AKERU_RANGE_MIN 0x0F600000u
#define AKERU_RANGE_MAX 0x0F700000u
#ifndef AKERU_DUMP_START
#define AKERU_DUMP_START 0x0F600000u
#endif
#ifndef AKERU_DUMP_LENGTH
#define AKERU_DUMP_LENGTH 0x00100000u
#endif
_Static_assert(AKERU_DUMP_START >= AKERU_RANGE_MIN, "start sotto la fascia ammessa");
_Static_assert(AKERU_DUMP_LENGTH > 0u, "lunghezza nulla");
_Static_assert(AKERU_DUMP_START + AKERU_DUMP_LENGTH <= AKERU_RANGE_MAX, "fine oltre la fascia ammessa");

extern uint32_t nikon_v11_save_original(const char *, const void *, uint32_t, uint32_t);
extern uint32_t nikon_v11_write_original(void *, const void *, uint32_t, uint32_t, uint32_t *);

uint32_t akeru_memdump_held_route(struct akeru_memdump_held *ctx,
    uintptr_t current, const char *name, const void *data, uint32_t length,
    uint32_t selector)
{
    static const char expected[] = "B:\\MEMDUMP.BIN";
    uint32_t count = 0, status, phase, want = length;
    const void *source = data;
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
    /* Le richieste del diagnostico restano controllate come nella v5; solo la sorgente e la lunghezza della seconda cambiano. */
    if ((phase == 0u && (data == NULL || length != 256u)) ||
        (phase == 1u && ((uintptr_t)data != 0x100u || length != 0x104064cu)))
        return 1u;
    if (phase == 1u) {
        source = (const void *)(uintptr_t)AKERU_DUMP_START;
        want = AKERU_DUMP_LENGTH;
    }
    status = nikon_v11_write_original(ctx->handle, source, want, selector, &count);
    if (status != 0u)
        return status;
    if (count != want)
        return 1u;
    ctx->phase = phase + 1u;
    return 0u;
}
