#include "nikon_v11_memdump_held.h"

static unsigned saves, writes, reenter;
static uint32_t write_status, write_count;
static struct akeru_memdump_held *active;
static const char path[] = "B:\\MEMDUMP.BIN";

uint32_t nikon_v11_save_original(const char *name, const void *data,
    uint32_t length, uint32_t selector)
{
    (void)name; (void)data; (void)length; (void)selector;
    ++saves;
    return 73;
}

uint32_t nikon_v11_write_original(void *handle, const void *data,
    uint32_t length, uint32_t selector, uint32_t *count)
{
    if (handle != (void *)(uintptr_t)0x1234 || selector != 1 || count == 0)
        return 99;
    ++writes;
    if (reenter && akeru_memdump_held_route(active, 0x200, path, data, length, selector) != 1)
        return 98;
    *count = write_count;
    return write_status;
}

int run_checks(void)
{
    struct akeru_memdump_held ctx = {0x200, (void *)(uintptr_t)0x1234, 0};
    const void *first = (void *)(uintptr_t)0x300;
    const void *second = (void *)(uintptr_t)0x100;
    active = &ctx;
    if (akeru_memdump_held_route(&ctx, 0x201, path, first, 256, 1) != 73 || saves != 1 || writes) return 1;
    write_count = 256; reenter = 1;
    if (akeru_memdump_held_route(&ctx, 0x200, path, first, 256, 1) != 0 || ctx.phase != 1 || writes != 1) return 2;
    reenter = 0; write_count = 0x104064c;
    if (akeru_memdump_held_route(&ctx, 0x200, path, second, 0x104064c, 1) != 0 || ctx.phase != 2 || writes != 2) return 3;
    if (akeru_memdump_held_route(&ctx, 0x200, path, second, 0x104064c, 1) != 1 || writes != 2 || ctx.phase != 3) return 4;
    ctx.phase = 0; write_count = 0;
    if (akeru_memdump_held_route(&ctx, 0x200, path, first, 256, 1) != 1 || ctx.phase != 3 || writes != 3) return 5;
    ctx.phase = 0; write_status = 0x1a00014;
    if (akeru_memdump_held_route(&ctx, 0x200, path, first, 256, 1) != 0x1a00014 || ctx.phase != 3 || writes != 4) return 6;
    ctx.phase = 0; write_status = 0; write_count = 256;
    if (akeru_memdump_held_route(&ctx, 0x200, "B:\\OTHER.BIN", first, 256, 1) != 1 || ctx.phase != 3 || writes != 4) return 7;
    ctx.phase = 0;
    if (akeru_memdump_held_route(&ctx, 0x200, path, first, 256, 2) != 1 || writes != 4) return 8;
    ctx.phase = 1;
    if (akeru_memdump_held_route(&ctx, 0x200, path, first, 0x104064c, 1) != 1 || writes != 4) return 9;
    ctx.phase = 0; ctx.handle = 0;
    if (akeru_memdump_held_route(&ctx, 0x200, path, first, 256, 1) != 1 || writes != 4) return 10;
    ctx.owner = 0;
    if (akeru_memdump_held_route(&ctx, 0x200, path, first, 256, 1) != 73 || saves != 2) return 11;
    return 0;
}

#ifdef HOST_TEST
int main(void) { return run_checks(); }
#endif
