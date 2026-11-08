#include "nikon_v11_memdump_held.h"
#define CHECK(x) do { if (!(x)) return __LINE__; } while (0)

static uint8_t wrapper[16];
static uint32_t count, status;

uint32_t nikon_v11_save_original(const char *name, const void *data, uint32_t length, uint32_t selector)
{ (void)name; (void)data; (void)length; (void)selector; return 73; }

uint32_t nikon_v11_write_original(void *handle, const void *data, uint32_t length, uint32_t selector, uint32_t *written)
{ (void)data; (void)length; if (handle != wrapper || selector != 1) return 99; *written = count; return status; }

int run_checks(void)
{
    struct akeru_memdump_held ctx = {0x200, wrapper, 0};
    const char *name = "B:\\MEMDUMP.BIN";
    const void *first = (const void *)(uintptr_t)0x300;
    const void *second = (const void *)(uintptr_t)0x100;
    count = 256;
    CHECK(akeru_memdump_held_route(&ctx, 0x201, name, first, 256, 1) == 73);
    CHECK(akeru_memdump_held_route(&ctx, 0x200, name, first, 256, 1) == 0 && ctx.phase == 1);
    count = 0x104064c;
    for (unsigned i = 12; i < 16; ++i) {
        wrapper[i] = 1; ctx.phase = 1;
        CHECK(akeru_memdump_held_route(&ctx, 0x200, name, second, count, 1) != 0 && ctx.phase == 3);
        wrapper[i] = 0;
    }
    ctx.phase = 1;
    CHECK(akeru_memdump_held_route(&ctx, 0x200, name, second, count, 1) == 0 && ctx.phase == 2);
    ctx.phase = 0; count = 0;
    CHECK(akeru_memdump_held_route(&ctx, 0x200, name, first, 256, 1) != 0 && ctx.phase == 3);
    ctx.phase = 0; status = 0x1a00014;
    CHECK(akeru_memdump_held_route(&ctx, 0x200, name, first, 256, 1) == status && ctx.phase == 3);
    return 0;
}

#ifdef HOST_TEST
int main(void) { return run_checks(); }
#endif
