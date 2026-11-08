#include "nikon_v11_memdump_held.h"

static unsigned locks, enters, leaves, writes, saves;
static uint32_t count_to_write;
#ifdef ORIGINAL_TASK_GETTER
static void set_current(uintptr_t value) { *(volatile uint32_t *)(uintptr_t)0x0201801c = (uint32_t)value; }
#else
static uintptr_t current;
static void set_current(uintptr_t value) { current = value; }
uintptr_t akeru_nikon_v11_current_task(void) { return current; }
#endif
void nikon_v11_enter_critical_original(void) { ++locks; ++enters; }
void nikon_v11_leave_critical_original(void) { if (locks) --locks; ++leaves; }
uint32_t nikon_v11_save_original(const char *name, const void *data, uint32_t length, uint32_t selector)
{
    (void)name; (void)data; (void)length; (void)selector;
    if (locks) return 99;
    ++saves; return 73;
}
uint32_t nikon_v11_write_original(void *handle, const void *data, uint32_t length, uint32_t selector, uint32_t *count)
{
    (void)data; (void)length;
    if (locks || handle != (void *)(uintptr_t)0x1234 || selector != 1 || count == 0) return 99;
    ++writes; *count = count_to_write; return 0;
}
int run_checks(void)
{
    struct akeru_memdump_held ctx = {0, 0, 0};
    const char *name = "B:\\MEMDUMP.BIN";
    const void *data = (void *)(uintptr_t)0x300;
    if (!akeru_memdump_held_attach(&ctx, (void *)(uintptr_t)0x1234) || enters) return 1;
#ifdef ORIGINAL_TASK_GETTER
    *(volatile uint32_t *)(uintptr_t)0x369348 = 0x02018000;
#endif
    set_current(0x200);
    if (akeru_memdump_held_attach(&ctx, 0) == 0 || enters) return 2;
    if (akeru_memdump_held_attach(&ctx, (void *)(uintptr_t)0x1234) || ctx.owner != 0x200 || ctx.phase || locks) return 3;
    set_current(0x201);
    if (akeru_memdump_held_attach(&ctx, (void *)(uintptr_t)0x5678) == 0 || ctx.owner != 0x200 || ctx.handle != (void *)(uintptr_t)0x1234) return 4;
    if (akeru_memdump_held_route_current(&ctx, name, data, 256, 1) != 73 || saves != 1 || writes) return 5;
    if (akeru_memdump_held_detach(&ctx) == 0 || ctx.owner != 0x200 || locks) return 6;
    set_current(0x200); count_to_write = 256;
    if (akeru_memdump_held_route_current(&ctx, name, data, 256, 1) || ctx.phase != 1 || writes != 1) return 7;
    if (akeru_memdump_held_detach(&ctx) || ctx.owner || ctx.handle || ctx.phase || locks) return 8;
    if (akeru_memdump_held_route_current(&ctx, name, data, 256, 1) != 73 || saves != 2) return 9;
    if (enters != leaves || enters != 4) return 10;
    return 0;
}
#ifdef HOST_TEST
int main(void) { return run_checks(); }
#endif
