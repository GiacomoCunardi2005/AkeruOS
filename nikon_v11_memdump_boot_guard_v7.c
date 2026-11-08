#include <stdint.h>

extern uint32_t nikon_v11_signal_original(uint32_t event, uint32_t mask);

uint32_t akeru_memdump_boot_guard(uint32_t event, uint32_t mask)
{
    uint32_t result = nikon_v11_signal_original(event, mask);
    const volatile uint32_t *signature = (const volatile uint32_t *)0x00e99e00u;
    if (signature[0] == 0x4d444b41u && signature[1] == 7u)
        ((void (*)(void))0x00e99e08u)();
    return result;
}
