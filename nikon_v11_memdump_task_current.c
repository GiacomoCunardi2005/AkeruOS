#include <stdint.h>

/* V1.1 kernel pointer and current-task field; lifetime is not hardware verified. */
uintptr_t akeru_nikon_v11_current_task(void)
{
    uintptr_t kernel = *(const volatile uint32_t *)(uintptr_t)0x369348u;
    if (kernel == 0u)
        return 0u;
    return *(const volatile uint32_t *)(kernel + 0x1cu);
}
