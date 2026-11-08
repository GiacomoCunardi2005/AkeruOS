#include "nikon_v11_memdump_held.h"
#include <stddef.h>

extern uintptr_t akeru_nikon_v11_current_task(void);
extern void nikon_v11_enter_critical_original(void);
extern void nikon_v11_leave_critical_original(void);

int akeru_memdump_held_attach(struct akeru_memdump_held *ctx, void *handle)
{
    uintptr_t current;
    int result = 1;
    if (ctx == NULL || handle == NULL)
        return result;
    current = akeru_nikon_v11_current_task();
    if (current == 0u)
        return result;
    nikon_v11_enter_critical_original();
    if (ctx->owner == 0u) {
        ctx->handle = handle;
        ctx->phase = 0u;
        ctx->owner = current;
        result = 0;
    }
    nikon_v11_leave_critical_original();
    return result;
}

int akeru_memdump_held_detach(struct akeru_memdump_held *ctx)
{
    uintptr_t current;
    int result = 1;
    if (ctx == NULL)
        return result;
    current = akeru_nikon_v11_current_task();
    if (current == 0u)
        return result;
    nikon_v11_enter_critical_original();
    if (ctx->owner == current) {
        ctx->owner = 0u;
        ctx->handle = NULL;
        ctx->phase = 0u;
        result = 0;
    }
    nikon_v11_leave_critical_original();
    return result;
}

uint32_t akeru_memdump_held_route_current(struct akeru_memdump_held *ctx,
    const char *name, const void *data, uint32_t length, uint32_t selector)
{
    uintptr_t current = akeru_nikon_v11_current_task();
    return akeru_memdump_held_route(ctx, current, name, data, length, selector);
}
