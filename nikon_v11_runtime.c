#include "nikon_v11_runtime.h"
#include <stddef.h>

_Static_assert(sizeof(struct akeru_nikon_v11_ticks) == 12u, "ticks ABI");
_Static_assert(sizeof(struct akeru_nikon_v11_seconds_ms) == 8u, "time ABI");
#if defined(__arc__)
_Static_assert(sizeof(void *) == 4u, "ARC V1.1 pointers");
_Static_assert(sizeof(struct akeru_nikon_v11_task_template) == 32u, "template ABI");
_Static_assert(offsetof(struct akeru_nikon_v11_task_template, parameter) == 24u,
               "custom template parameter ABI");
#endif

int akeru_nikon_v11_wait_ms(uint32_t milliseconds)
{
    if (milliseconds == 0u)
        return AKERU_NIKON_V11_ARGUMENT;
    nikon_v11_delay_ms_original(milliseconds);
    return AKERU_NIKON_V11_OK;
}

int akeru_nikon_v11_now_ms(uint32_t *milliseconds)
{
    struct akeru_nikon_v11_ticks ticks;
    struct akeru_nikon_v11_seconds_ms time;
    if (milliseconds == NULL)
        return AKERU_NIKON_V11_ARGUMENT;
    nikon_v11_get_ticks_original(&ticks);
    if (nikon_v11_ticks_to_time_original(&ticks, &time) != 1u)
        return AKERU_NIKON_V11_CLOCK;
    *milliseconds = time.seconds * 1000u + time.milliseconds;
    return AKERU_NIKON_V11_OK;
}

int akeru_nikon_v11_create_task(akeru_nikon_v11_task_entry entry,
    uint32_t parameter, const char *name, uint32_t stack_bytes,
    uint32_t priority, uint32_t *task_id)
{
    struct akeru_nikon_v11_task_template record;
    uint32_t id;
    if (task_id == NULL)
        return AKERU_NIKON_V11_ARGUMENT;
    *task_id = 0u;
    /* Constructor: align_up(max(stack,200),64)+64+32+236.
     * Largest stack avoiding unsigned overflow in that request is FFFFFE80.
     */
    if (entry == NULL || name == NULL || stack_bytes == 0u ||
        stack_bytes > UINT32_C(0xfffffe80))
        return AKERU_NIKON_V11_ARGUMENT;
    record.index = 0u;
    record.entry = entry;
    record.stack_bytes = stack_bytes;
    record.priority = priority;
    record.name = name;
    record.attributes = 0u;
    record.parameter = parameter;
    record.timeslice = 0u;
    id = nikon_v11_create_task_original(0u, 0u, &record);
    if (id == 0u)
        return AKERU_NIKON_V11_CREATE;
    *task_id = id;
    return AKERU_NIKON_V11_OK;
}
