#ifndef AKERU_NIKON_V11_RUNTIME_H
#define AKERU_NIKON_V11_RUNTIME_H

#include <stdint.h>

enum akeru_nikon_v11_result {
    AKERU_NIKON_V11_OK = 0,
    AKERU_NIKON_V11_ARGUMENT = -1,
    AKERU_NIKON_V11_CLOCK = -2,
    AKERU_NIKON_V11_CREATE = -3
};

typedef void (*akeru_nikon_v11_task_entry)(uint32_t parameter);

struct akeru_nikon_v11_task_template {
    uint32_t index;
    akeru_nikon_v11_task_entry entry;
    uint32_t stack_bytes;
    uint32_t priority;
    const char *name;
    uint32_t attributes;
    uint32_t parameter;
    uint32_t timeslice;
};

struct akeru_nikon_v11_ticks {
    uint32_t low, high, hardware;
};

struct akeru_nikon_v11_seconds_ms {
    uint32_t seconds, milliseconds;
};

/* Linker-provided V1.1 code symbols. Test binaries supply explicit mocks.
 * No runtime address casts, data allocation or BSS initialization is required.
 */
extern void nikon_v11_delay_ms_original(uint32_t milliseconds); /* 0x19A774 */
extern void nikon_v11_get_ticks_original(struct akeru_nikon_v11_ticks *); /* 0x2FB6FC */
extern uint32_t nikon_v11_ticks_to_time_original(
    const struct akeru_nikon_v11_ticks *,
    struct akeru_nikon_v11_seconds_ms *); /* 0x269888: 1 normal, 0 saturated */
extern uint32_t nikon_v11_create_task_original(uint32_t processor,
    uint32_t template_index,
    const struct akeru_nikon_v11_task_template *); /* 0x23C990: ID or 0 */

/* Call from an ordinary task with scheduler unlocked and tick IRQ running.
 * Zero is rejected: the original zero-duration branch does not yield.
 * Success records return from the original void API, not measured elapsed time.
 */
int akeru_nikon_v11_wait_ms(uint32_t milliseconds);

/* Kernel tick resolution; output remains unchanged on a conversion error.
 * Scalar timestamp wraps modulo 2^32 milliseconds.
 */
int akeru_nikon_v11_now_ms(uint32_t *milliseconds);

/* entry/name must remain resident for the task lifetime. parameter is a value;
 * any object it points to requires its own ownership. The template is copied by
 * the original custom-template path. The new task can run before this returns.
 * On error, a non-null output is set to zero. Runtime priority limit and pool
 * availability are checked by Nikon, not guessed here. No hook is installed.
 */
int akeru_nikon_v11_create_task(akeru_nikon_v11_task_entry entry,
    uint32_t parameter, const char *name, uint32_t stack_bytes,
    uint32_t priority, uint32_t *task_id);

#endif
