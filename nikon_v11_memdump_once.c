#include "nikon_v11_memdump_once.h"
#include "nikon_v11_memdump_worker.h"
#include "nikon_v11_runtime.h"
#include <stddef.h>

extern void nikon_v11_enter_critical_original(void); /* 0x1786E8 */
extern void nikon_v11_leave_critical_original(void); /* 0x179354 */

int akeru_nikon_v11_memdump_start_once(volatile uint32_t *claim,
                                      uint32_t priority, uint32_t *task_id)
{
    int result;
    if (claim == NULL || task_id == NULL || (const void *)claim == task_id)
        return AKERU_NIKON_V11_ARGUMENT;
    *task_id = 0;
    nikon_v11_enter_critical_original();
    if (*claim != 0u) {
        nikon_v11_leave_critical_original();
        return 1;
    }
    *claim = 1u;
    nikon_v11_leave_critical_original();
    result = akeru_nikon_v11_memdump_start(priority, task_id);
    if (result != AKERU_NIKON_V11_OK) {
        nikon_v11_enter_critical_original();
        *claim = 0u;
        nikon_v11_leave_critical_original();
    }
    return result;
}
