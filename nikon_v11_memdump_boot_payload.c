#include <stdint.h>
#include "nikon_v11_memdump_worker.h"
#include "nikon_v11_memdump_once.h"

/* The payload copy is writable only in the laboratory model; reload resets it. */
static volatile uint32_t claimed __attribute__((section(".data.akeru_claim"))) = 0;

/* Priority 19 is copied from the V1.1 Load Later task record, not validated. */
void akeru_memdump_payload_entry(void)
{
    uint32_t task_id;
    (void)akeru_nikon_v11_memdump_start_once(&claimed, 19u, &task_id);
}
