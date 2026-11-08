#include "nikon_v11_memdump_map.h"
#include "nikon_v11_memdump_worker.h"
#include "nikon_v11_runtime.h"

extern struct akeru_memdump_map akeru_map_session;
extern uint32_t nikon_v11_volume_status_original(const char *, uint8_t *);
extern uint32_t nikon_v11_output_base_original(char *);

/* No physical map has been established. Zero count disables capture. */
volatile uint32_t akeru_map_count __attribute__((section(".data.akeru_map_count"))) = 0;
const struct akeru_dump_region akeru_map_regions[AKERU_DUMP_MAX_REGIONS] = {{0, 0}};

static void memdump_task(uint32_t parameter)
{
    uint32_t count = akeru_map_count;
    uint8_t ready;
    char base[276];
    unsigned attempt;
    (void)parameter;
    if (!count || count > AKERU_DUMP_MAX_REGIONS) return;
    /* shortcut: 30 polls are a laboratory bound; tune after scheduler/SD timing is measured. */
    for (attempt = 0; attempt < 30; ++attempt) {
        ready = 0;
        if (nikon_v11_volume_status_original("B:", &ready) == 0 && ready == 1) break;
        if (attempt != 29) nikon_v11_delay_ms_original(1000);
    }
    if (attempt == 30) return;
    base[0] = base[1] = base[2] = 0;
    if (nikon_v11_output_base_original(base) != 0 ||
        base[0] != 'B' || base[1] != ':' || base[2] != 0) return;
    (void)akeru_memdump_map_run(&akeru_map_session, akeru_map_regions, count);
}

int akeru_nikon_v11_memdump_start(uint32_t priority, uint32_t *task_id)
{
    return akeru_nikon_v11_create_task(memdump_task, 0, "MEMDUMP", 0x8000,
                                     priority, task_id);
}
