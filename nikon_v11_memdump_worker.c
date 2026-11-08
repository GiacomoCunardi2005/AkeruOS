#include "nikon_v11_memdump_worker.h"
#include "nikon_v11_runtime.h"

/* V1.1 0x16ED40: diagnostic writer; it does not return reliable file status. */
extern void nikon_v11_memdump_original(void);
extern uint32_t nikon_v11_output_base_original(char *buffer); /* 0x12B0DC */
extern uint32_t nikon_v11_volume_status_original(const char *name, uint8_t *ready); /* 0x12B8E8 */
extern uint32_t nikon_v11_open_new_original(const char *name, uint32_t mode, void **handle); /* 0x12DBFC */
extern uint32_t nikon_v11_close_original(void **handle); /* 0x12D604 */

static void memdump_task(uint32_t parameter)
{
    char base[276];
    uint8_t ready = 0;
    void *handle = 0;
    unsigned attempt;
    (void)parameter;
    /* shortcut: 30 polls are a laboratory bound; tune after scheduler/SD timing is measured. */
    for (attempt = 0; attempt < 30u; ++attempt) {
        ready = 0;
        if (nikon_v11_volume_status_original("B:", &ready) == 0u && ready == 1u)
            break;
        if (attempt != 29u)
            nikon_v11_delay_ms_original(1000u);
    }
    if (attempt == 30u)
        return;
    base[0] = base[1] = base[2] = '\0';
    if (nikon_v11_output_base_original(base) != 0u ||
        base[0] != 'B' || base[1] != ':' || base[2] != '\0')
        return;
    if (nikon_v11_open_new_original("B:\\MEMDUMP.BIN", 3u, &handle) != 0u ||
        handle == 0)
        return;
    if (nikon_v11_close_original(&handle) != 0u || handle != 0)
        return;
    base[0] = base[1] = base[2] = '\0';
    if (nikon_v11_output_base_original(base) == 0u &&
        base[0] == 'B' && base[1] == ':' && base[2] == '\0')
        nikon_v11_memdump_original();
}

int akeru_nikon_v11_memdump_start(uint32_t priority, uint32_t *task_id)
{
    return akeru_nikon_v11_create_task(memdump_task, 0, "MEMDUMP", 0x8000,
                                     priority, task_id);
}
