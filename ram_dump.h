#ifndef AKERU_RAM_DUMP_H
#define AKERU_RAM_DUMP_H

#include <stdint.h>

#define AKERU_DUMP_CHUNK 4096u
#define AKERU_DUMP_MAX_REGIONS 16u
#define AKERU_DUMP_MAX_BYTES (512u * 1024u * 1024u)
#define AKERU_DUMP_ARM_FILE "B:AKERUDMP.ON"

enum akeru_dump_result {
    AKERU_DUMP_OK = 0, AKERU_DUMP_DISARMED = 1,
    AKERU_DUMP_CONFIG = -1, AKERU_DUMP_IO = -2,
    AKERU_DUMP_READ = -3, AKERU_DUMP_WAIT = -4
};

struct akeru_dump_region { uint32_t address, length; };

/* Adapter contract, not the unverified ABI of any Nikon function address.
 * All callbacks execute in an ordinary task. read_ram returns an owned copy.
 * open_new MUST create exclusively: 0 success, 1 exists, negative error.
 * write returns a positive byte count, or <=0 on failure. close consumes the
 * handle even on error. wait_ms MUST block/yield via the RTOS, never busy-wait.
 * armed returns 1 only if AKERU_DUMP_ARM_FILE is present on SD, 0 if absent,
 * negative on an I/O error. File existence must not create or truncate it.
 */
struct akeru_dump_io {
    void *context;
    int (*armed)(void *);
    int (*wait_ms)(void *, uint32_t);
    uint32_t (*now_ms)(void *);
    int (*read_ram)(void *, uint32_t, uint8_t *, uint32_t);
    int (*open_new)(void *, const char *, void **);
    int32_t (*write)(void *, void *, const uint8_t *, uint32_t);
    int (*close)(void *, void *);
};

/* Caller owns configuration, adapter and scratch memory for the task lifetime.
 * Single task owns this object. No memory is allocated or assumed free here.
 */
struct akeru_ram_dumper {
    struct akeru_dump_io io;
    const struct akeru_dump_region *regions;
    uint32_t region_count, interval_ms, max_snapshots, next_sequence, completed;
    uint32_t full_declared_map;
    int last_result;
    uint8_t scratch[AKERU_DUMP_CHUNK];
};

extern const struct akeru_dump_region akeru_dump_default_regions[];
extern const uint32_t akeru_dump_default_region_count;
void akeru_ram_dump_defaults(struct akeru_ram_dumper *);
/* Default configuration deliberately has no guessed physical RAM map.
 * Platform must supply ALL verified RAM banks (sorted, without overlap/MMIO).
 * This is a platform declaration, not a physical-map discovery routine.
 */
void akeru_ram_dump_use_full_map(struct akeru_ram_dumper *,
    const struct akeru_dump_region *, uint32_t);
/* Optional small diagnostic profile, explicitly not a complete RAM dump. */
void akeru_ram_dump_use_selected_regions(struct akeru_ram_dumper *);
int akeru_ram_dump_run(struct akeru_ram_dumper *);
void akeru_ram_dump_task(void *);

#endif
