#include "nikon_v11_sd_marker.h"
#include <stddef.h>

static uint32_t word(const void *base, uint32_t offset)
{
    const volatile uint8_t *p = (const volatile uint8_t *)base+offset;
    return (uint32_t)p[0] | ((uint32_t)p[1] << 8) |
           ((uint32_t)p[2] << 16) | ((uint32_t)p[3] << 24);
}
static const void *pointer(const void *base, uint32_t offset)
{
    return (const void *)(uintptr_t)word(base, offset);
}
static int fat_backend(const void *context)
{
    uint32_t backend = word(context, 0x70);
    return backend == 1u || backend == 6u || backend == 12u;
}

int akeru_nikon_v11_sd_marker_check(const void *file)
{
    static const uint8_t name[] = "AKERUDMPON ";
    const void *device, *context, *volume, *object;
    const volatile uint8_t *label, *record;
    void *semaphore;
    int valid = 0;
    if (file == NULL || word(file, 12) != 0u)
        return 0;
    device = pointer(file, 0);
    if (device == NULL || word(device, 12) != 0x1F43ACu ||
        word(device, 16) != 0x1F48A4u)
        return 0;
    label = pointer(device, 8);
    if (label == NULL || label[0] != 'B' || label[1] != ':' || label[2] != 0)
        return 0;
    context = pointer(device, 0x24);
    if (context == NULL || !fat_backend(context))
        return 0; /* Backend7 has a different private layout. */
    semaphore = (uint8_t *)context+388;
    if (word(semaphore, 0x14) != 0x6C77736Du)
        return -1;
    if (nikon_v11_fs_wait_original(semaphore) != 0u)
        return -1;
    volume = pointer(context, 424);
    object = pointer(file, 4);
    if (fat_backend(context) && word(context, 0x40) == 1u &&
        volume != NULL && pointer(volume, 0) == device &&
        (word(context, 108) & 0xffffu) != 0u && object != NULL &&
        word(object, 8) == 0x4D465356u && word(object, 60) == 0u &&
        (word(object, 44) & 0xffffu) == 0u && word(file, 12) == 0u) {
        record = (const volatile uint8_t *)object+12;
        valid = (record[11] & 0x18u) == 0u;
        for (uint32_t i = 0; i < sizeof(name)-1u; ++i)
            if (record[i] != name[i]) valid = 0;
    }
    if (nikon_v11_fs_post_original(semaphore) != 0u ||
        word(semaphore, 0x14) != 0x6C77736Du)
        return -1;
    return valid;
}
