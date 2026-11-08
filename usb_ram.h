#ifndef AKERU_USB_RAM_H
#define AKERU_USB_RAM_H
#include "ram_dump.h"

#define AKERU_USB_RAM_FRAME (32u+AKERU_DUMP_CHUNK)

/* Single task owns state/map/buffers. No map or Nikon address is supplied here.
 * read_ram must copy exactly length bytes on return0, fail otherwise; never
 * perform speculative reads. epoch must identify device and service boot.
 * flags bit0 synthetic, bit1 complete physical map (platform declaration).
 */
struct akeru_usb_ram {
    void *context;
    int (*read_ram)(void *, uint32_t, uint8_t *, uint32_t);
    const struct akeru_dump_region *regions;
    uint32_t region_count, flags;
    uint8_t epoch[16];
    uint32_t reads, last_address, last_length, last_status, aborted;
};

/* Only complete requests, no overlapping buffers. Response has FRAME capacity.
 * Returns bytes to send or -1 for invalid framing/configuration, with no read.
 * No USB I/O or asynchronous cancellation here; ABORT prevents later reads.
 */
int32_t akeru_usb_ram_serve(struct akeru_usb_ram *, const uint8_t *request,
    uint32_t request_bytes, uint8_t *response, uint32_t response_capacity);
#endif
