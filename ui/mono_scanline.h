#ifndef AKERU_MONO_SCANLINE_H
#define AKERU_MONO_SCANLINE_H
#include <stdint.h>

struct akeru_mono_row {
    uint16_t width;
    uint16_t bit_offset;
    uint32_t reserved;
    const uint8_t *color;
};

void akeru_mono_scanline(uint8_t *dst, const uint8_t *src,
                         const struct akeru_mono_row *row);
#endif
