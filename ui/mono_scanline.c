#include "mono_scanline.h"

void akeru_mono_scanline(uint8_t *dst, const uint8_t *src,
                         const struct akeru_mono_row *row)
{
    if (!row || !row->width || !dst || !src || !row->color)
        return;
    for (uint32_t i = 0; i < row->width; ++i) {
        uint32_t bit = (uint32_t)row->bit_offset + i;
        if (src[bit / 8] & (0x80u >> (bit % 8)))
            dst[i] = *row->color;
    }
}
