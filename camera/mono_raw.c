#include "mono_raw.h"
#include <stdint.h>

static unsigned weighted_average(unsigned sum, unsigned weight, unsigned count)
{
    unsigned value = sum * weight;
    if (count == 1) return value;
    if (count == 2) return value >> 1;
    if (count == 3) return value / 3;
    return value >> 2;
}

/* shortcut: fixed RGGB and experimental gains, replace after camera calibration. */
int akeru_mono_raw_rows(const uint16_t *raw, uint16_t *out, size_t width,
                        size_t height, size_t first, size_t rows)
{
    size_t count, out_count, i, y, x;
    uintptr_t a = (uintptr_t)raw, b = (uintptr_t)out;
    if (!raw || !out || width < 2 || height < 2 || width > SIZE_MAX / height ||
        first >= height || !rows || rows > height - first)
        return -1;
    count = width * height;
    out_count = width * rows;
    if (count > SIZE_MAX / sizeof(*raw)) return -1;
    if (a > UINTPTR_MAX - count * sizeof(*raw) || b > UINTPTR_MAX - out_count * sizeof(*out)) return -1;
    if (a < b + out_count * sizeof(*out) && b < a + count * sizeof(*raw)) return -1;
    /* shortcut: rescans the entire frame per strip until frame ownership is verified. */
    for (i = 0; i < count; ++i) if (raw[i] > 4095) return -1;
    for (y = first; y < first + rows; ++y) for (x = 0; x < width; ++x) {
        unsigned sum[3] = {0, 0, 0}, n[3] = {0, 0, 0};
        size_t yy, xx, y0 = y ? y - 1 : y, x0 = x ? x - 1 : x;
        size_t y1 = y + 1 < height ? y + 1 : y, x1 = x + 1 < width ? x + 1 : x;
        unsigned own = (y & 1) ? ((x & 1) ? 2 : 1) : ((x & 1) ? 1 : 0);
        for (yy = y0; yy <= y1; ++yy) for (xx = x0; xx <= x1; ++xx) {
            unsigned c = (yy & 1) ? ((xx & 1) ? 2 : 1) : ((xx & 1) ? 1 : 0);
            if (c != own || (yy == y && xx == x)) { sum[c] += raw[yy * width + xx]; ++n[c]; }
        }
        /* Q16 coefficients approximate luminance weights after the provisional gains. */
        out[(y - first) * width + x] = (uint16_t)(((weighted_average(sum[0], 24383u, n[0])) +
                                          (weighted_average(sum[1], 46871u, n[1])) +
                                          (weighted_average(sum[2], 6766u, n[2])) + 32768u) >> 16);
    }
    return 0;
}

int akeru_mono_raw(const uint16_t *raw, uint16_t *out, size_t width, size_t height)
{
    return akeru_mono_raw_rows(raw, out, width, height, 0, height);
}
