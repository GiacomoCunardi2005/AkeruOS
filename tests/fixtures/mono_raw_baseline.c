#include "mono_raw.h"
#include <stdint.h>

/* shortcut: fixed RGGB and experimental gains, replace after camera calibration. */
int akeru_mono_raw(const uint16_t *raw, uint16_t *out, size_t width, size_t height)
{
    size_t count, i, y, x;
    uintptr_t a = (uintptr_t)raw, b = (uintptr_t)out;
    if (!raw || !out || width < 2 || height < 2 || width > SIZE_MAX / height)
        return -1;
    count = width * height;
    if (count > SIZE_MAX / sizeof(*raw)) return -1;
    if (a > UINTPTR_MAX - count * sizeof(*raw) || b > UINTPTR_MAX - count * sizeof(*out)) return -1;
    if (a < b + count * sizeof(*out) && b < a + count * sizeof(*raw)) return -1;
    for (i = 0; i < count; ++i) if (raw[i] > 4095) return -1;
    for (y = 0; y < height; ++y) for (x = 0; x < width; ++x) {
        unsigned sum[3] = {0, 0, 0}, n[3] = {0, 0, 0};
        size_t yy, xx, y0 = y ? y - 1 : y, x0 = x ? x - 1 : x;
        size_t y1 = y + 1 < height ? y + 1 : y, x1 = x + 1 < width ? x + 1 : x;
        unsigned own = (y & 1) ? ((x & 1) ? 2 : 1) : ((x & 1) ? 1 : 0);
        for (yy = y0; yy <= y1; ++yy) for (xx = x0; xx <= x1; ++xx) {
            unsigned c = (yy & 1) ? ((xx & 1) ? 2 : 1) : ((xx & 1) ? 1 : 0);
            if (c != own || (yy == y && xx == x)) { sum[c] += raw[yy * width + xx]; ++n[c]; }
        }
        /* Q16 coefficients approximate luminance weights after the provisional gains. */
        out[y * width + x] = (uint16_t)(((sum[0] * 24383u / n[0]) +
                                          (sum[1] * 46871u / n[1]) +
                                          (sum[2] * 6766u / n[2]) + 32768u) >> 16);
    }
    return 0;
}
