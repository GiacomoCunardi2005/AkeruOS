#include "ui/mono_scanline.h"
#include <stddef.h>
#include <stdint.h>

#ifdef AKERU_GNU_TEST
extern void test_fail(void);
#define CHECK(x) do { if (!(x)) test_fail(); } while (0)
#else
#include <assert.h>
#define CHECK(x) assert(x)
#endif

int main(void)
{
    const uint8_t src[6] = {0x80, 0x01, 0xa5, 0x5a, 0xff, 0x00};
    const char bits[] = "100000000000000110100101010110101111111100000000";
    uint8_t out[28];
    uint8_t color;
    struct akeru_mono_row row = {0, 0, 0, &color};
    CHECK(offsetof(struct akeru_mono_row, color) == 8);
    for (unsigned c = 0; c < 2; ++c) {
        color = c ? 0x7e : 0;
        for (unsigned offset = 0; offset < 16; ++offset) {
            for (unsigned width = 0; width <= 24; ++width) {
                for (unsigned i = 0; i < sizeof(out); ++i) out[i] = 0xa5;
                row.width = width;
                row.bit_offset = offset;
                akeru_mono_scanline(out + 2, src, &row);
                for (unsigned i = 0; i < sizeof(out); ++i) {
                    uint8_t expected = 0xa5;
                    if (i >= 2 && i < width + 2 && bits[offset + i - 2] == '1')
                        expected = color;
                    CHECK(out[i] == expected);
                }
            }
        }
    }
    akeru_mono_scanline(NULL, src, &row);
    akeru_mono_scanline(out, NULL, &row);
    akeru_mono_scanline(out, src, NULL);
    row.color = NULL;
    akeru_mono_scanline(out, src, &row);
    return 0;
}
