#ifndef AKERU_MONO_RAW_H
#define AKERU_MONO_RAW_H
#include <stddef.h>
#include <stdint.h>

/* RGGB, provisional 0/4092 levels and RGB gains 1.75/1/1.43; output uses RAW code units. */
int akeru_mono_raw(const uint16_t *raw, uint16_t *out, size_t width, size_t height);
/* Full input frame, packed output rows; y preserves the Bayer phase. */
int akeru_mono_raw_rows(const uint16_t *raw, uint16_t *out, size_t width,
                        size_t height, size_t y, size_t rows);
#endif
