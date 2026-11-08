#include "color_mode.h"
#include "mono_raw.h"

int akeru_color_select(enum akeru_color_mode *mode, enum akeru_action action)
{
    if (!mode || (*mode != AKERU_COLOR_STANDARD && *mode != AKERU_COLOR_MONO_RAW)) return -1;
    if (action == AKERU_REQUEST_COLOR) *mode = AKERU_COLOR_STANDARD;
    else if (action == AKERU_REQUEST_MONO) *mode = AKERU_COLOR_MONO_RAW;
    else return 0;
    return 1;
}

int akeru_color_process(enum akeru_color_mode snapshot, const uint16_t *raw,
                        uint16_t *out, size_t width, size_t height)
{
    return akeru_color_process_rows(snapshot, raw, out, width, height, 0, height);
}

int akeru_color_process_rows(enum akeru_color_mode snapshot, const uint16_t *raw,
                             uint16_t *out, size_t width, size_t height,
                             size_t y, size_t rows)
{
    if (snapshot == AKERU_COLOR_STANDARD) return 0;
    if (snapshot != AKERU_COLOR_MONO_RAW) return -1;
    return akeru_mono_raw_rows(raw, out, width, height, y, rows) == 0 ? 1 : -1;
}
