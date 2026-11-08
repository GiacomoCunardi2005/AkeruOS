#ifndef AKERU_COLOR_MODE_H
#define AKERU_COLOR_MODE_H
#include <stddef.h>
#include <stdint.h>
#include "../ui/menu.h"

enum akeru_color_mode { AKERU_COLOR_STANDARD, AKERU_COLOR_MONO_RAW };
/* Returns 1 for a selection, 0 for another action, -1 for invalid state. */
int akeru_color_select(enum akeru_color_mode *mode, enum akeru_action action);
/* Applies color selections synchronously; action is valid only for this event. */
int akeru_color_menu_event(enum akeru_screen *screen, unsigned event,
                           enum akeru_action *action, enum akeru_color_mode *mode);
/* 0: caller continues its color path; 1: mono output produced; -1: invalid. */
int akeru_color_process(enum akeru_color_mode snapshot, const uint16_t *raw,
                        uint16_t *out, size_t width, size_t height);
/* As above, but mono output contains only rows [y, y + rows). */
int akeru_color_process_rows(enum akeru_color_mode snapshot, const uint16_t *raw,
                             uint16_t *out, size_t width, size_t height,
                             size_t y, size_t rows);
#endif
