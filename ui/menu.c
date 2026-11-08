#include "menu.h"

enum akeru_action akeru_menu_press(enum akeru_screen *screen, unsigned slot)
{
    if (!screen || slot < 1 || slot > 4) return AKERU_INVALID;
    switch (*screen) {
    case AKERU_MAIN:
        if (slot == 1) { *screen = AKERU_EXPOSURE; return AKERU_REDRAW; }
        if (slot == 2) { *screen = AKERU_COLOR; return AKERU_REDRAW; }
        if (slot == 4) return AKERU_OPEN_SETTINGS;
        return AKERU_NONE;
    case AKERU_EXPOSURE:
        if (slot == 1) { *screen = AKERU_MAIN; return AKERU_REDRAW; }
        if (slot == 2) return AKERU_OPEN_ISO;
        if (slot == 3) { *screen = AKERU_APERTURE; return AKERU_REDRAW; }
        *screen = AKERU_EXPOSURE_MORE; return AKERU_REDRAW;
    case AKERU_EXPOSURE_MORE:
        if (slot == 1) { *screen = AKERU_EXPOSURE; return AKERU_REDRAW; }
        if (slot == 2) return AKERU_OPEN_SHUTTER;
        if (slot == 3) { *screen = AKERU_FLASH; return AKERU_REDRAW; }
        return AKERU_NONE;
    case AKERU_FLASH:
        if (slot == 1) { *screen = AKERU_EXPOSURE_MORE; return AKERU_REDRAW; }
        if (slot == 2) return AKERU_FLASH_ON;
        if (slot == 3) return AKERU_FLASH_OFF;
        return AKERU_NONE;
    case AKERU_APERTURE:
        if (slot == 1) { *screen = AKERU_EXPOSURE; return AKERU_REDRAW; }
        if (slot == 2) return AKERU_IRIS_STATE_1;
        if (slot == 3) return AKERU_IRIS_STATE_9;
        return AKERU_NONE;
    case AKERU_COLOR:
        if (slot == 1) { *screen = AKERU_MAIN; return AKERU_REDRAW; }
        if (slot == 2) return AKERU_REQUEST_COLOR;
        if (slot == 3) return AKERU_REQUEST_MONO;
        return AKERU_NONE;
    default:
        return AKERU_INVALID;
    }
}

int akeru_menu_event(enum akeru_screen *screen, unsigned event, enum akeru_action *action)
{
    unsigned slot;
    if (!screen || !action || *screen < AKERU_MAIN || *screen > AKERU_APERTURE) return -1;
    switch (event) {
    case 0x480:
        if (*screen == AKERU_MAIN) *action = AKERU_RETURN_LIVEVIEW;
        else { *screen = AKERU_MAIN; *action = AKERU_REDRAW; }
        return 1;
    case 0x580: slot = 1; break;
    case 0x700: slot = 2; break;
    case 0x2180: slot = 3; break;
    case 0x2700: slot = 4; break;
    case 0x481: case 0x581: case 0x701: case 0x2181: case 0x2701:
        *action = AKERU_NONE;
        return 1;
    default:
        return 0;
    }
    *action = akeru_menu_press(screen, slot);
    return 1;
}

int akeru_menu_defer_event(enum akeru_screen *screen, unsigned event,
                           enum akeru_action *pending)
{
    enum akeru_screen next;
    enum akeru_action action = AKERU_NONE;
    int handled;
    if (!screen || !pending || *pending < AKERU_NONE ||
        *pending > AKERU_IRIS_STATE_9 || *pending == AKERU_INVALID)
        return -1;
    next = *screen;
    handled = akeru_menu_event(&next, event, &action);
    if (handled != 1) return handled;
    if (action != AKERU_NONE && *pending != AKERU_NONE) return -2;
    *screen = next;
    if (action != AKERU_NONE) *pending = action;
    return 1;
}

enum akeru_action akeru_menu_take_action(enum akeru_action *pending)
{
    enum akeru_action action;
    if (!pending || *pending < AKERU_NONE ||
        *pending > AKERU_IRIS_STATE_9 || *pending == AKERU_INVALID)
        return AKERU_INVALID;
    action = *pending;
    *pending = AKERU_NONE;
    return action;
}

static int queue_valid(const struct akeru_menu_queue *q)
{
    return q && q->screen >= AKERU_MAIN && q->screen <= AKERU_APERTURE &&
           q->count <= 4 && q->active <= 2 && q->overflow <= 1;
}

int akeru_menu_enqueue(struct akeru_menu_queue *q, unsigned event)
{
    if (!queue_valid(q)) return -1;
    if (q->active == 2) return 0;
    switch (event) {
    case 0x481: case 0x581: case 0x701: case 0x2181: case 0x2701:
        return 1;
    case 0x480: case 0x580: case 0x700: case 0x2180: case 0x2700:
        break;
    default:
        return 0;
    }
    if (q->overflow || q->count == 4) { q->overflow = 1; return -2; }
    q->events[q->count++] = event;
    return 1;
}

enum akeru_action akeru_menu_next(struct akeru_menu_queue *q)
{
    enum akeru_action action = AKERU_NONE;
    if (!queue_valid(q) || q->active || q->overflow) return AKERU_INVALID;
    while (q->count && action == AKERU_NONE) {
        unsigned event = q->events[0];
        for (unsigned i = 1; i < q->count; ++i) q->events[i-1] = q->events[i];
        --q->count;
        if (akeru_menu_event(&q->screen, event, &action) != 1) return AKERU_INVALID;
    }
    if (action == AKERU_OPEN_ISO || action == AKERU_OPEN_APERTURE ||
        action == AKERU_OPEN_SHUTTER || action == AKERU_OPEN_SETTINGS ||
        action == AKERU_RETURN_LIVEVIEW) {
        q->count = 0;
        q->active = 2;
    } else if (action != AKERU_NONE) q->active = 1;
    return action;
}

int akeru_menu_complete(struct akeru_menu_queue *q, int discard)
{
    if (!queue_valid(q) || (discard != 0 && discard != 1) || (!q->active && !discard)) return -1;
    if (q->overflow && !discard) return -2;
    if (discard) { q->count = 0; q->overflow = 0; }
    q->active = 0;
    return 1;
}
