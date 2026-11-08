#include "../camera/color_mode.h"

int akeru_color_menu_event(enum akeru_screen *screen, unsigned event,
                           enum akeru_action *action, enum akeru_color_mode *mode)
{
    int handled;
    if (!mode || (*mode != AKERU_COLOR_STANDARD && *mode != AKERU_COLOR_MONO_RAW)) return -1;
    handled = akeru_menu_event(screen, event, action);
    if (handled == 1) (void)akeru_color_select(mode, *action);
    return handled;
}
