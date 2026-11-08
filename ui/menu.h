#ifndef AKERU_MENU_H
#define AKERU_MENU_H

enum akeru_screen { AKERU_MAIN, AKERU_EXPOSURE, AKERU_COLOR, AKERU_EXPOSURE_MORE, AKERU_FLASH, AKERU_APERTURE };
enum akeru_action {
    AKERU_NONE, AKERU_REDRAW, AKERU_OPEN_ISO, AKERU_OPEN_APERTURE,
    AKERU_OPEN_SHUTTER, AKERU_REQUEST_COLOR, AKERU_REQUEST_MONO,
    AKERU_OPEN_SETTINGS, AKERU_FLASH_ON, AKERU_FLASH_OFF, AKERU_INVALID, AKERU_RETURN_LIVEVIEW,
    AKERU_IRIS_STATE_1, AKERU_IRIS_STATE_9
};

/* Slots 1..4 are logical UI positions; the hardware mapping is not established. */
enum akeru_action akeru_menu_press(enum akeru_screen *screen, unsigned slot);
/* NULL means the logical slot is empty or the input is invalid. */
const char *akeru_menu_label(enum akeru_screen screen, unsigned slot);
/* Return 1 when consumed, 0 for an unrelated event, -1 for invalid inputs; 0 and -1 leave action untouched. */
int akeru_menu_event(enum akeru_screen *screen, unsigned event, enum akeru_action *action);

/* Sequential caller: -2 means pending action is full; retry the event after taking it. */
int akeru_menu_defer_event(enum akeru_screen *screen, unsigned event,
                           enum akeru_action *pending);
enum akeru_action akeru_menu_take_action(enum akeru_action *pending);

/* shortcut: four queued presses, replace after measuring a safe device bound. */
struct akeru_menu_queue {
    enum akeru_screen screen;
    unsigned events[4];
    unsigned count, active, overflow;
};
/* Sequential only. An external screen drops queued presses and returns 0 for
   new events so its owner can handle them; overflow is latched until discard. */
int akeru_menu_enqueue(struct akeru_menu_queue *queue, unsigned event);
enum akeru_action akeru_menu_next(struct akeru_menu_queue *queue);
/* For an external screen, complete only on return or failed opening. Discard
   also clears the queue, even when no action is active. */
int akeru_menu_complete(struct akeru_menu_queue *queue, int discard);

#endif
