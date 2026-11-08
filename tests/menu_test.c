#include "ui/menu.h"
#include "camera/iris_action.h"
#ifdef AKERU_GNU_TEST
void test_fail(unsigned line) __attribute__((noreturn));
#define CHECK(x) ((x) ? (void)0 : test_fail(__LINE__))
#else
#include <assert.h>
#define CHECK(x) assert(x)
#endif

static unsigned calls, argument, response;
static int same_text(const char *a, const char *b)
{
    if (!a || !b) return a == b;
    while (*a && *a == *b) { ++a; ++b; }
    return *a == *b;
}

static unsigned iris_stub(unsigned state)
{
    ++calls;
    argument = state;
    return response;
}

int main(void)
{
    static const char *const labels[6][4] = {
        {"Esposizione", "Colore / Mono", 0, "Impostazioni"},
        {"Indietro", "ISO", "Apertura", "Altro"},
        {"Indietro", "Colore", "Mono RAW", 0},
        {"Indietro", "Tempo", "Flash", 0},
        {"Indietro", "Acceso", "Spento", 0},
        {"Indietro", "Posizione A", "Posizione B", 0}
    };
    static const enum akeru_action expected[6][4] = {
        {AKERU_REDRAW, AKERU_REDRAW, AKERU_NONE, AKERU_OPEN_SETTINGS},
        {AKERU_REDRAW, AKERU_OPEN_ISO, AKERU_REDRAW, AKERU_REDRAW},
        {AKERU_REDRAW, AKERU_REQUEST_COLOR, AKERU_REQUEST_MONO, AKERU_NONE},
        {AKERU_REDRAW, AKERU_OPEN_SHUTTER, AKERU_REDRAW, AKERU_NONE},
        {AKERU_REDRAW, AKERU_FLASH_ON, AKERU_FLASH_OFF, AKERU_NONE},
        {AKERU_REDRAW, AKERU_IRIS_STATE_1, AKERU_IRIS_STATE_9, AKERU_NONE}
    };
    for (unsigned view = 0; view < 6; ++view) {
        for (unsigned key = 1; key <= 4; ++key) {
            enum akeru_screen screen = (enum akeru_screen)view;
            CHECK(same_text(akeru_menu_label(screen, key), labels[view][key-1]));
            CHECK(akeru_menu_press(&screen, key) == expected[view][key-1]);
            if (view == AKERU_MAIN && key == 1) CHECK(screen == AKERU_EXPOSURE);
            else if (view == AKERU_MAIN && key == 2) CHECK(screen == AKERU_COLOR);
            else if (view == AKERU_EXPOSURE && key == 3) CHECK(screen == AKERU_APERTURE);
            else if (view == AKERU_APERTURE && key == 1) CHECK(screen == AKERU_EXPOSURE);
            else if (view == AKERU_EXPOSURE && key == 4) CHECK(screen == AKERU_EXPOSURE_MORE);
            else if (view == AKERU_EXPOSURE_MORE && key == 1) CHECK(screen == AKERU_EXPOSURE);
            else if (view == AKERU_EXPOSURE_MORE && key == 3) CHECK(screen == AKERU_FLASH);
            else if (view == AKERU_FLASH && key == 1) CHECK(screen == AKERU_EXPOSURE_MORE);
            else if (view != AKERU_MAIN && key == 1) CHECK(screen == AKERU_MAIN);
            else CHECK(screen == (enum akeru_screen)view);
        }
    }
    CHECK(!akeru_menu_label(AKERU_MAIN, 0) && !akeru_menu_label(AKERU_MAIN, 5));
    CHECK(!akeru_menu_label((enum akeru_screen)-1, 1) && !akeru_menu_label((enum akeru_screen)99, 1));
    static const unsigned events[4] = {0x580, 0x700, 0x2180, 0x2700};
    for (unsigned view = 0; view < 6; ++view) {
        for (unsigned key = 0; key < 4; ++key) {
            enum akeru_screen actual = (enum akeru_screen)view;
            enum akeru_screen reference = actual;
            enum akeru_action action = AKERU_INVALID;
            enum akeru_action want = akeru_menu_press(&reference, key+1);
            CHECK(akeru_menu_event(&actual, events[key], &action) == 1);
            CHECK(action == want && actual == reference);
            CHECK(akeru_menu_event(&actual, events[key]+1, &action) == 1);
            CHECK(action == AKERU_NONE && actual == reference);
        }
    }
    enum akeru_screen screen = AKERU_MAIN;
    enum akeru_action action = AKERU_INVALID;
    for (unsigned view = 0; view < 6; ++view) {
        screen = (enum akeru_screen)view;
        CHECK(akeru_menu_event(&screen, 0x480, &action) == 1);
        CHECK(action == (view == AKERU_MAIN ? AKERU_RETURN_LIVEVIEW : AKERU_REDRAW));
        CHECK(screen == AKERU_MAIN);
        CHECK(akeru_menu_event(&screen, 0x481, &action) == 1 && action == AKERU_NONE && screen == AKERU_MAIN);
    }
    CHECK(akeru_menu_event(&screen, 0x2180, &action) == 1 && action == AKERU_NONE && screen == AKERU_MAIN);
    action = AKERU_OPEN_SETTINGS;
    CHECK(akeru_menu_event(&screen, 0x500, &action) == 0 && action == AKERU_OPEN_SETTINGS && screen == AKERU_MAIN);
    CHECK(akeru_menu_event(&screen, 0x4401, &action) == 0 && action == AKERU_OPEN_SETTINGS && screen == AKERU_MAIN);
    CHECK(akeru_menu_event(&screen, 0x4403, &action) == 0 && action == AKERU_OPEN_SETTINGS && screen == AKERU_MAIN);
    CHECK(akeru_menu_event(0, 0x580, &action) == -1);
    CHECK(akeru_menu_event(&screen, 0x580, 0) == -1 && screen == AKERU_MAIN);
    screen = (enum akeru_screen)99;
    CHECK(akeru_menu_event(&screen, 0x580, &action) == -1 && (int)screen == 99);
    screen = AKERU_MAIN;
    CHECK(akeru_menu_press(&screen, 1) == AKERU_REDRAW && screen == AKERU_EXPOSURE);
    CHECK(akeru_menu_press(&screen, 2) == AKERU_OPEN_ISO && screen == AKERU_EXPOSURE);
    CHECK(akeru_menu_press(&screen, 3) == AKERU_REDRAW && screen == AKERU_APERTURE);
    CHECK(akeru_menu_press(&screen, 2) == AKERU_IRIS_STATE_1 && screen == AKERU_APERTURE);
    CHECK(akeru_menu_press(&screen, 3) == AKERU_IRIS_STATE_9 && screen == AKERU_APERTURE);
    CHECK(akeru_menu_press(&screen, 1) == AKERU_REDRAW && screen == AKERU_EXPOSURE);
    CHECK(akeru_menu_press(&screen, 4) == AKERU_REDRAW && screen == AKERU_EXPOSURE_MORE);
    CHECK(akeru_menu_press(&screen, 2) == AKERU_OPEN_SHUTTER);
    CHECK(akeru_menu_press(&screen, 3) == AKERU_REDRAW && screen == AKERU_FLASH);
    CHECK(akeru_menu_press(&screen, 2) == AKERU_FLASH_ON && screen == AKERU_FLASH);
    CHECK(akeru_menu_press(&screen, 3) == AKERU_FLASH_OFF && screen == AKERU_FLASH);
    CHECK(akeru_menu_press(&screen, 1) == AKERU_REDRAW && screen == AKERU_EXPOSURE_MORE);
    CHECK(akeru_menu_press(&screen, 1) == AKERU_REDRAW && screen == AKERU_EXPOSURE);
    CHECK(akeru_menu_press(&screen, 1) == AKERU_REDRAW && screen == AKERU_MAIN);
    CHECK(akeru_menu_press(&screen, 2) == AKERU_REDRAW && screen == AKERU_COLOR);
    CHECK(akeru_menu_press(&screen, 3) == AKERU_REQUEST_MONO && screen == AKERU_COLOR);
    CHECK(akeru_menu_press(&screen, 1) == AKERU_REDRAW && screen == AKERU_MAIN);
    CHECK(akeru_menu_press(&screen, 0) == AKERU_INVALID && screen == AKERU_MAIN);
    CHECK(akeru_menu_press(&screen, 5) == AKERU_INVALID && screen == AKERU_MAIN);
    CHECK(akeru_menu_press(0, 1) == AKERU_INVALID);
    screen = (enum akeru_screen)99;
    CHECK(akeru_menu_press(&screen, 1) == AKERU_INVALID && (int)screen == 99);
    screen = AKERU_EXPOSURE;
    action = AKERU_NONE;
    CHECK(akeru_menu_defer_event(&screen, 0x2180, &action) == 1);
    CHECK(action == AKERU_REDRAW && screen == AKERU_APERTURE);
    CHECK(akeru_menu_defer_event(&screen, 0x2181, &action) == 1);
    CHECK(akeru_menu_defer_event(&screen, 0x4401, &action) == 0);
    CHECK(action == AKERU_REDRAW && screen == AKERU_APERTURE);
    CHECK(akeru_menu_defer_event(&screen, 0x580, &action) == -2);
    CHECK(action == AKERU_REDRAW && screen == AKERU_APERTURE);
    CHECK(akeru_menu_take_action(&action) == AKERU_REDRAW && action == AKERU_NONE);
    CHECK(akeru_menu_defer_event(&screen, 0x580, &action) == 1);
    CHECK(action == AKERU_REDRAW && screen == AKERU_EXPOSURE);
    CHECK(akeru_menu_take_action(&action) == AKERU_REDRAW);
    CHECK(akeru_menu_take_action(&action) == AKERU_NONE);
    screen = AKERU_APERTURE;
    CHECK(akeru_menu_defer_event(&screen, 0x700, &action) == 1 && action == AKERU_IRIS_STATE_1);
    CHECK(akeru_menu_defer_event(&screen, 0x701, &action) == 1 && action == AKERU_IRIS_STATE_1);
    CHECK(akeru_menu_take_action(&action) == AKERU_IRIS_STATE_1);
    CHECK(akeru_menu_defer_event(&screen, 0x2180, &action) == 1 && action == AKERU_IRIS_STATE_9);
    CHECK(akeru_menu_take_action(&action) == AKERU_IRIS_STATE_9);
    screen = AKERU_EXPOSURE;
    CHECK(akeru_menu_take_action(0) == AKERU_INVALID);
    CHECK(akeru_menu_defer_event(0, 0x580, &action) == -1);
    CHECK(akeru_menu_defer_event(&screen, 0x580, 0) == -1);
    action = AKERU_INVALID;
    CHECK(akeru_menu_defer_event(&screen, 0x580, &action) == -1);
    CHECK(screen == AKERU_EXPOSURE && action == AKERU_INVALID);
    struct akeru_menu_queue q = { .screen = AKERU_EXPOSURE };
    CHECK(akeru_menu_enqueue(&q, 0x700) == 1);
    CHECK(akeru_menu_next(&q) == AKERU_OPEN_ISO && q.active);
    CHECK(akeru_menu_enqueue(&q, 0x2180) == 0);
    CHECK(akeru_menu_enqueue(&q, 0x2181) == 0);
    CHECK(akeru_menu_enqueue(&q, 0x580) == 0 && q.count == 0);
    CHECK(akeru_menu_next(&q) == AKERU_INVALID && q.screen == AKERU_EXPOSURE);
    CHECK(akeru_menu_complete(&q, 0) == 1);
    unsigned observed = 77;
    response = 1;
    CHECK(akeru_iris_apply(AKERU_IRIS_STATE_1, iris_stub, &observed) == 1);
    CHECK(calls == 1 && argument == 1 && observed == 1);
    CHECK(akeru_iris_apply(AKERU_IRIS_STATE_9, iris_stub, &observed) == 0);
    CHECK(calls == 2 && argument == 9 && observed == 1);
    response = 9;
    CHECK(akeru_iris_apply(AKERU_IRIS_STATE_9, iris_stub, &observed) == 1);
    CHECK(calls == 3 && argument == 9 && observed == 9);
    CHECK(akeru_iris_apply(AKERU_OPEN_ISO, iris_stub, &observed) == -1);
    CHECK(akeru_iris_apply(AKERU_IRIS_STATE_1, 0, &observed) == -1);
    CHECK(akeru_iris_apply(AKERU_IRIS_STATE_1, iris_stub, 0) == -1);
    CHECK(calls == 3 && observed == 9);
    CHECK(akeru_menu_next(&q) == AKERU_NONE && q.screen == AKERU_EXPOSURE);
    const struct { enum akeru_screen screen; unsigned event; enum akeru_action action; } external[] = {
        {AKERU_EXPOSURE, 0x700, AKERU_OPEN_ISO},
        {AKERU_EXPOSURE_MORE, 0x700, AKERU_OPEN_SHUTTER},
        {AKERU_MAIN, 0x2700, AKERU_OPEN_SETTINGS},
        {AKERU_MAIN, 0x480, AKERU_RETURN_LIVEVIEW},
    };
    for (unsigned i = 0; i < sizeof(external)/sizeof(external[0]); ++i) {
        q.screen = external[i].screen;
        CHECK(akeru_menu_enqueue(&q, external[i].event) == 1);
        CHECK(akeru_menu_enqueue(&q, 0x580) == 1);
        CHECK(akeru_menu_next(&q) == external[i].action && q.count == 0);
        CHECK(akeru_menu_enqueue(&q, 0x580) == 0 && q.count == 0);
        CHECK(akeru_menu_complete(&q, 0) == 1 && akeru_menu_next(&q) == AKERU_NONE);
        CHECK(q.screen == external[i].screen);
    }
    q.screen = AKERU_MAIN;
    for (unsigned i = 0; i < 4; ++i) CHECK(akeru_menu_enqueue(&q, 0x700) == 1);
    CHECK(akeru_menu_enqueue(&q, 0x580) == -2 && q.overflow && q.count == 4);
    CHECK(akeru_menu_next(&q) == AKERU_INVALID);
    CHECK(akeru_menu_complete(&q, 1) == 1 && !q.count && !q.overflow);
    CHECK(akeru_menu_enqueue(&q, 0x2180) == 1);
    CHECK(akeru_menu_next(&q) == AKERU_NONE && !q.active);
    CHECK(akeru_menu_enqueue(&q, 0x580) == 1 && akeru_menu_next(&q) == AKERU_REDRAW);
    for (unsigned i = 0; i < 4; ++i) CHECK(akeru_menu_enqueue(&q, 0x700) == 1);
    CHECK(akeru_menu_enqueue(&q, 0x580) == -2);
    CHECK(akeru_menu_complete(&q, 0) == -2 && q.active && q.count == 4);
    CHECK(akeru_menu_complete(&q, 1) == 1 && !q.active && !q.count && !q.overflow);
    q.screen = AKERU_EXPOSURE_MORE;
    CHECK(akeru_menu_enqueue(&q, 0x2180) == 1 && akeru_menu_next(&q) == AKERU_REDRAW);
    CHECK(q.screen == AKERU_FLASH && akeru_menu_complete(&q, 0) == 1);
    CHECK(akeru_menu_enqueue(&q, 0x700) == 1 && akeru_menu_next(&q) == AKERU_FLASH_ON);
    CHECK(akeru_menu_complete(&q, 0) == 1);
    CHECK(akeru_menu_enqueue(&q, 0x2180) == 1 && akeru_menu_next(&q) == AKERU_FLASH_OFF);
    CHECK(akeru_menu_complete(&q, 0) == 1);
    q.screen = AKERU_APERTURE;
    CHECK(akeru_menu_enqueue(&q, 0x700) == 1 && akeru_menu_enqueue(&q, 0x2180) == 1);
    CHECK(akeru_menu_next(&q) == AKERU_IRIS_STATE_1 && q.active == 1);
    CHECK(akeru_menu_complete(&q, 0) == 1);
    CHECK(akeru_menu_next(&q) == AKERU_IRIS_STATE_9 && q.active == 1);
    CHECK(akeru_menu_complete(&q, 0) == 1);
    CHECK(akeru_menu_enqueue(0, 0x580) == -1 && akeru_menu_next(0) == AKERU_INVALID);
    CHECK(akeru_menu_complete(&q, 0) == -1 && akeru_menu_complete(&q, 2) == -1);
    return 0;
}
