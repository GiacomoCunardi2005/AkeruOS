#include "menu.h"

const char *akeru_menu_label(enum akeru_screen screen, unsigned slot)
{
    static const char *const labels[6][4] = {
        {"Esposizione", "Colore / Mono", 0, "Impostazioni"},
        {"Indietro", "ISO", "Apertura", "Altro"},
        {"Indietro", "Colore", "Mono RAW", 0},
        {"Indietro", "Tempo", "Flash", 0},
        {"Indietro", "Acceso", "Spento", 0},
        {"Indietro", "Posizione A", "Posizione B", 0}
    };
    if (screen < AKERU_MAIN || screen > AKERU_APERTURE || slot < 1 || slot > 4) return 0;
    return labels[screen][slot - 1];
}
