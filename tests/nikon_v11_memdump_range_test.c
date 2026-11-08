#include "nikon_v11_memdump_held.h"

static unsigned writes;
static uint32_t last_len, last_src, write_status;
static uint32_t write_count_override;
static int use_override;
static const char path[] = "B:\\MEMDUMP.BIN";

uint32_t nikon_v11_save_original(const char *name, const void *data, uint32_t length, uint32_t selector)
{
    (void)name; (void)data; (void)length; (void)selector;
    return 73;
}

uint32_t nikon_v11_write_original(void *handle, const void *data, uint32_t length, uint32_t selector, uint32_t *count)
{
    if (handle != (void *)(uintptr_t)0x1234 || selector != 1 || count == 0)
        return 99;
    ++writes;
    last_len = length;
    last_src = (uint32_t)(uintptr_t)data;
    *count = use_override ? write_count_override : length;
    return write_status;
}

int run_checks(void)
{
    struct akeru_memdump_held ctx = {0x200, (void *)(uintptr_t)0x1234, 0};
    const void *first = (void *)(uintptr_t)0x300;
    const void *second = (void *)(uintptr_t)0x100;
    /* primo segmento invariato: 256 byte dalla sorgente richiesta */
    if (akeru_memdump_held_route(&ctx, 0x200, path, first, 256, 1) != 0 || ctx.phase != 1 || last_len != 256 || last_src != 0x300) return 1;
    /* secondo segmento: richiesta Nikon 0x100/0x104064C, scrittura reale dell'intervallo scelto */
    if (akeru_memdump_held_route(&ctx, 0x200, path, second, 0x104064c, 1) != 0 || ctx.phase != 2 || last_src != 0x0F600000u || last_len != 0x100000u) return 2;
    /* una terza chiamata e' rifiutata senza scrivere */
    writes = 0;
    if (akeru_memdump_held_route(&ctx, 0x200, path, second, 0x104064c, 1) != 1 || writes != 0) return 3;
    /* richiesta diversa da quella attesa: rifiutata, nessuna scrittura */
    ctx.phase = 1;
    if (akeru_memdump_held_route(&ctx, 0x200, path, (void *)(uintptr_t)0x400, 0x104064c, 1) != 1 || writes != 0) return 4;
    ctx.phase = 1;
    if (akeru_memdump_held_route(&ctx, 0x200, path, second, 0x1000, 1) != 1 || writes != 0) return 5;
    /* conteggio corto: fallimento, stato non avanza */
    ctx.phase = 1; use_override = 1; write_count_override = 0x80000;
    if (akeru_memdump_held_route(&ctx, 0x200, path, second, 0x104064c, 1) != 1 || ctx.phase == 2) return 6;
    /* errore di scrittura: propagato */
    ctx.phase = 1; use_override = 0; write_status = 0x1a00014;
    if (akeru_memdump_held_route(&ctx, 0x200, path, second, 0x104064c, 1) != 0x1a00014u) return 7;
    /* altro task: inoltrato al percorso Nikon originale */
    write_status = 0;
    if (akeru_memdump_held_route(&ctx, 0x201, path, second, 0x104064c, 1) != 73) return 8;
    /* nome diverso: rifiutato */
    ctx.phase = 0;
    if (akeru_memdump_held_route(&ctx, 0x200, "B:\\OTHER.BIN", first, 256, 1) != 1) return 9;
    return 0;
}

int main(void) { return run_checks(); }
