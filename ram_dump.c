#include "ram_dump.h"

/* V1.1 candidate RAM objects documented in the service/iris/timer reports.
 * No MMIO, DMA buffers, guessed contiguous RAM or kernel pointer chasing.
 */
const struct akeru_dump_region akeru_dump_default_regions[] = {
    {0x366dd0u, 0x120u}, {0x367898u, 0x64u}, {0x369348u, 4u},
    {0x36a464u, 0x60u}, {0x36a6c8u, 8u}, {0x392ac0u, 0x40u},
    {0x424500u, 0xd8u}, {0x424b18u, 0x8cu}, {0x4437f4u, 0xc8u},
    {0x446808u, 0x228u}, {0x5545f8u, 0x40u}
};
const uint32_t akeru_dump_default_region_count =
    sizeof(akeru_dump_default_regions) / sizeof(akeru_dump_default_regions[0]);

static void word(uint8_t *out, uint32_t value)
{
    unsigned i;
    for (i = 0; i < 4; ++i) out[i] = (uint8_t)(value >> (i * 8));
}

static uint32_t crc_update(uint32_t crc, const uint8_t *p, uint32_t n)
{
    uint32_t i;
    unsigned bit;
    for (i = 0; i < n; ++i) {
        crc ^= p[i];
        for (bit = 0; bit < 8; ++bit)
            crc = (crc >> 1) ^ ((crc & 1u) ? 0xedb88320u : 0u);
    }
    return crc;
}

void akeru_ram_dump_defaults(struct akeru_ram_dumper *d)
{
    if (!d) return;
    d->regions = 0;
    d->region_count = 0;
    d->interval_ms = 5000;
    d->max_snapshots = 1;
    d->next_sequence = d->completed = 0;
    d->last_result = AKERU_DUMP_OK;
    d->full_declared_map = 0;
}

void akeru_ram_dump_use_full_map(struct akeru_ram_dumper *d,
    const struct akeru_dump_region *regions, uint32_t count)
{
    if (!d) return;
    d->regions = regions; d->region_count = count; d->full_declared_map = 1;
}

void akeru_ram_dump_use_selected_regions(struct akeru_ram_dumper *d)
{
    if (!d) return;
    d->regions = akeru_dump_default_regions;
    d->region_count = akeru_dump_default_region_count; d->full_declared_map = 0;
}

static int valid(const struct akeru_ram_dumper *d, uint32_t *total)
{
    uint32_t i, sum = 0, previous_end = 0;
    if (!d || !d->regions || d->region_count == 0 ||
        d->region_count > AKERU_DUMP_MAX_REGIONS ||
        d->interval_ms < 1000 || d->max_snapshots == 0 ||
        d->max_snapshots > 100 || d->completed > d->max_snapshots || d->full_declared_map > 1 ||
        !d->io.armed || !d->io.wait_ms || !d->io.now_ms ||
        !d->io.read_ram || !d->io.open_new || !d->io.write || !d->io.close)
        return 0;
    for (i = 0; i < d->region_count; ++i) {
        uint32_t a = d->regions[i].address, n = d->regions[i].length;
        /* Bounds exclude the known SoC MMIO window. This does NOT prove that
         * arbitrary lower addresses are RAM; the read adapter must validate.
         */
        if (n == 0 || a >= 0x0fe00000u || n > 0x0fe00000u - a ||
            n > AKERU_DUMP_MAX_BYTES - sum || (i && a < previous_end)) return 0;
        sum += n;
        previous_end = a+n;
    }
    *total = sum;
    return 1;
}

static int enabled(struct akeru_ram_dumper *d)
{
    int result = d->io.armed(d->io.context);
    if (result == 1) return AKERU_DUMP_OK;
    return result == 0 ? AKERU_DUMP_DISARMED : AKERU_DUMP_IO;
}

static int write_all(struct akeru_ram_dumper *d, void *file,
                     const uint8_t *data, uint32_t length)
{
    while (length) {
        int32_t n = d->io.write(d->io.context, file, data, length);
        if (n <= 0 || (uint32_t)n > length) return AKERU_DUMP_IO;
        data += n;
        length -= (uint32_t)n;
    }
    return AKERU_DUMP_OK;
}

static void filename(char *name, uint32_t sequence)
{
    static const char pattern[] = "B:AKR00000.DMP";
    unsigned i;
    for (i = 0; i < sizeof(pattern); ++i) name[i] = pattern[i];
    for (i = 0; i < 5; ++i) {
        name[9-i] = (char)('0' + sequence % 10);
        sequence /= 10;
    }
}

static int capture(struct akeru_ram_dumper *d, uint32_t total)
{
    uint8_t header[32] = {'A','K','R','D','M','P','1',0};
    uint8_t region_header[12], region_end[8];
    uint8_t footer[16] = {'A','K','R','D','O','N','E',0};
    char name[15];
    void *file = 0;
    uint32_t i, sequence = 0, attempt;
    int result = AKERU_DUMP_IO, opened = 0;
    for (attempt = 0; attempt < 32; ++attempt) {
        if (d->next_sequence > 99999u) return AKERU_DUMP_IO;
        sequence = d->next_sequence++;
        filename(name, sequence);
        result = d->io.open_new(d->io.context, name, &file);
        if (result == 0) { opened = 1; break; }
        if (result != 1) return AKERU_DUMP_IO;
    }
    if (!opened) return AKERU_DUMP_IO;
    word(header+8, 1); word(header+12, sequence);
    word(header+16, d->region_count); word(header+20, total);
    word(header+24, d->io.now_ms(d->io.context));
    /* Bit 0: sequential/non-atomic. Bit 1: all platform-declared RAM banks.
     * No claim that the supplied map has been measured on physical hardware.
     */
    word(header+28, 1u | (d->full_declared_map << 1));
    result = write_all(d, file, header, sizeof(header));
    for (i = 0; result == 0 && i < d->region_count; ++i) {
        uint32_t offset = 0, crc = 0xffffffffu;
        const struct akeru_dump_region *region = d->regions+i;
        word(region_header, region->address); word(region_header+4, region->length);
        word(region_header+8, d->io.now_ms(d->io.context));
        crc = crc_update(crc, region_header, sizeof(region_header));
        result = write_all(d, file, region_header, sizeof(region_header));
        while (result == 0 && offset < region->length) {
            uint32_t n = region->length - offset;
            if (n > AKERU_DUMP_CHUNK) n = AKERU_DUMP_CHUNK;
            result = enabled(d);
            if (result != 0) break;
            if (d->io.read_ram(d->io.context, region->address+offset, d->scratch, n) != 0) {
                result = AKERU_DUMP_READ; break;
            }
            crc = crc_update(crc, d->scratch, n);
            result = write_all(d, file, d->scratch, n);
            offset += n;
            if (result == 0 && d->io.wait_ms(d->io.context, 1) != 0)
                result = AKERU_DUMP_WAIT;
        }
        if (result == 0) {
            word(region_end, d->io.now_ms(d->io.context));
            crc = crc_update(crc, region_end, 4);
            word(region_end+4, crc ^ 0xffffffffu);
            result = write_all(d, file, region_end, sizeof(region_end));
        }
    }
    if (result == 0) {
        word(footer+8, d->region_count); word(footer+12, d->io.now_ms(d->io.context));
        result = write_all(d, file, footer, sizeof(footer));
    }
    /* A partial file is retained without a complete footer. No delete/rename.
     * Close is always attempted; a failed close is never counted as success.
     */
    if (d->io.close(d->io.context, file) != 0 && result == 0) result = AKERU_DUMP_IO;
    if (result == 0) ++d->completed;
    return result;
}

int akeru_ram_dump_run(struct akeru_ram_dumper *d)
{
    uint32_t total;
    int result;
    if (!valid(d, &total)) {
        if (d) d->last_result = AKERU_DUMP_CONFIG;
        return AKERU_DUMP_CONFIG;
    }
    while (d->completed < d->max_snapshots) {
        result = enabled(d);
        if (result != 0) { d->last_result = result; return result; }
        if (d->io.wait_ms(d->io.context, d->interval_ms) != 0) {
            d->last_result = AKERU_DUMP_WAIT; return d->last_result;
        }
        result = enabled(d);
        if (result == 0) result = capture(d, total);
        if (result != 0) { d->last_result = result; return result; }
    }
    d->last_result = AKERU_DUMP_OK;
    return AKERU_DUMP_OK;
}

void akeru_ram_dump_task(void *argument)
{
    (void)akeru_ram_dump_run((struct akeru_ram_dumper *)argument);
}
