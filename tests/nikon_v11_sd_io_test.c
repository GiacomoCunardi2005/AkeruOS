#include "nikon_v11_sd_io.h"
#include "ram_dump.h"
#include <assert.h>
#include <stdio.h>
#include <string.h>

struct fixture {
    struct akeru_nikon_v11_sd_io port;
    uint8_t wrapper[32], replacement[32], output[8192];
    uint32_t writes, closes, used, fail_at, status, error, count, close_status;
    int counted, close_kind;
};
static struct fixture *active;

uint32_t nikon_v11_file_write_original(void *file, const uint8_t *data,
    uint32_t size, uint32_t selector, uint32_t *written)
{
    struct fixture *f = active;
    uint32_t n = size, error = 0, status = 0;
    assert(file == f->wrapper && selector == 0);
    ++f->writes;
    if (f->fail_at == 0 || f->writes == f->fail_at) {
        n = f->counted ? f->count : size;
        error = f->error; status = f->status;
    }
    *written = n;
    for (unsigned i = 0; i < 4; ++i)
        f->wrapper[12+i] = (uint8_t)(error >> (8*i));
    if (n <= size) {
        assert(f->used+n <= sizeof(f->output));
        memcpy(f->output+f->used, data, n); f->used += n;
    }
    return status;
}

uint32_t nikon_v11_file_close_original(void **file)
{
    struct fixture *f = active;
    assert(*file == f->wrapper);
    ++f->closes;
    if (f->close_kind != 1) {
        memset(f->wrapper, 0xdd, sizeof(f->wrapper));
        *file = f->close_kind == 2 ? f->replacement : NULL;
    }
    return f->close_status;
}

static void reset(struct fixture *f)
{
    memset(f, 0, sizeof(*f)); active = f;
}
static void *take(struct fixture *f)
{
    void *token = NULL;
    assert(akeru_nikon_v11_sd_io_take(&f->port, f->wrapper, &token) == 0);
    assert(token == &f->port);
    return token;
}
static int armed(void *context) { assert(context == active); return 1; }
static int wait_ms(void *context, uint32_t ms)
{ assert(context == active && ms > 0); return 0; }
static uint32_t now(void *context) { assert(context == active); return 1234; }
static int read_ram(void *context, uint32_t address, uint8_t *data, uint32_t n)
{
    assert(context == active && address >= 0x1000 && address+n <= 0x1040);
    for (uint32_t i = 0; i < n; ++i) data[i] = (uint8_t)(address+i);
    return 0;
}
static int open_new(void *context, const char *name, void **token)
{
    struct fixture *f = context;
    assert(strcmp(name, "B:AKR00000.DMP") == 0);
    return akeru_nikon_v11_sd_io_take(&f->port, f->wrapper, token);
}
static int run_engine(struct fixture *f, uint32_t *completed)
{
    const struct akeru_dump_region synthetic = {0x1000, 64};
    struct akeru_ram_dumper d;
    akeru_ram_dump_defaults(&d);
    akeru_ram_dump_use_full_map(&d, &synthetic, 1);
    d.io = (struct akeru_dump_io){&f->port, armed, wait_ms, now, read_ram,
        open_new, akeru_nikon_v11_sd_io_write, akeru_nikon_v11_sd_io_close};
    int result = akeru_ram_dump_run(&d);
    *completed = d.completed;
    return result;
}

int main(int argc, char **argv)
{
    struct fixture f;
    void *token, *other;
    const uint8_t data[4] = {1,2,3,4};
    uint32_t completed;
    unsigned tests = 0;
    assert(argc == 2);
    reset(&f);
    assert(akeru_nikon_v11_sd_io_take(NULL, f.wrapper, &token) == -1 && token == NULL);
    assert(akeru_nikon_v11_sd_io_take(&f.port, NULL, &token) == -1);
    assert(akeru_nikon_v11_sd_io_take(&f.port, f.wrapper, NULL) == -1); ++tests;
    token = take(&f);
    assert(akeru_nikon_v11_sd_io_take(&f.port, f.replacement, &other) == -1);
    assert(f.port.native == f.wrapper && other == NULL); ++tests;
    assert(akeru_nikon_v11_sd_io_write(&f.port, token, data, 4) == 4);
    assert(f.writes == 1 && f.used == 4 && memcmp(f.output, data, 4) == 0); ++tests;
    assert(akeru_nikon_v11_sd_io_write(&f.port, &other, data, 4) == -1);
    assert(akeru_nikon_v11_sd_io_write(&f.port, token, NULL, 4) == -1);
    assert(akeru_nikon_v11_sd_io_write(&f.port, token, data, 0) == -1);
    assert(akeru_nikon_v11_sd_io_write(&f.port, token, data, UINT32_MAX) == -1);
    assert(f.writes == 1); ++tests;
    assert(akeru_nikon_v11_sd_io_close(&f.port, &other) == -1 && f.closes == 0);
    assert(akeru_nikon_v11_sd_io_close(&f.port, token) == 0);
    assert(f.port.close_ownership == AKERU_NIKON_CLOSE_CONSUMED);
    assert(akeru_nikon_v11_sd_io_close(&f.port, token) == -1 && f.closes == 1);
    assert(akeru_nikon_v11_sd_io_write(&f.port, token, data, 4) == -1); ++tests;
    token = take(&f);
    assert(akeru_nikon_v11_sd_io_close(&f.port, token) == 0 && f.closes == 2); ++tests;
    for (unsigned kind = 0; kind < 5; ++kind) {
        reset(&f); token = take(&f);
        if (kind == 0) f.status = 0x1a00006;
        if (kind == 1) f.error = 0x1a00006;
        if (kind >= 2) { f.counted = 1; f.count = kind == 2 ? 0 : kind == 3 ? 3 : 5; }
        assert(akeru_nikon_v11_sd_io_write(&f.port, token, data, 4) == -1);
        assert(f.port.failed && f.port.write_status == f.status && f.port.file_error == f.error);
        assert(akeru_nikon_v11_sd_io_write(&f.port, token, data, 4) == -1 && f.writes == 1);
        assert(akeru_nikon_v11_sd_io_close(&f.port, token) == 0);
        assert(akeru_nikon_v11_sd_io_take(&f.port, f.wrapper, &other) == -1); ++tests;
    }
    for (unsigned kind = 0; kind < 4; ++kind) {
        reset(&f); token = take(&f);
        f.close_kind = kind == 3 ? 2 : kind == 0 ? 0 : 1;
        f.close_status = kind == 2 ? 0 : 0x1a0000c;
        assert(akeru_nikon_v11_sd_io_close(&f.port, token) == -1 && f.port.failed);
        assert(f.port.close_ownership == (kind == 0 ? AKERU_NIKON_CLOSE_CONSUMED :
            kind == 3 ? AKERU_NIKON_CLOSE_REPLACED : AKERU_NIKON_CLOSE_RETAINED));
        assert(f.port.native == (kind == 0 ? NULL : kind == 3 ? f.replacement : f.wrapper));
        assert(akeru_nikon_v11_sd_io_close(&f.port, token) == -1 && f.closes == 1);
        assert(akeru_nikon_v11_sd_io_take(&f.port, f.wrapper, &other) == -1); ++tests;
    }
    reset(&f);
    assert(run_engine(&f, &completed) == AKERU_DUMP_OK && completed == 1);
    FILE *output = fopen(argv[1], "wb"); assert(output);
    assert(fwrite(f.output, 1, f.used, output) == f.used && fclose(output) == 0); ++tests;
    for (unsigned kind = 0; kind < 4; ++kind) {
        reset(&f); f.fail_at = 3;
        if (kind == 0) { f.counted = 1; f.count = 3; }
        if (kind == 1) f.error = 0x1a00006;
        if (kind == 2) f.close_status = 0x1a0000c;
        if (kind == 3) f.close_kind = 1;
        assert(run_engine(&f, &completed) == AKERU_DUMP_IO && completed == 0);
        assert(f.closes == 1 && f.port.issued == 0 && f.port.failed);
        if (kind < 2) assert(f.writes == 3);
        assert(akeru_nikon_v11_sd_io_close(&f.port, &f.port) == -1 && f.closes == 1); ++tests;
    }
    printf("PASS sd_io_cases=%u\n", tests);
    return 0;
}
