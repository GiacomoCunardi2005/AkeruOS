#include "ram_dump.h"
#include <assert.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

struct fixture {
    uint8_t output[8192];
    uint32_t used, now, reads, waits, opens, closes, writes, interval_waits;
    uint32_t last_sequence;
    int marker, remove_on_wait, remove_on_read, read_error, open_error;
    int write_error, zero_write, oversized_write, close_error, wait_error;
    int collision, short_writes, marker_error, discard_output;
    uint32_t streamed_bytes, last_read_end;
};

static int armed(void *context)
{
    struct fixture *f = context;
    return f->marker_error ? -1 : f->marker;
}
static int wait_ms(void *context, uint32_t ms)
{
    struct fixture *f = context;
    ++f->waits; f->now += ms;
    if (ms == 5000) ++f->interval_waits;
    if (f->remove_on_wait) f->marker = 0;
    return f->wait_error ? -1 : 0;
}
static uint32_t now(void *context) { return ((struct fixture *)context)->now; }
static int read_ram(void *context, uint32_t address, uint8_t *out, uint32_t n)
{
    struct fixture *f = context;
    uint32_t i;
    assert(n <= AKERU_DUMP_CHUNK);
    ++f->reads;
    f->last_read_end = address+n;
    if (f->read_error) return -1;
    for (i = 0; i < n; ++i) out[i] = (uint8_t)((address+i)^((address+i)>>8));
    if (f->remove_on_read) f->marker = 0;
    return 0;
}
static int open_new(void *context, const char *name, void **file)
{
    struct fixture *f = context;
    char expected[32];
    unsigned sequence;
    assert(sscanf(name, "B:AKR%5u.DMP", &sequence) == 1);
    assert(snprintf(expected,sizeof(expected),"B:AKR%05u.DMP",sequence) == 14);
    assert(strcmp(name,expected) == 0);
    f->last_sequence = sequence; ++f->opens;
    if (f->open_error) return -1;
    if (f->collision) return 1;
    f->used = 0; *file = f;
    return 0;
}
static int32_t write_bytes(void *context, void *file, const uint8_t *p, uint32_t n)
{
    struct fixture *f = context;
    assert(file == f); ++f->writes;
    if (f->write_error) return -1;
    if (f->zero_write) return 0;
    if (f->oversized_write) return (int32_t)n+1;
    if (f->short_writes && n > 7) n = 7;
    f->streamed_bytes += n;
    if (f->discard_output) return (int32_t)n;
    assert(f->used+n <= sizeof(f->output));
    memcpy(f->output+f->used,p,n); f->used += n;
    return (int32_t)n;
}
static int close_file(void *context, void *file)
{
    struct fixture *f = context;
    assert(file == f); ++f->closes;
    return f->close_error ? -1 : 0;
}
static void setup(struct akeru_ram_dumper *d, struct fixture *f)
{
    memset(d,0,sizeof(*d));memset(f,0,sizeof(*f)); f->marker = 1;
    akeru_ram_dump_defaults(d);
    akeru_ram_dump_use_selected_regions(d);
    d->io = (struct akeru_dump_io){f,armed,wait_ms,now,read_ram,open_new,write_bytes,close_file};
    d->max_snapshots = 1;
}
static uint32_t le32(const uint8_t *p)
{
    return p[0]|((uint32_t)p[1]<<8)|((uint32_t)p[2]<<16)|((uint32_t)p[3]<<24);
}

int main(int argc, char **argv)
{
    struct akeru_ram_dumper d;
    struct fixture f;
    struct akeru_dump_region region;
    unsigned tests = 0;
    FILE *output;
    assert(argc == 2);
    setup(&d,&f);
    assert(akeru_ram_dump_run(&d) == 0 && d.completed == 1);
    assert(f.opens == 1 && f.closes == 1 && f.interval_waits == 1);
    assert(memcmp(f.output,"AKRDMP1\0",8) == 0);
    assert(memcmp(f.output+f.used-16,"AKRDONE\0",8) == 0);
    output = fopen(argv[1],"wb");assert(output);
    assert(fwrite(f.output,1,f.used,output) == f.used);assert(fclose(output) == 0);
    ++tests;
    setup(&d,&f);d.max_snapshots = 12;
    assert(akeru_ram_dump_run(&d) == 0 && d.completed == 12);
    assert(f.opens == 12 && f.closes == 12 && f.interval_waits == 12 && f.last_sequence == 11);++tests;
    setup(&d,&f);f.marker = 0;
    assert(akeru_ram_dump_run(&d) == AKERU_DUMP_DISARMED && f.waits == 0 && f.opens == 0);++tests;
    setup(&d,&f);f.remove_on_wait = 1;
    assert(akeru_ram_dump_run(&d) == AKERU_DUMP_DISARMED && f.opens == 0);++tests;
    setup(&d,&f);f.remove_on_read = 1;
    assert(akeru_ram_dump_run(&d) == AKERU_DUMP_DISARMED && f.closes == 1 && d.completed == 0);
    assert(memcmp(f.output+f.used-16,"AKRDONE\0",8) != 0);++tests;
    setup(&d,&f);f.marker_error = 1;
    assert(akeru_ram_dump_run(&d) == AKERU_DUMP_IO && f.opens == 0);++tests;
    setup(&d,&f);f.open_error = 1;
    assert(akeru_ram_dump_run(&d) == AKERU_DUMP_IO && f.closes == 0);++tests;
    setup(&d,&f);f.collision = 1;
    assert(akeru_ram_dump_run(&d) == AKERU_DUMP_IO && f.opens == 32 && f.closes == 0);++tests;
    setup(&d,&f);f.short_writes = 1;
    assert(akeru_ram_dump_run(&d) == 0 && d.completed == 1);++tests;
    setup(&d,&f);f.write_error = 1;
    assert(akeru_ram_dump_run(&d) == AKERU_DUMP_IO && f.closes == 1 && d.completed == 0);++tests;
    setup(&d,&f);f.zero_write = 1;
    assert(akeru_ram_dump_run(&d) == AKERU_DUMP_IO && f.closes == 1);++tests;
    setup(&d,&f);f.oversized_write = 1;
    assert(akeru_ram_dump_run(&d) == AKERU_DUMP_IO && f.closes == 1);++tests;
    setup(&d,&f);f.read_error = 1;
    assert(akeru_ram_dump_run(&d) == AKERU_DUMP_READ && f.closes == 1);++tests;
    setup(&d,&f);f.close_error = 1;
    assert(akeru_ram_dump_run(&d) == AKERU_DUMP_IO && d.completed == 0);++tests;
    setup(&d,&f);f.wait_error = 1;
    assert(akeru_ram_dump_run(&d) == AKERU_DUMP_WAIT && f.opens == 0);++tests;
    setup(&d,&f);d.next_sequence = 99999;
    assert(akeru_ram_dump_run(&d) == 0 && f.last_sequence == 99999 && d.next_sequence == 100000);++tests;
    setup(&d,&f);d.next_sequence = 100000;
    assert(akeru_ram_dump_run(&d) == AKERU_DUMP_IO && f.opens == 0);++tests;
    setup(&d,&f);f.now = 0xfffffff0u;
    assert(akeru_ram_dump_run(&d) == 0 && le32(f.output+24) == (uint32_t)(0xfffffff0u+5000u));++tests;
    setup(&d,&f);d.interval_ms = 0;
    assert(akeru_ram_dump_run(&d) == AKERU_DUMP_CONFIG && f.waits == 0);++tests;
    setup(&d,&f);region = (struct akeru_dump_region){0x0ff04024u,2};d.regions = &region;d.region_count = 1;
    assert(akeru_ram_dump_run(&d) == AKERU_DUMP_CONFIG && f.reads == 0);++tests;
    setup(&d,&f);region = (struct akeru_dump_region){0xfffffff0u,32};d.regions = &region;d.region_count = 1;
    assert(akeru_ram_dump_run(&d) == AKERU_DUMP_CONFIG);++tests;
    setup(&d,&f);region = (struct akeru_dump_region){0x360800u,AKERU_DUMP_MAX_BYTES+1};d.regions = &region;d.region_count = 1;
    assert(akeru_ram_dump_run(&d) == AKERU_DUMP_CONFIG);++tests;
    setup(&d,&f);d.io.wait_ms = 0;
    assert(akeru_ram_dump_run(&d) == AKERU_DUMP_CONFIG);++tests;
    assert(akeru_ram_dump_run(0) == AKERU_DUMP_CONFIG);++tests;
    setup(&d,&f);akeru_ram_dump_defaults(&d);
    assert(akeru_ram_dump_run(&d) == AKERU_DUMP_CONFIG && f.opens == 0);++tests;
    setup(&d,&f);region = (struct akeru_dump_region){0,128u*1024u*1024u};
    akeru_ram_dump_use_full_map(&d,&region,1);f.discard_output = 1;
    assert(akeru_ram_dump_run(&d) == 0 && d.completed == 1);
    assert(f.last_read_end == region.length && f.reads == region.length/AKERU_DUMP_CHUNK);
    assert(f.streamed_bytes == region.length+32+12+8+16 && f.interval_waits == 1);++tests;
    setup(&d,&f);region = (struct akeru_dump_region){0x360800,16};
    akeru_ram_dump_use_full_map(&d,&region,1);
    assert(akeru_ram_dump_run(&d) == 0 && le32(f.output+28) == 3);++tests;
    setup(&d,&f);
    { struct akeru_dump_region overlap[]={{0x1000,32},{0x1010,32}};
      akeru_ram_dump_use_full_map(&d,overlap,2);
      assert(akeru_ram_dump_run(&d) == AKERU_DUMP_CONFIG && f.reads == 0); }++tests;
    printf("PASS host_cases=%u\n",tests);
    return 0;
}
