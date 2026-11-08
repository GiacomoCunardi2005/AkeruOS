#include "nikon_v11_memdump_map.h"
#define CHECK(x) do { if (!(x)) return __LINE__; } while (0)

static struct akeru_memdump_map session;
static uint8_t wrapper[16];
static unsigned opens, closes, writes, calls;
static int write_error, close_error, keep_handle, exists, short_write, detach_error;
static char names[2][16];
static uintptr_t sources[4];
static uint32_t sizes[4];
static void clear(void *p, unsigned n) { uint8_t *b=p;while(n--) *b++=0; }
static int equal(const char *a,const char *b) { while (*a && *a==*b) {++a;++b;} return *a==*b; }

uint32_t nikon_v11_save_original(const char *n,const void *p,uint32_t z,uint32_t s)
{ (void)n;(void)p;(void)z;(void)s;return 73; }
uint32_t nikon_v11_write_original(void *h,const void *p,uint32_t z,uint32_t s,uint32_t *n)
{
    if (h != wrapper || s != 1 || writes >= 4) return 99;
    sources[writes]=(uintptr_t)p;sizes[writes++]=z;*n=short_write && writes==2 ? z-1 : z;
    if (write_error && writes==2) wrapper[12]=1;
    return 0;
}
uint32_t nikon_v11_open_new_original(const char *name,uint32_t mode,void **file)
{
    if (mode != 3 || opens >= 2 || *file) return 99;
    if (exists) return 1;
    for (unsigned i=0;i<16;++i) names[opens][i]=name[i];
    ++opens;clear(wrapper,sizeof(wrapper));*file=wrapper;return 0;
}
uint32_t nikon_v11_close_original(void **file)
{
    if (*file != wrapper) return 99;
    ++closes;if (!keep_handle) *file=0;return close_error ? 1 : 0;
}
int akeru_memdump_held_attach(struct akeru_memdump_held *held,void *file)
{ if (held->owner || !file) return 1; held->owner=0x200;held->handle=file;held->phase=0;return 0; }
int akeru_memdump_held_detach(struct akeru_memdump_held *held)
{ if (held->owner!=0x200 || detach_error) return 1;held->owner=0;held->handle=0;held->phase=0;return 0; }
void nikon_v11_memdump_original(void)
{
    const char *name="B:\\MEMDUMP.BIN";
    ++calls;
    if (akeru_memdump_held_route(&session.held,0x200,name,(void *)(uintptr_t)0x300,256,1)==0)
        (void)akeru_memdump_held_route(&session.held,0x200,name,(void *)(uintptr_t)0x100,0x104064c,1);
}
static void reset(void)
{
    clear(&session,sizeof(session));clear(wrapper,sizeof(wrapper));
    opens=closes=writes=calls=0;write_error=close_error=keep_handle=exists=short_write=detach_error=0;
}
int run_checks(void)
{
    const struct akeru_dump_region map[]={{0,512},{0x100000,256}};
    const struct akeru_dump_region overlap[]={{0,512},{511,1}};
    const struct akeru_dump_region mmio[]={{0x0fdfffff,2}};
    const struct akeru_dump_region overflow[]={{0xfffffff0,32}};
    reset();
    CHECK(akeru_memdump_map_run(&session,0,2)!=0 && opens==0);
    CHECK(akeru_memdump_map_run(&session,overlap,2)!=0 && opens==0);
    CHECK(akeru_memdump_map_run(&session,mmio,1)!=0 && opens==0);
    CHECK(akeru_memdump_map_run(&session,overflow,1)!=0 && opens==0);
    CHECK(akeru_memdump_map_run(&session,map,2)==0 && session.completed==2 && opens==2 && closes==2);
    CHECK(equal(names[0],"B:\\00000000.BIN") && equal(names[1],"B:\\00100000.BIN"));
    CHECK(calls==2 && writes==4 && sources[1]==0 && sizes[1]==512 && sources[3]==0x100000 && sizes[3]==256);
    CHECK(akeru_memdump_map_run(&session,map,2)!=0 && opens==2);
    reset();write_error=1;
    CHECK(akeru_memdump_map_run(&session,map,2)!=0 && session.completed==0 && opens==1 && closes==1 && writes==2);
    reset();short_write=1;
    CHECK(akeru_memdump_map_run(&session,map,2)!=0 && session.completed==0 && opens==1 && closes==1 && writes==2);
    reset();close_error=1;keep_handle=1;
    CHECK(akeru_memdump_map_run(&session,map,2)!=0 && session.file==wrapper && session.completed==0 && opens==1);
    CHECK(akeru_memdump_map_run(&session,map,2)!=0 && opens==1);
    reset();close_error=1;
    CHECK(akeru_memdump_map_run(&session,map,2)!=0 && !session.file && session.completed==0 && opens==1 && closes==1);
    reset();detach_error=1;
    CHECK(akeru_memdump_map_run(&session,map,2)!=0 && session.file==wrapper && session.held.owner==0x200 && closes==0);
    CHECK(akeru_memdump_map_run(&session,map,2)!=0 && opens==1);
    reset();exists=1;
    CHECK(akeru_memdump_map_run(&session,map,2)!=0 && opens==0 && writes==0 && closes==0);
    CHECK(akeru_memdump_held_route(&session.held,0x201,0,0,0,0)==73);
    return 0;
}
#ifdef HOST_TEST
int main(void) { return run_checks(); }
#endif
