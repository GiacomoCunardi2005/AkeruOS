/* Original class notification and event APIs with an empty modeled waiter ring. */
#include <stdint.h>
#define W(a) (*(volatile uint32_t *)(uintptr_t)(a))
#define B(a) (*(volatile uint8_t *)(uintptr_t)(a))
#define REC 0x373308u
#define HANDLE 0x02200001u
#define CALL1(a,x) (((uint32_t (*)(uint32_t))(uintptr_t)(a))(x))
#define CALL2(a,x,y) (((uint32_t (*)(uint32_t,uint32_t))(uintptr_t)(a))(x,y))
static uint32_t iface[16], context[8], ep[4], vtable[6];
static uint32_t kernel[0x210/4], task[0x100/4], ready[2];
static uint32_t closes, bits_at_close;
extern void lab_stop(uint32_t);
#define CHECK(x) do { if (!(x)) lab_stop(__LINE__); } while (0)

uint32_t event_log(void) { return 0; }
static uint32_t endpoint_close(uint32_t endpoint)
{
    CHECK(endpoint==(uint32_t)(uintptr_t)ep);
    ++closes; bits_at_close=W(REC+0x24); return (uint32_t)-7;
}
static void prepare(uint32_t mode, uint32_t bits, uint32_t enabled)
{
    W(REC)=mode==2 ? 0 : 0x45564e4c;
    W(REC+8)=mode==1 ? 2 : 0x80000002;
    W(REC+0x14)=W(REC+0x18)=REC+0x14;
    W(REC+0x1c)=0; W(REC+0x24)=bits; W(REC+0x28)=0;
    W(0x369348)=(uint32_t)(uintptr_t)kernel;
    kernel[7]=(uint32_t)(uintptr_t)task; kernel[11]=(uint32_t)(uintptr_t)ready;
    ready[0]=(uint32_t)(uintptr_t)task; task[26]=1;
    iface[15]=(uint32_t)(uintptr_t)context;
    context[3]=enabled; context[4]=enabled ? (uint32_t)(uintptr_t)ep : 0;
    context[5]=context[6]=0; ep[2]=(uint32_t)(uintptr_t)vtable;
    vtable[1]=(uint32_t)(uintptr_t)endpoint_close;
    B(0x423c24)=0; closes=0; bits_at_close=0;
}
int main(void)
{
    CHECK(W(REC)==0x45564e4c && W(REC+4)==HANDLE && W(REC+8)==2);
    for (uint32_t mode=0;mode<3;++mode) for (uint32_t enabled=0;enabled<2;++enabled) {
        uint32_t expected=mode==1 ? 0x200304 : mode==2 ? 0x200307 : 0;
        prepare(mode,0xa5000002,enabled);
        CHECK(CALL1(0x19199c,(uint32_t)(uintptr_t)iface)==expected);
        CHECK(closes==enabled && (!enabled || bits_at_close==0xa5000002));
        CHECK(context[3]==0 && context[4]==0);
        CHECK(W(REC+0x24)==(mode==0 ? 0xa5010002 : 0xa5000002));
        CHECK(task[26]==1);
        if (mode==0) {
            uint32_t result=0;
            CHECK(CALL2(0x158e28,HANDLE,(uint32_t)(uintptr_t)&result)==0);
            CHECK(result==0xa5010002);
            CHECK(CALL2(0x158cbc,HANDLE,0x10000)==0 && W(REC+0x24)==result);
            CHECK(CALL2(0x158ce0,HANDLE,0x10000)==0 && W(REC+0x24)==0xa5000002);
        }
    }
    return 0;
}
