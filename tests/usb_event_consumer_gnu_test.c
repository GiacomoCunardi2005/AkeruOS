/* Original USB consumers and event APIs, with a modeled scheduler boundary. */
#include <stdint.h>
#define W(a) (*(volatile uint32_t *)(uintptr_t)(a))
#define B(a) (*(volatile uint8_t *)(uintptr_t)(a))
#define REC 0x373308u
#define HANDLE 0x02200001u
#define CALL1(a,x) (((uint32_t (*)(uint32_t))(uintptr_t)(a))(x))
#define CALL2(a,x,y) (((uint32_t (*)(uint32_t,uint32_t))(uintptr_t)(a))(x,y))
static uint32_t iface[16], context[8], ep1[4], ep2[4], vtable[6];
static uint32_t kernel[0x210/4], task[0x100/4], ready[2], count;
static uint8_t buffer[64];
static uint32_t rx, close_cause, injected, closes, cancels, acquires, releases;
extern void lab_stop(uint32_t);
#define CHECK(x) do { if (!(x)) lab_stop(__LINE__); } while (0)

uint32_t fixture_connected(void) { return 1; }
uint32_t fixture_zero(void) { return 0; }
uint32_t fixture_acquire(uint32_t id,uint32_t flags) { CHECK(id==0x2200005 && flags==0); ++acquires; return 0; }
uint32_t fixture_release(uint32_t id) { CHECK(id==0x2200005); ++releases; return 0; }
static uint32_t endpoint_close(uint32_t endpoint)
{ CHECK(endpoint==(uint32_t)(uintptr_t)ep1 || endpoint==(uint32_t)(uintptr_t)ep2); ++closes; return (uint32_t)-7; }
static uint32_t endpoint_cancel(uint32_t endpoint,uint32_t request)
{ CHECK(endpoint==(uint32_t)(uintptr_t)ep2 && request==0x47da4c); ++cancels; return (uint32_t)-7; }

/* The hook is a scheduler fixture, reached after the original worker-event SET. */
uint32_t fixture_scheduler(void)
{
    if (!injected && (W(REC+0x24)&(rx ? 0x200 : 0x100))) {
        injected=1;
        if (close_cause) CHECK(CALL1(0x19199c,(uint32_t)(uintptr_t)iface)==0);
        else CHECK(CALL2(0x158cbc,HANDLE,rx ? 0x2000 : 0x1000)==0);
        task[26]=0;
    }
    return 0;
}
static void prepare(uint32_t auto_clear)
{
    W(REC)=0x45564e4c; W(REC+8)=0x80000002;
    W(REC+0x14)=W(REC+0x18)=REC+0x14; W(REC+0x1c)=0;
    W(REC+0x24)=2; W(REC+0x28)=auto_clear;
    W(0x369348)=(uint32_t)(uintptr_t)kernel;
    kernel[7]=(uint32_t)(uintptr_t)task; kernel[11]=(uint32_t)(uintptr_t)ready;
    ready[0]=(uint32_t)(uintptr_t)task; task[26]=1; B(0x36a3a4)=0;
    W(0x368114)=(uint32_t)(uintptr_t)context; W(0x3680e4)=512;
    iface[15]=(uint32_t)(uintptr_t)context;
    context[3]=1; context[4]=(uint32_t)(uintptr_t)ep1; context[5]=(uint32_t)(uintptr_t)ep2; context[6]=0;
    ep1[2]=ep2[2]=(uint32_t)(uintptr_t)vtable;
    vtable[1]=(uint32_t)(uintptr_t)endpoint_close; vtable[5]=(uint32_t)(uintptr_t)endpoint_cancel;
    for (uint32_t i=0;i<64;++i) { B(0x423c00+i)=0; buffer[i]=0xa5; }
    count=0xa5a5a5a5; injected=closes=cancels=acquires=releases=0;
}
int main(void)
{
    CHECK(W(REC)==0x45564e4c && W(REC+4)==HANDLE && W(REC+8)==2);
    for (rx=0;rx<2;++rx) for (uint32_t auto_clear=0;auto_clear<2;++auto_clear)
    for (close_cause=0;close_cause<2;++close_cause) {
        prepare(auto_clear);
        uint32_t result;
        if (rx) result=((uint32_t (*)(uint32_t,uint32_t,uint32_t,uint32_t,uint32_t,uint32_t,uint32_t,uint32_t,uint32_t))(uintptr_t)0x1906b4)
            (2,(uint32_t)(uintptr_t)buffer,64,20,(uint32_t)(uintptr_t)&count,1,0,1,1);
        else result=((uint32_t (*)(uint32_t,uint32_t,uint32_t,uint32_t,uint32_t,uint32_t))(uintptr_t)0x1908dc)
            (1,(uint32_t)(uintptr_t)buffer,64,20,(uint32_t)(uintptr_t)&count,1);
        CHECK(result==(close_cause && !auto_clear ? 0x2200341u : 0));
        CHECK(injected && count==0 && acquires==1 && releases==1);
        CHECK(closes==(close_cause?2:0) && cancels==(close_cause&&rx?1:0));
        CHECK(B(0x423c00+(rx?36:16))==0 && task[26]==0);
        for (uint32_t i=0;i<64;++i) CHECK(buffer[i]==0xa5);
    }
    return 0;
}
