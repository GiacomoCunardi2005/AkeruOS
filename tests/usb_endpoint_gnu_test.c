/* Real endpoint wrappers/list handling; controller start, allocation and RTOS are fixtures. */
#include <stdint.h>
#define W(a) (*(volatile uint32_t *)(uintptr_t)(a))
#define B(a) (*(volatile uint8_t *)(uintptr_t)(a))
#define TOP 0x500000u
#define DEV 0x500800u
#define NODE (DEV+0x68u)
#define EP 0x501100u
#define REQ 0x501200u
#define BUF 0x502000u
#define CALL1(a,x) (((uint32_t (*)(uint32_t))(uintptr_t)(a))(x))
#define CALL2(a,x,y) (((uint32_t (*)(uint32_t,uint32_t))(uintptr_t)(a))((x),(y)))
#define CALL3(a,x,y,z) (((uint32_t (*)(uint32_t,uint32_t,uint32_t))(uintptr_t)(a))((x),(y),(z)))
void lab_stop(uint32_t code) __attribute__((noreturn));
#define CHECK(x) do { if (!(x)) lab_stop(82); } while (0)
static uint32_t heap[4][8],used,freed,depth,acquires,releases,starts,callbacks;
static uint32_t fail_alloc,resource_error,reenter,callback_req,callback_status,callback_actual,cases;

uint32_t ep_logging(void) { return 0; }
uint32_t ep_alloc(uint32_t size)
{
    CHECK(size==32 && used<4);if (fail_alloc) return 0;
    for (uint32_t i=0;i<8;++i) heap[used][i]=0;
    return (uint32_t)(uintptr_t)heap[used++];
}
uint32_t ep_free(uint32_t address)
{
    CHECK(depth==1 && address>=(uint32_t)(uintptr_t)heap &&
        address<(uint32_t)(uintptr_t)(heap+4));++freed;return 0;
}
uint32_t ep_acquire(uint32_t id,uint32_t timeout)
{
    CHECK(id==0x2200005 && timeout==0 && depth==0);++acquires;
    if (!resource_error) ++depth;
    return resource_error;
}
uint32_t ep_release(uint32_t id)
{
    CHECK(id==0x2200005);++releases;if (depth) --depth;return resource_error;
}
uint32_t ep_start(uint32_t controller,uint32_t descriptor)
{
    CHECK(controller==0x500C00 && descriptor==NODE+16 && depth==1);
    ++starts;return 999; /* Original caller does not propagate this status. */
}
uint32_t ep_open(uint32_t device,uint32_t descriptor,uint32_t endpoint)
{
    CHECK(device==DEV && descriptor==0 && endpoint==TOP+0x4C);return 0;
}
static uint32_t callback(uint32_t device,uint32_t endpoint,uint32_t request,
                         uint32_t status,uint32_t actual)
{
    CHECK(device==DEV && endpoint==EP && depth==0 && freed==0);
    CHECK((W(NODE+12)&1)==1 && W(NODE+4)==NODE+4 && W(NODE+8)==NODE+4);
    ++callbacks;callback_req=request;callback_status=status;callback_actual=actual;
    if (reenter) CHECK(CALL3(0x278854,EP,REQ+64,32)==0 && used==2 && starts==1);
    return 0;
}
static void reset(void)
{
    for (uint32_t i=0;i<0x3000;++i) B(TOP+i)=0;
    W(0x36B588)=TOP;W(TOP)=DEV;W(TOP+0x48)=W(TOP+0x14)=1;
    W(DEV)=0x500E00;W(0x500E0C)=(uint32_t)(uintptr_t)callback;
    W(DEV+4)=0x500C00;W(0x500C00)=0x500D00;W(0x500D00)=1;
    W(DEV+0x860)=0x501F00;W(0x501F00)=0x2200005;
    W(NODE)=1;W(NODE+4)=W(NODE+8)=NODE+4;
    W(NODE+16)=1|(64u<<18);W(NODE+0x3C)=DEV;W(NODE+0x40)=EP;
    W(EP+8)=0x51A360;
    for (uint32_t i=0;i<2;++i) {
        uint32_t req=REQ+64*i;W(req)=W(req+8)=BUF;W(req+4)=64;
        W(req+12)=2;W(req+16)=0x190F10;W(req+32)=0xA5;W(req+36)=0xA5;
    }
    used=freed=depth=acquires=releases=starts=callbacks=0;
    fail_alloc=resource_error=reenter=callback_req=callback_status=callback_actual=0;
}
static void queued(uint32_t node,uint32_t request)
{
    CHECK(W(node)==request && W(node+4)==BUF && W(node+8)==BUF && W(node+12)==64);
    CHECK((W(node+20)&1)==1 && W(request+32)==(uint32_t)-10 && W(request+36)==0);
}
int endpoint_tests(void)
{
    cases=0;reset();CALL1(0x278BCC,TOP);
    CHECK(W(0x51A360)==0x27864C && W(0x51A364)==0x278770);
    CHECK(W(0x51A370)==0x278854 && W(0x51A374)==0x278930);++cases;
    for (uint32_t invalid=0;invalid<5;++invalid) {
        reset();uint32_t ep=EP,req=REQ;
        if (invalid==0) req=0;
        if (invalid==1) W(REQ)=0;
        if (invalid==2) W(REQ+16)=0;
        if (invalid==3) ep=0;
        if (invalid==4) W(TOP+0x48)=0;
        CHECK(CALL3(0x278854,ep,req,32)==(uint32_t)(invalid==4?-58:-7));
        CHECK(used==0 && acquires==0);++cases;
    }
    reset();fail_alloc=1;
    CHECK(CALL3(0x278854,EP,REQ,32)==(uint32_t)-7 && depth==0 && starts==0);++cases;
    reset();W(NODE)=0;
    CHECK(CALL3(0x278854,EP,REQ,32)==(uint32_t)-7 && used==0);++cases;
    reset();CHECK(CALL3(0x278854,EP,REQ,32)==0);
    uint32_t first=(uint32_t)(uintptr_t)heap[0];queued(first,REQ);
    CHECK(W(NODE+4)==first && W(NODE+8)==first && W(first+24)==NODE+4 &&
        W(first+28)==NODE+4 && W(DEV+16)==1 && starts==1 && depth==0);++cases;
    CHECK(CALL3(0x278854,EP,REQ+64,32)==0);
    uint32_t second=(uint32_t)(uintptr_t)heap[1];queued(second,REQ+64);
    CHECK(starts==1 && W(first+24)==second && W(second+28)==first &&
        W(NODE+8)==second && W(DEV+16)==2);++cases;
    reset();CHECK(CALL3(0x278854,EP,REQ,32)==0);W(first+16)=17;
    CHECK(CALL2(0x278930,EP,REQ)==0 && callbacks==1 && freed==1 && depth==0);
    CHECK(callback_req==REQ && callback_status==(uint32_t)-1008 && callback_actual==17);
    CHECK(W(NODE+4)==NODE+4 && W(NODE+8)==NODE+4 && W(DEV+16)==0 && (W(NODE+12)&1)==0);++cases;
    reset();CHECK(CALL2(0x278930,EP,REQ)==(uint32_t)-7 && depth==0 && callbacks==0);++cases;
    reset();CHECK(CALL3(0x278854,EP,REQ,32)==0);reenter=1;
    CHECK(CALL2(0x278930,EP,REQ)==0 && callbacks==1 && freed==1 && used==2 && depth==0);
    CHECK(W(NODE+4)==second && W(NODE+8)==second && W(DEV+16)==1 && starts==1);++cases;
    reset();CHECK(CALL3(0x278854,EP,REQ,31)==0 && starts==1);++cases;
    reset();W(REQ+4)=0;CHECK(CALL3(0x278854,EP,REQ,32)==0 && W(first+12)==0);++cases;
    reset();resource_error=999;
    /* Stop before the fixture controller can be called without a resource. */
    W(NODE+12)=1;
    CHECK(CALL3(0x278854,EP,REQ,32)==0 && used==1 && depth==0 && acquires==1 && releases==1);
    CHECK(W(NODE+4)==first && W(DEV+16)==1);++cases;
    CHECK(cases==16);return 0;
}
