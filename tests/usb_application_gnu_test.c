/* Original application registration and status notification; app callbacks/MMIO are fixtures. */
#include "transport_application_fixture.h"
static int32_t init_status,stop_status;
static uint32_t init_calls,stop_calls;
#define APP_CALL(a,p) (((uint32_t (*)(uint32_t))(uintptr_t)(a))((uint32_t)(uintptr_t)(p)))

static uint32_t app_unused(void) { lab_stop(84); }
static uint32_t app_init(uint32_t interface)
{
    CHECK(phase==3 && depth==0 && interface==PUBLIC+4);
    CHECK(W(PUBLIC+0x48)==(uint32_t)(uintptr_t)app_ops);
    CHECK(W(PUBLIC+0x38)==(uint32_t)(uintptr_t)(app_ops+8));
    ++init_calls;return (uint32_t)init_status;
}
static uint32_t app_stop(uint32_t interface)
{
    CHECK(phase==3 && depth==0 && interface==PUBLIC+4);
    CHECK(W(PUBLIC+0x48)==(uint32_t)(uintptr_t)app_ops);
    ++stop_calls;return (uint32_t)stop_status;
}
static void register_application(void)
{
    init_calls=stop_calls=0;init_status=stop_status=0;
    for (uint32_t i=0;i<9;++i) app_ops[i]=0;
    app_ops[0]=0x349034;app_ops[1]=3;app_ops[8]=0xA5A50000;
    for (uint32_t i=2;i<=5;++i) app_ops[i]=(uint32_t)(uintptr_t)app_unused;
    app_ops[2]=(uint32_t)(uintptr_t)app_init;app_ops[3]=(uint32_t)(uintptr_t)app_stop;
    CHECK(APP_CALL(0x278578,0)==(uint32_t)-7);
    for (uint32_t i=1;i<=5;++i) {
        uint32_t saved=app_ops[i];app_ops[i]=0;
        CHECK(APP_CALL(0x278578,app_ops)==(uint32_t)-7);
        CHECK(W(PUBLIC+0x48)==0 && init_calls==0);app_ops[i]=saved;
    }
    W(0x36B588)=0;
    CHECK(APP_CALL(0x278578,app_ops)==(uint32_t)-4 && init_calls==0);
    W(0x36B588)=PUBLIC;
    init_status=-17;
    CHECK(APP_CALL(0x278578,app_ops)==(uint32_t)-17 && init_calls==1);
    CHECK(W(PUBLIC+0x48)==0 && W(PUBLIC+0x38)==0);
    init_status=0;
    CHECK(APP_CALL(0x278578,app_ops)==0 && init_calls==2);
    CHECK(APP_CALL(0x278578,app_ops)==(uint32_t)-5 && init_calls==2);
    CHECK(APP_CALL(0x278610,0)==(uint32_t)-7);
    CHECK(APP_CALL(0x278610,app_ops+1)==(uint32_t)-7 && stop_calls==0);
    stop_status=-19;
    CHECK(APP_CALL(0x278610,app_ops)==0 && stop_calls==1);
    CHECK(W(PUBLIC+0x48)==0 && W(PUBLIC+0x38)==(uint32_t)(uintptr_t)(app_ops+8));
    CHECK(APP_CALL(0x278610,app_ops)==(uint32_t)-7 && stop_calls==1);
    CHECK(APP_CALL(0x278578,app_ops)==0 && init_calls==3 && W(PUBLIC+0x14)==0);
}
static void notify_status(uint32_t selector)
{
    static const uint32_t expected[]={3,2,1,2};
    uint32_t previous=W(PUBLIC+0x14),reads_before=ram_reads,allocated_before=allocations;
    registers[0x808/4]=selector<<1;
    irq_status=1u<<13;irq_mask=0;phase=4;
    CALL2(W(0x50B4B8),0,W(0x50B4BC));++irq_cases;
    CHECK(W(PUBLIC+0x14)==previous && depth==0);
    irq_mask=1u<<13;
    CALL2(W(0x50B4B8),0,W(0x50B4BC));++irq_cases;
    CHECK(W(PUBLIC+0x14)==expected[selector] && W(DEV+8)==1 && depth==0);
    CHECK(ram_reads==reads_before && allocations==allocated_before && node_owned==0);
    phase=3;
}
int main(void)
{
    CHECK(transport_guard_tests()==0);cases=irq_cases=done_cases=0;
    for (uint32_t p=0;p<2;++p) {
        reset(0,1,p ? 512:64,0,2);W(0x353404)=0x11223344;
        for (uint32_t i=0;i<0x1000/4;++i) registers[i]=0;
        for (uint32_t i=0;i<65;++i) W(OPTIONS+4*i)=0xFFFFFFFF;
        registers[0x48/4]=(3u<<10)|(1u<<3)|(1u<<20);
        registers[0x50/4]=(1u<<25)|(3u<<26)|3u;
        registers[0x40/4]=0x4F542000;registers[0x2C/4]=0x10000;
        phase=1;construct_allocations=reg_reads=reg_writes=reg_modifies=delays=0;
        wrapper_allocations=registrations=device_allocations=completions=freed=node_owned=0;module_value=0;
        CHECK(((uint32_t (*)(uint32_t))(uintptr_t)0x243838)(TOP)==0);
        CHECK(W(DEV)==0x51A3A4 && W(W(DEV))==0x278B00);
        CHECK(W(0x50B4B8)==0x278BC4 && W(0x50B4BC)==DEV);
        CHECK(W(PUBLIC+0x48)==0 && W(PUBLIC+0x14)==0);
        phase=3;register_application();
        CHECK(CALL2(0x27864C,PUBLIC+0x1E4,USB)==(uint32_t)-58);
        for (uint32_t selector=0;selector<4;++selector) notify_status(selector);
        for (uint32_t i=0;i<7;++i) B(USB+16+i)=B(USB+i);
        B(USB+18)=0x81;
        CHECK(CALL2(0x27864C,PUBLIC+0x1E4,USB)==0);
        CHECK(CALL2(0x27864C,PUBLIC+0x64,USB+16)==0);
        transport_service(&service);service.read_ram=task_read;
        CHECK(akeru_usb_ram_transport_init(&transport,&service,packet)==0);
        for (uint32_t v=0;v<18;++v) {
            CHECK(akeru_usb_ram_transport_receive(&transport)==32);
            complete_io(0,transport.rx,32,v);
            int32_t n=akeru_usb_ram_transport_received(&transport,(int32_t)notified_status,notified_actual);
            CHECK(n==(int32_t)reply_sizes[v]);
            for (uint32_t i=0;i<(uint32_t)n;++i) CHECK(transport.tx[i]==replies[reply_offsets[v]+i]);
            CHECK(akeru_usb_ram_transport_send(&transport)==n);
            complete_io(1,transport.tx,(uint32_t)n,v);
            for (uint32_t i=0;i<(uint32_t)n;++i) CHECK(transport.tx[i]==replies[reply_offsets[v]+i]);
            CHECK(akeru_usb_ram_transport_sent(&transport,(int32_t)notified_status,notified_actual)==0);++cases;
        }
        CHECK(ram_reads==4 && service.reads==3 && service.aborted==1 && allocations==36);
        stop_status=0;CHECK(APP_CALL(0x278610,app_ops)==0 && stop_calls==2);
        CHECK(W(PUBLIC+0x48)==0 && W(PUBLIC+0x38)==(uint32_t)(uintptr_t)(app_ops+8));
    }
    CHECK(cases==36 && irq_cases==93 && done_cases==72);return 0;
}
