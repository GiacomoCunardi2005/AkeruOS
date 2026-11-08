/* Original class notification -> cancel/close -> event; register responses remain fixtures. */
#include "class_close_fixture.h"
static uint32_t close_mode,close_mask,close_enabled,pre_cancel,event_status,stuck_flush;
static uint32_t close_nodes[3][8],close_requests[3][10],owned_nodes[3],callback_seen[3];
static uint32_t allocating_endpoint,remaining,close_events,close_cases,close_callbacks,close_frees;
static uint32_t cancel_callbacks,drain_callbacks,flush_left,flush_reads,flush_delays;
static const uint32_t close_eps[]={PUBLIC+0x64,PUBLIC+0x1E4,PUBLIC+0x7C};
static const uint32_t close_records[]={DEV+0x68,DEV+0x464,DEV+0xAC};
static const uint32_t close_registers[]={BASE+0x920,BASE+0xB20,BASE+0x940};
static uint32_t close_request(uint32_t i)
{
    return i==1 ? 0x47DA4Cu:(uint32_t)(uintptr_t)close_requests[i];
}
uint32_t close_alloc(uint32_t size)
{
    if (!close_mode || !class_io || phase<3) return class_alloc(size);
    CHECK(phase==3 && size==32 && allocating_endpoint<3 && owned_nodes[allocating_endpoint]==0);
    uint32_t i=allocating_endpoint;owned_nodes[i]=1;
    for (uint32_t j=0;j<8;++j) close_nodes[i][j]=0xA5A5A5A5;
    return (uint32_t)(uintptr_t)close_nodes[i];
}
static uint32_t close_callback(uint32_t ep,uint32_t request)
{
    uint32_t i=0;while (i<3 && request!=close_request(i)) ++i;
    CHECK(i<3 && ep==close_eps[i] && phase==3 && depth==0);
    CHECK(owned_nodes[i] && callback_seen[i]==0 && W(DEV+16)==remaining);
    CHECK(W(request+32)==(uint32_t)(i==1 && pre_cancel ? -54:-58) && W(request+36)==0xA5A5A5A5);
    CHECK(registers[(close_registers[i]-BASE)/4]&0x8000);
    CHECK(close_events==0 && class_owned && request_owned);
    callback_seen[i]=1;++close_callbacks;
    if (i==1 && pre_cancel) ++cancel_callbacks;else ++drain_callbacks;
    return 0;
}
uint32_t close_free(uint32_t address)
{
    if (close_mode) for (uint32_t i=0;i<3;++i) if (address==(uint32_t)(uintptr_t)close_nodes[i]) {
        CHECK(phase==3 && depth==1 && owned_nodes[i] && callback_seen[i]==1);
        CHECK(remaining>0 && W(DEV+16)==remaining-1 && close_events==0);
        CHECK(registers[(close_registers[i]-BASE)/4]&0x8000);
        owned_nodes[i]=0;--remaining;++close_frees;return 0;
    }
    return class_free(address);
}
uint32_t close_read(uint32_t address)
{
    if (close_mode && phase==3 && address==BASE+0x10 && (registers[0x10/4]&0x20)) {
        CHECK(depth==1);++flush_reads;
        if (!stuck_flush && --flush_left==0) registers[0x10/4]&=~0x20u;
    }
    return init_read(address);
}
uint32_t close_write(uint32_t address,uint32_t value)
{
    uint32_t result=init_write(address,value);
    if (close_mode && phase==3 && address==BASE+0x10 && (value&0x20)) flush_left=2;
    return result;
}
uint32_t close_delay(uint32_t value)
{
    if (!close_mode || phase!=3) return init_delay(value);
    CHECK(value==1 && depth==1);++flush_delays;return 0;
}
uint32_t close_event(uint32_t group,uint32_t bits)
{
    CHECK(close_mode && phase==3 && depth==0 && group==0x2200001 && bits==0x10000);
    CHECK(class_owned && request_owned && B(CLASS_ADDRESS+12)==0);
    for (uint32_t i=0;i<3;++i) {
        uint32_t present=(close_mask>>i)&1,done=present && (close_enabled || (i==1 && pre_cancel));
        CHECK(owned_nodes[i]==(present && !done) && callback_seen[i]==done);
        CHECK(W(CLASS_ADDRESS+16+4*i)==(present && !close_enabled ? close_eps[i]:0));
    }
    ++close_events;return event_status;
}
int main(void)
{
    CHECK(class_lifecycle_reference_tests()==0);close_mode=1;
    for (uint32_t p=0;p<2;++p)
    for (uint32_t kind=0;kind<34;++kind) {
        uint32_t special=kind>=32;
        close_mask=special ? 1:kind&7;close_enabled=special ? 1:(kind>>3)&1;
        pre_cancel=special ? 0:(kind>>4)&1;stuck_flush=kind==33;
        event_status=kind&1 ? (uint32_t)-9:0;
        reset(0,1,p ? 512:64,0,2);W(0x353404)=0x11223344;
        class_io=class_owned=request_owned=node_owned=fail_class_size=0;W(CLASS_GLOBAL)=0;
        B(0x423C24)=pre_cancel;remaining=close_events=flush_left=0;
        uint32_t first_reads=flush_reads,first_delays=flush_delays;
        for (uint32_t i=0;i<3;++i) owned_nodes[i]=callback_seen[i]=0;
        for (uint32_t i=0;i<0x1000/4;++i) registers[i]=0;
        for (uint32_t i=0;i<65;++i) W(OPTIONS+4*i)=0xFFFFFFFF;
        registers[0x48/4]=(3u<<10)|(1u<<3)|(1u<<20);
        registers[0x50/4]=(1u<<25)|(3u<<26)|3u;
        registers[0x40/4]=0x4F542000;registers[0x2C/4]=0x10000;
        phase=1;construct_allocations=reg_reads=reg_writes=reg_modifies=delays=0;
        wrapper_allocations=registrations=device_allocations=completions=freed=0;module_value=0;
        CHECK(((uint32_t (*)(uint32_t))(uintptr_t)0x243838)(TOP)==0);
        W(0x51A390)=0;phase=3;
        CHECK(((uint32_t (*)(void))(uintptr_t)0x190408)()==0);
        notify_status(p ? 0:1);
        for (uint32_t i=0;i<3;++i) {
            if (!(close_mask&(1u<<i))) continue;
            W(CLASS_ADDRESS+16+4*i)=close_eps[i];
            if (kind==32) {
                CHECK(APP_CALL(0x278770,close_eps[i])==(uint32_t)-7);continue;
            }
            uint32_t descriptor=USB+16*i;
            B(descriptor)=7;B(descriptor+1)=5;B(descriptor+2)=i==0 ? 0x81:i==1 ? 1:0x82;
            B(descriptor+3)=2;H(descriptor+4)=packet;
            CHECK(CALL2(0x27864C,close_eps[i],descriptor)==0);
            uint32_t req=close_request(i);
            for (uint32_t j=0;j<40;++j) B(req+j)=0;
            W(req)=W(req+8)=BUF+64*i;W(req+4)=32;W(req+12)=2;
            W(req+16)=(uint32_t)(uintptr_t)close_callback;
            allocating_endpoint=i;class_io=1;
            CHECK(CALL3(0x278854,close_eps[i],req,32)==0);++remaining;
            CHECK(W(close_records[i]+4)==(uint32_t)(uintptr_t)close_nodes[i]);
        }
        if (kind==32) close_mask=0;
        B(CLASS_ADDRESS+12)=close_enabled;
        CHECK(W(W(DEV)+4)==0x278B0C);
        CHECK(CALL2(W(W(DEV)+4),DEV,0)==0);
        CHECK(close_events==1 && W(DEV+16)==remaining && depth==0);
        if (kind==32) CHECK(W(CLASS_ADDRESS+16)==0);
        uint32_t in_closed=close_enabled && kind!=32 ? ((close_mask&1)!=0)+((close_mask&4)!=0):0;
        CHECK(flush_reads-first_reads==(stuck_flush ? 10001:2*in_closed));
        CHECK(flush_delays-first_delays==(stuck_flush ? 10001:3*in_closed));
        if (stuck_flush) CHECK(registers[0x10/4]&0x20);
        for (uint32_t i=0;i<3;++i) if (close_enabled && (close_mask&(1u<<i))) {
            CHECK(W(close_records[i])==0 && !(registers[(close_registers[i]-BASE)/4]&0x8000));
        }
        if (close_enabled) {
            CHECK(remaining==0 && APP_CALL(0x278610,CLASS_TABLE)==0 && !class_owned && !request_owned);
        }
        /* Cases with closing disabled retain their live objects and pending nodes here. */
        ++close_cases;
    }
    CHECK(close_cases==68 && close_callbacks==58 && close_frees==58);
    CHECK(cancel_callbacks==16 && drain_callbacks==42);return 0;
}
