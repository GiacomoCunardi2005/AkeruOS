/* Original parent/device setup and registered completion chain; resources/MMIO are fixtures. */
#define main open_buffer_reference_tests
#include "usb_open_buffer_gnu_test.c"
#undef main
#define AUX 0x501500u
#define PARAM 0x501600u
#define EVENT 0x501740u
static uint32_t phase,construct_allocations,module_value,delays,registers[0x1000/4];
static uint32_t reg_reads,reg_writes,reg_modifies;
uint32_t init_alloc(uint32_t size);
static uint32_t endpoint_register;
#define WRAP 0x5017A0u
#define OPTIONS 0x3F5EFCu
#define PUBLIC 0x503000u
static uint32_t wrapper_allocations,registrations,device_allocations;
static uint32_t completions,freed,irq_cases,done_cases;
static uint32_t irq_status,irq_mask,irq_direction_bit,irq_endpoint_status,irq_residual;
static uint32_t app_ops[9];
static uint32_t endpoint;
uint32_t device_acquire(uint32_t id,uint32_t timeout)
{
    CHECK(id==0x2200002 && timeout==0 && depth==0);++depth;++acquires;return 0;
}
uint32_t device_release(uint32_t id)
{
    CHECK(id==0x2200002 && depth==1);--depth;++releases;return 0;
}
uint32_t device_copy(uint32_t address,uint32_t source,uint32_t size)
{
    CHECK(phase==2 && address==PUBLIC+0x24 && source==0x351E23 && size==7);
    for (uint32_t i=0;i<size;++i) B(address+i)=B(source+i);
    return address;
}
uint32_t request_complete(uint32_t ep,uint32_t request)
{
    CHECK(phase==4 && depth==0 && ep==endpoint && request==REQ);
    CHECK(W(REQ+32)==0 && W(DEV+16)==1 && completions==0);
    ++completions;return 0;
}
uint32_t parent_alloc(uint32_t size)
{
    if (phase==2) {
        uint32_t address;
        if (size==0x874) address=DEV;
        else if (size==40) address=0x504000;
        else if (size==2) address=0x504040;
        else if (size==16) address=0x504080;
        else { CHECK(size==868);address=PUBLIC; }
        for (uint32_t i=0;i<size;++i) B(address+i)=0;
        ++device_allocations;return address;
    }
    if (size!=24) return init_alloc(size);
    CHECK(phase==1 && wrapper_allocations==0);++wrapper_allocations;return WRAP;
}
uint32_t parent_clear(uint32_t address,uint32_t size)
{
    CHECK((phase==1 && address==WRAP && size==24) || (phase==2 && address==PUBLIC && size==868));
    for (uint32_t i=0;i<size;++i) B(address+i)=0;
    return address;
}
uint32_t parent_register(void)
{
    CHECK(phase==1 && W(0x50B4B0)==0x243540 && W(0x50B4B4)==WRAP);
    ++registrations;phase=2;return 0;
}

uint32_t init_alloc(uint32_t size)
{
    if (phase!=1) return boundary_alloc(size);
    static const uint32_t sizes[]={160,252,76,16,260};
    static const uint32_t addresses[]={CTRL,TABLE,AUX,EVENT,PARAM};
    CHECK(construct_allocations<5 && size==sizes[construct_allocations]);
    uint32_t address=addresses[construct_allocations++];
    for (uint32_t i=0;i<size;++i) B(address+i)=0;
    return address;
}
uint32_t init_module(void) { CHECK(phase==1);return module_value; }
uint32_t init_platform(void) { CHECK(phase==2);return 0; }
uint32_t init_delay(uint32_t value)
{
    CHECK(phase==2 && (value==1 || value==10 || value==100));++delays;return 0;
}
uint32_t init_free(uint32_t address)
{
    CHECK(phase==4 && depth==1 && address==(uint32_t)(uintptr_t)heap[0]);
    CHECK(completions==1 && freed==0 && W(DEV+16)==0);++freed;return 0;
}
static uint32_t index_of(uint32_t address)
{
    CHECK(address>=BASE && address<BASE+0x1000 && !(address&3));
    return (address-BASE)/4;
}
uint32_t init_read(uint32_t address)
{
    ++reg_reads;
    if (phase==4) {
        if (address==BASE+0x14) return irq_status;
        CHECK(depth==1);
        if (address==BASE+0x18) return irq_mask;
        if (address==BASE+0x818 || address==BASE+0x81C || address==BASE+0x838 || address==BASE+0x83C) return irq_direction_bit;
        if (address==BASE+0x810 || address==BASE+0x814 || address==BASE+0x844 || address==BASE+0x884) return 1;
        if (address==endpoint_register+8) return irq_endpoint_status;
        if (address==endpoint_register+0x10) return irq_residual;
    }
    CHECK(phase<3 ? depth==0:depth==1);
    uint32_t index=index_of(address);
    /* The reset-complete and mode responses are injected, without real polling time. */
    if (phase==2 && address==BASE+0x10) return 0x80000000;
    if (phase==2 && address==BASE+0x14) return 0;
    return registers[index];
}
uint32_t init_write(uint32_t address,uint32_t value)
{
    CHECK(phase<3 ? depth==0:depth==1);++reg_writes;
    registers[index_of(address)]=value;return 0;
}
uint32_t init_modify(uint32_t address,uint32_t mask,uint32_t value)
{
    CHECK(phase<3 ? depth==0:depth==1);++reg_modifies;
    uint32_t index=index_of(address);
    registers[index]=(registers[index]&~mask)|value;return 0;
}
int main(void)
{
    cases=0;
    for (uint32_t mode=0;mode<3;++mode)
    for (uint32_t profile=0;profile<2;++profile)
    for (uint32_t dir=0;dir<2;++dir)
    for (uint32_t p=0;p<2;++p)
    for (uint32_t kind=0;kind<5;++kind) {
        reset(dir,1,p ? 512:64,0,2);
        for (uint32_t i=0;i<0x1000/4;++i) registers[i]=0;
        for (uint32_t i=0;i<65;++i) W(OPTIONS+4*i)=0xFFFFFFFF;
        if (profile) W(OPTIONS+244)=1;
        registers[0x48/4]=(3u<<10)|(mode<<3)|(1u<<20);
        registers[0x50/4]=(1u<<25)|(3u<<26)|3u;
        registers[0x40/4]=0x4F542000;
        registers[0x2C/4]=0x10000;
        phase=1;construct_allocations=reg_reads=reg_writes=reg_modifies=delays=0;
        wrapper_allocations=registrations=device_allocations=completions=freed=0;
        module_value=0;
        CHECK(((uint32_t (*)(uint32_t))(uintptr_t)0x243838)(TOP)==0);
        CHECK(wrapper_allocations==1 && construct_allocations==5 && registrations==1 && device_allocations==5);
        CHECK(W(WRAP+12)==DEV && W(DEV+4)==CTRL && W(0x36B588)==PUBLIC && W(PUBLIC)==DEV);
        CHECK(W(DEV+0x860)==0x36ACBC && W(0x36ACBC)==0x2200002);
        CHECK(W(0x50B4B8)==0x278BC4 && W(0x50B4BC)==DEV);
        CHECK(W(DEV)==0x51A3A4 && W(0x51A3B0)==0x278AA4);
        CHECK(B(CTRL+98)==(mode!=0) && B(CTRL+99)==0 && B(CTRL+101)==profile);
        endpoint=PUBLIC+(dir ? 0x64u:0x1E4u);
        node=DEV+(dir ? 0x68u:0x464u);
        CHECK(W(node+4)==node+4 && W(node+8)==node+4 && (W(node+12)&1)==1);
        phase=3;
        CHECK(CALL2(0x27864C,endpoint,USB)==(uint32_t)-58);
        CHECK(W(PUBLIC+0x48)==0 && W(PUBLIC+0x14)==0);
        CHECK(CALL2(0x278B00,DEV,1)==0 && W(PUBLIC+0x14)==1);
        CHECK(CALL2(0x27864C,endpoint,USB)==(uint32_t)-58);
        W(PUBLIC+0x48)=(uint32_t)(uintptr_t)app_ops;
        CHECK(CALL2(0x27864C,endpoint,USB)==0);
        CHECK(W(node)==USB && W(node+64)==endpoint && H(endpoint+20)==packet);
        endpoint_register=BASE+(dir ? 0x920u:0xB20u);
        CHECK(allocations==0 && depth==0);
        W(REQ+4)=32;W(REQ+16)=(uint32_t)(uintptr_t)request_complete;
        CHECK(CALL3(0x278854,endpoint,REQ,32)==0);
        CHECK(allocations==1 && W(REQ+32)==(uint32_t)-10 && W(DEV+16)==1);
        CHECK(registers[(endpoint_register+0x10-BASE)/4]==((1u<<19)|(dir ? 32:packet)));
        if (mode) {
            uint32_t actual=kind==3 ? 17:kind==4 ? 0:32;
            irq_mask=kind==0 ? 0:dir ? (1u<<18):(1u<<19);
            irq_status=dir ? (1u<<18):(1u<<19);
            irq_direction_bit=kind==0 ? 0:dir ? 2u:0x20000u;
            irq_endpoint_status=kind==1 ? 0:1;
            irq_residual=dir ? (kind==3 ? 1:kind==4 ? 1u<<19:0):packet-actual;
            phase=4;
            uint32_t previous_acquires=acquires;
            irq_status|=1;
            CALL2(W(0x50B4B8),0,W(0x50B4BC));
            CHECK(depth==0 && acquires==previous_acquires && completions==0 && freed==0);
            CHECK(W(REQ+32)==(uint32_t)-10 && W(DEV+16)==1);
            irq_status&=~1u;
            CALL2(W(0x50B4B8),0,W(0x50B4BC));
            uint32_t done=kind>=2 && (!dir || kind==2);
            CHECK(depth==0 && completions==done && freed==done && W(DEV+16)==!done);
            CHECK(W(REQ+32)==(done ? 0:(uint32_t)-10) && W(REQ+36)==(done ? actual:0));
            CHECK(W(node+4)==(done ? node+4:(uint32_t)(uintptr_t)heap[0]));
            done_cases+=done;++irq_cases;
        }
        for (uint32_t i=0;i<256;++i) CHECK(W(BUF+4*i)==0x12340000+i);
        ++cases;
    }
    CHECK(cases==120 && irq_cases==80 && done_cases==32);return 0;
}
