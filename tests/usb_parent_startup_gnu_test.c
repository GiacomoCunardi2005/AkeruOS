/* Original parent startup, override mapper and controller chain; resources/MMIO are fixtures. */
#define main open_buffer_reference_tests
#include "usb_open_buffer_gnu_test.c"
#undef main
#define AUX 0x501500u
#define PARAM 0x501600u
#define EVENT 0x501740u
static uint32_t phase,construct_allocations,module_value,delays,registers[0x1000/4];
static uint32_t reg_reads,reg_writes,reg_modifies,submissions,sg_cases,retained;
uint32_t init_alloc(uint32_t size);
static uint32_t endpoint_register;
#define WRAP 0x5017A0u
#define OPTIONS 0x3F5EFCu
static uint32_t wrapper_allocations,registrations,device_initializations;
uint32_t parent_alloc(uint32_t size)
{
    if (size!=24) return init_alloc(size);
    CHECK(phase==1 && wrapper_allocations==0);++wrapper_allocations;return WRAP;
}
uint32_t parent_clear(uint32_t address,uint32_t size)
{
    CHECK(phase==1 && address==WRAP && size==24);
    for (uint32_t i=0;i<size;++i) B(address+i)=0;
    return address;
}
uint32_t parent_register(void)
{
    CHECK(phase==1 && W(0x50B4B0)==0x243540 && W(0x50B4B4)==WRAP);
    ++registrations;phase=2;return 0;
}
uint32_t parent_device(uint32_t context)
{
    CHECK(phase==2 && context==TOP && W(TOP+32)==WRAP && W(WRAP+4)==CTRL);
    ++device_initializations;return 0;
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
uint32_t init_free(uint32_t address) { (void)address;CHECK(0);return 0; }
static uint32_t index_of(uint32_t address)
{
    CHECK(address>=BASE && address<BASE+0x1000 && !(address&3));
    return (address-BASE)/4;
}
uint32_t init_read(uint32_t address)
{
    CHECK(phase<3 ? depth==0:depth==1);++reg_reads;
    uint32_t index=index_of(address);
    /* The reset-complete and mode responses are injected, without real polling time. */
    if (phase==2 && address==BASE+0x10) return 0x80000000;
    if (phase==2 && address==BASE+0x14) return 1;
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
    for (uint32_t profile=0;profile<2;++profile)
    for (uint32_t mode=0;mode<3;++mode)
    for (uint32_t sg=0;sg<2;++sg)
    for (uint32_t feature=0;feature<2;++feature)
    for (uint32_t module=0;module<1;++module)
    for (uint32_t dir=0;dir<2;++dir)
    for (uint32_t p=0;p<2;++p)
    for (uint32_t ready=0;ready<2;++ready) {
        reset(dir,1,p ? 512:64,0,2);
        W(DEV+0x860)=0x501780;W(0x501780)=0x2200005;
        for (uint32_t i=0;i<0x1000/4;++i) registers[i]=0;
        for (uint32_t i=0;i<0x58/4;++i) CHECK(W(0x3533A0+4*i)==0);
        registers[0x48/4]=(3u<<10)|(mode<<3)|(1u<<20);
        registers[0x50/4]=(sg<<30)|(feature<<25)|(3u<<26)|3u;
        registers[0x40/4]=0x4F542000;
        registers[0x2C/4]=ready<<16;
        for (uint32_t i=0;i<65;++i) W(OPTIONS+4*i)=0xFFFFFFFF;
        if (profile) { W(OPTIONS+8)=0;W(OPTIONS+12)=0;W(OPTIONS+244)=1; }
        phase=1;construct_allocations=reg_reads=reg_writes=reg_modifies=delays=0;
        wrapper_allocations=registrations=device_initializations=0;
        module_value=module;
        CHECK(((uint32_t (*)(uint32_t))(uintptr_t)0x243838)(TOP)==0);
        CHECK(wrapper_allocations==1 && registrations==1 && device_initializations==1);
        CHECK(W(TOP+32)==WRAP && W(WRAP)==BASE && W(WRAP+4)==CTRL && B(WRAP+20)==1);
        CHECK(construct_allocations==5 && reg_writes>0 && reg_modifies>0);
        CHECK(W(CTRL)==PARAM && W(CTRL+4)==BASE && W(CTRL+8)==TABLE && W(CTRL+12)==AUX);
        CHECK(W(TABLE)==BASE+0x800 && W(AUX)==BASE+0x400 && W(AUX+4)==BASE+0x440);
        for (uint32_t i=0;i<16;++i) {
            CHECK(W(TABLE+4+4*i)==BASE+0x900+32*i);
            CHECK(W(TABLE+0x44+4*i)==BASE+0xB00+32*i);
            CHECK(W(AUX+8+4*i)==BASE+0x500+32*i);
            CHECK(W(CTRL+0x1C+4*i)==BASE+0x1000+0x1000*i);
        }
        CHECK(W(CTRL+0x18)==BASE+0xE00 && W(CTRL+0x98)==EVENT);
        CHECK(W(PARAM+8)==(mode!=0 && !profile) && W(PARAM+12)==(mode!=0 && sg && !profile));
        CHECK(W(PARAM+244)==0 && W(PARAM+248)==profile);
        CHECK(W(PARAM+0x88)==1 && W(PARAM+20)==module);
        CHECK(B(TABLE+133)==3 && B(TABLE+134)==3);
        CHECK(B(CTRL+98)==(mode!=0 && !profile) && B(CTRL+99)==(mode!=0 && sg && !profile));
        CHECK(B(CTRL+100)==0 && B(CTRL+101)==profile && B(CTRL+102)==feature);
        CHECK(B(CTRL+128)==1 && delays>0);
        for (uint32_t i=0;i<0x58/4;++i) CHECK(W(0x3533A0+4*i)==0);
        phase=3;
        CHECK(CALL2(0x27864C,EP,USB)==0 && depth==0 && configured==0);
        CHECK(W(node)==USB && W(node+64)==EP && H(EP+20)==packet);
        uint32_t scatter=mode!=0 && sg && !profile;
        CHECK(allocations==scatter && allocated_bytes==512*scatter);
        endpoint_register=BASE+(dir ? 0x920u:0xB20u);
        CHECK((registers[(endpoint_register-BASE)/4]&0x10008000)==0x10008000);
        if (!scatter) {
            W(REQ+4)=32;
            uint32_t previous_writes=reg_writes;
            uint32_t previous_control=registers[(endpoint_register-BASE)/4];
            CHECK(CALL3(0x278854,EP,REQ,32)==0);
            CHECK(allocations==1 && W(REQ+32)==(uint32_t)-10 && W(DEV+16)==1);
            CHECK(W(node+4)==(uint32_t)(uintptr_t)heap[0] && depth==0);
            if (dir && !feature && !ready) {
                CHECK(reg_writes==previous_writes);
                CHECK(registers[(endpoint_register-BASE)/4]==previous_control);
                CHECK(registers[(endpoint_register+0x10-BASE)/4]==0);
                ++retained;
            } else {
                CHECK(registers[(endpoint_register+0x10-BASE)/4]==((1u<<19)|(dir ? 32:packet)));
                if (mode && !profile) CHECK(registers[(endpoint_register+0x14-BASE)/4]==BUF);
            }
            ++submissions;
        } else ++sg_cases;
        for (uint32_t i=0;i<256;++i) CHECK(W(BUF+4*i)==0x12340000+i);
        ++cases;
    }
    CHECK(cases==192 && submissions==160 && sg_cases==32 && retained==20);return 0;
}
