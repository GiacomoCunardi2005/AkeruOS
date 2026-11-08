/* Original class init/stop; allocation failures and pending shutdown are laboratory cases. */
#include "application_lifecycle_fixture.h"
#define CLASS_TABLE 0x47DA9Cu
#define CLASS_GLOBAL 0x368114u
static uint32_t lifecycle,class_io,fail_class_size,class_owned,request_owned;
static uint32_t class_storage[8],request_storage[10];
static uint32_t class_allocs,request_allocs,class_frees,request_frees,pending_frees,optional_calls,lifecycle_cases;
#define CLASS_ADDRESS ((uint32_t)(uintptr_t)class_storage)
#define REQUEST_ADDRESS ((uint32_t)(uintptr_t)request_storage)

uint32_t class_alloc(uint32_t size)
{
    if (!lifecycle || phase<3 || class_io) return transport_alloc(size);
    CHECK(phase==3 && depth==0 && (size==32 || size==40));
    uint32_t address;
    if (size==32) { ++class_allocs;CHECK(class_owned==0);address=CLASS_ADDRESS; }
    else { ++request_allocs;CHECK(class_owned==1 && request_owned==0);address=REQUEST_ADDRESS; }
    if (size==fail_class_size) return 0;
    for (uint32_t i=0;i<size/4;++i) W(address+4*i)=0xA5A5A5A5;
    if (size==32) class_owned=1;else request_owned=1;
    return address;
}
uint32_t class_clear(uint32_t address,uint32_t size)
{
    if (!lifecycle || phase<3) return parent_clear(address,size);
    CHECK(phase==3 && depth==0);
    CHECK((address==CLASS_ADDRESS && size==32 && class_owned) ||
          (address==REQUEST_ADDRESS && size==40 && request_owned));
    for (uint32_t i=0;i<size;++i) B(address+i)=0;
    return address;
}
uint32_t class_free(uint32_t address)
{
    if (!lifecycle || phase==4) return transport_free(address);
    CHECK(phase==3 && depth==0);
    if (address==REQUEST_ADDRESS) {
        CHECK(request_owned==1 && class_owned==1 && W(CLASS_ADDRESS+8)==address);
        CHECK(W(address+16)==0x1910C0);
        if (W(DEV+16)) {
            CHECK(W(DEV+16)==1 && W(address+32)==(uint32_t)-10);
            CHECK(node_owned==1 && W((uint32_t)(uintptr_t)heap[0])==address);++pending_frees;
        }
        request_owned=0;++request_frees;
    } else {
        CHECK(address==CLASS_ADDRESS && class_owned==1 && request_owned==0);
        CHECK(W(CLASS_GLOBAL)==address && W(PUBLIC+0x40)==address);
        class_owned=0;++class_frees;
    }
    return 0;
}
static uint32_t optional_notify(uint32_t interface,uint32_t value)
{
    CHECK(phase==3 && depth==0 && interface==PUBLIC+4 && value==1);
    CHECK(class_owned && request_owned && W(CLASS_ADDRESS+8)==REQUEST_ADDRESS);
    CHECK(W(REQUEST_ADDRESS+16)==0x1910C0 && W(PUBLIC+0x40)==CLASS_ADDRESS);
    ++optional_calls;return (uint32_t)-23;
}
int main(void)
{
    CHECK(application_reference_tests()==0);lifecycle=1;
    for (uint32_t p=0;p<2;++p)
    for (uint32_t kind=0;kind<5;++kind) {
        reset(0,1,p ? 512:64,0,2);W(0x353404)=0x11223344;
        class_io=class_owned=request_owned=node_owned=0;
        fail_class_size=kind==0 ? 32:kind==1 ? 40:0;
        W(CLASS_GLOBAL)=0;
        for (uint32_t i=0;i<0x1000/4;++i) registers[i]=0;
        for (uint32_t i=0;i<65;++i) W(OPTIONS+4*i)=0xFFFFFFFF;
        registers[0x48/4]=(3u<<10)|(1u<<3)|(1u<<20);
        registers[0x50/4]=(1u<<25)|(3u<<26)|3u;
        registers[0x40/4]=0x4F542000;registers[0x2C/4]=0x10000;
        phase=1;construct_allocations=reg_reads=reg_writes=reg_modifies=delays=0;
        wrapper_allocations=registrations=device_allocations=completions=freed=0;module_value=0;
        CHECK(((uint32_t (*)(uint32_t))(uintptr_t)0x243838)(TOP)==0);
        /* This optional interface slot is not written by the constructor under test. */
        W(0x51A390)=kind==3 ? (uint32_t)(uintptr_t)optional_notify:0;
        CHECK(W(PUBLIC+4)==0x51A388 && W(PUBLIC+8)==PUBLIC+0x4C);
        phase=3;
        uint32_t result=((uint32_t (*)(void))(uintptr_t)0x190408)();
        CHECK(result==(uint32_t)(kind<2 ? -16:0));
        CHECK(W(CLASS_TABLE+4)==3 && W(CLASS_TABLE+8)==0x191A04 && W(CLASS_TABLE+12)==0x1919D4);
        if (kind<2) {
            CHECK(class_owned==0 && request_owned==0 && W(CLASS_GLOBAL)==0);
            CHECK(W(PUBLIC+0x40)==0 && W(PUBLIC+0x48)==0 && W(PUBLIC+0x38)==0);
        } else {
            CHECK(class_owned && request_owned && W(CLASS_GLOBAL)==CLASS_ADDRESS);
            CHECK(W(PUBLIC+0x48)==CLASS_TABLE && W(PUBLIC+0x38)==CLASS_TABLE+32);
            CHECK(W(PUBLIC+0x40)==CLASS_ADDRESS && W(PUBLIC+0x4C)==CLASS_ADDRESS);
            CHECK(W(CLASS_ADDRESS+4)==PUBLIC+4 && W(CLASS_ADDRESS+8)==REQUEST_ADDRESS);
            CHECK(W(REQUEST_ADDRESS+16)==0x1910C0);
            for (uint32_t i=0;i<10;++i) if (i!=4) CHECK(request_storage[i]==0);
            if (kind==4) {
                notify_status(p ? 0:1);
                CHECK(CALL2(0x27864C,PUBLIC+0x1E4,USB)==0);
                W(REQUEST_ADDRESS)=W(REQUEST_ADDRESS+8)=BUF;W(REQUEST_ADDRESS+4)=32;W(REQUEST_ADDRESS+12)=2;
                class_io=1;
                CHECK(CALL3(0x278854,PUBLIC+0x1E4,REQUEST_ADDRESS,32)==0);
                CHECK(node_owned==1 && W(DEV+16)==1 && W(REQUEST_ADDRESS+32)==(uint32_t)-10);
            }
            CHECK(APP_CALL(0x278610,CLASS_TABLE)==0);
            CHECK(class_owned==0 && request_owned==0 && W(CLASS_GLOBAL)==0 && W(PUBLIC+0x40)==0);
            CHECK(W(PUBLIC+0x48)==0 && W(PUBLIC+0x38)==CLASS_TABLE+32);
            CHECK(W(PUBLIC+0x4C)==CLASS_ADDRESS);
            if (kind==4) {
                CHECK(W(DEV+16)==1 && node_owned==1 && W(DEV+0x468)==(uint32_t)(uintptr_t)heap[0]);
                CHECK(W((uint32_t)(uintptr_t)heap[0])==REQUEST_ADDRESS);
                CHECK(W(REQUEST_ADDRESS+32)==(uint32_t)-10 && completions==0 && freed==0);
                /* Stop this isolated case before any IRQ can dereference the freed request. */
            }
        }
        ++lifecycle_cases;
    }
    CHECK(lifecycle_cases==10 && class_allocs==10 && request_allocs==8);
    CHECK(class_frees==8 && request_frees==6 && pending_frees==2 && optional_calls==2);
    return 0;
}
