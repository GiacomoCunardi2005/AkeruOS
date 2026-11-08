/* Original directional USB dispatchers; status/mask/residual and MMIO effects are fixtures. */
#define main open_buffer_reference_tests
#define boundary_read reference_read
#define boundary_write reference_write
#define boundary_modify reference_modify
#include "usb_open_buffer_gnu_test.c"
#undef main
#undef boundary_read
#undef boundary_write
#undef boundary_modify
#define G 0x3680A0u
#define R 0x423C00u
#define TX 0x47DA24u
#define RX 0x47DA4Cu
#define CONTEXT 0x501700u
#define VT 0x501780u
#define DVT 0x5017C0u
#define CALL0(a) (((uint32_t (*)(void))(uintptr_t)(a))())
static uint32_t irq_phase,global_mask,global_status,endpoint_mask,endpoint_status,residual;
static uint32_t freed,events,event_bits,acknowledgements,global_clears;

uint32_t irq_read(uint32_t address)
{
    if (irq_phase) {
        CHECK(depth==1);
        if (address==BASE+0x18) { ++reads;return global_mask; }
        if (address==BASE+0x1C) { ++reads;return global_status; }
        if (address==BASE+0x34) { ++reads;return 0; }
        if (address==BASE+0x10 || address==BASE+0x14) { ++reads;return endpoint_mask; }
        if (address==EPREG+8) { ++reads;return endpoint_status; }
        if (address==EPREG+0x10) { ++reads;return residual; }
    }
    return reference_read(address);
}
uint32_t irq_write(uint32_t address,uint32_t value)
{
    if (irq_phase && address==EPREG+8) {
        CHECK(depth==1 && value==1);++acknowledgements;return 0;
    }
    return reference_write(address,value);
}
uint32_t irq_modify(uint32_t address,uint32_t mask,uint32_t value)
{
    if (irq_phase && address==BASE+0x34) {
        CHECK(depth==1 && direction && mask==2 && value==0);++global_clears;return 0;
    }
    return reference_modify(address,mask,value);
}
uint32_t irq_free(uint32_t address)
{
    CHECK(depth==1 && address==(uint32_t)(uintptr_t)heap[0] && freed==0);
    CHECK(W(address+24)==0 && W(address+28)==0 && (W(node+12)&1)==0);
    ++freed;return 0;
}
uint32_t irq_event(uint32_t group,uint32_t bits)
{
    CHECK(group==0x2200001 && depth==0);++events;event_bits|=bits;return 0;
}
int main(void)
{
    cases=0;
    for (uint32_t dir=0;dir<2;++dir)
    for (uint32_t p=0;p<2;++p)
    for (uint32_t kind=0;kind<7;++kind) {
        irq_phase=0;
        reset(dir,1,p ? 512:64,0,2);opened(0,2);B(CTRL+98)=1;
        for (uint32_t i=0;i<0x100;++i) B(G+i)=0;
        for (uint32_t i=0;i<64;++i) B(R+i)=0;
        for (uint32_t i=0;i<0xB0;++i) B(0x47D9C8+i)=0;
        for (uint32_t i=0;i<0x200;++i) B(0x351E00+i)=0;
        freed=events=event_bits=acknowledgements=global_clears=0;
        B(TABLE+133)=B(TABLE+134)=1;
        W(G+0x74)=CONTEXT;W(G+0x4C)=packet;
        W(CONTEXT+16)=W(CONTEXT+20)=EP;
        W(EP+8)=VT;W(VT+16)=0x278854;W(VT+20)=0x278930;
        W(DEV)=DVT;W(DVT+12)=0x278AA4;
        uint32_t offset=dir ? 0:20,req=dir ? TX:RX;
        W(R+offset)=BUF;W(R+offset+4)=32;B(R+offset+16)=1;
        CHECK(CALL0(dir ? 0x190EA4:0x190DAC)==0);
        CHECK(allocations==1 && W(req+4)==32 && W(req+32)==(uint32_t)-10);
        uint32_t first_writes=writes,bit=dir ? 2u:0x20000u;
        global_mask=kind==0 ? 0:bit;global_status=kind==1 ? 0:bit;
        endpoint_mask=kind==2 ? 0:1;endpoint_status=kind==3 ? 0:1;
        uint32_t actual=kind==5 ? 17:kind==6 ? 0:32;
        residual=dir ? (kind==5 ? 1:kind==6 ? 1u<<19:0):packet-actual;
        irq_phase=1;boundary_acquire(0x2200005,0);
        CHECK(((uint32_t (*)(uint32_t))(uintptr_t)(dir ? 0x27D1AC:0x27D6D4))(DEV)==1);
        boundary_release(0x2200005);irq_phase=0;
        uint32_t admitted=kind>=4,done=admitted && (!dir || kind==4);
        CHECK(acknowledgements==admitted && global_clears==(admitted && dir));
        CHECK(writes==first_writes && allocations==1 && depth==0);
        CHECK(freed==done && W(DEV+16)==!done);
        CHECK(W(R+offset+8)==(done ? actual:0) && B(R+offset+18)==done);
        CHECK(W(req+32)==(done ? 0:(uint32_t)-10) && W(req+36)==(done ? actual:0));
        CHECK(W(node+4)==(done ? node+4:(uint32_t)(uintptr_t)heap[0]));
        CHECK(events==0 && B(R+offset+16)==1);
        CALL0(0x190D54);
        CHECK(events==done && event_bits==(done ? (dir ? 0x1000u:0x2000u):0));
        CHECK(B(R+offset+18)==0 && B(R+offset+16)==1);
        for (uint32_t i=0;i<256;++i) CHECK(W(BUF+4*i)==0x12340000+i);
        ++cases;
    }
    CHECK(cases==28);return 0;
}
