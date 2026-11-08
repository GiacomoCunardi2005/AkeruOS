/* Original residual handler and queue restart; register values remain explicit fixtures. */
#define main open_buffer_reference_tests
#define boundary_read reference_read
#include "usb_open_buffer_gnu_test.c"
#undef main
#undef boundary_read
#define G 0x3680A0u
#define R 0x423C00u
#define TX 0x47DA24u
#define RX 0x47DA4Cu
#define CONTEXT 0x501700u
#define VT 0x501780u
#define DVT 0x5017C0u
#define CALL0(a) (((uint32_t (*)(void))(uintptr_t)(a))())
static uint32_t freed,events,event_bits,completion_phase,residual;

uint32_t consumer_read(uint32_t address)
{
    if (completion_phase && address==EPREG+0x10) {
        CHECK(depth==1);++reads;return residual;
    }
    return reference_read(address);
}
uint32_t consumer_free(uint32_t address)
{
    CHECK(depth==1 && freed<2 && address==(uint32_t)(uintptr_t)heap[freed]);
    CHECK(W(address+24)==0 && W(address+28)==0 && (W(node+12)&1)==0);
    CHECK(B(R+(direction ? 16:36))==1);++freed;return 0;
}
uint32_t consumer_event(uint32_t group,uint32_t bits)
{
    CHECK(group==0x2200001 && depth==0);++events;event_bits|=bits;return 0;
}
static void complete(uint32_t word)
{
    completion_phase=1;residual=word;
    boundary_acquire(0x2200005,0);
    ((void (*)(uint32_t))(uintptr_t)0x27CDA8)(node);
    boundary_release(0x2200005);
    completion_phase=0;
}
int main(void)
{
    cases=0;
    for (uint32_t dir=0;dir<2;++dir)
    for (uint32_t p=0;p<2;++p)
    for (uint32_t kind=0;kind<4;++kind) {
        reset(dir,1,p ? 512:64,0,2);opened(0,2);B(CTRL+98)=1;
        for (uint32_t i=0;i<0x100;++i) B(G+i)=0;
        for (uint32_t i=0;i<64;++i) B(R+i)=0;
        for (uint32_t i=0;i<0xB0;++i) B(0x47D9C8+i)=0;
        freed=events=event_bits=completion_phase=residual=0;
        W(G+0x74)=CONTEXT;W(G+0x4C)=packet;
        W(CONTEXT+16)=W(CONTEXT+20)=EP;
        W(EP+8)=VT;W(VT+16)=0x278854;W(VT+20)=0x278930;
        W(DEV)=DVT;W(DVT+12)=0x278AA4;
        uint32_t offset=dir ? 0:20,req=dir ? TX:RX;
        uint32_t total=kind==3 ? packet+32:32;
        W(R+offset)=BUF;W(R+offset+4)=total;B(R+offset+16)=1;
        CHECK(CALL0(dir ? 0x190EA4:0x190DAC)==0);
        CHECK(allocations==1 && W(req+4)==(kind==3 ? packet:32));
        CHECK(W(req+32)==(uint32_t)-10 && W(req+36)==0);
        uint32_t actual=kind==3 ? packet:kind==1 ? 17:kind==2 ? 0:32;
        uint32_t word=dir ? (kind==1 ? 1:kind==2 ? 1u<<19:0):packet-actual;
        complete(word);
        uint32_t retained=dir && (kind==1 || kind==2);
        if (retained) {
            CHECK(freed==0 && allocations==1 && W(DEV+16)==1);
            CHECK(W(R+offset+8)==0 && B(R+offset+18)==0);
            CHECK(W(req+32)==(uint32_t)-10 && W(req+36)==0);
            CHECK(W(node+4)==(uint32_t)(uintptr_t)heap[0]);
        } else if (kind==3) {
            uint32_t second=(uint32_t)(uintptr_t)heap[1];
            CHECK(freed==1 && allocations==2 && W(DEV+16)==1);
            CHECK(W(R+offset+8)==packet && B(R+offset+18)==0);
            CHECK(W(node+4)==second && W(node+8)==second && W(second+12)==32);
            CHECK(W(req)==BUF+packet && W(req+8)==BUF+packet && W(req+4)==32);
            CHECK(W(node+24)==BUF+packet && W(node+36)==BUF+packet && W(node+40)==BUF+packet);
            CHECK((W(node+44)&0x7FFFF)==(dir ? 32:packet));
            CHECK((W(node+48)&0x7FFFF)==0 && (W(node+52)&0x7FFFF)==32);
            CHECK(writes==(dir ? 8u:6u));
            complete(dir ? 0:packet-32);
            CHECK(freed==2 && W(DEV+16)==0 && W(R+offset+8)==total);
            CHECK(W(req+32)==0 && W(req+36)==32 && B(R+offset+18)==1);
            CHECK(W(node+4)==node+4 && W(node+8)==node+4);
        } else {
            CHECK(freed==1 && allocations==1 && W(DEV+16)==0);
            CHECK(W(req+32)==0 && W(req+36)==actual);
            CHECK(W(R+offset+8)==actual && B(R+offset+18)==1);
            CHECK(W(node+4)==node+4 && W(node+8)==node+4);
        }
        CHECK(depth==0 && events==0 && B(R+offset+16)==1);
        CALL0(0x190D54);
        CHECK(events==!retained && event_bits==(retained ? 0:dir ? 0x1000u:0x2000u));
        CHECK(B(R+offset+18)==0 && B(R+offset+16)==1);
        for (uint32_t i=0;i<256;++i) CHECK(W(BUF+4*i)==0x12340000+i);
        ++cases;
    }
    CHECK(cases==16);return 0;
}
