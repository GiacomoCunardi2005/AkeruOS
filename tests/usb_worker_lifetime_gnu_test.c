/* Reuse the open/submit/controller fixtures; add original worker and completion bridge. */
#define main open_buffer_reference_tests
#define boundary_modify reference_modify
#include "usb_open_buffer_gnu_test.c"
#undef main
#undef boundary_modify
#define G 0x3680A0u
#define R 0x423C00u
#define TX 0x47DA24u
#define RX 0x47DA4Cu
#define CONTEXT 0x501700u
#define VT 0x501780u
#define DVT 0x5017C0u
#define CALL0(a) (((uint32_t (*)(void))(uintptr_t)(a))())
static uint32_t freed,events,event_bits,free_count,free_head,free_status,free_active;

uint32_t lifetime_modify(uint32_t address,uint32_t mask,uint32_t value)
{
    if (address==BASE+0x10) {
        CHECK(depth==1 && direction && mask==0 && value==(0x22334455u|16u));
        ++modifies;return 0;
    }
    return reference_modify(address,mask,value);
}

uint32_t lifetime_free(uint32_t address)
{
    CHECK(depth==1 && address==(uint32_t)(uintptr_t)heap[0] && freed==0);
    CHECK((W(node+12)&1)==0 && W(address+24)==0 && W(address+28)==0);
    uint32_t offset=direction ? 0:20,req=direction ? TX:RX;
    free_count=W(R+offset+8);free_active=B(R+offset+16);
    free_head=W(node+4);free_status=W(req+32);++freed;return 0;
}
uint32_t lifetime_event(uint32_t group,uint32_t bits)
{
    CHECK(group==0x2200001 && depth==0);++events;event_bits|=bits;return 0;
}
int main(void)
{
    cases=0;
    for (uint32_t dir=0;dir<2;++dir)
    for (uint32_t p=0;p<2;++p)
    for (uint32_t dma=0;dma<2;++dma)
    for (uint32_t kind=0;kind<7;++kind) {
        if (dir && kind==6) continue;
        reset(dir,1,p ? 512:64,0,2);opened(0,2);B(CTRL+98)=dma;
        for (uint32_t i=0;i<0x100;++i) B(G+i)=0;
        for (uint32_t i=0;i<64;++i) B(R+i)=0;
        for (uint32_t i=0;i<0xB0;++i) B(0x47D9C8+i)=0;
        freed=events=event_bits=free_count=free_head=free_status=free_active=0;
        W(G+0x74)=CONTEXT;W(G+0x4C)=packet;
        W(0x351E2C)=0x22334455;
        W(CONTEXT+16)=W(CONTEXT+20)=EP;
        W(EP+8)=VT;W(VT+16)=0x278854;W(VT+20)=0x278930;
        W(DEV)=DVT;W(DVT+12)=0x278AA4;
        uint32_t offset=dir ? 0:20,req=dir ? TX:RX;
        uint32_t total=(kind==1 || kind==2 || kind==3) ? packet+32:32;
        if (kind==6) total=packet;
        uint32_t requested=total>packet ? packet:total;
        W(R+offset)=BUF;W(R+offset+4)=total;B(R+offset+16)=1;
        B(R+37)=kind==6;
        CHECK(CALL0(dir ? 0x190EA4:0x190DAC)==0);
        CHECK(allocations==1 && W(req)==BUF && W(req+8)==BUF && W(req+4)==requested);
        CHECK(W(req+16)==(dir ? 0x190F10u:0x190E1Cu));
        CHECK(W(req+32)==(uint32_t)-10 && W(req+36)==0 && W(DEV+16)==1);
        CHECK(W(node+4)==(uint32_t)(uintptr_t)heap[0] && configured==1);
        uint32_t first_writes=writes,first_reads=reads,first_modifies=modifies;
        uint32_t actual=kind==1 || kind==4 ? 17:kind==2 ? 0:kind==5 ? 33:requested;
        W((uint32_t)(uintptr_t)heap[0]+16)=actual;
        if (kind==4) CHECK(CALL2(0x278930,EP,req)==0);
        else {
            boundary_acquire(0x2200005,0);
            CALL3(0x2794D0,node,(uint32_t)(uintptr_t)heap[0],0);
            boundary_release(0x2200005);
        }
        uint32_t requeued=kind==3 || kind==5 || kind==6;
        uint32_t done=kind<3,count=kind==4 ? 0:actual;
        CHECK(freed==1 && allocations==1+requeued && depth==0);
        CHECK(W(R+offset+8)==count && B(R+offset+18)==done && B(R+offset+16)==1);
        CHECK(free_count==count && free_active==1 && W(DEV+16)==requeued);
        CHECK(reads==first_reads && writes==first_writes);
        CHECK(modifies==first_modifies+(requeued && dir && !dma));
        if (requeued) {
            uint32_t second=(uint32_t)(uintptr_t)heap[1];
            uint32_t next=kind==6 ? BUF:BUF+actual;
            uint32_t n=kind==6 ? 1:kind==5 ? packet:32;
            CHECK(W(node+4)==second && W(node+8)==second && free_head==second);
            CHECK(W(second)==req && W(second+4)==next && W(second+8)==next && W(second+12)==n);
            CHECK(W(req+32)==(uint32_t)-10 && W(req+36)==0 && free_status==(uint32_t)-10);
            CHECK(W(req)==next && W(req+8)==next && W(req+4)==n);
            if (kind==6) CHECK(B(R+37)==0);
        } else {
            CHECK(W(node+4)==node+4 && W(node+8)==node+4 && free_head==node+4);
            uint32_t status=kind==4 ? (uint32_t)-54:0;
            CHECK(W(req+32)==status && W(req+36)==actual && free_status==status);
        }
        CHECK(events==0);
        CALL0(0x190D54);
        CHECK(events==done && event_bits==(done ? (dir ? 0x1000u:0x2000u):0u));
        CHECK(B(R+offset+18)==0 && B(R+offset+16)==1);
        for (uint32_t i=0;i<256;++i) CHECK(W(BUF+4*i)==0x12340000+i);
        ++cases;
    }
    CHECK(cases==52);return 0;
}
