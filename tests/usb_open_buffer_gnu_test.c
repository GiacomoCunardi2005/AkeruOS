/* Original open/submit/controller chain; allocation, locks and register I/O are fixtures. */
#include <stdint.h>
#define W(a) (*(volatile uint32_t *)(uintptr_t)(a))
#define H(a) (*(volatile uint16_t *)(uintptr_t)(a))
#define B(a) (*(volatile uint8_t *)(uintptr_t)(a))
#define TOP 0x500000u
#define DEV 0x500100u
#define CTRL 0x501000u
#define TABLE 0x501100u
#define EP 0x501200u
#define USB 0x501300u
#define REQ 0x501400u
#define BUF 0x502000u
#define BASE 0x0FE50000u
#define EPREG (BASE+0x120u)
#define CALL2(a,x,y) (((uint32_t (*)(uint32_t,uint32_t))(uintptr_t)(a))((x),(y)))
#define CALL3(a,x,y,z) (((uint32_t (*)(uint32_t,uint32_t,uint32_t))(uintptr_t)(a))((x),(y),(z)))
void lab_stop(uint32_t) __attribute__((noreturn));
static volatile uint32_t check_line,cases;
#define CHECK(x) do { if (!(x)) { check_line=__LINE__; lab_stop(82); } } while (0)
static uint32_t heap[2][128],allocations,allocated_bytes,fail_size,depth,acquires,releases;
static uint32_t configured,reads,writes,modifies,packet,direction,node;
static uint32_t write_address[8],write_value[8];

uint32_t boundary_log(void) { return 0; }
uint32_t boundary_alloc(uint32_t size)
{
    CHECK((size==32 || size==512) && allocations<2);
    ++allocations;allocated_bytes+=size;
    if (size==fail_size) return 0;
    for (uint32_t i=0;i<128;++i) heap[allocations-1][i]=0xA5A5A5A5;
    return (uint32_t)(uintptr_t)heap[allocations-1];
}
uint32_t boundary_acquire(uint32_t id,uint32_t timeout)
{
    CHECK(id==0x2200005 && timeout==0 && depth==0);++depth;++acquires;return 0;
}
uint32_t boundary_release(uint32_t id)
{
    CHECK(id==0x2200005 && depth==1);--depth;++releases;return 0;
}
uint32_t boundary_configure(uint32_t controller,uint32_t descriptor)
{
    CHECK(controller==CTRL && descriptor==node+16 && depth==1);
    CHECK(((W(descriptor)>>18)&0x7FF)==packet);
    CHECK(((W(descriptor)>>8)&1)==direction);++configured;return 999;
}
uint32_t boundary_read(uint32_t address)
{
    CHECK(depth==1);++reads;
    if (address==BASE+0x2C) return 0x10000;
    CHECK(address==EPREG || address==EPREG+0x10 || address==BASE+0x100);return 0;
}
uint32_t boundary_write(uint32_t address,uint32_t value)
{
    CHECK(depth==1 && writes<8);write_address[writes]=address;write_value[writes++]=value;return 0;
}
uint32_t boundary_modify(uint32_t address,uint32_t mask,uint32_t value)
{
    CHECK(depth==1 && direction && address==BASE+0x34 && mask==0 && value==2);
    ++modifies;return 0;
}
static void reset(uint32_t dir,uint32_t number,uint32_t maxpacket,uint32_t sg,uint32_t type)
{
    for (uint32_t i=0;i<0x1800;++i) B(TOP+i)=0;
    allocations=allocated_bytes=fail_size=depth=acquires=releases=configured=reads=writes=modifies=0;
    direction=dir;packet=maxpacket;
    node=DEV+(dir ? 0x68u:0x464u)+(number-1)*68;
    W(0x36B588)=TOP;W(TOP)=DEV;W(TOP+0x48)=W(TOP+0x14)=1;
    W(DEV+4)=CTRL;W(CTRL)=0x501600;W(0x501600)=1;W(0x501678)=0x8000;
    W(DEV+0x860)=0x501500;W(0x501500)=0x2200005;
    W(CTRL+4)=BASE;W(CTRL+8)=TABLE;B(CTRL+99)=sg;B(CTRL+102)=1;
    W(TABLE)=BASE;W(TABLE+4)=BASE+0x100;
    W(TABLE+4+4*number)=W(TABLE+0x44+4*number)=EPREG;
    W(0x353400)=0x11223344;
    ((void (*)(uint32_t,uint32_t,uint32_t,uint32_t))(uintptr_t)0x278F30)(DEV,node,dir,number);
    CHECK(W(node)==0 && W(node+4)==node+4 && W(node+8)==node+4 && (W(node+12)&1)==1);
    B(USB)=7;B(USB+1)=5;B(USB+2)=number|(dir<<7);B(USB+3)=type;
    H(USB+4)=maxpacket;
    W(REQ)=W(REQ+8)=BUF;W(REQ+4)=65;W(REQ+12)=2;W(REQ+16)=0x190F10;
    for (uint32_t i=0;i<256;++i) W(BUF+4*i)=0x12340000+i;
}
static void opened(uint32_t sg,uint32_t type)
{
    CHECK(CALL2(0x27864C,EP,USB)==0);
    CHECK(W(node)==USB && W(node+64)==EP && (W(node+12)&1)==0);
    CHECK(((W(node+16)>>8)&1)==direction && ((W(node+16)>>18)&0x7FF)==packet);
    CHECK(((W(node+16)>>14)&3)==type && H(EP+20)==packet);
    CHECK(configured==1 && depth==0 && acquires==1 && releases==1);
    uint32_t ring=sg && type!=1;
    CHECK(allocations==ring && allocated_bytes==512*ring);
    CHECK(W(node+32)==(ring ? (uint32_t)(uintptr_t)heap[0]:0));
    CHECK(W(node+28)==W(node+32));
}
static void write_is(uint32_t index,uint32_t address,uint32_t value)
{
    CHECK(index<writes && write_address[index]==address && write_value[index]==value);
}
int main(void)
{
    static const uint32_t numbers[]={1,2,15},lengths[]={0,1,32,65,513};
    for (uint32_t dir=0;dir<2;++dir)
    for (uint32_t e=0;e<3;++e)
    for (uint32_t p=0;p<2;++p)
    for (uint32_t sg=0;sg<2;++sg)
    for (uint32_t type=1;type<3;++type) {
        reset(dir,numbers[e],p ? 512:64,sg,type);opened(sg,type);++cases;
    }
    CHECK(cases==48);
    for (uint32_t dir=0;dir<2;++dir)
    for (uint32_t p=0;p<2;++p)
    for (uint32_t dma=0;dma<2;++dma)
    for (uint32_t k=0;k<5;++k) {
        reset(dir,1,p ? 512:64,0,2);opened(0,2);B(CTRL+98)=dma;
        uint32_t n=lengths[k],packets=n ? (n+packet-1)>>(p ? 9:6):1;
        uint32_t programmed=dir ? n:packets*packet;
        W(REQ+4)=n;
        CHECK(CALL3(0x278854,EP,REQ,32)==0);
        CHECK(allocations==1 && allocated_bytes==32 && acquires==2 && releases==2 && depth==0);
        uint32_t queued=(uint32_t)(uintptr_t)heap[0];
        CHECK(W(queued)==REQ && W(queued+4)==BUF && W(queued+8)==BUF && W(queued+12)==n);
        CHECK(W(node+24)==BUF && W(node+36)==BUF && W(node+40)==BUF);
        CHECK((W(node+44)&0x7FFFF)==((!dir && n) ? programmed:n));
        CHECK((W(node+48)&0x7FFFF)==0 && (W(node+52)&0x7FFFF)==n);
        CHECK(W(node+4)==queued && W(node+8)==queued && W(DEV+16)==1);
        CHECK(W(REQ+32)==(uint32_t)-10 && W(REQ+36)==0);
        CHECK(reads==(dir ? 4u:2u) && writes==2+dma+dir);
        write_is(0,EPREG+0x10,(packets<<19)|programmed);
        if (dma) write_is(1,EPREG+0x14,BUF);
        write_is(1+dma,EPREG,0x84000000);
        if (dir) write_is(2+dma,BASE+0x100,0x800);
        CHECK(modifies==((dir && !dma && n) ? 1u:0u));
        for (uint32_t i=0;i<256;++i) CHECK(W(BUF+4*i)==0x12340000+i);
        ++cases;
    }
    CHECK(cases==88);
    reset(0,1,64,1,2);fail_size=512;
    CHECK(CALL2(0x27864C,EP,USB)==(uint32_t)-7);
    CHECK(allocations==1 && configured==0 && depth==0 && acquires==1 && releases==1);
    CHECK(W(node)==USB && W(node+64)==EP && (W(node+12)&1)==0 && W(node+32)==0);
    CHECK(H(EP+20)==0);++cases;
    reset(0,1,64,0,2);opened(0,2);fail_size=32;
    CHECK(CALL3(0x278854,EP,REQ,32)==(uint32_t)-7);
    CHECK(allocations==1 && configured==1 && acquires==1 && releases==1 && reads==0 && writes==0);
    CHECK(W(node+4)==node+4 && W(DEV+16)==0 && W(REQ+32)==(uint32_t)-10);++cases;
    CHECK(cases==90);return 0;
}
