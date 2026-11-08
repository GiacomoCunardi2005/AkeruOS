/* Original controller preparation; register helpers are request-recording fixtures. */
#include <stdint.h>
#define W(a) (*(volatile uint32_t *)(uintptr_t)(a))
#define B(a) (*(volatile uint8_t *)(uintptr_t)(a))
#define CTRL 0x500000u
#define DESC 0x500100u
#define TABLE 0x500200u
#define BUFFER 0x502000u
#define BASE 0x0FE50000u
#define EPREG 0x0FE50120u
#define SHARED 0x0FE50100u
void lab_stop(uint32_t) __attribute__((noreturn));
static volatile uint32_t cases, check_line;
#define CHECK(x) do { if (!(x)) { check_line=__LINE__; lab_stop(82); } } while (0)
static uint32_t reads, writes, modifies, seed, enable, software, packet;
static uint32_t write_address[4], write_value[4], modify_address, modify_mask, modify_value;

uint32_t controller_read(uint32_t address)
{
    ++reads;
    if (address==BASE+0x2C) return enable ? 0x10000 : 0;
    if (address==EPREG) return seed;
    if (address==EPREG+0x10) return seed;
    if (address==SHARED) return seed;
    CHECK(0);return 0;
}
uint32_t controller_write(uint32_t address,uint32_t value)
{
    CHECK(writes<4);write_address[writes]=address;write_value[writes++]=value;
    return 0;
}
uint32_t controller_modify(uint32_t address,uint32_t mask,uint32_t value)
{
    CHECK(modifies==0);++modifies;modify_address=address;modify_mask=mask;modify_value=value;
    return 0;
}
static void reset(uint32_t direction,uint32_t dma,uint32_t n,uint32_t offset)
{
    for (uint32_t i=0;i<0x300;++i) B(CTRL+i)=0;
    W(0x353400)=0x11223344;
    W(CTRL+4)=BASE;W(CTRL+8)=TABLE;
    B(CTRL+98)=dma;B(CTRL+99)=0;B(CTRL+102)=software;
    W(TABLE)=BASE;W(TABLE+4)=SHARED;
    W(TABLE+8)=W(TABLE+0x48)=EPREG; /* Endpoint index1, IN and OUT tables. */
    W(DESC)=1u|(direction<<8)|(packet<<18);
    W(DESC+4)=n;W(DESC+8)=BUFFER+offset;
    W(DESC+28)=W(DESC+32)=offset;W(DESC+36)=offset+n;
    for (uint32_t i=0;i<16;++i) W(BUFFER+4*i)=0xA5A50000+i;
    reads=writes=modifies=0;
}
static void check_write(uint32_t index,uint32_t address,uint32_t value)
{
    CHECK(index<writes && write_address[index]==address && write_value[index]==value);
}
int main(void)
{
    static const uint32_t lengths[]={0,1,17,63,64,65,511,512,513};
    cases=0;enable=1;software=1;
    for (uint32_t direction=0;direction<2;++direction)
    for (uint32_t dma=0;dma<2;++dma)
    for (uint32_t p=0;p<2;++p)
    for (uint32_t s=0;s<2;++s)
    for (uint32_t o=0;o<2;++o)
    for (uint32_t k=0;k<sizeof(lengths)/sizeof(lengths[0]);++k) {
        packet=p ? 512:64;seed=s ? 0xA5A55A5A:0;uint32_t n=lengths[k],offset=o ? 7:0;
        reset(direction,dma,n,offset);
        ((void (*)(uint32_t,uint32_t))(uintptr_t)0x2DBFB8)(CTRL,DESC);
        uint32_t packets=n ? (n+packet-1)>>(p ? 9:6):1;
        uint32_t programmed=direction ? n:packets*packet;
        uint32_t cursor=offset+((!direction && n) ? programmed:n);
        CHECK((W(DESC+28)&0x7FFFFu)==cursor);
        CHECK(W(DESC+32)==offset && W(DESC+36)==offset+n);
        CHECK(reads==(direction ? 4:2) && writes==(dma ? 3u:2u)+direction);
        check_write(0,EPREG+0x10,(seed&0xE0000000u)|(packets<<19)|programmed);
        if (dma) check_write(1,EPREG+0x14,BUFFER+offset);
        check_write(dma ? 2:1,EPREG,seed|0x84000000u);
        if (direction) check_write(dma ? 3:2,SHARED,(seed&~0x7800u)|0x800u);
        CHECK(modifies==((direction && !dma && offset+n) ? 1u:0u));
        if (modifies) CHECK(modify_address==BASE+0x34 && modify_mask==0 && modify_value==2);
        for (uint32_t i=0;i<16;++i) CHECK(W(BUFFER+4*i)==0xA5A50000+i);
        CHECK(W(0x353400)==0x11223344);++cases;
    }
    /* IN admission gate: no write/request completion is implied by return. */
    packet=64;seed=0;enable=0;software=0;reset(1,0,65,0);
    ((void (*)(uint32_t,uint32_t))(uintptr_t)0x2DBFB8)(CTRL,DESC);
    CHECK(reads==1 && writes==0 && modifies==0 && W(DESC+28)==0);++cases;
    enable=1;reset(1,0,65,0);
    ((void (*)(uint32_t,uint32_t))(uintptr_t)0x2DBFB8)(CTRL,DESC);
    CHECK(reads==4 && writes==3 && modifies==1);
    CHECK(modify_address==BASE+0x18 && modify_mask==(0x11223344u|32u) && modify_value==modify_mask);
    ++cases;CHECK(cases==290);return 0;
}
