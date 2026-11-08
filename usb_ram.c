#include "usb_ram.h"
#include <stddef.h>

static uint32_t get32(const uint8_t *p)
{
    return p[0]|((uint32_t)p[1]<<8)|((uint32_t)p[2]<<16)|((uint32_t)p[3]<<24);
}
static void put32(uint8_t *p, uint32_t value)
{
    for (uint32_t i=0; i<4; ++i) p[i]=(uint8_t)(value>>(8*i));
}
static uint32_t crc32(uint32_t crc, const uint8_t *p, uint32_t n)
{
    for (uint32_t i=0; i<n; ++i) {
        crc^=p[i];
        for (uint32_t b=0; b<8; ++b)
            crc=(crc>>1)^((0u-(crc&1u))&0xEDB88320u);
    }
    return crc;
}
static int configured(const struct akeru_usb_ram *s)
{
    uint32_t end=0, epoch=0;
    if (s==NULL || s->read_ram==NULL || s->regions==NULL ||
        s->region_count==0u || s->region_count>AKERU_DUMP_MAX_REGIONS ||
        (s->flags&~3u)!=0u)
        return 0;
    for (uint32_t i=0; i<16; ++i) epoch|=s->epoch[i];
    if (epoch==0u) return 0;
    for (uint32_t i=0; i<s->region_count; ++i) {
        uint32_t address=s->regions[i].address, length=s->regions[i].length;
        if (address<end || address>=0x0FE00000u || length==0u ||
            length>0x0FE00000u-address)
            return 0;
        end=address+length;
    }
    return 1;
}
static int allowed(const struct akeru_usb_ram *s, uint32_t address, uint32_t length)
{
    if (length==0u || length>AKERU_DUMP_CHUNK) return 0;
    for (uint32_t i=0; i<s->region_count; ++i) {
        uint32_t start=s->regions[i].address, size=s->regions[i].length;
        if (address>=start && address-start<size && length<=size-(address-start))
            return 1;
    }
    return 0;
}

int32_t akeru_usb_ram_serve(struct akeru_usb_ram *s, const uint8_t *q,
    uint32_t bytes, uint8_t *out, uint32_t capacity)
{
    uint32_t op, address, length, status=0, payload=0;
    if (q==NULL || out==NULL || bytes!=32u || capacity<AKERU_USB_RAM_FRAME ||
        !configured(s)) return -1;
    if (get32(q)!=0x4D524B41u || q[4]!=1u || q[5]!=0u ||
        get32(q+24)!=0u || (crc32(0xFFFFFFFFu,q,28)^0xFFFFFFFFu)!=get32(q+28))
        return -1;
    op=(uint32_t)q[6]|((uint32_t)q[7]<<8);
    address=get32(q+12); length=get32(q+16);
    if (get32(q+20)!=0u || op<1u || op>5u ||
        (op!=3u && (address!=0u || length!=0u))) status=1;
    else if (op==1u) {
        const uint8_t name[8]={'A','k','e','r','u','R','A','M'};
        for (uint32_t i=0; i<8; ++i) out[32+i]=name[i];
        for (uint32_t i=0; i<16; ++i) out[40+i]=s->epoch[i];
        put32(out+56,AKERU_DUMP_CHUNK); put32(out+60,s->flags); payload=32;
    } else if (op==2u) {
        payload=8u*s->region_count;
        for (uint32_t i=0; i<s->region_count; ++i) {
            put32(out+32+8*i,s->regions[i].address);
            put32(out+36+8*i,s->regions[i].length);
        }
    } else if (op==5u) s->aborted=1;
    else if (op==4u) {
        put32(out+32,s->reads); put32(out+36,s->last_address);
        put32(out+40,s->last_length); put32(out+44,s->last_status);
        put32(out+48,s->aborted); payload=20;
    } else {
        if (s->aborted!=0u) status=4;
        else if (!allowed(s,address,length)) status=2;
        else if (s->read_ram(s->context,address,out+32,length)!=0) status=3;
        else { payload=length; ++s->reads; }
    }
    if (op==3u) {
        s->last_address=address; s->last_length=length; s->last_status=status;
    }
    for (uint32_t i=0; i<20; ++i) out[i]=q[i];
    out[7]|=0x80u;
    put32(out+20,status); put32(out+24,payload);
    put32(out+28,crc32(crc32(0xFFFFFFFFu,out,28),out+32,payload)^0xFFFFFFFFu);
    return (int32_t)(32u+payload);
}
