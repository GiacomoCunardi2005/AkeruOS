#include "usb_ram_transport.h"
static uint32_t ram_reads;
static const struct akeru_dump_region transport_regions[]={{0x1000,9000},{0x8000,513}};
static int transport_read(void *context,uint32_t address,uint8_t *data,uint32_t n)
{
    assert(context==&ram_reads && n>0 && n<=4096);
    assert((address>=0x1000 && address+n<=0x1000+9000) ||
           (address>=0x8000 && address+n<=0x8000+513));
    ++ram_reads;
    for (uint32_t i=0;i<n;++i) data[i]=(uint8_t)((address+i)^((address+i)>>8));
    return address==0x2000 ? -1:0;
}
static void transport_service(struct akeru_usb_ram *service)
{
    for (uint32_t i=0;i<sizeof(*service);++i) ((uint8_t *)service)[i]=0;
    ram_reads=0;service->context=&ram_reads;service->read_ram=transport_read;
    service->regions=transport_regions;service->region_count=2;service->flags=1;
    for (uint32_t i=0;i<16;++i) service->epoch[i]=(uint8_t)(i+1);
}
