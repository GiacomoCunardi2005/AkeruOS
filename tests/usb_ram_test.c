#include "usb_ram.h"
#include <stddef.h>
#ifdef AKERU_GNU_TEST
#include "usb_ram_vectors.h"
void test_fail(unsigned line) __attribute__((noreturn));
#define assert(value) ((value) ? (void)0 : test_fail(__LINE__))
#else
#include <assert.h>
#include <stdio.h>
#endif

static unsigned reads;
static int read_ram(void *context, uint32_t address, uint8_t *data, uint32_t n)
{
    assert(context==&reads && n>0 && n<=4096);
    assert((address>=0x1000 && address+n<=0x1000+9000) ||
           (address>=0x8000 && address+n<=0x8000+513));
    ++reads;
    for (uint32_t i=0; i<n; ++i) data[i]=(uint8_t)((address+i)^((address+i)>>8));
    return address==0x2000 ? -1 : 0;
}
#ifdef AKERU_GNU_TEST
int main(void)
#else
int main(int argc, char **argv)
#endif
{
    const struct akeru_dump_region regions[]={{0x1000,9000},{0x8000,513}};
    struct akeru_usb_ram s={0};
    uint8_t request[32], before[32], guarded[AKERU_USB_RAM_FRAME+32];
    unsigned cases=0;
    reads=0;
#ifndef AKERU_GNU_TEST
    assert(argc==3);
#endif
    s.context=&reads; s.read_ram=read_ram; s.regions=regions; s.region_count=2;
    s.flags=1; for (unsigned i=0; i<16; ++i) s.epoch[i]=(uint8_t)(i+1);
#ifdef AKERU_GNU_TEST
    for (; cases<18;) {
        for (unsigned i=0;i<32;++i) request[i]=requests[cases][i];
#else
    FILE *input=fopen(argv[1],"rb"), *output=fopen(argv[2],"wb"); assert(input&&output);
    while (fread(request,1,32,input)==32) {
#endif
        for (unsigned i=0;i<32;++i) before[i]=request[i];
        for (unsigned i=0;i<sizeof(guarded);++i) guarded[i]=0xA5;
        int32_t n=akeru_usb_ram_serve(&s,request,32,guarded+16,AKERU_USB_RAM_FRAME);
        assert(n>=32 && n<=(int32_t)AKERU_USB_RAM_FRAME);
        for (unsigned i=0;i<32;++i) assert(before[i]==request[i]);
        for (unsigned i=0; i<16; ++i)
            assert(guarded[i]==0xA5 && guarded[16+AKERU_USB_RAM_FRAME+i]==0xA5);
#ifdef AKERU_GNU_TEST
        assert((uint32_t)n==reply_sizes[cases]);
        for (unsigned i=0;i<(uint32_t)n;++i)
            assert(guarded[16+i]==replies[reply_offsets[cases]+i]);
#else
        uint8_t size[4];for (unsigned i=0;i<4;++i)size[i]=(uint8_t)((uint32_t)n>>(8*i));
        assert(fwrite(size,1,4,output)==4 && fwrite(guarded+16,1,(size_t)n,output)==(size_t)n);
#endif
        ++cases;
    }
#ifndef AKERU_GNU_TEST
    assert(feof(input)&&fclose(input)==0&&fclose(output)==0);
#endif
    assert(cases==18 && reads==4);
    unsigned previous=reads;
    assert(akeru_usb_ram_serve(NULL,request,32,guarded+16,AKERU_USB_RAM_FRAME)==-1);
    assert(akeru_usb_ram_serve(&s,request,31,guarded+16,AKERU_USB_RAM_FRAME)==-1);
    assert(akeru_usb_ram_serve(&s,request,32,guarded+16,AKERU_USB_RAM_FRAME-1)==-1);
    request[0]^=1;
    assert(akeru_usb_ram_serve(&s,request,32,guarded+16,AKERU_USB_RAM_FRAME)==-1);request[0]^=1;
    s.region_count=0;
    assert(akeru_usb_ram_serve(&s,request,32,guarded+16,AKERU_USB_RAM_FRAME)==-1);
    s.region_count=2;for (unsigned i=0;i<16;++i) s.epoch[i]=0;
    assert(akeru_usb_ram_serve(&s,request,32,guarded+16,AKERU_USB_RAM_FRAME)==-1);
    s.epoch[0]=1;s.flags=4;
    assert(akeru_usb_ram_serve(&s,request,32,guarded+16,AKERU_USB_RAM_FRAME)==-1);
    s.flags=1;
    const struct akeru_dump_region overlap[]={{0x1000,100},{0x1001,1}};
    s.regions=overlap;
    assert(akeru_usb_ram_serve(&s,request,32,guarded+16,AKERU_USB_RAM_FRAME)==-1);
    const struct akeru_dump_region mmio[]={{0x0FDFFFFF,2}};
    s.regions=mmio;s.region_count=1;
    assert(akeru_usb_ram_serve(&s,request,32,guarded+16,AKERU_USB_RAM_FRAME)==-1);
    const struct akeru_dump_region overflow[]={{0xFFFFFFF0,32}};
    s.regions=overflow;
    assert(akeru_usb_ram_serve(&s,request,32,guarded+16,AKERU_USB_RAM_FRAME)==-1);
    assert(reads==previous);
#ifndef AKERU_GNU_TEST
    printf("PASS c_wire_cases=%u invalid_cases=10 read_callbacks=%u\n",cases,reads);
#endif
    return 0;
}
