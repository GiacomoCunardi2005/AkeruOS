#include "usb_ram_transport.h"
#include <stddef.h>
#ifdef AKERU_GNU_TEST
void lab_stop(uint32_t) __attribute__((noreturn));
#define assert(v) ((v) ? (void)0:lab_stop(1000+__LINE__))
#else
#include <assert.h>
#include <stdio.h>
#endif
#include "usb_ram_transport_fixture.h"
#include "usb_ram_vectors.h"
static struct { uint8_t before[64];struct akeru_usb_ram_transport t;uint8_t after[64]; } guarded;
static struct akeru_usb_ram service;
static uint8_t held[AKERU_USB_RAM_TX_CAPACITY];
static void guards(void)
{
    for (uint32_t i=0;i<64;++i) assert(guarded.before[i]==0xA5 && guarded.after[i]==0xA5);
}
static void fresh(uint32_t packet)
{
    transport_service(&service);
    for (uint32_t i=0;i<sizeof(guarded);++i) ((uint8_t *)&guarded)[i]=0xA5;
    assert(akeru_usb_ram_transport_init(&guarded.t,&service,packet)==0);
    assert((uintptr_t)guarded.t.rx%64==0 && (uintptr_t)guarded.t.tx%64==0);
}
int transport_guard_tests(void)
{
    struct akeru_usb_ram_transport *t=&guarded.t;
    assert(akeru_usb_ram_transport_init(NULL,&service,64)==-1);
    assert(akeru_usb_ram_transport_init(t,NULL,64)==-1);
    assert(akeru_usb_ram_transport_init(t,&service,63)==-1);
    assert(akeru_usb_ram_transport_receive(NULL)==-1 && akeru_usb_ram_transport_send(NULL)==-1);
    assert(akeru_usb_ram_transport_received(NULL,0,32)==-1 && akeru_usb_ram_transport_sent(NULL,0,32)==-1);
    for (uint32_t packet=64;packet<=512;packet*=8) {
        fresh(packet);
        for (uint32_t v=0;v<18;++v) {
            uint32_t reads_before=ram_reads;
            assert(akeru_usb_ram_transport_sent(t,0,32)==-1 && t->state==AKERU_USB_RX_READY);
            assert(akeru_usb_ram_transport_receive(t)==32);
            assert(akeru_usb_ram_transport_receive(t)==-1 && akeru_usb_ram_transport_send(t)==-1);
            for (uint32_t i=0;i<packet;++i) t->rx[i]=i<32 ? requests[v][i]:0xCC;
            assert(ram_reads==reads_before);
            int32_t n=akeru_usb_ram_transport_received(t,0,32);
            assert(n==(int32_t)reply_sizes[v] && t->state==AKERU_USB_TX_READY);
            for (uint32_t i=0;i<(uint32_t)n;++i) assert(t->tx[i]==replies[reply_offsets[v]+i]);
            for (uint32_t i=0;i<sizeof(held);++i) held[i]=t->tx[i];
            assert(akeru_usb_ram_transport_received(t,0,32)==-1);
            assert(akeru_usb_ram_transport_sent(t,0,(uint32_t)n)==-1);
            assert(akeru_usb_ram_transport_receive(t)==-1);
            assert(akeru_usb_ram_transport_send(t)==n);
            assert(akeru_usb_ram_transport_send(t)==-1 && akeru_usb_ram_transport_receive(t)==-1);
            assert(akeru_usb_ram_transport_received(t,0,32)==-1 && t->state==AKERU_USB_TX_PENDING);
            for (uint32_t i=0;i<sizeof(held);++i) assert(t->tx[i]==held[i]);
            assert(akeru_usb_ram_transport_sent(t,0,(uint32_t)n)==0 && t->state==AKERU_USB_RX_READY);
            assert(akeru_usb_ram_transport_sent(t,0,(uint32_t)n)==-1);guards();
        }
        assert(ram_reads==4 && service.aborted==1);
        const uint32_t lengths[]={0,1,31,33,packet,packet+1,0xFFFFFFFF};
        for (uint32_t k=0;k<7;++k) {
            fresh(packet);assert(akeru_usb_ram_transport_receive(t)==32);
            for (uint32_t i=0;i<32;++i) t->rx[i]=requests[3][i];
            assert(akeru_usb_ram_transport_received(t,0,lengths[k])==(lengths[k]>packet ? -1:0));
            assert(ram_reads==0 && t->state==(lengths[k]>packet ? AKERU_USB_STOPPED:AKERU_USB_RX_READY));
            guards();
        }
        fresh(packet);assert(akeru_usb_ram_transport_receive(t)==32);
        assert(akeru_usb_ram_transport_received(t,-54,32)==-1 && t->state==AKERU_USB_STOPPED && ram_reads==0);
        fresh(packet);assert(akeru_usb_ram_transport_receive(t)==32);
        for (uint32_t i=0;i<32;++i) t->rx[i]=requests[3][i];
        t->rx[28]^=1;
        assert(akeru_usb_ram_transport_received(t,0,32)==0 && ram_reads==0 && t->state==AKERU_USB_RX_READY);
        for (uint32_t k=0;k<3;++k) {
            fresh(packet);assert(akeru_usb_ram_transport_receive(t)==32);
            for (uint32_t i=0;i<32;++i) t->rx[i]=requests[0][i];
            assert(akeru_usb_ram_transport_received(t,0,32)==64 && akeru_usb_ram_transport_send(t)==64);
            for (uint32_t i=0;i<sizeof(held);++i) held[i]=t->tx[i];
            assert(akeru_usb_ram_transport_sent(t,k==0 ? -7:0,k==2 ? 65:63)==-1);
            assert(t->state==AKERU_USB_STOPPED && akeru_usb_ram_transport_receive(t)==-1 && akeru_usb_ram_transport_send(t)==-1);
            for (uint32_t i=0;i<sizeof(held);++i) assert(t->tx[i]==held[i]);
            guards();
        }
    }
    return 0;
}
#ifndef AKERU_GNU_TEST
int main(void)
{
    transport_guard_tests();puts("PASS transport_vectors=36 ownership_length_error_guards=PASS");return 0;
}
#endif
