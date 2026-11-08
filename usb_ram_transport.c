#include "usb_ram_transport.h"
#include <stddef.h>

int akeru_usb_ram_transport_init(struct akeru_usb_ram_transport *t,
    struct akeru_usb_ram *service, uint32_t maxpacket)
{
    if (t==NULL || service==NULL || (maxpacket!=64u && maxpacket!=512u))
        return -1;
    t->service=service; t->maxpacket=maxpacket; t->tx_bytes=0;
    t->state=AKERU_USB_RX_READY;
    return 0;
}

int32_t akeru_usb_ram_transport_receive(struct akeru_usb_ram_transport *t)
{
    if (t==NULL || t->state!=AKERU_USB_RX_READY) return -1;
    t->state=AKERU_USB_RX_PENDING;
    return 32;
}

int32_t akeru_usb_ram_transport_received(struct akeru_usb_ram_transport *t,
    int32_t status, uint32_t actual)
{
    if (t==NULL || t->state!=AKERU_USB_RX_PENDING) return -1;
    if (status!=0 || actual>t->maxpacket) {
        t->state=AKERU_USB_STOPPED;
        return -1;
    }
    if (actual!=32u) {
        t->state=AKERU_USB_RX_READY;
        return 0;
    }
    int32_t n=akeru_usb_ram_serve(t->service,t->rx,actual,t->tx,sizeof(t->tx));
    if (n<0) {
        t->state=AKERU_USB_RX_READY;
        return 0;
    }
    t->tx_bytes=(uint32_t)n;
    t->state=AKERU_USB_TX_READY;
    return n;
}

int32_t akeru_usb_ram_transport_send(struct akeru_usb_ram_transport *t)
{
    if (t==NULL || t->state!=AKERU_USB_TX_READY) return -1;
    t->state=AKERU_USB_TX_PENDING;
    return (int32_t)t->tx_bytes;
}

int akeru_usb_ram_transport_sent(struct akeru_usb_ram_transport *t,
    int32_t status, uint32_t actual)
{
    if (t==NULL || t->state!=AKERU_USB_TX_PENDING) return -1;
    if (status!=0 || actual!=t->tx_bytes) {
        t->state=AKERU_USB_STOPPED;
        return -1;
    }
    t->tx_bytes=0; t->state=AKERU_USB_RX_READY;
    return 0;
}
