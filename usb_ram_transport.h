#ifndef AKERU_USB_RAM_TRANSPORT_H
#define AKERU_USB_RAM_TRANSPORT_H
#include "usb_ram.h"

#define AKERU_USB_RAM_RX_CAPACITY 512u
#define AKERU_USB_RAM_TX_CAPACITY ((AKERU_USB_RAM_FRAME+63u)&~63u)

enum akeru_usb_ram_transport_state {
    AKERU_USB_RX_READY=1, AKERU_USB_RX_PENDING,
    AKERU_USB_TX_READY, AKERU_USB_TX_PENDING, AKERU_USB_STOPPED
};

/* One ordinary task owns service, state and buffers for the full session.
 * Init only an inactive object, once; it does not cancel existing I/O.
 * maxpacket is 64 or 512. No Nikon address, allocator or physical map is bound.
 */
struct akeru_usb_ram_transport {
    struct akeru_usb_ram *service;
    uint32_t maxpacket, state, tx_bytes;
    _Alignas(64) uint8_t rx[AKERU_USB_RAM_RX_CAPACITY];
    _Alignas(64) uint8_t tx[AKERU_USB_RAM_TX_CAPACITY];
};

int akeru_usb_ram_transport_init(struct akeru_usb_ram_transport *,
    struct akeru_usb_ram *, uint32_t maxpacket);
/* Reserve the owned buffer BEFORE submit. Returns logical byte count or -1.
 * Submit failure does not release ownership: backend must establish quiescence.
 */
int32_t akeru_usb_ram_transport_receive(struct akeru_usb_ram_transport *);
int32_t akeru_usb_ram_transport_send(struct akeru_usb_ram_transport *);
/* Call from the owner task after a matching completion AND backend quiescence,
 * including return from the Nikon callback/free path. IRQ callbacks only notify.
 * received: reply length, 0 for discarded framing, -1 for error/wrong order.
 * sent: 0 on exact success, -1 otherwise. Error stops reuse of both buffers.
 */
int32_t akeru_usb_ram_transport_received(struct akeru_usb_ram_transport *,
    int32_t status, uint32_t actual);
int akeru_usb_ram_transport_sent(struct akeru_usb_ram_transport *,
    int32_t status, uint32_t actual);
#endif
