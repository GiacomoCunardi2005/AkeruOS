/* Original V1.1 USB chain; RAM data, MMIO and resource boundaries are fixtures. */
#include "device_transport_fixture.h"
#include "usb_ram_transport.h"
#include "usb_ram_vectors.h"
#define assert(v) CHECK(v)
#include "usb_ram_transport_fixture.h"
int transport_guard_tests(void);
static struct akeru_usb_ram service;
static struct akeru_usb_ram_transport transport;
static uint32_t node_owned,active_request,notified_status,notified_actual,io_read_before;

uint32_t transport_alloc(uint32_t size)
{
    if (phase<3) return parent_alloc(size);
    CHECK(size==32 && node_owned==0);
    for (uint32_t i=0;i<128;++i) heap[0][i]=0xA5A5A5A5;
    node_owned=1;++allocations;return (uint32_t)(uintptr_t)heap[0];
}
uint32_t transport_free(uint32_t address)
{
    CHECK(node_owned==1);init_free(address);node_owned=0;return 0;
}
static uint32_t protocol_complete(uint32_t ep,uint32_t request)
{
    CHECK(phase==4 && depth==0 && ep==endpoint && request==active_request);
    CHECK(node_owned==1 && W(DEV+16)==1 && completions==0 && ram_reads==io_read_before);
    notified_status=W(request+32);notified_actual=W(request+36);
    ++completions;return 0;
}
static int task_read(void *context,uint32_t address,uint8_t *data,uint32_t n)
{
    CHECK(phase==3 && depth==0 && node_owned==0 && completions==1 && freed==1);
    return transport_read(context,address,data,n);
}
static void complete_io(uint32_t dir,uint8_t *data,uint32_t n,uint32_t vector)
{
    direction=dir;endpoint=PUBLIC+(dir ? 0x64u:0x1E4u);
    node=DEV+(dir ? 0x68u:0x464u);endpoint_register=BASE+(dir ? 0x920u:0xB20u);
    active_request=REQ+dir*64;
    for (uint32_t i=0;i<40;++i) B(active_request+i)=0;
    W(active_request)=W(active_request+8)=(uint32_t)(uintptr_t)data;
    W(active_request+4)=n;W(active_request+12)=2;
    W(active_request+16)=(uint32_t)(uintptr_t)protocol_complete;
    completions=freed=0;io_read_before=ram_reads;
    CHECK(phase==3 && node_owned==0 && depth==0 && W(DEV+16)==0);
    CHECK(CALL3(0x278854,endpoint,active_request,32)==0);
    CHECK(node_owned==1 && W(DEV+16)==1 && W(active_request+32)==(uint32_t)-10);
    uint32_t transferred=0,steps=0;
    do {
        uint32_t logical=dir ? n-transferred:n;
        uint32_t limit=2047u&~(packet-1);
        if (dir && logical>limit) logical=limit;
        uint32_t packets=logical ? (logical+packet-1)>>(packet==512 ? 9:6):1;
        uint32_t programmed=dir ? logical:packets*packet;
        CHECK(steps<4 && W(node+20)==(n>2047 ? limit:2047u));
        CHECK(registers[(endpoint_register+0x10-BASE)/4]==((packets<<19)|programmed));
        CHECK(registers[(endpoint_register+0x14-BASE)/4]==(uint32_t)(uintptr_t)data+transferred);
        CHECK(akeru_usb_ram_transport_receive(&transport)==-1 && akeru_usb_ram_transport_send(&transport)==-1);
        if (!dir) {
            CHECK(n==32 && programmed<=sizeof(transport.rx));
            /* Model the DMA payload only; the original CPU path does not move USB data. */
            for (uint32_t i=0;i<programmed;++i) data[i]=i<32 ? requests[vector][i]:0xCC;
        }
        irq_status=irq_mask=dir ? (1u<<18):(1u<<19);
        irq_direction_bit=dir ? 2u:0x20000u;irq_endpoint_status=1;
        irq_residual=dir ? 0:programmed-n;phase=4;
        CALL2(W(0x50B4B8),0,W(0x50B4BC));++irq_cases;++steps;
        transferred+=logical;
        if (completions==0) {
            CHECK(dir==1 && freed==0 && node_owned==1 && depth==0);
            CHECK(W(DEV+16)==1 && W(active_request+32)==(uint32_t)-10);
            CHECK(transport.state==AKERU_USB_TX_PENDING && ram_reads==io_read_before);
            CHECK(logical>0 && (transferred<n || (transferred==n && (n&(packet-1))==0)));
        }
    } while (completions==0);
    CHECK(transferred==n);
    CHECK(depth==0 && completions==1 && freed==1 && node_owned==0 && W(DEV+16)==0);
    CHECK(W(node+4)==node+4 && W(node+8)==node+4 && ram_reads==io_read_before);
    CHECK(notified_status==0 && notified_actual==n);
    ++done_cases;phase=3;
}
int main(void)
{
    CHECK(transport_guard_tests()==0);cases=irq_cases=done_cases=0;
    for (uint32_t p=0;p<2;++p) {
        reset(0,1,p ? 512:64,0,2);
        W(0x353404)=0x11223344;
        for (uint32_t i=0;i<0x1000/4;++i) registers[i]=0;
        for (uint32_t i=0;i<65;++i) W(OPTIONS+4*i)=0xFFFFFFFF;
        registers[0x48/4]=(3u<<10)|(1u<<3)|(1u<<20);
        registers[0x50/4]=(1u<<25)|(3u<<26)|3u;
        registers[0x40/4]=0x4F542000;registers[0x2C/4]=0x10000;
        phase=1;construct_allocations=reg_reads=reg_writes=reg_modifies=delays=0;
        wrapper_allocations=registrations=device_allocations=completions=freed=node_owned=0;module_value=0;
        CHECK(((uint32_t (*)(uint32_t))(uintptr_t)0x243838)(TOP)==0);
        CHECK(construct_allocations==5 && device_allocations==5 && registrations==1);
        CHECK(W(0x50B4B8)==0x278BC4 && W(0x50B4BC)==DEV);
        CHECK(B(CTRL+98)==1 && B(CTRL+99)==0 && B(CTRL+101)==0);
        phase=3;CHECK(CALL2(0x278B00,DEV,1)==0);
        W(PUBLIC+0x48)=(uint32_t)(uintptr_t)app_ops;
        for (uint32_t i=0;i<7;++i) B(USB+16+i)=B(USB+i);
        B(USB+18)=0x81;
        CHECK(CALL2(0x27864C,PUBLIC+0x1E4,USB)==0);
        CHECK(CALL2(0x27864C,PUBLIC+0x64,USB+16)==0);
        CHECK(allocations==0 && node_owned==0 && depth==0);
        transport_service(&service);service.read_ram=task_read;
        CHECK(akeru_usb_ram_transport_init(&transport,&service,packet)==0);
        CHECK(((uintptr_t)transport.rx&63)==0 && ((uintptr_t)transport.tx&63)==0);
        for (uint32_t v=0;v<18;++v) {
            CHECK(akeru_usb_ram_transport_receive(&transport)==32);
            complete_io(0,transport.rx,32,v);
            int32_t n=akeru_usb_ram_transport_received(&transport,(int32_t)notified_status,notified_actual);
            CHECK(n==(int32_t)reply_sizes[v]);
            for (uint32_t i=0;i<(uint32_t)n;++i) CHECK(transport.tx[i]==replies[reply_offsets[v]+i]);
            CHECK(akeru_usb_ram_transport_send(&transport)==n);
            complete_io(1,transport.tx,(uint32_t)n,v);
            for (uint32_t i=0;i<(uint32_t)n;++i) CHECK(transport.tx[i]==replies[reply_offsets[v]+i]);
            CHECK(akeru_usb_ram_transport_sent(&transport,(int32_t)notified_status,notified_actual)==0);
            ++cases;
        }
        CHECK(ram_reads==4 && service.reads==3 && service.aborted==1 && allocations==36);
    }
    CHECK(cases==36 && irq_cases==77 && done_cases==72);return 0;
}
