/* Original USB bodies run in GNU; endpoint/MMIO/event functions below are fixtures. */
#include <stdint.h>
#define W(a) (*(volatile uint32_t *)(uintptr_t)(a))
#define B(a) (*(volatile uint8_t *)(uintptr_t)(a))
#define G 0x3680A0u
#define R 0x423C00u
#define CTX 0x500000u
#define EP 0x500100u
#define VT 0x500200u
#define BUF 0x501000u
#define TX 0x47DA24u
#define RX 0x47DA4Cu
#define CALL0(a) (((uint32_t (*)(void))(uintptr_t)(a))())
#define CALL2(a,x,y) (((uint32_t (*)(uint32_t,uint32_t))(uintptr_t)(a))((x),(y)))
void lab_stop(uint32_t code) __attribute__((noreturn));
int endpoint_tests(void);
#define CHECK(x) do { if (!(x)) lab_stop(80); } while (0)

static uint32_t submitted,submit_status,last_req,last_size,last_flags;
static uint32_t events,event_mask,event_status,logs,log_pointer,closed,cancelled,restarted;
static uint32_t reads,writes,delays,mode,cases;
static uint32_t write_address[3],write_value[3],delay_value[16];

uint32_t lab_event(uint32_t group,uint32_t mask)
{
    CHECK(group==0x2200001u);++events;event_mask|=mask;return event_status;
}
uint32_t lab_log(uint32_t pointer)
{
    ++logs;log_pointer=pointer;return 0;
}
static uint32_t submit(uint32_t ep,uint32_t request,uint32_t parameter)
{
    CHECK(ep==EP && (request==TX || request==RX) && parameter==32);
    ++submitted;last_req=request;last_size=W(request+4);last_flags=W(request+12);
    return submit_status;
}
static uint32_t close_ep(uint32_t ep)
{
    CHECK(ep==EP);++closed;return 777;
}
static uint32_t restart_ep(uint32_t ep,uint32_t flag)
{
    CHECK(ep==EP && flag==0x500419u);++restarted;return 777;
}
static uint32_t cancel_ep(uint32_t ep,uint32_t request)
{
    CHECK(ep==EP && request==TX);++cancelled;return 777;
}
uint32_t lab_read(uint32_t address)
{
    CHECK(address==0xFE50920u || address==0xFE50010u);++reads;
    if (reads==10) {
        CHECK(mode!=0 && events==0 && cancelled==0 && B(R+16)==1);
        CHECK((mode==1 && writes==2) || (mode==2 && writes==3));
        lab_stop(97); /* Bounded observation of an original unbounded polling loop. */
    }
    if (mode==1 && address==0xFE50920u && reads>=3) return 1u<<30;
    if (mode==2 && address==0xFE50010u) return 1u<<5;
    return 0;
}
uint32_t lab_write(uint32_t address,uint32_t value)
{
    CHECK(writes<3);write_address[writes]=address;write_value[writes++]=value;return 0;
}
uint32_t lab_delay(uint32_t value)
{
    CHECK(delays<16);delay_value[delays++]=value;return 0;
}
static void reset(void)
{
    for (uint32_t i=0;i<0x100;++i) B(G+i)=0;
    for (uint32_t i=0;i<64;++i) B(R+i)=0;
    for (uint32_t i=0;i<0xB0;++i) B(0x47D9C8u+i)=0;
    for (uint32_t i=0;i<0x600;++i) B(CTX+i)=0;
    for (uint32_t i=0;i<8192;++i) B(BUF+i)=0xA5;
    W(G+4)=0x500400;W(G+0x74)=CTX;W(G+0x4C)=512;
    W(CTX+16)=EP;W(CTX+20)=EP;W(EP+8)=VT;
    W(VT)=(uint32_t)(uintptr_t)restart_ep;W(VT+4)=(uint32_t)(uintptr_t)close_ep;
    W(VT+16)=(uint32_t)(uintptr_t)submit;W(VT+20)=(uint32_t)(uintptr_t)cancel_ep;
    W(R)=W(R+20)=BUF;B(R+16)=B(R+36)=1;
    submitted=submit_status=events=event_mask=event_status=logs=log_pointer=0;
    closed=cancelled=restarted=reads=writes=delays=0;
}
static void untouched(void)
{
    for (uint32_t i=0;i<8192;++i) CHECK(B(BUF+i)==0xA5);
    CHECK(B(R+16)==1 && B(R+36)==1);++cases;
}
static void submit_case(uint32_t rx,uint32_t total,uint32_t count,uint32_t flag)
{
    reset();W(R+(rx?24:4))=total;W(R+(rx?28:8))=count;B(R+17)=(uint8_t)flag;
    CHECK(CALL0(rx?0x190DAC:0x190EA4)==0);
    uint32_t remaining=total-count,n=remaining>512?512:remaining;
    CHECK(submitted==(remaining!=0));
    if (remaining) {
        CHECK(last_req==(rx?RX:TX) && last_size==n);
        CHECK(W(last_req)==BUF+count && W(last_req+8)==BUF+count);
        CHECK(W(last_req+16)==(rx?0x190E1Cu:0x190F10u));
        CHECK((last_flags&6)==(rx?4u:(remaining<=512 && flag?2u:0u)));
    }
    CHECK(W(R+(rx?28:8))==count && events==0);untouched();
}
static void callback_case(uint32_t rx,int32_t status,uint32_t total,uint32_t requested,
                          uint32_t actual,uint32_t extra)
{
    reset();uint32_t req=rx?RX:TX;W(req+4)=requested;W(req+32)=(uint32_t)status;
    W(req+36)=actual;W(R+(rx?24:4))=total;B(R+37)=(uint8_t)extra;
    CALL2(rx?0x190E1C:0x190F10,EP,req);
    if (status) CHECK(logs==1 && log_pointer==(rx?0x368118u:0x368138u) &&
        submitted==0 && W(R+(rx?28:8))==0 && B(R+(rx?38:18))==0);
    else {
        CHECK(W(R+(rx?28:8))==actual && logs==0);
        uint32_t short_packet=actual<requested,done=actual==total;
        if (rx && !short_packet && done && extra) {
            CHECK(submitted==1 && last_size==1 && B(R+37)==0 && B(R+38)==0);
        } else if (short_packet || done) CHECK(submitted==0 && B(R+(rx?38:18))==1);
        else CHECK(submitted==1 && last_size==((total-actual)>512?512:total-actual));
    }
    CHECK(events==0);untouched();
}
int main(uint32_t selected)
{
    mode=selected;cases=0;
    if (mode==3) return endpoint_tests();
    if (mode) { reset();B(R+36)=0;CALL0(0x1905D8);lab_stop(81); }
    submit_case(0,0,0,1);submit_case(0,64,0,1);submit_case(0,2000,512,1);
    submit_case(0,1024,512,1);submit_case(0,64,0,0);submit_case(0,64,65,1);
    submit_case(1,64,64,0);submit_case(1,1000,100,0);submit_case(1,513,512,0);
    reset();W(R+24)=64;W(CTX+20)=0;
    CHECK(CALL0(0x190DAC)==0x2200342u && submitted==0 && event_mask==(1u<<19));untouched();
    for (uint32_t rx=0;rx<2;++rx) {
        reset();submit_status=999;W(R+(rx?24:4))=64;
        CHECK(CALL0(rx?0x190DAC:0x190EA4)==0 && submitted==1);untouched();
        callback_case(rx,0,64,64,64,0);callback_case(rx,0,128,64,17,0);
        callback_case(rx,0,128,64,0,0);callback_case(rx,0,128,64,64,0);
        callback_case(rx,0,64,64,65,0);
        for (uint32_t i=0;i<6;++i) {
            const int32_t errors[]={1,-1,-53,-54,-58,-59};
            callback_case(rx,errors[i],128,64,64,0);
        }
    }
    callback_case(1,0,512,512,512,1);
    reset();W(R+24)=512;W(RX+4)=512;W(RX+36)=512;B(R+37)=1;
    CALL2(0x190E1C,EP,RX);W(RX+36)=0;CALL2(0x190E1C,EP,RX);
    CHECK(W(R+28)==512 && B(R+38)==1 && submitted==1);untouched();
    for (uint32_t flags=0;flags<4;++flags) {
        reset();B(R+18)=flags&1;B(R+38)=(flags>>1)&1;
        if (flags==3) event_status=999;
        CALL0(0x190D54);
        CHECK(events==((flags&1)+((flags>>1)&1)) && event_mask==flags*0x1000u);
        CHECK(B(R+18)==0 && B(R+38)==0);untouched();
    }
    for (uint32_t flags=0;flags<4;++flags) {
        reset();B(R+16)=flags&1;B(R+36)=(flags>>1)&1;
        CALL0(0x1905D8);
        CHECK(events==1 && event_mask==0x8000 && cancelled==(flags&1));
        CHECK(closed==((flags>>1)&1) && restarted==((flags>>1)&1));
        CHECK(B(R+16)==(flags&1) && B(R+36)==((flags>>1)&1));
        CHECK(reads==(flags&1?4u:0u) && writes==(flags&1?3u:0u));
        if (flags&1) {
            CHECK(write_address[0]==0xFE50920 && write_value[0]==0x08000000);
            CHECK(write_address[1]==0xFE50920 && write_value[1]==0x48000000);
            CHECK(write_address[2]==0xFE50010 && write_value[2]==0x60);
            CHECK(delays==5 && delay_value[0]==100);
            for (uint32_t i=1;i<5;++i) CHECK(delay_value[i]==5);
        }
        ++cases;
    }
    CHECK(cases==44);return 0;
}
