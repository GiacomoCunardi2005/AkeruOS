#include "camera/color_mode.h"
#ifdef AKERU_GNU_TEST
void test_fail(unsigned line) __attribute__((noreturn));
#define CHECK(x) ((x) ? (void)0 : test_fail(__LINE__))
#else
#include <assert.h>
#define CHECK(x) assert(x)
#endif
int main(void)
{
    enum akeru_screen screen = AKERU_MAIN;
    enum akeru_action action = AKERU_NONE;
    enum akeru_color_mode mode = AKERU_COLOR_STANDARD, snapshot;
    uint16_t raw[4] = {1024,1024,1024,1024}, output[4] = {777,777,777,777};
    unsigned i;
    CHECK(akeru_color_menu_event(&screen,0x700,&action,&mode)==1 && screen==AKERU_COLOR && action==AKERU_REDRAW);
    CHECK(akeru_color_menu_event(&screen,0x2180,&action,&mode)==1 && action==AKERU_REQUEST_MONO && mode==AKERU_COLOR_MONO_RAW);
    CHECK(akeru_color_menu_event(&screen,0x2181,&action,&mode)==1 && action==AKERU_NONE && mode==AKERU_COLOR_MONO_RAW);
    snapshot=mode;
    CHECK(akeru_color_menu_event(&screen,0x700,&action,&mode)==1 && action==AKERU_REQUEST_COLOR && mode==AKERU_COLOR_STANDARD);
    CHECK(akeru_color_menu_event(&screen,0x701,&action,&mode)==1 && action==AKERU_NONE && mode==AKERU_COLOR_STANDARD);
    action=AKERU_OPEN_ISO;
    CHECK(akeru_color_menu_event(&screen,0x4401,&action,&mode)==0 && action==AKERU_OPEN_ISO && mode==AKERU_COLOR_STANDARD);
    CHECK(akeru_color_menu_event(&screen,0x580,&action,0)==-1 && screen==AKERU_COLOR && action==AKERU_OPEN_ISO);
    CHECK(akeru_color_menu_event(0,0x2180,&action,&mode)==-1 && mode==AKERU_COLOR_STANDARD && action==AKERU_OPEN_ISO);
    CHECK(akeru_color_menu_event(&screen,0x2180,0,&mode)==-1 && screen==AKERU_COLOR && mode==AKERU_COLOR_STANDARD);
    CHECK(akeru_color_process(mode,raw,output,2,2)==0);
    for(i=0;i<4;i++) CHECK(output[i]==777 && raw[i]==1024);
    CHECK(akeru_color_process(snapshot,raw,output,2,2)==1);
    for(i=0;i<4;i++) CHECK(output[i]==1219 && raw[i]==1024);
    snapshot=mode;
    CHECK(akeru_color_select(&mode,AKERU_REQUEST_MONO)==1 && mode==AKERU_COLOR_MONO_RAW);
    output[0]=777;
    CHECK(akeru_color_process(snapshot,raw,output,2,2)==0 && output[0]==777);
    CHECK(akeru_color_select(&mode,AKERU_REQUEST_COLOR)==1 && mode==AKERU_COLOR_STANDARD);
    CHECK(akeru_color_select(&mode,AKERU_OPEN_ISO)==0 && mode==AKERU_COLOR_STANDARD);
    CHECK(akeru_color_select(0,AKERU_REQUEST_MONO)==-1);
    mode=(enum akeru_color_mode)99;
    CHECK(akeru_color_menu_event(&screen,0x580,&action,&mode)==-1 && screen==AKERU_COLOR && action==AKERU_OPEN_ISO);
    CHECK(akeru_color_select(&mode,AKERU_REQUEST_MONO)==-1 && (int)mode==99);
    CHECK(akeru_color_process(mode,raw,output,2,2)==-1 && output[0]==777);
    raw[3]=4096;
    CHECK(akeru_color_process(AKERU_COLOR_MONO_RAW,raw,output,2,2)==-1 && output[0]==777);
    CHECK(akeru_color_process(AKERU_COLOR_MONO_RAW,raw,raw,2,2)==-1 && raw[0]==1024);
    {
        uint16_t frame[25], full[25], strips[25];
        for (i=0;i<25;i++) { frame[i]=(uint16_t)(i*71); full[i]=strips[i]=0xaaaa; }
        CHECK(akeru_color_process(AKERU_COLOR_MONO_RAW,frame,full,5,5)==1);
        CHECK(akeru_color_process_rows(AKERU_COLOR_STANDARD,frame,strips,5,5,0,1)==0 && strips[0]==0xaaaa);
        CHECK(akeru_color_process_rows(AKERU_COLOR_MONO_RAW,frame,strips,5,5,0,1)==1);
        CHECK(akeru_color_process_rows(AKERU_COLOR_MONO_RAW,frame,strips+5,5,5,1,2)==1);
        CHECK(akeru_color_process_rows(AKERU_COLOR_MONO_RAW,frame,strips+15,5,5,3,2)==1);
        for (i=0;i<25;i++) CHECK(strips[i]==full[i] && frame[i]==i*71);
        strips[0]=0xaaaa;
        CHECK(akeru_color_process_rows(AKERU_COLOR_MONO_RAW,frame,strips,5,5,5,1)==-1 && strips[0]==0xaaaa);
        CHECK(akeru_color_process_rows((enum akeru_color_mode)99,frame,strips,5,5,0,1)==-1 && strips[0]==0xaaaa);
    }
    return 0;
}
