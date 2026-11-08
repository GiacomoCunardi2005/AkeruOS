#include "camera/mono_raw.h"
#ifdef AKERU_GNU_TEST
void test_fail(unsigned line) __attribute__((noreturn));
#define CHECK(x) ((x) ? (void)0 : test_fail(__LINE__))
#else
#include <assert.h>
#define CHECK(x) assert(x)
#endif
int akeru_mono_raw_baseline(const uint16_t *, uint16_t *, size_t, size_t);
int main(void)
{
    uint16_t raw[100], old[100], current[100];
    uint32_t seed=123456789u;
    size_t w,h,i; unsigned mode;
    for (h=2;h<=10;h++) for (w=2;w<=10;w++) for (mode=0;mode<3;mode++) {
        for (i=0;i<w*h;i++) {
            seed=1664525u*seed+1013904223u;
            raw[i]=mode==0 ? 0 : mode==1 ? 4095 : (uint16_t)((seed>>12)&4095);
        }
        CHECK(akeru_mono_raw_baseline(raw,old,w,h)==0);
        CHECK(akeru_mono_raw(raw,current,w,h)==0);
        for (i=0;i<w*h;i++) CHECK(old[i]==current[i]);
    }
    return 0;
}
