#include "camera/mono_raw.h"
#ifdef AKERU_GNU_TEST
void test_fail(unsigned line) __attribute__((noreturn));
#define CHECK(x) ((x) ? (void)0 : test_fail(__LINE__))
#else
#include <assert.h>
#define CHECK(x) assert(x)
#endif
int main(void)
{
    static const uint16_t input[25] = {0,33,1000,4092,13,123,4092,333,7,3000,4095,120,1010,2050,3,1,1800,2048,8,4000,89,2345,700,3600,17};
    /* Independently generated with s33_mono_reference.luminance, rounded to RAW units. */
    static const uint16_t expected[25] = {478,632,1646,3116,2542,1272,1099,824,1883,2149,1886,1340,1342,1655,2159,965,1541,1876,2253,2865,1058,2010,2259,2709,2725};
    uint16_t out[25], strips[25], bad[4] = {0,0,0,4096};
    unsigned i;
    CHECK(akeru_mono_raw(input,out,5,5)==0);
    for (i=0;i<25;i++) CHECK(out[i]+1>=expected[i] && out[i]<=expected[i]+1);
    CHECK(akeru_mono_raw_rows(input,strips,5,5,0,1)==0);
    CHECK(akeru_mono_raw_rows(input,strips+5,5,5,1,2)==0);
    CHECK(akeru_mono_raw_rows(input,strips+15,5,5,3,2)==0);
    for (i=0;i<25;i++) CHECK(strips[i]==out[i]);
    strips[0]=1234;
    CHECK(akeru_mono_raw_rows(input,strips,5,5,5,1)==-1 && strips[0]==1234);
    CHECK(akeru_mono_raw_rows(input,strips,5,5,4,2)==-1 && strips[0]==1234);
    CHECK(akeru_mono_raw_rows(input,strips,5,5,0,0)==-1 && strips[0]==1234);
    CHECK(akeru_mono_raw_rows(bad,strips,2,2,0,1)==-1 && strips[0]==1234);
    CHECK(akeru_mono_raw_rows(input,(uint16_t *)input,5,5,1,1)==-1);
    out[0]=1234;
    CHECK(akeru_mono_raw(bad,out,2,2)==-1 && out[0]==1234);
    CHECK(akeru_mono_raw(input,out,1,5)==-1 && out[0]==1234);
    CHECK(akeru_mono_raw(input,out,SIZE_MAX,2)==-1 && out[0]==1234);
    CHECK(akeru_mono_raw(out,out,2,2)==-1 && out[0]==1234);
    CHECK(akeru_mono_raw(out,out+1,2,2)==-1 && out[0]==1234);
    CHECK(akeru_mono_raw(0,out,2,2)==-1 && out[0]==1234);
    CHECK(akeru_mono_raw(input,0,2,2)==-1);
    return 0;
}
