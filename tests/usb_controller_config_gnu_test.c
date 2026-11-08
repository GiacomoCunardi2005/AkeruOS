/* Original endpoint configuration; register I/O, allocation and locks are fixtures. */
#define main open_buffer_reference_tests
#define boundary_read reference_read
#define boundary_write reference_write
#define boundary_modify reference_modify
#include "usb_open_buffer_gnu_test.c"
#undef main
#undef boundary_read
#undef boundary_write
#undef boundary_modify
static uint32_t config_phase,initial_control,final_control,config_writes;
static uint32_t feature,sg_mode,ep_number,template_mask,template_ep,config_modifies;
static uint32_t submissions;

uint32_t config_read(uint32_t address)
{
    if (!config_phase) return reference_read(address);
    CHECK(depth==1 && address==EPREG);++reads;return initial_control;
}
uint32_t config_write(uint32_t address,uint32_t value)
{
    if (!config_phase) return reference_write(address,value);
    CHECK(depth==1);
    if (address==EPREG) { CHECK(config_writes==0);final_control=value; }
    else {
        CHECK(feature && address==BASE+(direction ? 0x40u:0x80u)+4*ep_number);
        uint32_t set=direction ? 0x12Fu:7u;
        CHECK(value==(template_ep|set|(sg_mode ? 0x200u:0)));
    }
    ++config_writes;return 0;
}
uint32_t config_modify(uint32_t address,uint32_t mask,uint32_t value)
{
    if (!config_phase) return reference_modify(address,mask,value);
    CHECK(depth==1 && mask==0 && address==BASE+(feature ? 0x3Cu:0x1Cu));
    uint32_t shift=direction ? 0:16;
    CHECK(value==((template_mask&~(0xFFFFu<<shift))|((1u<<ep_number)<<shift)));
    ++config_modifies;return 0;
}
int main(void)
{
    static const uint32_t numbers[]={1,3,15};
    cases=0;
    for (uint32_t dir=0;dir<2;++dir)
    for (uint32_t e=0;e<3;++e)
    for (uint32_t p=0;p<2;++p)
    for (uint32_t sg=0;sg<2;++sg)
    for (uint32_t f=0;f<2;++f)
    for (uint32_t active=0;active<2;++active)
    for (uint32_t type=1;type<4;++type)
    for (uint32_t pattern=0;pattern<2;++pattern) {
        config_phase=0;reset(dir,numbers[e],p ? 512:64,sg,type);
        feature=f;sg_mode=sg;ep_number=numbers[e];B(CTRL+101)=f;
        template_mask=pattern ? 0xA5A55A5Au:0;
        /* Keep bit9 set in the patterned template to test the sg=0 preservation path. */
        template_ep=pattern ? 0xA5A5A7FFu:0;
        W(0x3533EC)=template_mask;W(0x3533F0)=W(0x3533F4)=template_ep;
        initial_control=(pattern ? 0x4A358155u:0)&~0x8000u;
        initial_control|=active<<15;final_control=initial_control;
        reads=config_writes=config_modifies=0;
        config_phase=1;
        CHECK(CALL2(0x27864C,EP,USB)==0);
        CHECK(reads==1 && config_modifies==1 && depth==0 && configured==0);
        CHECK(acquires==1 && releases==1 && W(node)==USB && W(node+64)==EP);
        CHECK(config_writes==!active+f);
        uint32_t fifo=ep_number==1 ? 1:ep_number==3 ? 2:0;
        CHECK(((W(node+16)>>10)&15)==fifo);
        uint32_t expected=(initial_control&~(0x7FFu|0xC0000u|0x3C00000u))
                          |packet|(type<<18)|(fifo<<22)|0x10008000u;
        CHECK(final_control==(active ? initial_control:expected));
        CHECK((W(node+52)&0x7FFFFu)==0 && H(EP+20)==packet);
        uint32_t ring=sg && type!=1;
        CHECK(allocations==ring && allocated_bytes==512*ring);
        CHECK(W(node+32)==(ring ? (uint32_t)(uintptr_t)heap[0]:0));
        config_phase=0;
        if (type==2 && !sg) {
            reads=writes=modifies=0;B(CTRL+98)=1;W(REQ+4)=32;
            CHECK(CALL3(0x278854,EP,REQ,32)==0);
            CHECK(allocations==1 && W(REQ+32)==(uint32_t)-10 && W(DEV+16)==1);
            CHECK(W(node+4)==(uint32_t)(uintptr_t)heap[0] && depth==0);
            CHECK(writes==3+dir);
            write_is(0,EPREG+0x10,(1u<<19)|(dir ? 32:packet));
            write_is(1,EPREG+0x14,BUF);write_is(2,EPREG,0x84000000);
            ++submissions;
        }
        for (uint32_t i=0;i<256;++i) CHECK(W(BUF+4*i)==0x12340000+i);
        ++cases;
    }
    CHECK(cases==576 && submissions==96);return 0;
}
