#!/usr/bin/env python3
"""Execute full original FED38 outer callers with original registration-disabled state."""
import struct
from pathlib import Path
from s33_run_gnu_arc700 import ROOT
from s33_tbib_nested_context_harness import execute
PARENT=ROOT/'Risultati/Processor_Registers/20261026T111110Z'
raw=(ROOT/'OriginalSoftware_NikonS33_V1.1/firmware.bin').read_bytes();base,size,_,_=struct.unpack_from('<4I',raw,0x6c);body=raw[0x7c:0x7c+size]
assert body[0x10411e4-base]==0 and body[0x1041390-base:0x1041390-base+4]==bytes(4)
TABLES=[]
for pointer in [0x1040800,0x104088c]:
    ack,mask,count=struct.unpack_from('<IIH',body,pointer-base)
    records=[struct.unpack_from('<HBBI',body,pointer-base+12+8*i) for i in range(count)]
    TABLES.append(dict(pointer=pointer,ack=ack,mask=mask,count=count,records=records))

def build(seed,pattern,depth):
    initial={a:(seed^(a>>2))&65535 for a in [TABLES[0]['ack'],TABLES[0]['mask'],TABLES[1]['mask']]};state=dict(initial);masks=[0,0];calls=[]
    items=[(j,i,r) for j,t in enumerate(TABLES) for i,r in enumerate(t['records'])]
    if pattern==0:sequence=[(on,item) for item in items for on in [True,False]]
    else:
        sequence=[(True,item) for item in items]
        if pattern==2:sequence += [(True,item) for item in items]
        sequence += [(False,item) for item in (list(reversed(items)) if pattern==0xffffffff else items)]
    for on,(group,ordinal,(key,ab,mb,cb)) in sequence:
        before=list(masks);bit=(key&31)-1
        if on:
            ret=0x200604 if not any(masks) else 0;masks[group]|=1<<bit
        else:
            masks[group]&=~(1<<bit);ret=0x200604 if not any(masks) else 0
        t=TABLES[group];events=[]
        if group==0:
            a=t['ack'];v=1<<ab;events.append((0x1014b58,'write',a,v));state[a]=v
        a=t['mask'];old=state[a];new=(old|(1<<mb)) if on else (old&~(1<<mb));pc=0x1014ba8 if on else 0x1014bb8
        events.extend([(pc,'read',a,old),(pc+8,'write',a,new)]);state[a]=new
        calls.append(dict(entry=0x1014bcc if on else 0x1014c64,kind='enable_outer' if on else 'disable_outer',arguments=[key],return0=ret,
                          events=events,table=t['pointer'],record_index=ordinal,ram_masks_before=before,ram_masks_after=list(masks),group=group))
    assert masks==[0,0]
    return dict(initial=initial,final=state,calls=calls)

if __name__=='__main__':
    execute(source=Path(__file__),parent=PARENT,action='original-tbib-outer-callers',status='PASS_ORIGINAL_TBIB_OUTER_CALLERS',builder=build,
        extra=dict(original_tables=TABLES,pattern_meaning={'0':'pair_each','1':'all_then_clear','2':'all_duplicate_then_clear','ffffffff':'all_then_reverse_clear'}),
        limits=['Complete1014BCC/1014C64 execute withoriginal global10411E4=0 registrationdisabled;failurecode200604 doesnot preventlaterMMIO.',
                'Patterns pair/all/duplicate/reverse selected throughharnessflag;outerarguments areoriginal15selectors only. No proof ofinvalid orotherselector domains.',
                'RAM masks1041390/+2 andcontextglobal104126C returntooriginalbytes;contextdepth1/2/7,gate+24=1 arefixtures,notreset evidence.',
                'Real registrationenabled branch(identity/callbackinstall),non-nestedFLAG/IRQ andphysicaldevicebehavior unproven;nohardware/boot/install.'])
