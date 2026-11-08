#!/usr/bin/env python3
"""Execute original1014B08 using both original descriptor groups and nested services."""
import struct
from pathlib import Path
from s33_tbib_nested_context_harness import execute
from s33_run_gnu_arc700 import ROOT
PARENT=ROOT/'Risultati/Processor_Registers/20261025T210538Z'
raw=(ROOT/'OriginalSoftware_NikonS33_V1.1/firmware.bin').read_bytes();base,size,_,_=struct.unpack_from('<4I',raw,0x6c);body=raw[0x7c:0x7c+size]
TABLES=[]
for pointer in [0x1040800,0x104088c]:
    ack,mask,count=struct.unpack_from('<IIH',body,pointer-base)
    records=[struct.unpack_from('<HBBI',body,pointer-base+12+8*i) for i in range(count)]
    TABLES.append(dict(pointer=pointer,ack=ack,mask=mask,count=count,records=records))
assert [t['count'] for t in TABLES]==[7,8]

def build(seed,flag,depth):
    initial={a:(seed^(a>>2))&65535 for a in [TABLES[0]['ack'],TABLES[0]['mask'],TABLES[1]['mask']]};state=dict(initial);calls=[]
    for j,t in enumerate(TABLES):
        for i,(key,ab,mb,callback) in enumerate(t['records']):
            events=[]
            if j==0:
                a=t['ack'];v=1<<ab;events.append((0x1014b58,'write',a,v));state[a]=v
            a=t['mask'];old=state[a];v=old|(1<<mb) if flag else old&~(1<<mb);pc=0x1014ba8 if flag else 0x1014bb8
            events.extend([(pc,'read',a,old),(pc+8,'write',a,v)]);state[a]=v
            calls.append(dict(entry=0x1014b08,arguments=[key,flag],return0=depth,events=events,table=t['pointer'],record_index=i,kind='original_descriptor_mask'))
    for key in [0,0x3000,0x3008,0x4000,0x4009]:
        calls.append(dict(entry=0x1014b08,arguments=[key,flag],return0=key,events=[],kind='no_match_no_status_normalization'))
    return dict(initial=initial,final=state,calls=calls)

if __name__=='__main__':
    execute(source=Path(__file__),parent=PARENT,action='original-tbib-delegated-table',status='PASS_ORIGINAL_TBIB_DELEGATED_TABLE',builder=build,extra=dict(original_tables=TABLES),
        limits=['Complete1014B08 andoriginalnestedservices execute;outer1014BCC/4C64 callbacks andruntimeflagstate notexecuted.',
                'Originaltables1040800(count7)/104088C(count8) usedunchanged;secondackheaderFED3834 notaccessed andnotadmitted.',
                'Contextglobal104126C temporarily points to explicit harness.data andisrestored;depth1/2/7,gate+24=1;FLAG/IRQ/non-nestedpaths unproved.',
                'Matched helperreturns depth through1013DFC inselectedfixture;unmatched preservesselector,not a normalized publicerrorcontract.',
                'MMIOmodel/seeds,notphysicalreset/W1C/IRQ/timing;nohardwareorTBIBboot.'])
