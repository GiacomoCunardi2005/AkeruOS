#!/usr/bin/env python3
"""Execute both original category7/B table helpers and their original scan callbacks."""
import struct
from pathlib import Path
from s33_run_gnu_arc700 import ROOT
from s33_tbib_nested_context_harness_v2 import execute
PARENT=ROOT/'Risultati/Processor_Registers/20261026T114224Z'
raw=(ROOT/'OriginalSoftware_NikonS33_V1.1/firmware.bin').read_bytes();base,size,_,_=struct.unpack_from('<4I',raw,0x6c);body=raw[0x7c:0x7c+size]
SPECS=[dict(entry=0x1014e58,callback=0x1014fe8,pointer=0x1040a00,category=0x7000,write=0x1014ea8,setread=0x1014eba,clearread=0x1014eca,
            cbmask=0x101500c,cbpending=0x1015024,cbwrite=0x1015052),
       dict(entry=0x1015068,callback=0x10151fc,pointer=0x1040b00,category=0xb000,write=0x10150b8,setread=0x10150ca,clearread=0x10150da,
            cbmask=0x1015224,cbpending=0x101523c,cbwrite=0x101526a)]
for s in SPECS:
    s['ack'],s['mask'],s['count']=struct.unpack_from('<IIH',body,s['pointer']-base)
    s['records']=[struct.unpack_from('<HBBI',body,s['pointer']-base+12+8*i) for i in range(s['count'])]
assert [s['count'] for s in SPECS]==[16,13]

def build(seed,flag,depth):
    initial={a:(seed^(a>>2))&65535 for s in SPECS for a in [s['ack'],s['mask']]};state=dict(initial);calls=[]
    for s in SPECS:
        for ordinal,(key,ab,mb,cb) in enumerate(s['records']):
            assert ab==mb and cb==0
            old=state[s['mask']];new=old|(1<<mb) if flag else old&~(1<<mb);pc=s['setread'] if flag else s['clearread']
            ev=[(s['write'],'write',s['ack'],1<<ab),(pc,'read',s['mask'],old),(pc+8,'write',s['mask'],new)]
            state[s['ack']]=1<<ab;state[s['mask']]=new
            calls.append(dict(entry=s['entry'],arguments=[key,flag],return0=depth,events=ev,kind='original_onehot_then_mask',table=s['pointer'],record_index=ordinal))
        ev=[]
        for key,ab,mb,cb in s['records']:
            enabled=state[s['mask']];ev.append((s['cbmask'],'read',s['mask'],enabled))
            if not enabled&(1<<mb):continue
            pending=state[s['ack']];ev.append((s['cbpending'],'read',s['ack'],pending))
            if not pending&(1<<ab):continue
            assert cb==0;v=1<<ab;ev.append((s['cbwrite'],'write',s['ack'],v));state[s['ack']]=v
        calls.append(dict(entry=s['callback'],arguments=[],return0=s['count'],events=ev,kind='original_callback_zero_child_slots',table=s['pointer']))
        for key in [0,s['category'],s['category']+s['count']+1,0xffffffff]:
            calls.append(dict(entry=s['entry'],arguments=[key,flag],return0=key,events=[],kind='unmatched_selector',table=s['pointer']))
    assert len(calls)==39
    return dict(initial=initial,final=state,calls=calls)

if __name__=='__main__':
    execute(source=Path(__file__),parent=PARENT,action='original-tbib-7b-tables',status='PASS_ORIGINAL_TBIB_7B_TABLES',builder=build,extra=dict(specs=SPECS),
        limits=['Complete helpers1014E58/1015068 andcallbacks1014FE8/10151FC execute withoriginaltables1040A00/1040B00;outerregistration1014EE0/4F48/50F0/5158 notexecuted.',
                'All29original selectors plus4unmatched perhelper aretested;flag0/1/2/FFFFFFFF. No universalcaller-domain orphysicalregisteruniverse claim.',
                'Callbacks calledbyharness,childslots remainoriginalzero;no parentdispatcher/IRQdelivery claim. OrdinaryMMIOstorage isnotW1C/ack/reset evidence.',
                'Nestedcontextdepth1/2/7,gate+24=1,global104126C temporarilybound andrestored;noFLAG/LR/SR orhardware/TBIBboot/install.'])
