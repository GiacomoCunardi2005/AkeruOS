#!/usr/bin/env python3
"""Execute registration-enabled outer calls and their original FED38 callback."""
import struct
from pathlib import Path
from s33_run_gnu_arc700 import ROOT
from s33_tbib_nested_context_harness_v2 import execute
PARENT=ROOT/'Risultati/Processor_Registers/20261026T112040Z'
raw=(ROOT/'OriginalSoftware_NikonS33_V1.1/firmware.bin').read_bytes();base,size,_,_=struct.unpack_from('<4I',raw,0x6c);body=raw[0x7c:0x7c+size]
TABLES=[]
for ptr in [0x1040800,0x104088c]:
    ack,mask,n=struct.unpack_from('<IIH',body,ptr-base);rs=[struct.unpack_from('<HBBI',body,ptr-base+12+8*i) for i in range(n)]
    TABLES.append(dict(pointer=ptr,ack=ack,mask=mask,count=n,records=rs))

def build(seed,flag,depth):
    addresses={0xfef0028,*[a for t in TABLES for a in [t['ack'],t['mask']]]}
    initial={a:(seed^(a>>2))&65535 for a in addresses};state=dict(initial);calls=[];masks=[0,0]
    def outer(on,group,index,r):
        key,ab,mb,cb=r;t=TABLES[group];events=[];before=list(masks);bit=(key&31)-1
        register=(not any(masks)) if on else False
        if on:masks[group]|=1<<bit
        else:masks[group]&=~(1<<bit);register=not any(masks)
        if register:
            a=0xfef0028;old=state[a];v=(old|0x8000) if on else (old&0x7fff);pc=0x10048ec if on else 0x10049ae
            events.extend([(pc,'read',a,old),(pc+8,'write',a,v)]);state[a]=v
        if group==0:events.append((0x1014b58,'write',t['ack'],1<<ab));state[t['ack']]=1<<ab
        a=t['mask'];old=state[a];v=(old|(1<<mb)) if on else (old&~(1<<mb));pc=0x1014ba8 if on else 0x1014bb8
        events.extend([(pc,'read',a,old),(pc+8,'write',a,v)]);state[a]=v
        calls.append(dict(entry=0x1014bcc if on else 0x1014c64,arguments=[key],return0=0,events=events,kind='registration_enabled_outer',
                          group=group,record_index=index,ram_masks_before=before,ram_masks_after=list(masks),parent_registration=register))
    for j,t in enumerate(TABLES):
        for i,r in enumerate(t['records']):outer(True,j,i,r)
    events=[]
    for group,t in enumerate(TABLES):
        for index,(key,ab,mb,cb) in enumerate(t['records']):
            pc=0x1014d98 if group==0 else 0x1014dfa
            enabled=state[t['mask']];events.append((pc,'read',t['mask'],enabled))
            if not enabled&(1<<mb):continue
            pc=0x1014db0 if group==0 else 0x1014e12
            pending=state[t['ack']];events.append((pc,'read',t['ack'],pending))
            if not pending&(1<<ab):continue
            assert cb==0
            v=1<<ab;events.append((0x1014dde if group==0 else 0x1014e40,'write',t['ack'],v));state[t['ack']]=v
    calls.append(dict(entry=0x1014d6c,arguments=[],return0=8,events=events,kind='original_registered_callback_zero_child_slots'))
    for j,t in enumerate(TABLES):
        for i,r in enumerate(t['records']):outer(False,j,i,r)
    calls.append(dict(entry=0x1004a78,arguments=[0x610,0],return0=0,events=[],kind='original_registration_api_clear_callback_slot'))
    assert masks==[0,0] and len(calls)==32
    return dict(initial=initial,final=state,calls=calls,
        setup_asm='mov r0,1\nstb r0,[0x10411e4]\n',
        teardown_asm='ld r0,[0x1040628]\ncmp r0,0\nbne fail\nmov r0,0\nstb r0,[0x10411e4]\n')

if __name__=='__main__':
    execute(source=Path(__file__),parent=PARENT,action='original-tbib-registered-callback',status='PASS_ORIGINAL_TBIB_REGISTERED_CALLBACK',builder=build,values=[0],
        extra=dict(original_tables=TABLES,identity_value_is_model_state=True),
        limits=['Harness temporarily sets RAMgate10411E4=1,as originalinit stores1;restores0. No code/table descriptor header patches;callbackslot1040628 installed/cleared byoriginal1004A78.',
                'IDENTITY AUX4 reads0 from GNUlowbank model;not NikonID/BCR/resetmeasurement andnot branch13030513. No SRidentity ornewCPUmodel.',
                'Originalcallback1014D6C is called byharness afteroriginalregistration;not an IRQ ororiginalparentdispatcher delivery proof. Childcallbackslots remainoriginalzero.',
                'MMIO hasplainstoragefixtures:onehotstore overwritespendingword inmodel;doesnotprove realW1C/ack/IRQbehavior orsnapshotatomicity.',
                'Nestedcontextdepth1/2/7,gate+24=1;no non-nestedFLAGpaths/hardware/TBIBboot/install.'])
