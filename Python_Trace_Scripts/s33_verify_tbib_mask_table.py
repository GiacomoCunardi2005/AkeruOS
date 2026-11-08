#!/usr/bin/env python3
"""Execute original TBIB masked initializer with its original caller-bound table."""
import struct
from pathlib import Path
from s33_tbib_accessor_harness import execute
from s33_run_gnu_arc700 import ROOT

PARENT=ROOT/'Risultati/Processor_Registers/20261025T204714Z'
TABLE=0x1043258
raw=(ROOT/'OriginalSoftware_NikonS33_V1.1/firmware.bin').read_bytes()
base,size,_,_=struct.unpack_from('<4I',raw,0x6c);body=raw[0x7c:0x7c+size]
ROWS=[]
for i in range(256):
    a,m,v=struct.unpack_from('<IHH',body,TABLE-base+8*i)
    if a==0:break
    assert 0xfe00000<=a<0x10000000
    ROWS.append((a,m,v))
assert i==68 and len({r[0] for r in ROWS})==44


def build(seed,value):
    initial={a:(seed^(a>>2))&65535 for a in {x[0] for x in ROWS}}
    state=dict(initial);calls=[]
    def append(e,kind,args,events,ret=None,**meta):
        for p,op,a,v in events:
            if op=='write':state[a]=v
        calls.append(dict(entry=e,kind=kind,arguments=args,events=events,return0=ret,**meta))
    def getter(e,a,bit,inverted=False):
        old=state[a];ret=((old>>bit)&1)^int(inverted)
        append(e,'inverted_bit_getter' if inverted else 'bit_getter',[value],[(e+12,'read',a,old)],ret)
    def single(e,a,setbit):
        old=state[a];new=(old|2) if setbit else (old&~2)
        append(e,'set_bit1' if setbit else 'clear_bit1',[value],[(e+12,'read',a,old),(e+20,'write',a,new)])
    getter(0x1004568,0xff04020,15);getter(0x1004580,0xff04024,0)
    getter(0x10045f4,0xfef00d8,1,True)
    single(0x10045bc,0xfef00d8,False);getter(0x10045f4,0xfef00d8,1,True)
    single(0x10045d8,0xfef00d8,True);getter(0x10045f4,0xfef00d8,1,True)
    getter(0x1004614,0xff04000,8,True);getter(0x1004630,0xff04000,5)
    a=0xff04004;ev=[]
    if value in [1,4]:
        pc=0x100468c if value==1 else 0x1004670;new=state[a]&~0x200 if value==1 else state[a]|0x200
        ev=[(pc,'read',a,state[a]),(pc+8,'write',a,new)]
    append(0x1004648,'mode1_clear_mode4_set_else_error',[value],ev,int(value not in [1,4]))
    a=0xfef00d8;ev=[]
    if value in [1,2]:
        pc=0x10046d4 if value==1 else 0x10046ec;new=state[a]|1 if value==1 else state[a]&~1
        ev=[(pc,'read',a,state[a]),(pc+8,'write',a,new)]
    append(0x10046ac,'mode1_set_mode2_clear_else_error',[value],ev,int(value not in [1,2]))
    a=0xfef0144;events=[(0x1004484,'read',a,state[a]),(0x1004492,'write',a,(state[a]&~0x3ff)|0x2aa)]
    state[a]=(state[a]&~0x3ff)|0x2aa
    for a,mask,v in ROWS:
        old=state[a];new=((old&~mask)|(v&mask))&65535
        events.extend([(0x10044a2,'read',a,old),(0x10044b4,'write',a,new)]);state[a]=new
    append(0x1004468,'original_68_record_masked_initializer',[TABLE],events,None,table_address=TABLE,table_record_count=68,original_table_records=ROWS)
    getter(0x10045f4,0xfef00d8,1,True);getter(0x1004614,0xff04000,8,True)
    getter(0x1004568,0xff04020,15);getter(0x1004580,0xff04024,0)
    assert len(calls)==16 and len(state)==44
    return dict(initial=initial,final=state,calls=calls)


if __name__=='__main__':
    execute(source=Path(__file__),parent=PARENT,action='original-tbib-masked-table',status='PASS_ORIGINAL_TBIB_MASKED_TABLE',
        values=[0,1,2,3,4,0xffffffff],seeds=[0,65535,0xa55a],builder=build,
        limits=['1004468 completed with original68record table1043258;originalBLcaller/tablepointer isstaticproof,not complete1004440initializerexecution.',
            'Table records,duplicates andterminator areoriginalbytes;not syntheticrecordadmissions orlegalbounds forothercallerparameters.',
            'MMIObacking,seeds,stack arefixtures;allphysicalreset/W1C/IRQ/timing/latch/SoCnames andrealcallerreachability unproved.',
            'Leafmodeerrors are software return1 withnoMMIOoninvalidtestedvalues,not observeddeviceerrorcodes.'])
