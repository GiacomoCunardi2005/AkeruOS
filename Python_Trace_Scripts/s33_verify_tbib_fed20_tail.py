#!/usr/bin/env python3
"""TBIB remaining FED2038 controls and FED2054/58/5C accessors."""
from pathlib import Path
from s33_tbib_accessor_harness import execute
from s33_run_gnu_arc700 import ROOT

PARENT=ROOT/'Risultati/Processor_Registers/20261025T203954Z'
VALUES=[0,1,2,7,8,15,16,23,24,31,32,0x80000000,0xffffffff]


def build(seed,value):
    initial={a:(seed^(a>>2))&65535 for a in [0xfed2038,0xfed2054,0xfed2058,0xfed205c]};state=dict(initial);calls=[]
    def call(entry,kind,args,events,ret=None):
        for pc,op,a,v in events:
            if op=='write':state[a]=v
        calls.append(dict(entry=entry,kind=kind,arguments=args,events=events,return0=ret))
    for entry,kind,bit in [(0x10036a4,'bit',2),(0x10036bc,'set',3),(0x10036d8,'bit',4),
        (0x10036f0,'set',5),(0x100370c,'bit',6),(0x1003724,'toggle',7)]:
        a=0xfed2038;old=state[a]
        if kind=='bit':call(entry,kind,[value],[(entry+12,'read',a,old)],(old>>bit)&1)
        elif kind=='set':call(entry,kind,[value],[(entry+12,'read',a,old),(entry+20,'write',a,old|(1<<bit))])
        else:
            rd,wr=(20,28) if value else (36,44);n=(old&~128)|(128 if value else 0)
            call(entry,kind,[value],[(entry+rd,'read',a,old),(entry+wr,'write',a,n)])
    a=0xfed2054;word=(seed^(value*0x1357))&65535
    call(0x1003758,'store16',[word],[(0x1003764,'write',a,word)])
    for entry,kind in [(0x100376c,'indexed_set'),(0x1003788,'indexed_clear')]:
        old=state[a];mask=1<<(value&31);n=((old|mask) if kind=='indexed_set' else (old&~mask))&65535
        call(entry,kind,[value],[(entry+12,'read',a,old),(entry+20,'write',a,n)])
    call(0x10037a4,'read_low8',[value],[(0x10037b0,'read',a,state[a])],state[a]&255)
    mask=1<<((value+8)&31)
    call(0x10037bc,'indexed_upper_bitmap',[value],[(0x10037cc,'read',a,state[a])],((state[a]&mask)>>8)&255)
    call(0x10037e4,'read_upper8',[value],[(0x10037f0,'read',a,state[a])],state[a]>>8)
    call(0x1003804,'pulse_0_then_1',[value],[(0x1003814,'write',0xfed2058,0),(0x100381a,'write',0xfed2058,1)])
    a=0xfed205c;old=state[a];n=(old&~3)|(value&3)
    call(0x1003824,'replace_low2',[value],[(0x1003834,'read',a,old),(0x1003842,'write',a,n)])
    call(0x100384c,'read_low2',[value],[(0x1003858,'read',a,state[a])],state[a]&3)
    call(0x1003864,'read_bits2_3',[value],[(0x1003870,'read',a,state[a])],(state[a]>>2)&3)
    assert len(calls)==16 and sum(len(c['events']) for c in calls)==23
    return dict(initial=initial,final=state,calls=calls)


if __name__=='__main__':
    execute(source=Path(__file__),parent=PARENT,action='original-tbib-fed20-tail',status='PASS_ORIGINAL_TBIB_FED20_TAIL',values=VALUES,seeds=[0,65535,0xa55a],builder=build,
        limits=['16originalroutines completed perselectedscenario;not fullTBIB boot orglobalreachability.',
            'Indexwrap is GNUmodelbehavior checked forselected32bitarguments;realNikon callerindexdomains andphysicalCPUimplementation unknown.',
            'Indexeduppergetter returns selectedbitmap inupperbyte,not normalizedboolean.',
            'Fullstores0→1 toFED2058 aresoftwareevents;physicalpulse/reset/W1C/timing notproved.',
            'OriginalTBIB intact;MMIObacking,seeds,stack andcallerarguments arefixtures;nohardware.'])
