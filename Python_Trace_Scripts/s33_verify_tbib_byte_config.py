#!/usr/bin/env python3
"""Execute two original TBIB wrappers and their byte-to-halfword MMIO writer."""
import struct
from pathlib import Path
from s33_tbib_accessor_harness import execute
from s33_run_gnu_arc700 import ROOT

PARENT=ROOT/'Risultati/Processor_Registers/20261025T205524Z'
raw=(ROOT/'OriginalSoftware_NikonS33_V1.1/firmware.bin').read_bytes()
base,size,_,_=struct.unpack_from('<4I',raw,0x6c)
body=raw[0x7c:0x7c+size]
POOLS=[0x10053c0,0x10053d4,0x10053e8,0x10053fc,0x1005410,0x1005424,
       0x1005438,0x100544c,0x1005460,0x1005474,0x1005488,0x100549c]
STORES=[0x10053c4,0x10053d8,0x10053ec,0x1005400,0x1005414,0x1005428,
        0x100543c,0x1005450,0x1005464,0x1005478,0x100548c,0x10054a0]
ADDRESSES=[struct.unpack_from('<I',body,p-base)[0] for p in POOLS]

def word(p):return struct.unpack_from('<I',body,p-base)[0]

def build(seed,value):
    initial={a:(seed^(a>>2))&65535 for a in ADDRESSES}
    state=dict(initial);calls=[]
    for entry,pool in [(0x10056c4,0x10056ec),(0x10056cc,0x10056f4)]:
        pointer=word(pool);common=word(0x10056f0)
        values=list(struct.unpack_from('<11H',body,pointer-base))+[struct.unpack_from('<H',body,common-base)[0]]
        events=[(pc,'write',a,v) for pc,a,v in zip(STORES,ADDRESSES,values)]
        state.update(zip(ADDRESSES,values))
        calls.append(dict(entry=entry,kind='original_wrapper_byte_config',arguments=[],events=events,return0=None,
                          original_data_pointer=pointer,original_common_pointer=common))
    return dict(initial=initial,final=state,calls=calls)

if __name__=='__main__':
    execute(source=Path(__file__),parent=PARENT,action='original-tbib-byte-config',status='PASS_ORIGINAL_TBIB_BYTE_CONFIG',
            values=[0],seeds=[0,65535,0xa55a],builder=build,
            limits=['Both original wrappers10056C4/56CC and complete writer10053A8 execute with their original data pointers;not full100559C initializer orTBIBboot.',
                    'The tested tables supply22bytes plus2commonbytes;legal argument domains for other callers andphysical meanings remainunknown.',
                    'MMIO backing,seed andstack arefixtures;no hardware/reset/W1C/IRQ/timing or controller behavior proven.'])
