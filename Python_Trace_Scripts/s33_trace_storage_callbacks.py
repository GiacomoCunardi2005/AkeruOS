#!/usr/bin/env python3
"""Offline V1.1 registered storage callback family and pre-close control paths."""
import json
import re
import struct
import tempfile
from pathlib import Path
from s33_trace_state_dispatch import verified_payloads, run, sha

ROOT=Path(__file__).resolve().parents[1]
WINDOWS=[
 (0x1F3554,0x1F359E,'RegisterCallbackFamily'),
 (0x2A3C5C,0x2A3CB0,'RegistrarSavesCallbackArguments'),
 (0x2A3DA2,0x2A3DC8,'RegistrarStoresCallbackSlots'),
 (0x1F22C0,0x1F2348,'GenericCloseCallbackAndResult'),
 (0x1F2348,0x1F2394,'GenericControlDispatcher'),
 (0x1FA090,0x1FA0C0,'GenericWriteCallback'),
 (0x1F48A4,0x1F48E8,'RegisteredCloseCallback'),
 (0x1F4958,0x1F49A4,'RegisteredWriteCallback'),
 (0x1F56B4,0x1F5724,'RegisteredControlEntry'),
 (0x1F5738,0x1F57C8,'ControlTableDispatch'),
 (0x1F5F24,0x1F5F42,'Control3015'),
 (0x1F615A,0x1F6188,'Control3038AndResultOverwrite'),
 (0x1F60EC,0x1F60F2,'ControlUnlockAndReturn'),
 (0x1F6116,0x1F611A,'Control3015Tail'),
 (0x12D604,0x12D6FC,'FileCloseControlsAndHandleClear'),
 (0x1F2484,0x1F250C,'Control3015Worker'),
]


def main():
    blocks,payloads,block_dir=verified_payloads(ROOT)
    info={b['index']:b for b in blocks}
    out=ROOT/'Ghidra_Results/ghidra_reports/storage_callbacks'
    out.mkdir(parents=True,exist_ok=True)
    tools=ROOT/'work/build-arc/binutils'
    def word(a):return struct.unpack_from('<I',payloads[0],a-info[0]['load_address_candidate'])[0]
    callbacks={0xC:0x1F43AC,0x10:0x1F48A4,0x14:0x1F48E8,0x18:0x1F4958,0x1C:0x1F56B4,0x20:0x1F618C}
    assert [word(a) for a in range(0x1F3900,0x1F3918,4)]==list(callbacks.values())
    for site,offset,target in [(0x1F357E,228,0x1F4958),(0x1F3582,228,0x1F56B4),(0x1F3586,228,0x1F618C)]:
        assert word((site&~3)+offset*4)==target
    assert word(0x12D708)==0x3038 and word(0x12D70C)==0x3015
    assert word(0x1F6290)==0x1A09
    assert word(0x1F5734)==0x1F35FC
    table=[]
    for command,target in [(0x3015,0x1F5F24),(0x3038,0x1F615A)]:
        entry=0x1F57C8+2*(command-0x3002)
        delta=struct.unpack_from('<h',payloads[0],entry-info[0]['load_address_candidate'])[0]
        assert 0x1F57C8+2*delta==target
        table.append(dict(command=hex(command),entry=hex(entry),signed_halfword=delta,target=hex(target)))
    listings=[]
    with tempfile.TemporaryDirectory(prefix='s33-storage-') as td:
        elf,back=Path(td)/'0.elf',Path(td)/'0.bin'
        run([tools/'objcopy','-I','binary','-O','elf32-littlearc','-B','arc',
             '--rename-section','.data=.text,alloc,load,readonly,code,contents',
             '--change-section-vma',f'.data={info[0]["load_address_candidate"]:#x}',
             '--strip-all',block_dir/info[0]['file'],elf])
        run([tools/'objcopy','--dump-section',f'.text={back}',elf])
        assert back.read_bytes()==payloads[0]
        for start,end,label in WINDOWS:
            t=run([tools/'objdump','-d','-m','arc:ARC700','-EL',f'--start-address={start:#x}',f'--stop-address={end:#x}',elf])
            assert 'out of bounds' not in t.lower(),label
            listings.append(f'WINDOW {label}\n'+t.replace(str(elf),'verified-block0.elf'))
    listing='\n'.join(listings)
    def line(a):
        found=[l for l in listing.splitlines() if re.match(rf'^\s*{a:x}:',l)]
        assert len(found)==1,(hex(a),found)
        return found[0]
    edges=[(0x1F358A,0x2A3C5C),(0x12D682,0x1F2348),(0x12D69A,0x1F2348),
           (0x12D6BC,0x1F22C0),(0x1F5F38,0x1F2484),(0x1F616A,0x1F28A4),
           (0x1F5F3E,0x1F6116),(0x1F6118,0x1F60EC),(0x1F60F0,0x1F6180),
           (0x1F24EC,0x2A0C60)]
    for a,b in edges:assert f';0x{b:x}' in line(a),line(a)
    checked={0x2A3DAE:'r21,[r0,16]',0x2A3DB6:'r23,[r0,24]',0x2A3DBA:'r24,[r0,28]',
             0x1F2324:'jl_s.d',0x1FA0B6:'jl_s',0x1F2372:'jl.d',
             0x1F6174:'st_s\tr0,[sp,0xc]',0x1F617C:'ld_s\tr0,[pcl,0x114]',
             0x1F617E:'st_s\tr0,[sp,0xc]',0x12D6D6:'st\tr0,[r16]',
             0x1F24EA:'mov_s\tr1,0xa'}
    for a,needle in checked.items():assert needle in line(a),line(a)
    result=dict(firmware='S33 V1.1 static only',verified_blocks=16,elf_roundtrip_blocks=[0],
        script_sha256=sha(Path(__file__).read_bytes()),block_sha256={str(b['index']):b['sha256'] for b in blocks},
        windows=[dict(start=hex(a),end=hex(b),label=l) for a,b,l in WINDOWS],
        registered_family=dict(registration='0x1f3554 -> 0x2a3c5c',slots={hex(k):hex(v) for k,v in callbacks.items()},
            condition='Valid for handles whose device pointer selects an instance installed through this path; active SD binding not proved'),
        control_table=table,checked_edges=[dict(site=hex(a),target=hex(b)) for a,b in edges],
        observations={
            '3015':'Selected worker result from 0x1f2484 is not copied to local result slot before control return',
            '3038':'Result slot written at 0x1f6174 is overwritten with literal 0x1a09 at 0x1f617c/7e',
            'close':'First control return is ignored; second return gates driver close; after close, caller handle is cleared even on callback error',
            'worker':'0x1f2484 conditionally calls 0x2a0c60 with operation 10; low-level storage effect not yet resolved',
        },
        limits=['Does not prove every camera file uses this registered family',
                'Alternate backends exist in registered write/close callbacks',
                'No SD persistence guarantee, runtime call trace or hardware V1.0 equivalence'])
    (out/'gnu_verified.txt').write_text(listing)
    (out/'verified_evidence.json').write_text(json.dumps(result,indent=2)+'\n')
    print(f'PASS: 16 hashes, block-00 roundtrip, {len(WINDOWS)} windows, {len(edges)} edges, 2 table entries, {len(checked)} instruction checks')

if __name__=='__main__':main()
