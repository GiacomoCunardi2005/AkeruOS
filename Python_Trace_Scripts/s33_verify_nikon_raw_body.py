#!/usr/bin/env python3
"""Run the proposed wrapper through original25F428; record hardware boundaries."""
from datetime import datetime, timezone
from pathlib import Path
from types import SimpleNamespace
import json
import re
import struct
import sys
from s33_run_gnu_arc700 import ROOT,LEGACY,TOOLCHAIN,Runner,sha
from s33_verify_gnu_dsp_lab import compile_probe
sys.path.insert(0,str(ROOT/'S33-sections/analysis_codex'))
from static_common import BS,PS,raw,u32,locate,disasm
CURRENT,STATES,STRIDE=0x2010000,0x2100000,4096
CODE,BUFFER=0x500000,0x2060000
BRIDGE=r'''
#include "nikon_raw_read.h"
void *memset(void *destination,int value,size_t length)
{
    volatile uint8_t *p=destination;
    size_t i;
    for(i=0;i<length;++i) p[i]=(uint8_t)value;
    return destination;
}
int bridge(unsigned chip,unsigned block,unsigned page)
{
    struct nikon_raw_context context={512}; /* Independent proof is fixture-only. */
    return nikon_raw_read(&context,(uint8_t)chip,(uint16_t)block,(uint8_t)page,
                          (uint8_t *)0x2060001,2112);
}
'''

def main():
    out=ROOT/'Risultati/USB_SCSI/Accesso_NAND_PC'/datetime.now(timezone.utc).strftime('raw_body_%Y%m%dT%H%M%SZ')
    r=Runner(SimpleNamespace(legacy_root=LEGACY,toolchain=TOOLCHAIN,output=out,action='original-raw-body-with-proposed-wrapper'));r.prepare()
    try:
        src=ROOT/'S33-sections/usb_nand_readonly';inputs={str(p):sha(p)for p in [src/'nikon_raw_read.c',src/'nikon_raw_read.h',src/'akrn_read.h',ROOT/'DUMPS/MainCode.dmp']};r.input_hashes.update(inputs)
        (out/'bridge.c').write_text(BRIDGE)
        (out/'bridge.ld').write_text('SECTIONS { . = 0x500000; .text : { *(.text .text.*) } .rodata : { *(.rodata .rodata.*) } .data : { *(.data .data.*) } .bss : { *(.bss .bss.*) *(COMMON) } }\nnikon_1593ac = 0x1593ac; nikon_1594a4 = 0x1594a4; nikon_25bfb8 = 0x25bfb8; nikon_25caec = 0x25caec; nikon_25f428 = 0x25f428;\n')
        objects=[];cc=TOOLCHAIN/'arc-elf32-gcc';r.input_hashes[str(cc)]=sha(cc)
        for p in [src/'nikon_raw_read.c',out/'bridge.c']:
            obj=out/(p.stem+'.o');objects.append(obj)
            v=r.command(p.stem+'_compile',[cc,'-std=c99','-Wall','-Wextra','-Werror','-Wconversion','-mcpu=arc700','-mlittle-endian','-mno-sdata','-ffreestanding','-fno-builtin','-Os','-I',src,'-c',p,'-o',obj]);assert v.returncode==0,v.stdout
        v=r.command('bridge_link',[TOOLCHAIN/'arc-elf32-ld','-EL','-T',out/'bridge.ld','-o',out/'bridge.elf',*objects]);assert v.returncode==0,v.stdout
        v=r.command('symbols',[TOOLCHAIN/'arc-elf32-nm','-n',out/'bridge.elf']);bridge=int(re.search(r'^([0-9a-f]+) T bridge$',v.stdout,re.M)[1],16)
        v=r.command('bridge_extract',[TOOLCHAIN/'arc-elf32-objcopy','-O','binary',out/'bridge.elf',out/'bridge.bin']);assert v.returncode==0,v.stdout
        images={i:bytearray(PS[i])for i in (0,1)};maps=[];patches=[]
        def mmap(name,address,data):
            (out/name).write_bytes(bytes(address%8)+data);maps.extend(['--memory-mapfile','/result/'+name,'--memory-region',f'{address:#x},{len(data)}'])
        def binary(name,code):
            elf=compile_probe(r,name,code);dest=out/(name+'.bin');v=r.command(name+'_extract',[TOOLCHAIN/'arc-elf32-objcopy','-O','binary','--only-section=.text',elf,dest]);assert v.returncode==0,v.stdout
            return dest.read_bytes()
        common=f' mov r10,{CURRENT:#x}\n ld r10,[r10]\n'
        # The original raw body itself executes; only these controller/service
        # boundaries are recorders. They do not claim DMA, ECC or real reads.
        specs={
          0x1593ac:common+' ld r0,[r10,12]\n add r0,r0,1\n st r0,[r10,12]\n ld r0,[r10,32]\n j_s [blink]\n',
          0x1594a4:common+' ld r0,[r10,16]\n add r0,r0,1\n st r0,[r10,16]\n ld r0,[r10,36]\n j_s [blink]\n',
          0x25deac:' mov r0,0\n j_s [blink]\n',
          0x25cb3c:common+' ld r1,[r10,40]\n add r1,r1,1\n st r1,[r10,40]\n mov r0,0\n j_s [blink]\n',
          0x25cb54:common+' ldb r1,[r0]\n st r1,[r10,44]\n ldb r1,[r0,1]\n st r1,[r10,48]\n ldw r1,[r0,2]\n st r1,[r10,52]\n mov r0,0\n j_s [blink]\n',
          0x25d0d0:common+' ld r0,[r10,28]\n j_s [blink]\n',
          0x25cb0c:' mov r0,0\n j_s [blink]\n',
          0x25caf4:' mov r0,0\n j_s [blink]\n',
          0x25dee8:' mov r0,0\n j_s [blink]\n',
        }
        for address,length,value,field in [(0x25f2b8,512,0x10,20),(0x25f31c,16,0xe0,24)]:
            specs[address]=common+f' ld r2,[r10,{field}]\n add r3,r2,1\n st r3,[r10,{field}]\n add r2,r2,{value}\n mov r3,0\nfill_{address:x}:\n stb r2,[r0]\n add r0,r0,1\n add r3,r3,1\n cmp r3,{length}\n blo fill_{address:x}\n mov r0,0\n j_s [blink]\n'
        for i,(address,asm)in enumerate(specs.items()):
            dest=0x2030000+i*0x200;data=binary(f'recorder_{address:x}',asm);mmap(f'recorder_{address:x}.bin',dest,data+bytes(16))
            entry=binary(f'entry_{address:x}',f' mov_s r12,{dest:#x}\n j_s [r12]\n');assert len(entry)==8
            b,o=locate(address,8);before=bytes(images[b['index']][o:o+8]);images[b['index']][o:o+8]=entry;patches.append(dict(address=hex(address),before=before.hex(),after=entry.hex()))
        mmap('bridge.bin',CODE,(out/'bridge.bin').read_bytes()+bytes(16))
        for i,data in images.items():mmap(f'block{i}_LAB_IO.bin',BS[i]['load_address_candidate'],data)
        mmap('current.bin',CURRENT,bytes(8));mmap('states.bin',STATES,bytes(STRIDE*10));mmap('buffer.bin',BUFFER,bytes([0xa5])*2120);mmap('geometry.bin',0x50f500,bytes(128))
        assert u32(0x25c398)==0x36b264 and u32(0x25cec4)==0x50f52c
        cases=[dict(name='first_block',chip=0,block=0,page=0),dict(name='first_block_last_page',chip=0,block=0,page=63),dict(name='second_block',chip=0,block=1,page=0),dict(name='last_block_page',chip=0,block=511,page=63),dict(name='other_chip',chip=1,block=0,page=0),dict(name='first_timeout',chip=0,block=0,page=0,wait=7),dict(name='other_timeout',chip=0,block=1,page=0,wait=7),dict(name='not_ready',chip=0,block=0,page=0,ready=0),dict(name='lock_error',chip=0,block=0,page=0,lock=123),dict(name='release_error',chip=0,block=0,page=0,release=124)]
        asm=''
        for i,c in enumerate(cases):
            address=STATES+i*STRIDE;asm+=f' mov r20,{address:#x}\n mov r10,{CURRENT:#x}\n st r20,[r10]\n st sp,[r20,4]\n'
            for off,value in [(28,c.get('wait',0)),(32,c.get('lock',0)),(36,c.get('release',0))]:asm+=f' mov r0,{value}\n st r0,[r20,{off}]\n'
            g=bytearray(20);struct.pack_into('<H',g,2,0x630);g[4]=2 if c['chip']else 1;g[5]=64;struct.pack_into('<HH',g,6,512,500);struct.pack_into('<H',g,14,2048);g[16]=4
            asm+=' mov r10,0x50f52c\n'
            for off in range(0,20,4):asm+=f' mov r0,{int.from_bytes(g[off:off+4],"little"):#x}\n st r0,[r10,{off}]\n'
            asm+=f' mov r10,0x36b264\n mov r0,{c.get("ready",1)}\n stb r0,[r10]\n mov r0,{c["chip"]}\n mov r1,{c["block"]}\n mov r2,{c["page"]}\n mov r12,{bridge:#x}\n jl [r12]\n st r0,[r20]\n st sp,[r20,8]\n'
            asm+=f' mov r0,{address+128:#x}\n mov r1,{BUFFER:#x}\n mov r2,2114\n mov r12,0xad920\n jl [r12]\n'
        asm+=' mov r0,0\n mov r8,1\n trap_s 1\n';elf=compile_probe(r,'raw_body_cases',asm);case,log=r.run('raw_body_cases','/result/'+elf.name,maps,trace=True);assert case['exit_code']==0 and case['fault']is None,log
        data=(out/'states.bin').read_bytes();rows=[]
        for i,c in enumerate(cases):
            state=data[i*STRIDE:(i+1)*STRIDE];w=struct.unpack_from('<14I',state)
            expected=0x1b00004 if c.get('wait')else 0xfffffffe if not c.get('ready',1)else c.get('lock',0)or c.get('release',0)
            assert w[0]==expected and w[1]==w[2],(c,w)
            filled=not c.get('wait')and c.get('ready',1)and not c.get('lock')
            assert w[3]==1 and w[4]==(0 if c.get('lock')else 1)and w[5]==w[6]==(4 if filled else 0),(c,w)
            if filled:
                expected_page=(b''.join(bytes([0x10+j])*512+bytes([0xe0+j])*16 for j in range(4))if c['chip']==c['block']==0 else b''.join(bytes([0x10+j])*512 for j in range(4))+b''.join(bytes([0xe0+j])*16 for j in range(4)))
                assert state[128]==state[128+2113]==0xa5
                assert state[129:129+2112]==expected_page,c
            rows.append(dict(name=c['name'],status=hex(w[0]),lock_calls=w[3],release_calls=w[4],data_steps=w[5],spare_steps=w[6],layout='interleaved512+16'if c['chip']==c['block']==0 else 'data2048+spare64',layout_checked=bool(filled),stack_preserved=True))
        assert all(sha(Path(p))==h for p,h in r.input_hashes.items())
        dump=(ROOT/'DUMPS/MainCode.dmp').read_bytes();b,o=locate(0x25f428,192);assert raw(0x25f428,192)==dump[b['offset']+o:b['offset']+o+192]
        (out/'original_raw_gnu.txt').write_text(disasm(0x25f428,0x25f4e8));(out/'cases.json').write_text(json.dumps(rows,indent=2)+'\n');(out/'patches.json').write_text(json.dumps(patches,indent=2)+'\n');(out/'verifier_snapshot.py').write_bytes(Path(__file__).read_bytes())
        r.results.update(status='PASS_ORIGINAL_RAW_BODY_AND_PROPOSED_WRAPPER',cpu_cases=len(cases),tool_inputs=r.input_hashes,assumptions=['Explicit configured geometry fixture, physical block count512 not measured','Nikon25F428/getter/ready execute; controller, raw-step transfers and mutex services are recorders','Separate from BOT test; no USB executed here'],limits=['No hardware/controller/DMA/ECC or real page content','NAND wait error becomes01B00004; success does not validate physical data integrity','No installable update or residency/buffer ownership proof'])
        (out/'verified_evidence.json').write_text(json.dumps(r.results,indent=2)+'\n');(out.parent/'raw_body_latest.json').write_text(json.dumps(dict(evidence=str((out/'verified_evidence.json').relative_to(ROOT))),indent=2)+'\n');print('PASS',out)
    except Exception as exc:
        r.results.update(status='FAIL',error=repr(exc));(out/'verified_evidence.json').write_text(json.dumps(r.results,indent=2)+'\n');raise
if __name__=='__main__':main()
