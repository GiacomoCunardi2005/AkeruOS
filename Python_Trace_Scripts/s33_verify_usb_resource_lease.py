#!/usr/bin/env python3
"""Original resource-query/acquire/release instructions against an explicit lab manager."""
from datetime import datetime, timezone
from pathlib import Path
from types import SimpleNamespace
import json
import re
import struct
import sys
from s33_run_gnu_arc700 import ROOT, LEGACY, TOOLCHAIN, Runner, sha
from s33_verify_gnu_dsp_lab import compile_probe
sys.path.insert(0,str(ROOT/'S33-sections/analysis_codex'))
from static_common import BS,PS,raw,u32,locate,disasm
MANAGER,TABLE,RECORD,STATES=0x441f68,0x2010000,0x2020000,0x2030000

def main():
    out=ROOT/'Risultati/USB_SCSI/Accesso_NAND_PC'/datetime.now(timezone.utc).strftime('resource_cpu_%Y%m%dT%H%M%SZ')
    r=Runner(SimpleNamespace(legacy_root=LEGACY,toolchain=TOOLCHAIN,output=out,action='original-resource-query-lease'))
    r.prepare()
    try:
        paths=[ROOT/'OriginalSoftware_NikonS33_V1.1/firmware.bin',ROOT/'DUMPS/MainCode.dmp'];inputs={str(p.relative_to(ROOT)):sha(p)for p in paths}
        firmware,dump=[p.read_bytes()for p in paths];spans=[]
        def check(a,n):
            b,o=locate(a,n);f=0x480b8+b['offset']+o
            assert raw(a,n)==firmware[f:f+n]==dump[b['offset']+o:b['offset']+o+n]
            spans.append(dict(cpu=hex(a),firmware_offset=hex(f),size=n))
        assert u32(0xc6434)==0x3766f4
        original_record=raw(0x37709c,24);assert struct.unpack('<6I',original_record)==(30,78,0,0,65536,4)
        check(0xc63d8,40);check(0xc6434,4);check(0x37709c,24)
        asm=''
        def call(a):return f' mov r12,{a:#x}\n jl [r12]\n'
        cases=[('uninitialized',0,232,0,1),('id_out_of_range',1,30,0,1),('missing_id',1,232,0xffffffff,1),('leased',1,232,0,1),('unleased',1,232,0,0)]
        for i,(name,init,count,index,leased)in enumerate(cases):
            a=STATES+i*128
            asm+=f' mov r20,{a:#x}\n st sp,[r20,4]\n mov r10,{MANAGER:#x}\n'
            for offset,value in [(8,RECORD),(12,1),(16,TABLE),(20,count),(32,0),(36,0),(40,init)]:asm+=f' mov r0,{value:#x}\n st r0,[r10,{offset}]\n'
            asm+=f' mov r10,{TABLE+120:#x}\n mov r0,{index:#x}\n st r0,[r10]\n mov r10,{RECORD:#x}\n'
            for offset,value in enumerate((30,78,leased,0x2060000,65536,4)):asm+=f' mov r0,{value:#x}\n st r0,[r10,{offset*4}]\n'
            asm+=f' mov r0,30\n add r1,r20,64\n'+call(0x12a748)+' st r0,[r20]\n st sp,[r20,8]\n'
            asm+=f' mov r10,{RECORD:#x}\n ld r0,[r10,8]\n st r0,[r20,12]\n'
        # Original lease lifecycle, with exactly one fixture record and no overlap.
        a=STATES+5*128
        asm+=f' mov r20,{a:#x}\n st sp,[r20,4]\n mov r10,{RECORD:#x}\n mov r0,0\n st r0,[r10,8]\n mov r0,30\n add r1,r20,32\n add r2,r20,36\n'+call(0x12a71c)+' st r0,[r20]\n'
        asm+=' ld r0,[r20,32]\n'+call(0x81dc88)
        asm+=' mov r0,30\n add r1,r20,64\n'+call(0x12a748)+' st r0,[r20,16]\n'
        asm+=f' mov r10,0x89ab7c\n ld r0,[r10,0x34]\n st r0,[r20,40]\n'
        asm+=' mov r0,30\n'+call(0x12a738)+' st r0,[r20,20]\n'
        asm+=f' mov r10,{RECORD:#x}\n ldb r0,[r10,8]\n st r0,[r20,12]\n'
        asm+=' mov r0,30\n'+call(0x12a738)+' st r0,[r20,24]\n st sp,[r20,8]\n mov r0,0\n mov r8,1\n trap_s 1\n'
        maps=[]
        def mmap(name,a,data):
            (out/name).write_bytes(data);maps.extend(['--memory-mapfile','/result/'+name,'--memory-region',f'{a:#x},{len(data)}'])
        for i in (0,1,4,5):mmap(f'block{i}_ORIGINAL.bin',BS[i]['load_address_candidate'],PS[i])
        mmap('manager.bin',MANAGER,bytes(56));mmap('table.bin',TABLE,bytes(232*4));mmap('record.bin',RECORD,original_record+bytes(8));mmap('states.bin',STATES,bytes([0xa5])*768)
        elf=compile_probe(r,'resource_cases',asm);result,log=r.run('resource_cases','/result/'+elf.name,maps,trace=True)
        assert result['exit_code']==0 and result['fault']is None,log
        data=(out/'states.bin').read_bytes();rows=[]
        for i,(name,init,count,index,leased)in enumerate(cases):
            a=i*128;w=struct.unpack_from('<4I',data,a);copied=data[a+64:a+88]
            expected=0x1d00001 if not init else 0x1d00004 if count<=30 else 0x1d00005 if index==0xffffffff else 0
            assert w[0]==expected and w[1]==w[2] and w[3]==leased,(name,w)
            assert copied==(struct.pack('<6I',30,78,leased,0x2060000,65536,4)if expected==0 else b'\xa5'*24),(name,copied.hex())
            rows.append(dict(name=name,status=hex(w[0]),record=copied.hex(),lease_flag_unchanged=True,stack_restored=True))
        w=struct.unpack_from('<11I',data,640)
        assert w[0]==w[3]==w[4]==w[5]==0 and w[6]==0x1d00008 and w[1]==w[2],w
        assert w[8:11]==(0x2060000,65536,0x2060000),w
        assert data[640+64:640+88]==struct.pack('<6I',30,78,1,0x2060000,65536,4)
        rows.append(dict(name='acquire_query_register_release_release',acquire_status=0,query_status=0,release_status=0,second_release_status=hex(w[6]),base=hex(w[8]),size=w[9],global_buffer=hex(w[10]),query_flag=1,final_flag=0,stack_restored=True))
        pcs=sorted({int(m[1],16)for m in re.finditer(r'^0x([0-9a-f]+)\s',(out/'resource_cases.trace').read_text(),re.M)})
        for pc in pcs:
            try:locate(pc,8)
            except ValueError:continue
            check(pc,8)
        assert {0x1ef920,0x1ef954,0x1ef8a6,0x1ef916,0x81f52c}.issubset(pcs)
        assert all(sha(p)==inputs[str(p.relative_to(ROOT))]for p in paths)and all(sha(Path(p))==h for p,h in r.input_hashes.items())
        (out/'cases.json').write_text(json.dumps(rows,indent=2)+'\n');(out/'executed_spans.json').write_text(json.dumps(spans,indent=2)+'\n')
        (out/'fixture.json').write_text(json.dumps(dict(manager=hex(MANAGER),fixture_record=hex(RECORD),fixture_base='2060000',original_template='37709C: ID1E dependency4E size10000 alignment4',limits=['Declared initialized manager with one resource; no original full resource allocator/startup','Query copies all24bytes even if unleased; flag and base match must be checked','Flag1 and globalbase match do not identify owner or establish synchronization/lifetime','No hardware,NAND,SD,USB,firmware changes; GNU read only']),indent=2)+'\n')
        (out/'verifier_snapshot.py').write_bytes(Path(__file__).read_bytes());r.results.update(status='PASS_ORIGINAL_RESOURCE_QUERY_AND_LEASE',cases=len(rows),inputs=inputs,tool_inputs=r.input_hashes)
        (out/'verified_evidence.json').write_text(json.dumps(r.results,indent=2)+'\n');(out.parent/'resource_cpu_latest.json').write_text(json.dumps(dict(evidence=str((out/'verified_evidence.json').relative_to(ROOT))),indent=2)+'\n');print('PASS',out)
    except Exception as exc:
        r.results.update(status='FAIL',error=repr(exc));(out/'verified_evidence.json').write_text(json.dumps(r.results,indent=2)+'\n');raise
if __name__=='__main__':main()
