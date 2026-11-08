#!/usr/bin/env python3
"""Execute unmodified TBIB namespace resolver; static SD callbacks are not hardware tests."""
from datetime import datetime,timezone
from itertools import product
from pathlib import Path
from types import SimpleNamespace
import json,struct
from s33_run_gnu_arc700 import ROOT,LEGACY,TOOLCHAIN,Runner,sha
from s33_verify_gnu_dsp_lab import compile_probe
BASE,STATE,STRINGS=0x1000000,0x2100000,0x2200000
TABLE=0x10421cc

def main():
    out=ROOT/'Risultati/USB_SCSI/Accesso_NAND_PC'/datetime.now(timezone.utc).strftime('tbib_namespace_%Y%m%dT%H%M%SZ')
    r=Runner(SimpleNamespace(legacy_root=LEGACY,toolchain=TOOLCHAIN,output=out,action='unmodified-TBIB-namespace-resolver-and-state-predicates'));r.prepare()
    try:
        body=(ROOT/'OriginalSoftware_NikonS33_V1.1/firmware.bin').read_bytes()[0x7c:0x44c38]
        r.input_hashes.update({str(Path(__file__)):sha(Path(__file__)),str(ROOT/'Python_Trace_Scripts/s33_verify_gnu_dsp_lab.py'):sha(ROOT/'Python_Trace_Scripts/s33_verify_gnu_dsp_lab.py')})
        def word(a):return struct.unpack_from('<I',body,a-BASE)[0]
        assert word(0x1020394)==TABLE and word(0x1008574)==TABLE
        def mmap(name,address,data):
            path=out/name;path.write_bytes(bytes(address%8)+data);maps.extend(['--memory-mapfile','/result/'+name,'--memory-region',f'{address:#x},{len(data)}']);return path
        specs=[]
        for index in range(2):
            for enabled,busy,bypass,device,mounted,mode in product(range(2),repeat=6):
                expected=0 if bypass else 0x1a00040 if not enabled else 0x1a00010 if busy else (0x1a00030 if not mounted else 0x1a0001b)if not device else 0 if mounted else 0x1a00035 if not mode else 0x1a0001a
                specs.append(dict(path=('A:'if index==0 else'B:')+'\\TBM_SK501.BIN',index=index,state=[enabled,busy,bypass,device,mounted,mode],expected=expected))
        for text,index,status in [('A:',0,0x1a00030),('B:',1,0x1a00030),('A:\\folder\\file',0,0x1a00030),('B:\\folder\\file',1,0x1a00030),('a:',None,0x1a00034),('b:',None,0x1a00034),('C:',None,0x1a00034),('DEVSD:',None,0x1a00034),('B',None,0x1a00033),('',None,0x1a00033),('B'*261+':',None,0x1a00034)]:
            specs.append(dict(path=text,index=index,state=[1,0,0,0,0,0],expected=status))
        specs.extend([dict(path=None,index=None,state=[1,0,0,0,0,0],expected=0x1a00013),dict(path='B:',index=None,state=[1,0,0,0,0,0],null_output=True,expected=0x1a00013)])
        maps=[];tbib=mmap('tbib_original.bin',BASE,body);states=mmap('resolver_rows.bin',STATE,bytes(len(specs)*32));strings=bytearray();asm=''
        def store(a,v,byte=False):return f' mov r10,{a:#x}\n mov r0,{v:#x}\n '+('stb'if byte else'st')+' r0,[r10]\n'
        for i,c in enumerate(specs):
            at=STATE+i*32;path=c['path'];addr=0 if path is None else STRINGS+len(strings)
            if path is not None:strings.extend(path.encode()+b'\0')
            for index in range(2):
                record=TABLE+index*0x150;enabled,busy,bypass,device,mounted,mode=c['state']
                for offset,value in [(0x48,enabled),(0x49,busy),(0x4b,bypass)]:asm+=store(record+offset,value,True)
                for offset,value in [(0x50,device),(0x58,mounted),(0x4c,mode)]:asm+=store(record+offset,value)
            asm+=store(at+4,0xa5a5a5a5)+store(0x10415f8,0xa5a5a5a5)
            asm+=f' mov r20,{at:#x}\n st sp,[r20,8]\n mov r0,{addr:#x}\n mov r1,{0 if c.get("null_output")else at+4:#x}\n mov r12,0x102007c\n jl [r12]\n st r0,[r20]\n st sp,[r20,12]\n mov r10,0x10415f8\n ld r0,[r10]\n st r0,[r20,16]\n'
        mmap('paths.bin',STRINGS,strings);asm+=' mov r0,0\n mov r8,1\n trap_s 1\n';elf=compile_probe(r,'resolver',asm)
        case,log=r.run('resolver','/result/'+elf.name,maps);assert case['exit_code']==0 and case['fault']is None,log
        rows=[]
        for i,c in enumerate(specs):
            status,index,before,after,global_index=struct.unpack_from('<5I',states.read_bytes(),i*32)
            expected_index=c['index']if c['index']is not None else 0xa5a5a5a5
            assert status==c['expected']and index==global_index==expected_index and before==after,(i,c,status,index,global_index)
            rows.append(dict(**c,status=hex(status),resolved_index=index,stack_preserved=True))
        # Only state fields are deliberately changed in the original image.
        changed=tbib.read_bytes();allowed=set()
        for record in [TABLE,TABLE+0x150]:
            for off,n in [(0x48,1),(0x49,1),(0x4b,1),(0x50,4),(0x58,4),(0x4c,4)]:allowed.update(range(record-BASE+off,record-BASE+off+n))
        allowed.update(range(0x415f8,0x415fc));assert all(a==b or i in allowed for i,(a,b)in enumerate(zip(body,changed)))
        records=[]
        for i in range(2):
            addr=TABLE+i*0x150;data=body[addr-BASE:addr-BASE+0x150]
            records.append(dict(index=i,cpu=hex(addr),device=data[8:].split(b'\0')[0].decode(),manager=data[19:].split(b'\0')[0].decode(),prefix=data[30:].split(b'\0')[0].decode(),callbacks={hex(o):hex(struct.unpack_from('<I',data,o)[0])for o in [0x2c,0x30,0x34]},initial_flags=data[0x48:0x4c].hex()))
        windows=[(0x101ffd0,0x102007c),(0x102007c,0x10200d0),(0x1008394,0x100858c),(0x102060c,0x1020638),(0x1020648,0x1020714),(0x1002e74,0x1002e7c),(0x1002e7c,0x1002f34),(0x1002be4,0x1002c50)]
        for a,b in windows:
            v=r.command(f'gnu_{a:x}',[TOOLCHAIN/'arc-elf32-objdump','-d','-m','arc:ARC700','-EL',f'--start-address={a:#x}',f'--stop-address={b:#x}',out/'tbib.elf']);assert v.returncode==0 and'out of bounds'not in v.stdout
        assert all(sha(Path(f))==h for f,h in r.input_hashes.items())
        (out/'namespace_cases.json').write_text(json.dumps(rows,indent=2)+'\n');(out/'records.json').write_text(json.dumps(records,indent=2)+'\n');(out/'verifier_snapshot.py').write_bytes(Path(__file__).read_bytes())
        r.results.update(status='PASS_UNMODIFIED_TBIB_NAMESPACE_RESOLVER_ONLY',namespace_cases=len(rows),records=records,input_hashes=r.input_hashes,assumptions=['No function-entry replacement in TBIB; original resolver and state predicate executed','Six state inputs per record deliberately supplied; only zero/nonzero pointers, not real initialized objects','Original fixed table, case-sensitive namespace strings and lab stack; base GNU RAM is zero-filled'],limits=['Mount, driver registration, filesystem transfer, SD hardware and BootTask order not executed','Static SD callbacks recorded, not evidence of device readiness','No candidate modification, flash or USB command; installation readiness remains unproven'])
        (out/'verified_evidence.json').write_text(json.dumps(r.results,indent=2)+'\n');(out.parent/'tbib_namespace_latest.json').write_text(json.dumps(dict(evidence=str((out/'verified_evidence.json').relative_to(ROOT))),indent=2)+'\n');print('PASS',len(rows),out)
    except Exception as exc:
        r.results.update(status='FAIL',error=repr(exc));(out/'verified_evidence.json').write_text(json.dumps(r.results,indent=2)+'\n');raise
if __name__=='__main__':main()
