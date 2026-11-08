#!/usr/bin/env python3
"""Execute original MEMDUMP path construction with synthetic volume records."""
from datetime import datetime, timezone
from pathlib import Path
from types import SimpleNamespace
import json
from s33_run_gnu_arc700 import ROOT, LEGACY, TOOLCHAIN, Runner
from s33_verify_gnu_dsp_lab import compile_probe
import sys
sys.path.insert(0, str(ROOT/'S33-sections/analysis_codex'))
from static_common import BS, PS, locate, raw


def main():
    out=ROOT/'Risultati/Runtime_Kernel/MEMDUMP_Path'/datetime.now(timezone.utc).strftime('%Y%m%dT%H%M%S%fZ')
    r=Runner(SimpleNamespace(legacy_root=LEGACY,toolchain=TOOLCHAIN,output=out,action='memdump-path'))
    print('Prove:',out,flush=True)
    try:
        r.prepare()
        def binary(name,asm):
            elf=compile_probe(r,name,asm);dest=out/(name+'.bin')
            p=r.command(name+'_extract',[TOOLCHAIN/'arc-elf32-objcopy','-O','binary','--only-section=.text',elf,dest])
            assert p.returncode==0,p.stdout
            return dest.read_bytes()
        stubs={
            0xcb5e4:'j_s [blink]', 0xcb5b0:'j_s [blink]', 0x1567f8:'j_s [blink]',
            0x12bd5c:'''mov r10,0x2010000
 mov r11,32
copy_name:
 ldb r12,[r0]
 stb r12,[r10]
 add r0,r0,1
 add r10,r10,1
 sub.f r11,r11,1
 bne copy_name
 mov r0,5
 j_s [blink]'''
        }
        image=bytearray(PS[0]);services=[]
        for i,(addr,asm) in enumerate(stubs.items()):
            target=0x2030100+i*0x100
            data=binary('service_%d'%i,asm+'\n')
            entry=binary('entry_%d'%i,f' mov_s r12,{target:#x}\n j_s [r12]\n')
            block,offset=locate(addr,8);assert block['index']==0 and image[offset:offset+8]==raw(addr,8)
            image[offset:offset+8]=entry;services.append((target,data))
        results=[]
        for name,index,expected in [('volume_b',0,b'B:\\MEMDUMP.BIN'),('volume_a_dir',1,b'A:\\DCIM\\MEMDUMP.BIN'),('invalid_index',255,b'Z:\\MEMDUMP.BIN')]:
            maps=[]
            def mmap(label,addr,data):
                p=out/(name+'_'+label+'.bin');p.write_bytes(bytes(addr%8)+data)
                maps.extend(['--memory-mapfile','/result/'+p.name,'--memory-region',f'{addr:#x},{len(data)}'])
                return p
            maps.extend(['--memory-fill','0','--memory-region','0,0x80000'])
            mmap('main0',BS[0]['load_address_candidate'],image)
            p1=bytearray(PS[1]);p1[0x366889-BS[1]['load_address_candidate']]=index
            mmap('main1',BS[1]['load_address_candidate'],p1)
            table=bytearray(0x200);table[0x4c:0x4f]=b'B:\0';table[0x84:0x8c]=b'A:\\DCIM\0'
            mmap('table',0x442300,table)
            state=mmap('state',0x200ff00,bytes(0x200))
            service_image=bytearray(0x100*(len(services)+1))
            for target,data in services:service_image[target-0x2030000:target-0x2030000+len(data)]=data
            mmap('services',0x2030000,service_image)
            elf=compile_probe(r,name,'''mov r0,sp
 sub r0,r0,292
 mov r1,90
 stb r1,[r0]
 mov r1,58
 stb r1,[r0,1]
 mov r1,0
 stb r1,[r0,2]
 mov r12,0x16ed40
 jl [r12]
 mov r0,0
 mov r8,1
 trap_s 1
''')
            case,log=r.run(name,'/result/'+elf.name,maps,trace=True)
            assert case['exit_code']==0 and case['fault'] is None,log
            found=state.read_bytes()[0x100:0x120].split(b'\0',1)[0]
            assert found==expected,(name,found,expected)
            results.append(dict(case=name,index=index,modeled_base=expected.decode().split('\\MEMDUMP.BIN')[0],observed_path=found.decode(),writer_stubbed=True))
        (out/'cases.json').write_text(json.dumps(results,indent=2)+'\n')
        (out/'verifier_snapshot.py').write_bytes(Path(__file__).read_bytes())
        r.results.update(status='PASS_MEMDUMP_PATH_CONSTRUCTION_SYNTHETIC_VOLUMES',scenarios=results,
            assumptions=['Original 16ED40,12B0DC,12B290,32DE00 and string helpers; synthetic current volume, table and stack.', 'File write and UI services are fixtures.'],
            limits=['Failure case demonstrates continuation with deliberately seeded stale stack; real stack content is unknown.', 'No physical card, actual base-path records or filesystem operation validated.'])
        r.finish()
    except Exception as exc:
        r.results.update(status='FAIL',error=repr(exc));raise
    finally:r.save()
    print('PASS original MEMDUMP path with synthetic records:',out,flush=True)


if __name__=='__main__':main()
