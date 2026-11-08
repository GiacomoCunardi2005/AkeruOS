#!/usr/bin/env python3
"""Exercise original V1.1 CFA dispatcher with synthetic lower-level file services."""
from datetime import datetime, timezone
from pathlib import Path
from types import SimpleNamespace
import json
import struct
import sys
from s33_run_gnu_arc700 import ROOT, LEGACY, TOOLCHAIN, Runner, sha
from s33_verify_gnu_dsp_lab import LAB, BUILD, compile_probe
sys.path.insert(0,str(ROOT/'S33-sections/analysis_codex'))
from static_common import BS, PS, EXPECTED, ORIGINAL, raw, locate, disasm


def main():
    out=ROOT/'Risultati/HiddenMenu_RAW'/datetime.now(timezone.utc).strftime('cfa_dispatcher_cpu_%Y%m%dT%H%M%SZ')
    r=Runner(SimpleNamespace(legacy_root=LEGACY,toolchain=TOOLCHAIN,output=out,action='cfa-dispatcher'))
    print('Prove:',out,flush=True)
    try:
        r.prepare(); assert sha(ORIGINAL)==EXPECTED
        dump=ROOT/'DUMPS/MainCode.dmp'; d=dump.read_bytes();r.input_hashes[str(dump)]=sha(dump)
        sim=LAB/'install/bin/arc-elf32-run'; assert sha(sim)==json.loads(BUILD.read_text())['experimental_sha256']
        r.experimental_engine=LAB;r.input_hashes[str(sim)]=sha(sim);r.input_hashes[str(BUILD)]=sha(BUILD)
        spans=[(0x28d66c,0x28d6d8),(0x28d6e6,0x28d742),(0x28d7da,0x28d818)]
        for a,b in spans:
            block,off=locate(a,b-a);assert raw(a,b-a)==d[block['offset']+off:block['offset']+off+b-a]
        (out/'gnu_windows.txt').write_text('\n'.join(disasm(a,b) for a,b in spans))
        def binary(name,asm):
            elf=compile_probe(r,name,asm);path=out/(name+'.bin')
            p=r.command(name+'_extract',[TOOLCHAIN/'arc-elf32-objcopy','-O','binary','--only-section=.text',elf,path]);assert p.returncode==0,p.stdout
            return path.read_bytes()
        zero=' mov r0,0\n j_s [blink]\n'
        name='B:\\DCIM\\DSCN1000.JPG\0'
        name_asm=''
        for i,c in enumerate(name.encode()):name_asm+=f' mov r0,{c}\n stb r0,[r1,{i}]\n'
        name_asm+=' mov r0,0\n j_s [blink]\n'
        fixtures=[('guard1',0x13bedc,zero),('guard2',0x13beec,zero),('query',0x12b0dc,zero),
          ('ready',0x12b934,' mov r0,1\n stb r0,[r1]\n mov r0,0\n j_s [blink]\n'),
          ('name',0x1378b4,name_asm),
          ('open',0x12bc20,''' mov r10,0x2010000
 ld r11,[r10,12]
 add r11,r11,1
 st r11,[r10,12]
 mov r11,0x1234
 st r11,[r3]
 mov r11,0
 cp_name:
 add r12,r0,r11
 ldb r12,[r12]
 add r9,r10,r11
 stb r12,[r9,64]
 add r11,r11,1
 cmp r11,24
 blo cp_name
 ld r0,[r10]
 j_s [blink]
'''),
          ('write',0x12bcc4,''' mov r10,0x2010000
 ld r11,[r10,16]
 add r11,r11,1
 st r11,[r10,16]
 st r0,[r10,44]
 st r1,[r10,48]
 st r2,[r10,24]
 ld r11,[r10,28]
 st r11,[r4]
 ld r0,[r10,4]
 j_s [blink]
'''),
          ('close',0x12bce4,''' mov r10,0x2010000
 ld r11,[r10,20]
 add r11,r11,1
 st r11,[r10,20]
 st r0,[r10,52]
 ld r0,[r10,8]
 j_s [blink]
''')]
        image=bytearray(PS[0]); patches=[]; services=[]
        for i,(name,addr,asm) in enumerate(fixtures):
            target=0x2030000+i*0x400; code=binary(name,asm); services.append((target,code))
            entry=binary('entry_'+name,f' mov_s r12,{target:#x}\n j_s [r12]\n')[:8]
            block,off=locate(addr,8);assert block['index']==0 and image[off:off+8]==raw(addr,8)
            patches.append(dict(name=name,address=hex(addr),original=bytes(image[off:off+8]).hex(),fixture=entry.hex()));image[off:off+8]=entry
        specs=[('complete',0,0,0,2048),('short',0,0,0,0),('write_error',0,77,0,0),('open_error',78,0,0,2048),('close_error',0,0,79,2048)]
        rows=[]
        for name,oe,we,ce,count in specs:
            maps=[]
            def mmap(label,addr,data):
                path=out/(name+'_'+label+'.bin');path.write_bytes(data+bytes(8+(-len(data))%8))
                maps.extend(['--memory-mapfile','/result/'+path.name,'--memory-region',f'{addr:#x},{path.stat().st_size}']);return path
            mmap('block0',BS[0]['load_address_candidate'],image);mmap('block1',BS[1]['load_address_candidate'],PS[1]);mmap('dispatcher_state',0x520000,bytes(0x1000))
            for i,(addr,code) in enumerate(services):mmap('service'+str(i),addr,code)
            state=bytearray(128);struct.pack_into('<3I',state,0,oe,we,ce);struct.pack_into('<I',state,28,count);path=mmap('state',0x2010000,state)
            asm=''' mov r20,0x2010000
 st sp,[r20,32]
 mov r0,0
 mov r1,0
 mov r2,0x12345678
 mov r3,0
 mov r4,0
 mov r12,0x28d66c
 jl [r12]
 st r0,[r20,56]
 mov r0,0
 mov r1,1
 mov r2,0x12345678
 mov r3,0x2040000
 mov r4,2048
 mov r12,0x28d66c
 jl [r12]
 st r0,[r20,36]
 mov r0,0
 mov r1,2
 mov r2,0x12345678
 mov r3,0
 mov r4,0
 mov r12,0x28d66c
 jl [r12]
 st r0,[r20,40]
 st sp,[r20,60]
 mov r0,0
 mov r8,1
 trap_s 1
'''
            elf=compile_probe(r,name,asm);result,log=r.run(name,'/result/'+elf.name,maps,trace=True)
            assert result['exit_code']==0 and result['fault'] is None,log
            w=struct.unpack_from('<16I',path.read_bytes());filename=path.read_bytes()[64:88].split(b'\0')[0].decode()
            assert filename == 'B:\\DCIM\\CFAi1000.raw',(name,filename)
            assert (w[3],w[4],w[5])==(1,1,1) and w[8]==w[15],(name,w)
            assert (w[11],w[12],w[6])==(0x1234,0x2040000,2048),(name,w)
            assert w[14]==oe and w[10]==ce,(name,w)
            expected_write=we if we else (0 if count==2048 else 0x700103)
            assert w[9]==expected_write,(name,w)
            trace=(out/(name+'.trace')).read_text()
            for pc in ('0x28d66c','0x28d6e6','0x28d7f8','0x28d80e'):
                assert any(line.startswith(pc+' ') for line in trace.splitlines()),(name,pc)
            rows.append(dict(name=name,open_status=w[14],write_status=w[9],close_status=w[10],reported=count,requested=w[6],filename=filename,open_calls=w[3],write_calls=w[4],close_calls=w[5]))
        (out/'cases.json').write_text(json.dumps(rows,indent=2)+'\n');(out/'fixture_patches.json').write_text(json.dumps(patches,indent=2)+'\n');(out/'verifier_snapshot.py').write_bytes(Path(__file__).read_bytes())
        r.results.update(status='PASS_CFA_DISPATCHER_CPU_FIXTURES',scenarios=rows,assumptions=['Dispatcher original; open/write/close and guards/name/query synthetic.', 'Three modes called sequentially by harness regardless of prior status.', 'GNU DSP model experimental.'],limits=['No sensor, actual data or filesystem. A return status does not establish persistence.', 'Open failure fixture writes a handle anyway; no conclusions about real failed-open handle state.'])
        r.finish()
    except Exception as exc:r.results.update(status='FAIL',error=repr(exc));raise
    finally:r.save()
    print('PASS',out,flush=True)

if __name__=='__main__':main()
