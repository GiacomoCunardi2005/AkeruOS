#!/usr/bin/env python3
"""Run original HiddenMenu CFA flag accessors and CFA export gate on synthetic state."""
from datetime import datetime, timezone
from pathlib import Path
from types import SimpleNamespace
import json
import struct
import sys
from s33_run_gnu_arc700 import ROOT, LEGACY, TOOLCHAIN, Runner, sha
from s33_verify_gnu_dsp_lab import BUILD, LAB, compile_probe
sys.path.insert(0, str(ROOT / 'S33-sections/analysis_codex'))
from static_common import BS, PS, EXPECTED, ORIGINAL, raw, locate, disasm, u32


def main():
    out = ROOT/'Risultati/HiddenMenu_RAW'/datetime.now(timezone.utc).strftime('hidden_cfa_menu_gate_cpu_%Y%m%dT%H%M%SZ')
    r = Runner(SimpleNamespace(legacy_root=LEGACY, toolchain=TOOLCHAIN, output=out, action='hidden-cfa-menu-gate'))
    print('Prove:',out,flush=True)
    try:
        r.prepare()
        assert sha(ORIGINAL)==EXPECTED
        dump=ROOT/'DUMPS/MainCode.dmp'; data=dump.read_bytes(); r.input_hashes[str(dump)]=sha(dump)
        sim=LAB/'install/bin/arc-elf32-run'; build=json.loads(BUILD.read_text())
        assert sha(sim)==build['experimental_sha256']
        r.experimental_engine=LAB; r.input_hashes[str(sim)]=sha(sim); r.input_hashes[str(BUILD)]=sha(BUILD)
        spans=[(0x13af18,0x13af28),(0x1e6a54,0x1e6ad0),(0x7cf024,0x7cf054),(0x7cf51c,0x7cf570),(0x169f60,0x169fb4)]
        assert (u32(0x987058),u32(0x98705c))==(0x5004,0x7cf51c)
        for a,b in spans:
            block,off=locate(a,b-a)
            assert raw(a,b-a)==data[block['offset']+off:block['offset']+off+b-a]
        (out/'gnu_windows.txt').write_text('\n'.join(disasm(a,b) for a,b in spans))
        images={i:bytearray(PS[i]) for i in (0,1,2,3,4,5)}
        maps=[]; patches=[]
        def binary(name,asm):
            elf=compile_probe(r,name,asm); path=out/(name+'.bin')
            p=r.command(name+'_extract',[TOOLCHAIN/'arc-elf32-objcopy','-O','binary','--only-section=.text',elf,path])
            assert p.returncode==0,p.stdout
            chunk=path.read_bytes(); path.write_bytes(chunk+bytes(8+(-len(chunk))%8)); return path
        def mapping(path,addr):
            return ['--memory-mapfile','/result/'+path.name,'--memory-region',f'{addr:#x},{path.stat().st_size}']
        fixtures=[('dispatcher',0x28d66c,''' mov r10,0x2200000
 ld r11,[r10]
 asl r12,r11,5
 add r12,r12,r10
 st r0,[r12,8]
 st r1,[r12,12]
 st r2,[r12,16]
 st r3,[r12,20]
 st r4,[r12,24]
 add r11,r11,1
 st r11,[r10]
 ld r0,[r10,4]
 j_s [blink]
'''),('stop',0x1e6acc,' j [r26]\n')] + [(name,addr,' mov r0,0\n j_s [blink]\n') for name,addr in [('lookup',0x635bd8),('update',0x636040),('refresh',0x145150)]]
        for i,(name,addr,asm) in enumerate(fixtures):
            target=0x2030000+i*0x400; path=binary(name,asm); maps+=mapping(path,target)
            entry=binary('entry_'+name,f' mov_s r12,{target:#x}\n j_s [r12]\n').read_bytes()[:8]
            block,off=locate(addr,8); before=bytes(images[block['index']][off:off+8]); assert before==raw(addr,8)
            images[block['index']][off:off+8]=entry
            patches.append(dict(name=name,address=hex(addr),original=before.hex(),fixture=entry.hex()))
        tests=[('off',0,0,2,0),('enable',0,1,2,0),('disable',1,1,2,0),('toggle_twice',0,2,2,0),('enable_packed',0,1,1,0),('enable_error',0,1,2,77)]
        asm=''
        for i,(name,flag,toggles,fmt,err) in enumerate(tests):
            case=0x2001000+i*160
            asm+=f''' mov r21,{case:#x}
 mov r1,0x36c26e
 mov r0,1
 stb r0,[r1]
 mov r1,0x366f90
 mov r0,3
 st r0,[r1]
 mov r0,{flag}
 mov r12,0x13af20
 jl [r12]
'''
            for _ in range(toggles):
                asm+=''' mov r0,0x987000
 mov r1,0x5004
 mov r2,0
 mov r12,0x7cf024
 jl [r12]
'''
            asm+=f''' mov r1,0x366c20
 ldb r0,[r1]
 st r0,[r21,112]
 mov r1,0x36c26e
 ldb r0,[r1]
 st r0,[r21,116]
 mov r1,0x366f90
 ld r0,[r1]
 st r0,[r21,120]
 mov r1,0x2200000
 mov r0,0
 st r0,[r1]
 mov r0,{err}
 st r0,[r1,4]
 mov r1,0x2020000
 mov r0,{fmt}
 st r0,[r1,8]
 mov r0,0x2021000
 add r1,r1,492
 st r0,[r1]
 st sp,[r21,0]
 mov r0,0x2020000
 mov r26,after_{i}
 mov r12,0x1e6a54
 j [r12]
 after_{i}:
 mov r1,0x2200000
 ld r0,[r1]
 st r0,[r21,4]
 ld sp,[r21,0]
'''
        asm+=' mov r0,0\n mov r8,1\n trap_s 1\n'
        for i,img in images.items():
            path=out/f'block{i}_LAB_FIXTURE.bin'; path.write_bytes(img); maps+=mapping(path,BS[i]['load_address_candidate'])
        cases=out/'cases.bin'; cases.write_bytes(bytes(len(tests)*160)); maps+=mapping(cases,0x2001000)
        context=out/'context.bin'; context.write_bytes(bytes(1024)); maps+=mapping(context,0x2020000)
        payload=bytearray(128); struct.pack_into('<I',payload,4,0x12345678); struct.pack_into('<I',payload,16,0x2040000); struct.pack_into('<HH',payload,28,17,19)
        p=out/'payload.bin';p.write_bytes(payload);maps+=mapping(p,0x2021000)
        records=out/'records.bin';records.write_bytes(bytes(128));maps+=mapping(records,0x2200000)
        # Preserve each scenario's dispatcher records immediately after executing it.
        # The loop currently reuses records; copy them into the case with guest loads.
        asm=asm.replace(' st r0,[r21,4]\n ld sp,[r21,0]', ''' st r0,[r21,4]
 mov r2,0
 copy_records:
 asl r3,r2,2
 add r4,r1,r3
 ld r5,[r4,8]
 add r4,r21,r3
 st r5,[r4,8]
 add r2,r2,1
 cmp r2,24
 blo copy_records
 ld sp,[r21,0]''')
        # Labels must be unique across unrolled cases.
        for i in range(len(tests)):
            asm=asm.replace('copy_records:',f'copy_records_{i}:',1).replace('blo copy_records\n',f'blo copy_records_{i}\n',1)
        elf=compile_probe(r,'cases',asm); result,log=r.run('cases','/result/'+elf.name,maps,trace=True)
        assert result['exit_code']==0 and result['fault'] is None,log
        results=[]
        for i,(name,flag,toggles,fmt,err) in enumerate(tests):
            words=struct.unpack_from('<26I',cases.read_bytes(),i*160); count=words[1]
            effective=flag ^ (toggles % 2)
            actual,other_flag,other_mode=struct.unpack_from('<3I',cases.read_bytes(),i*160+112)
            assert (other_flag,other_mode)==(1,3),(name,other_flag,other_mode)
            assert actual==effective and count==(3 if effective else 0),(name,words,actual)
            if count:
                calls=[words[2+j*8:7+j*8] for j in range(3)]
                assert calls==[(0,0,0x12345678,0,0),(0,1,0x12345678,0x2040000,2048 if fmt==2 else 1536),(0,2,0x12345678,0,0)],(name,calls)
            results.append(dict(name=name,initial_flag=flag,toggles=toggles,final_flag=actual,format=fmt,fixture_status=err,calls=count,requested_bytes=(2048 if fmt==2 else 1536) if count else 0))
        trace=(out/'cases.trace').read_text()
        for addr in ('0x7cf024','0x169f60','0x7cf51c','0x13af18','0x13af20','0x1e6a54'):
            assert any(line.startswith(addr+' ') for line in trace.splitlines()),addr
        (out/'cases.json').write_text(json.dumps(results,indent=2)+'\n'); (out/'fixture_patches.json').write_text(json.dumps(patches,indent=2)+'\n')
        (out/'verifier_snapshot.py').write_bytes(Path(__file__).read_bytes())
        r.results.update(status='PASS_CFA_MENU_GATE_CPU_SYNTHETIC',scenarios=results,
          assumptions=['Original event table, wrapper, callback, setter/getter and 1E6A54 prefix; stop before 1E6ACC.',
          'UI services are fixtures; event 5004 is injected directly.',
          'Dispatcher is a recording fixture and does not access files or image memory.',
          'All context, payload, flags, dimensions and errors are synthetic; DSP v7 model experimental.'],
          limits=['No physical input, sensor, actual frame, filesystem, JPEG or hardware.',
          'Error status is fixture output; observing later calls does not establish real dispatcher behavior.'])
        r.finish()
    except Exception as exc:
        r.results.update(status='FAIL',error=repr(exc)); raise
    finally:
        r.save()
    print('PASS',out,flush=True)

if __name__=='__main__':
    main()
