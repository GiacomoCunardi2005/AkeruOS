#!/usr/bin/env python3
"""Run original register restore/return tails with distinct synthetic stack words."""
import json
from pathlib import Path
from types import SimpleNamespace

from s33_run_gnu_arc700 import ROOT,LEGACY,TOOLCHAIN,sha
from s33_verify_gnu_defined_memory import DefinedRunner,LAB,BUILD,known_sections
from s33_verify_gnu_dsp_lab import compile_probe
from s33_trace_state_dispatch import verified_payloads
from s33_verify_sensor_mmio_dialog import aligned_window


def main():
    r=DefinedRunner(SimpleNamespace(legacy_root=LEGACY,toolchain=TOOLCHAIN,output=None,action='register-original-millicode'))
    print('Evidence:',r.out,flush=True)
    try:
        r.prepare();build=json.loads(BUILD.read_text());assert sha(LAB/'install/bin/arc-elf32-run')==build['engine_sha256']
        r.experimental_engine=LAB
        for p in [BUILD,LAB/'install/bin/arc-elf32-run',Path(__file__)]:r.input_hashes[str(p)]=sha(p)
        (r.out/'verifier_snapshot.py').write_bytes(Path(__file__).read_bytes())
        blocks,payloads,directory=verified_payloads(ROOT);info=next(b for b in blocks if b['index']==0)
        body=payloads[0];main=r.out/'payload0_mmap.bin';main.write_bytes(body)
        original=(ROOT/'OriginalSoftware_NikonS33_V1.1/firmware.bin').read_bytes();off=original.find(body)
        assert off>=0 and original.find(body,off+1)<0
        r.input_hashes[str(directory/info['file'])]=sha(directory/info['file'])
        cases=[(0x33415c,10,4),(0x33416c,8,4),(0x334174,7,4),(0x334184,5,4),
               (0x33418c,4,4),(0x334194,3,4),(0x3341a4,1,4),(0x3341a6,1,8)]
        for entry,count,blink_increment in cases:
            name=f'restore_{entry:x}';total=count*4+blink_increment
            expected={n:0xc0000000+0x101*n if n<13+count else 0xb0000000+0x101*n for n in range(13,27)}
            asm='mov r9,sp\nmov r7,0x77665544\nmov r10,0x11223344\nmov r0,0x13579bdf\n'
            asm+=''.join(f'mov r{n},{0xb0000000+0x101*n:#x}\n'for n in range(13,27))
            asm+=f'sub sp,sp,{total}\n'
            for n in range(13,13+count):asm+=f'mov r2,{expected[n]:#x}\nst r2,[sp,{(n-13)*4}]\n'
            asm+=f'mov r2,returned\nst r2,[sp,{count*4}]\n'
            if blink_increment==8:asm+=f'mov r2,0xcafebabe\nst r2,[sp,{count*4+4}]\n'
            asm+=f'mov r12,{8 if entry==0x3341a6 else 0x12345678:#x}\nmov blink,0xdead0000\nmov r3,{entry:#x}\nj [r3]\nreturned:\n'
            asm+='cmp sp,r9\nbne fail\ncmp r7,0x77665544\nbne fail\ncmp r10,0x11223344\nbne fail\ncmp r0,0x13579bdf\nbne fail\n'
            for n,value in expected.items():asm+=f'cmp r{n},{value:#x}\nbne fail\n'
            if blink_increment==8:asm+='ld r2,[r9,-4]\ncmp r2,0xcafebabe\nbne fail\n'
            asm+='mov r0,0\nb finish\nfail:\nmov r0,7\nfinish:\nmov r8,1\ntrap_s 1\n'
            elf=compile_probe(r,name,asm)
            r.range_override=known_sections(elf,False)+f",{info['load_address_candidate']:#x}:{len(body):#x}"
            options=['--memory-mapfile','/result/'+main.name,'--memory-region',f"{info['load_address_candidate']:#x},{len(body):#x}"]
            case,log=r.run(name,'/result/'+elf.name,options,trace=True,extract=True)
            assert case['exit_code']==0 and case['fault']is None,log[-2000:]
            case.update(entry=hex(entry),restored_registers={str(n):hex(expected[n])for n in range(13,13+count)},
                        untouched_registers={str(n):hex(expected[n])for n in range(13+count,27)},
                        stack_bytes_consumed=total,blink_increment=blink_increment,synthetic_frame=True,
                        sentinel_registers=['r0','r7','r10'],original_return_target_reached=True)
            assert main.read_bytes()==body
            print(name,'PASS',case['instructions'],flush=True)
        listing=aligned_window(body,info['load_address_candidate'],0x33413c,0x3341e4)
        (r.out/'millicode_source_disassembly.txt').write_text(listing+'\n')
        r.results.update(status='PASS_ORIGINAL_REGISTER_MILLICODE',follow_range=dict(start='0x33413c',end_exclusive='0x3341e4'),
                         original_payload=dict(path=str(main),base=info['load_address_candidate'],size=len(body),firmware_offset=off,sha256=sha(main)),
                         limits=['Synthetic stack frames test original restore/return code; not Nikon task-stack state.',
                                 'No custom AUX access executed and no physical extension semantics inferred.'])
        r.finish()
    except Exception as exc:r.results.update(status='FAIL',error=repr(exc));raise
    finally:r.save()
    print(r.out/'verified_evidence.json',flush=True)


if __name__=='__main__':main()
