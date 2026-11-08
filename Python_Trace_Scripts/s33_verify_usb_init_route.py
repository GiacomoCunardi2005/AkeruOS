#!/usr/bin/env python3
"""Bounded original USB class-to-initializer route; only result-local RAM copies change."""
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
from static_common import BS, PS, raw, locate, disasm

CURRENT, STATES, WRAPPER, PROVIDER, BUFFER = 0x2000000,0x2001000,0x2040000,0x2041000,0x2042000

def main():
    out=ROOT/'Risultati/USB_SCSI/Accesso_NAND_PC'/datetime.now(timezone.utc).strftime('init_cpu_%Y%m%dT%H%M%SZ')
    r=Runner(SimpleNamespace(legacy_root=LEGACY,toolchain=TOOLCHAIN,output=out,action='original-usb-class-initializer-route'))
    r.prepare()
    try:
        originals=[ROOT/'OriginalSoftware_NikonS33_V1.1/firmware.bin',ROOT/'DUMPS/MainCode.dmp']
        inputs={str(p.relative_to(ROOT)):sha(p) for p in originals}
        firmware,dump=[p.read_bytes() for p in originals]
        spans=[]
        def check(a,n):
            b,o=locate(a,n);f=0x480b8+b['offset']+o;d=raw(a,n)
            assert d==firmware[f:f+n]==dump[b['offset']+o:b['offset']+o+n]
            spans.append(dict(cpu=hex(a),firmware_offset=hex(f),size=n))
        images={i:bytearray(PS[i]) for i in (0,1,4,5)};maps=[];replaced=[]
        def mmap(name,a,data):
            (out/name).write_bytes(data);maps.extend(['--memory-mapfile','/result/'+name,'--memory-region',f'{a:#x},{len(data)}'])
        def binary(name,assembly):
            elf=compile_probe(r,name,assembly);p=out/(name+'.bin')
            result=r.command(name+'_extract',[TOOLCHAIN/'arc-elf32-objcopy','-O','binary','--only-section=.text',elf,p]);assert result.returncode==0
            return p.read_bytes()
        def call(a):return f' mov r12,{a:#x}\n jl [r12]\n'
        def replace(a,target):
            entry=binary(f'entry_{a:x}',f' mov_s r12,{target:#x}\n j_s [r12]\n');assert len(entry)==8
            b,o=locate(a,8);replaced.append(dict(cpu=hex(a),original=raw(a,8).hex(),lab=entry.hex()));images[b['index']][o:o+8]=entry
        provider=binary('provider',f' mov r10,{CURRENT:#x}\n ld r10,[r10]\n st r0,[r10,16]\n ld r11,[r10,20]\n add r11,r11,1\n st r11,[r10,20]\n mov r11,0x2060000\n st r11,[r1]\n mov r11,0\n st r11,[r2]\n ld r0,[r10,12]\n j_s [blink]\n')
        buffer=binary('buffer',f' mov r10,{CURRENT:#x}\n ld r10,[r10]\n st r0,[r10,24]\n j_s [blink]\n')
        wrapper=binary('route_wrapper',f' push_s blink\n'+call(0x334114)+' sub sp,sp,16\n mov r18,1\n mov r14,0x2070000\n mov r15,0\n mov r12,0x191314\n j [r12]\n')
        for name,a,data in [('provider',PROVIDER,provider),('buffer',BUFFER,buffer),('route_wrapper',WRAPPER,wrapper)]:mmap(name+'.bin',a,data+bytes(8+(-len(data))%8))
        replace(0x12a71c,PROVIDER);replace(0x81dca4,BUFFER)
        cases=[('msdc_success',0x3901b0,8,0,True),('msdc_provider_error',0x3901b0,8,0x123,True),('ptp_provider_error',0x3900f0,6,0x123,True),('msdc_callback_null',0x3901b0,8,0,False)]
        asm=''
        for i,(name,descriptor,cls,status,callback) in enumerate(cases):
            a=STATES+128*i
            asm+=f' mov r20,{a:#x}\n st sp,[r20,4]\n mov r10,{CURRENT:#x}\n st r20,[r10]\n mov r0,{status:#x}\n st r0,[r20,12]\n'
            # Original descriptor registrar, without its higher-level constructor services.
            for n,value in enumerate([0,descriptor,0,0,0,0,0,0]):asm+=f' mov r{n},{value:#x}\n'
            asm+=call(0x190c3c)
            asm+=f' mov r0,{0x1392cc if callback else 0:#x}\n'+call(0x190c24)
            for base,offset,value in [(0x366b7c,0x1c,0),(0x366b7c,0x21,1 if cls==8 else 2),(0x89ab7c,0x40,0),(0x3add5c,8,0),(0x3680c4,0,0),(0x366b98,5,0)]:
                asm+=f' mov r10,{base:#x}\n mov r0,{value:#x}\n '+('stb' if (base==0x366b7c and offset==0x21) or base==0x366b98 else 'st')+f' r0,[r10,{offset}]\n'
            asm+=call(WRAPPER)+' st r0,[r20]\n st sp,[r20,8]\n'
            for off,base,field,byte in [(28,0x89ab7c,0x40,False),(32,0x3add5c,8,False),(36,0x3680c4,0,True),(40,0x366b98,5,True)]:
                asm+=f' mov r10,{base:#x}\n '+('ldb' if byte else 'ld')+f' r0,[r10,{field}]\n st r0,[r20,{off}]\n'
        asm+=' mov r0,0\n mov r8,1\n trap_s 1\n'
        for i,d in images.items():mmap(f'block{i}_LAB_ONLY.bin',BS[i]['load_address_candidate'],d)
        for name,a,data in [('states',STATES,bytes(512)),('current',CURRENT,bytes(8)),('window',0x2070000,bytes(64))]:mmap(name+'.bin',a,data)
        elf=compile_probe(r,'init_cases',asm);result,log=r.run('init_cases','/result/'+elf.name,maps,trace=True)
        assert result['exit_code']==0 and result['fault'] is None,log
        data=(out/'states.bin').read_bytes();rows=[]
        for i,(name,descriptor,cls,status,callback) in enumerate(cases):
            w=struct.unpack_from('<11I',data,128*i);success=callback and not status
            assert w[1]==w[2] and w[0]==0,(name,w)
            assert w[4:6]==((30 if cls==8 else 28),1) if callback else w[4:6]==(0,0),(name,w)
            assert w[7]==(0x139690 if success else 0) and w[8]==(0x820d04 if success else 0),(name,w)
            assert w[9]==cls and w[10]==int(success),(name,w)
            rows.append(dict(name=name,descriptor=hex(descriptor),class_argument=cls,provider_status=hex(status),provider_request=w[4],provider_calls=w[5],buffer_callback=hex(w[6]),inquiry_callback=hex(w[7]),bulk_callback=hex(w[8]),class_saved=w[9],mode=w[10],stack_restored=True))
        pcs=sorted({int(m[1],16)for m in re.finditer(r'^0x([0-9a-f]+)\s',(out/'init_cases.trace').read_text(),re.M)})
        for pc in pcs:
            if any(a<=pc<a+8 for a in (0x12a71c,0x81dca4)):continue
            try:locate(pc,8)
            except ValueError:continue
            check(pc,8)
        assert {0x191330,0x1392cc,0x1392e6,0x1393de,0x1393fc,0x81f7ca}.issubset(pcs)
        assert all(sha(p)==inputs[str(p.relative_to(ROOT))] for p in originals)
        assert all(sha(Path(p))==h for p,h in r.input_hashes.items())
        (out/'cases.json').write_text(json.dumps(rows,indent=2)+'\n');(out/'executed_spans.json').write_text(json.dumps(spans,indent=2)+'\n')
        (out/'fixture.json').write_text(json.dumps(dict(replaced=replaced,entry='191314 after explicit lab ABI frame; configuration1',services=['12A71C recorder supplies declared descriptor pointer/status','81DCA4 buffer registration recorder'],limits=['Original class extraction and indirectcall; not whole191110/USB SET_CONFIGURATION','Default GNU zeroRAM, no unknown read tracking','No hardware, boot, SD/NAND I/O; no installable update created']),indent=2)+'\n')
        (out/'verifier_snapshot.py').write_bytes(Path(__file__).read_bytes())
        r.results.update(status='PASS_ORIGINAL_CLASS_TO_INITIALIZER',cases=len(rows),inputs=inputs,spans=len(spans),tool_inputs=r.input_hashes)
        (out/'verified_evidence.json').write_text(json.dumps(r.results,indent=2)+'\n');(out.parent/'init_cpu_latest.json').write_text(json.dumps(dict(evidence=str((out/'verified_evidence.json').relative_to(ROOT))),indent=2)+'\n')
        print('PASS',out)
    except Exception as exc:
        r.results.update(status='FAIL',error=repr(exc));(out/'verified_evidence.json').write_text(json.dumps(r.results,indent=2)+'\n');raise

if __name__=='__main__':main()
