#!/usr/bin/env python3
"""Execute original RAW export wrapper with explicit synthetic file services."""
from datetime import datetime, timezone
from pathlib import Path
from types import SimpleNamespace
import json
import struct
from s33_run_gnu_arc700 import ROOT, LEGACY, TOOLCHAIN, Runner, sha
from s33_verify_gnu_dsp_lab import compile_probe
import sys
sys.path.insert(0,str(ROOT/'S33-sections/analysis_codex'))
from static_common import BS,PS,locate,raw


def main():
    source=ROOT/'Risultati/HiddenMenu_RAW_Firmware/20261027T110219Z/firmware_RAW_FORZATO_OFFLINE_NON_INSTALLARE.bin'
    out=ROOT/'Risultati/HiddenMenu_RAW_Firmware'/datetime.now(timezone.utc).strftime('writer_%Y%m%dT%H%M%SZ')
    r=Runner(SimpleNamespace(legacy_root=LEGACY,toolchain=TOOLCHAIN,output=out,action='raw-original-writer-fixture-errors'))
    print('Prove:',out,flush=True)
    try:
        r.prepare();r.input_hashes[str(source)]=sha(source)
        assert sha(source)=='56c9457646be23bde6e1bda47c6cefaada5bf52657ba299f83339306debf4cbf'
        def binary(name,asm):
            elf=compile_probe(r,name,asm);dest=out/(name+'.bin')
            result=r.command(name+'_extract',[TOOLCHAIN/'arc-elf32-objcopy','-O','binary','--only-section=.text',elf,dest])
            assert result.returncode==0,result.stdout
            return dest.read_bytes()
        name_stub=binary('name_stub',' mov r0,84\n stb r0,[r1]\n mov r0,69\n stb r0,[r1,1]\n mov r0,83\n stb r0,[r1,2]\n mov r0,84\n stb r0,[r1,3]\n mov r0,0\n stb r0,[r1,4]\n j_s [blink]\n')
        open_stub=binary('open_stub',' mov r10,0x2010000\n ld r11,[r10,12]\n add r11,r11,1\n st r11,[r10,12]\n mov r11,0x1234\n st r11,[r3]\n ld r0,[r10]\n j_s [blink]\n')
        write_stub=binary('write_stub',' mov r10,0x2010000\n ld r11,[r10,16]\n add r11,r11,1\n st r11,[r10,16]\n st r2,[r10,24]\n ld r11,[r10,28]\n st r11,[r4]\n ld r0,[r10,4]\n j_s [blink]\n')
        close_stub=binary('close_stub',' mov r10,0x2010000\n ld r11,[r10,20]\n add r11,r11,1\n st r11,[r10,20]\n ld r0,[r10,8]\n j_s [blink]\n')
        services=[(0x1378b4,0x2030000,name_stub),(0x12bc20,0x2031000,open_stub),
                  (0x12bcc4,0x2032000,write_stub),(0x12bce4,0x2033000,close_stub)]
        image=bytearray(PS[0]);patches=[]
        for index,(addr,target,data) in enumerate(services):
            entry=binary(f'entry_{index}',f' mov_s r12,{target:#x}\n j_s [r12]\n');assert len(entry)==8
            block,offset=locate(addr,8);assert block['index']==0 and image[offset:offset+8]==raw(addr,8)
            patches.append(dict(address=hex(addr),original=bytes(image[offset:offset+8]).hex(),fixture=entry.hex()))
            image[offset:offset+8]=entry
        requested=26527232
        specs=[('complete',0,0,0,requested,0,1,1,1),('short_success',0,0,0,0,0,1,1,1),
               ('write_error',0,77,0,0,77,1,1,0),('open_error',78,0,0,0,78,1,0,0),
               ('close_error',0,0,79,requested,79,1,1,1)]
        results=[]
        for name,open_err,write_err,close_err,count,ret,opens,writes,closes in specs:
            maps=[]
            def mmap(label,addr,data):
                path=out/(name+'_'+label+'.bin');path.write_bytes(bytes(addr%8)+data)
                maps.extend(['--memory-mapfile','/result/'+path.name,'--memory-region',f'{addr:#x},{len(data)}'])
                return path
            mmap('main0_fixture',BS[0]['load_address_candidate'],image)
            mmap('main1',BS[1]['load_address_candidate'],PS[1])
            state=bytearray(64);struct.pack_into('<3I',state,0,open_err,write_err,close_err);struct.pack_into('<I',state,28,count)
            path=mmap('state',0x2010000,state)
            for addr,target,data in services:mmap('service_'+hex(target),target,data+bytes(16))
            asm=f''' mov r20,0x2010000
 st sp,[r20,36]
 mov r0,0
 mov r1,0x2021000
 mov r2,0x2040000
 mov r3,{requested}
 mov r4,111
 mov r12,0x28d4d4
 jl [r12]
 st r0,[r20,32]
 st sp,[r20,40]
 mov r0,0
 mov r8,1
 trap_s 1
'''
            elf=compile_probe(r,name,asm)
            case,log=r.run(name,'/result/'+elf.name,maps,trace=True)
            assert case['exit_code']==0 and case['fault'] is None,log
            w=struct.unpack('<16I',path.read_bytes())
            assert (w[3],w[4],w[5],w[8])==(opens,writes,closes,ret),(name,w)
            assert w[9]==w[10] and (not writes or w[6]==requested),(name,w)
            results.append(dict(name=name,reported_bytes=count,requested_bytes=w[6],return_status=w[8],
                                open_calls=w[3],write_calls=w[4],close_calls=w[5]))
        (out/'fixture_patches.json').write_text(json.dumps(patches,indent=2)+'\n')
        (out/'cases.json').write_text(json.dumps(results,indent=2)+'\n')
        (out/'verifier_snapshot.py').write_bytes(Path(__file__).read_bytes())
        r.results.update(status='PASS_ORIGINAL_RAW_WRAPPER_WITH_EXPLICIT_IO_FIXTURES',scenarios=results,
            candidate_sha256=sha(source),
            assumptions=['Original unmodified 28D4D4 and original string length code; four declared file/name fixtures.',
                         'All statuses and write counts are synthetic, not measured hardware outcomes.'],
            limits=['The wrapper ignores the reported count in these fixtures; short-success reachability in the actual backend is not proven.',
                    'An error from write bypasses close in this local wrapper; actual handle lifetime and lower-layer cleanup remain unknown.',
                    'No actual SD write, file system, capture, sensor or physical behavior executed.'])
        r.finish()
    except Exception as exc:
        r.results.update(status='FAIL',error=repr(exc));raise
    finally:r.save()
    print('PASS original RAW wrapper with synthetic I/O:',out,flush=True)


if __name__=='__main__':main()
