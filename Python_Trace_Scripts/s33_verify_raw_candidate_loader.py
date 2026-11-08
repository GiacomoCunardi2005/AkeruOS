#!/usr/bin/env python3
"""Run original TBIB loader and bounded startup on RAW candidate, with file I/O fixture."""
from datetime import datetime, timezone
from pathlib import Path
from types import SimpleNamespace
import json
import struct
import sys

from s33_run_gnu_arc700 import ROOT, LEGACY, TOOLCHAIN, Runner, sha
from s33_verify_gnu_dsp_lab import compile_probe, LAB, BUILD
sys.path.insert(0, str(ROOT/'S33-sections/analysis_codex'))
sys.path.insert(0, str(ROOT/'coolpix-s33-re'))
from static_common import BS
from s33_extract import parse_firmware


def main():
    source = ROOT/'Risultati/HiddenMenu_RAW_Firmware/20261027T110219Z/firmware_RAW_FORZATO_OFFLINE_NON_INSTALLARE.bin'
    out = ROOT/'Risultati/HiddenMenu_RAW_Firmware'/datetime.now(timezone.utc).strftime('loader_%Y%m%dT%H%M%SZ')
    r = Runner(SimpleNamespace(legacy_root=LEGACY, toolchain=TOOLCHAIN, output=out, action='raw-original-loader-and-bounded-startup'))
    print('Prove:',out,flush=True)
    try:
        r.prepare()
        assert sha(source) == '56c9457646be23bde6e1bda47c6cefaada5bf52657ba299f83339306debf4cbf'
        package = source.read_bytes()
        sections,_ = parse_firmware(package)
        tbm = package[sections[1].data_start:sections[1].data_start+sections[1].data_length]
        tbib = (ROOT/'OriginalSoftware_NikonS33_V1.1/firmware.bin').read_bytes()[0x7c:0x44c38]
        blocks = [BS[i] for i in (0,1,8)]
        assert all(x['type']==1 for x in blocks)
        build = json.loads(BUILD.read_text())
        engine = LAB/'install/bin/arc-elf32-run'
        assert sha(engine) == build['experimental_sha256']
        r.experimental_engine = LAB
        for p in (source,BUILD,engine):r.input_hashes[str(p)] = sha(p)
        command = r.command
        def bounded(name,args,timeout=30):
            args=list(args)
            if name.startswith('loader_') and '10s' in args:
                args[args.index('10s')]='45s';timeout=55
            return command(name,args,timeout=timeout)
        r.command=bounded
        def binary(name,asm):
            elf=compile_probe(r,name,asm);dest=out/(name+'.bin')
            result=r.command(name+'_extract',[TOOLCHAIN/'arc-elf32-objcopy','-O','binary','--only-section=.text',elf,dest])
            assert result.returncode==0,result.stdout
            return dest.read_bytes()
        def jump(target):
            data=binary('entry_'+hex(target),f' mov_s r12,{target:#x}\n j_s [r12]\n')
            assert len(data)==8
            return data
        def call(addr):return f' mov r12,{addr:#x}\n jl [r12]\n'
        recorder=binary('sector_recorder',''' push_s blink
 mov r10,0x2010000
 ld r5,[r10,12]
 asl r6,r5,4
 add r6,r6,64
 add r6,r6,r10
 st r0,[r6]
 st r1,[r6,4]
 st r2,[r6,8]
 add r5,r5,1
 st r5,[r10,12]
 ld r6,[r10,16]
 cmp r5,r6
 beq read_fail
 asl r0,r0,9
 add r0,r0,0x4000000
 asl r1,r1,9
 mov r3,r2
 mov r2,r1
 mov r1,r0
 mov r0,r3
 mov r12,0x100abc0
 jl [r12]
 mov r0,0
 pop_s blink
 j_s [blink]
read_fail:
 mov r0,1
 pop_s blink
 j_s [blink]
''')
        stop=binary('kernel_stop',' mov r10,0x2010000\n st sp,[r10,24]\n st gp,[r10,28]\n mov r0,0x51\n st r0,[r10,20]\n mov r0,0\n mov r8,1\n trap_s 1\n')
        cpu_return=binary('cpu_config_return',' mov r0,0\n j_s [blink]\n')
        stop_entry=jump(0x2031000)
        cases=[]
        for name,expected,reads,startup in [('valid',0,4,False),('bad_magic',11,1,False),('bad_checksum',13,2,False),('read_failure',7,2,False),('startup_clear',0,4,True)]:
            maps=[]
            def mmap(label,address,data):
                path=out/(name+'_'+label+'.bin');path.write_bytes(bytes(address%8)+data)
                maps.extend(['--memory-mapfile','/result/'+path.name,'--memory-region',f'{address:#x},{len(data)}'])
                return path
            tbib_data=bytearray(tbib);tbib_data[0xa120:0xa128]=jump(0x2030000)
            mmap('tbib_fixture',0x1000000,tbib_data)
            source_data=bytearray(tbm)
            if name=='bad_magic':source_data[0]^=1
            if name=='bad_checksum':source_data[0x1c]^=1
            mmap('tbm',0x4000000,source_data)
            state=bytearray(512)
            if name=='read_failure':struct.pack_into('<I',state,16,2)
            state_path=mmap('state',0x2010000,state)
            mmap('recorder',0x2030000,recorder+bytes(16))
            mmap('stop',0x2031000,stop+bytes(16))
            loaded=[]
            for block in blocks:
                path=mmap('payload'+str(block['index']),block['load_address_candidate'],b'\xa5'*(block['size']+16))
                loaded.append((block,path))
            if startup:bss=mmap('bss_stack',0x42d140,b'\xa5'*(0x5daddc-0x42d140+16))
            asm=' mov r20,0x2010000\n st sp,[r20,4]\n'+call(0x10010c0)+' st r0,[r20]\n st sp,[r20,8]\n'
            if startup:
                # shortcut: CPU configuration is stubbed and the kernel is stopped before scheduling.
                asm+=' cmp r0,0\n bne finish\n'
                for address,data in ((0x330a78,cpu_return),(0x333d7c,stop_entry)):
                    for offset,value in enumerate(data):
                        asm+=f' mov r10,{address+offset:#x}\n mov r0,{value}\n stb r0,[r10]\n'
                asm+=' mov r12,0xbb540\n j [r12]\n'
            asm+='finish:\n mov r0,0\n mov r8,1\n trap_s 1\n'
            elf=compile_probe(r,name,asm)
            case,log=r.run('loader_'+name,'/result/'+elf.name,maps)
            assert case['exit_code']==0 and case['fault'] is None,log
            words=struct.unpack_from('<8I',state_path.read_bytes())
            assert words[0]==expected and words[1]==words[2] and words[3]==reads,(name,words)
            rows=[struct.unpack_from('<3I',state_path.read_bytes(),64+i*16) for i in range(reads)]
            assert rows[0][:2]==(0,1)
            for block,path in loaded:
                actual=path.read_bytes();size=block['size']
                assert actual[-16:]==b'\xa5'*16
                should_load=name in ('valid','startup_clear') or (name=='bad_checksum' and block['index']==0)
                want=tbm[block['offset']:block['offset']+size] if should_load else b'\xa5'*size
                if startup and block['index']==0:
                    want=bytearray(want)
                    for addr,patch in ((0x330a78,cpu_return),(0x333d7c,stop_entry)):
                        offset=addr-block['load_address_candidate'];want[offset:offset+len(patch)]=patch
                assert actual[:size]==want,(name,block['index'])
            if expected==0:
                assert rows[1:]==[(b['offset']//512,b['size']//512,b['load_address_candidate']) for b in blocks],rows
                assert struct.unpack_from('<I',(out/(name+'_tbib_fixture.bin')).read_bytes(),0x41100)[0]==0xbb540
            if startup:
                assert words[5]==0x51 and words[6:8]==(0x5dadc4,0x423844),words
                data=bss.read_bytes();assert data[:0x5da5dc-0x42d140]==bytes(0x5da5dc-0x42d140) and data[-16:]==b'\xa5'*16
            cases.append(dict(name=name,status=expected,reads=reads,stack_preserved=True,startup_clear=startup))
        (out/'verifier_snapshot.py').write_bytes(Path(__file__).read_bytes())
        r.results.update(status='PASS_ORIGINAL_LOADER_RAW_CANDIDATE_BOUNDED_STARTUP',candidate_sha256=sha(source),
                         loader_cases=cases,
                         assumptions=['Original TBIB descriptor, checksum and memcpy code; file-backed sector recorder.',
                                      'DSPv7 lab engine for bounded positive multiply; synthetic caller, RAM and guards.',
                                      'Startup stubs CPU configuration and stops before the kernel.'],
                         limits=['No physical NAND, ROM/reset, complete boot, scheduler, UI, sensor, SD or recovery.',
                                 'The two startup stubs exist only in the laboratory image after loader checksum.'])
        r.finish()
    except Exception as exc:
        r.results.update(status='FAIL',error=repr(exc));raise
    finally:r.save()
    print('PASS original loader and bounded startup:',out,flush=True)


if __name__=='__main__':main()
