#!/usr/bin/env python3
"""Exercise original RAW gate, pending-queue publication and descriptor recovery offline."""
from datetime import datetime, timezone
from pathlib import Path
from types import SimpleNamespace
import json
import struct
import sys
from s33_run_gnu_arc700 import ROOT, LEGACY, TOOLCHAIN, Runner, sha
from s33_verify_gnu_dsp_lab import BUILD, LAB, compile_probe
sys.path.insert(0, str(ROOT / 'S33-sections/analysis_codex'))
from static_common import BS, PS, EXPECTED, ORIGINAL, raw, locate, disasm


def main():
    out = ROOT/'Risultati/HiddenMenu_RAW'/datetime.now(timezone.utc).strftime('raw_queue_image_compare_cpu_%Y%m%dT%H%M%SZ')
    r = Runner(SimpleNamespace(legacy_root=LEGACY, toolchain=TOOLCHAIN, output=out, action='raw-queue-image-link'))
    print('Prove:', out, flush=True)
    try:
        r.prepare()
        assert sha(ORIGINAL) == EXPECTED
        dump = ROOT/'DUMPS/MainCode.dmp'
        data = dump.read_bytes()
        r.input_hashes[str(dump)] = sha(dump)
        build = json.loads(BUILD.read_text())
        sim = LAB/'install/bin/arc-elf32-run'
        assert sha(sim) == build['experimental_sha256']
        r.experimental_engine = LAB
        r.input_hashes[str(sim)] = sha(sim)
        r.input_hashes[str(BUILD)] = sha(BUILD)
        spans = [(0x1b9292,0x1b93cc), (0x18ee50,0x18ee74),
                 (0x18e8b4,0x18e8f8), (0x18e9d0,0x18ea0c),
                 (0x18e310,0x18e398), (0x18efc2,0x18f00e), (0x1e293e,0x1e2952)]
        for a,b in spans:
            block, offset = locate(a,b-a)
            assert raw(a,b-a) == data[block['offset']+offset:block['offset']+offset+b-a]
        (out/'gnu_windows.txt').write_text('\n'.join(disasm(a,b) for a,b in spans))
        images = {i:bytearray(PS[i]) for i in (0,1,2,3,4,5)}
        maps, patches = [], []
        def binary(name, asm):
            elf = compile_probe(r,name,asm)
            path = out/(name+'.bin')
            p = r.command(name+'_extract',[TOOLCHAIN/'arc-elf32-objcopy','-O','binary','--only-section=.text',elf,path])
            assert p.returncode == 0,p.stdout
            chunk = path.read_bytes()
            path.write_bytes(chunk+bytes(8+(-len(chunk))%8))
            return path
        def mapping(path, addr):
            return ['--memory-mapfile','/result/'+path.name,'--memory-region',f'{addr:#x},{path.stat().st_size}']
        fixtures = [
            ('writer',0x28d4d4,''' mov r10,0x2200000
 ld r11,[r10,12]
 add r11,r11,1
 st r11,[r10,12]
 st r11,[r10,16]
 st r2,[r10,20]
 st r3,[r10,24]
 mov r0,0
 j_s [blink]
'''),
            ('lock',0x1593ac,' mov r0,0\n j_s [blink]\n'),
            ('unlock',0x1594a4,' mov r0,0\n j_s [blink]\n'),
            ('push',0x27722c,''' mov r10,0x2200000
 ld r11,[r10,12]
 add r11,r11,1
 st r11,[r10,12]
 st r11,[r10,28]
 st r0,[r10,32]
 st r1,[r10]
 mov r0,0
 j_s [blink]
'''),
            ('pop',0x277244,''' mov r10,0x2200000
 ld r11,[r10,12]
 add r11,r11,1
 st r11,[r10,12]
 st r11,[r10,36]
 st r0,[r10,40]
 ld r11,[r10]
 st r11,[r1]
 mov r0,0
 j_s [blink]
'''),
            ('finish_a',0x12fd1c,' mov r0,0\n j_s [blink]\n'),
            ('finish_b',0xd01c0,' mov r0,0\n j_s [blink]\n'),
            ('stop_compare',0x1e2952,' j [r26]\n'),
            ('stop_fragment',0x18f00e,' j [r26]\n'),
            ('stop_no_match',0x18f252,' j [r26]\n')]
        for i,(name,addr,asm) in enumerate(fixtures):
            target=0x2030000+i*0x400
            path=binary(name,asm)
            maps+=mapping(path,target)
            entry=binary('entry_'+name,f' mov_s r12,{target:#x}\n j_s [r12]\n').read_bytes()[:8]
            block,off=locate(addr,8)
            before=bytes(images[block['index']][off:off+8])
            assert before==raw(addr,8)
            images[block['index']][off:off+8]=entry
            patches.append(dict(name=name,address=hex(addr),original=before.hex(),fixture=entry.hex()))
        asm=''
        for i, flag in enumerate((1,0,1,1,1)):
            case=0x2001000+i*128
            asm+=f''' mov r21,{case:#x}
 mov r1,0x2200000
 mov r0,0
 st r0,[r1]
 st r0,[r1,12]
 st r0,[r1,16]
 st r0,[r1,20]
 st r0,[r1,24]
 st r0,[r1,28]
 st r0,[r1,32]
 st r0,[r1,36]
 st r0,[r1,40]
 mov r1,0x36c26e
 mov r0,{flag}
 stb r0,[r1]
 mov r1,0x366f90
 mov r0,3
 st r0,[r1]
 mov r1,0x368024
 mov r0,0x2200100
 st r0,[r1,4]
 mov r0,1
 stb r0,[r1,24]
 stb r0,[r1,52]
 mov r0,0x2022000
 st r0,[r1,28]
 mov r1,0x2022008
 mov r0,{0x2041000 if i == 2 else 0x2040000:#x}
 st r0,[r1]
 mov r1,0x368024
 mov r0,0
 st r0,[r1,32]
 st r0,[r1,36]
 mov r1,0x47d7c0
 mov r0,0x2021000
 st r0,[r1]
 mov r0,1
 st r0,[r1,4]
 mov r1,0x2023000
 mov r0,0
 st r0,[r1]
 st r0,[r1,4]
 st r0,[r1,8]
 st sp,[r21,0]
 bl gate_{i}
 st r0,[r21,4]
 st sp,[r21,8]
 mov r1,0x368040
 ld r0,[r1]
 st r0,[r21,12]
 mov r14,0x2023000
 mov r26,after_fragment_{i}
 mov r12,0x18efc2
 j [r12]
 after_fragment_{i}:
 mov r21,{case:#x}
 st r0,[r21,64]
 mov r13,0x2023000
 mov r1,0x2023260
 mov r0,{0x2021800 if i in (3,4) else 0x2021000:#x}
 st r0,[r1]
 mov r20,{77 if i == 4 else 0}
 mov r26,after_compare_{i}
 mov r12,0x1e293e
 j [r12]
 after_compare_{i}:
 st r20,[r21,68]
 mov r1,0x2023000
 ld r0,[r1]
 st r0,[r21,16]
 ld r0,[r1,4]
 st r0,[r21,20]
 ld r0,[r1,8]
 st r0,[r21,24]
 mov r1,0x47d7c4
 ld r0,[r1]
 st r0,[r21,28]
 mov r1,0x368044
 ld r0,[r1]
 st r0,[r21,32]
 mov r1,0x2200000
 ld r0,[r1,16]
 st r0,[r21,36]
 ld r0,[r1,20]
 st r0,[r21,40]
 ld r0,[r1,24]
 st r0,[r21,44]
 ld r0,[r1,28]
 st r0,[r21,48]
 ld r0,[r1,32]
 st r0,[r21,52]
 ld r0,[r1,36]
 st r0,[r21,56]
 ld r0,[r1,40]
 st r0,[r21,60]
 b done_{i}
 .align 4
 gate_{i}:
 push_s blink
 mov r12,0x334104
 jl [r12]
 st.aw fp,[sp,-4]
 mov fp,sp
 sub sp,sp,204
 mov r0,10
 st r0,[fp,-204]
 mov r0,123
 st r0,[fp,-188]
 mov r15,0x2020000
 mov r16,0
 mov r12,0x1b9292
 j [r12]
 done_{i}:
'''
        asm+=' mov r0,0\n mov r8,1\n trap_s 1\n'
        for i,image in images.items():
            path=out/f'block{i}_LAB_FIXTURE.bin'; path.write_bytes(image)
            maps+=mapping(path,BS[i]['load_address_candidate'])
        for name,addr,content in [
            ('cases.bin',0x2001000,bytes(640)), ('queue.bin',0x2200000,bytes(256)),
            ('outer.bin',0x2020000,struct.pack('<I',0x2021000)+bytes(4)),
            ('descriptor.bin',0x2021000,bytes(4)+struct.pack('<I',0x2040000)+bytes(120)),
            ('node.bin',0x2022000,bytes(8)+struct.pack('<I',0x2040000)+bytes(4)),
            ('processing.bin',0x2023000,bytes(0x300)), ('tables.bin',0x47d000,bytes(0x1000))]:
            path=out/name;path.write_bytes(content);maps+=mapping(path,addr)
        elf=compile_probe(r,'cases',asm)
        result,log=r.run('cases','/result/'+elf.name,maps,trace=True)
        assert result['exit_code']==0 and result['fault'] is None,log
        rows=[]
        for i,flag in enumerate((1,0,1,1,1)):
            w=struct.unpack_from('<18I',(out/'cases.bin').read_bytes(),i*128)
            assert w[0]==w[2] and w[1]==123 and w[3]==0,w
            if i == 2:
                assert tuple(w[4:9])==(0,0,0,1,0x2022000) and w[16]==1,w
            else:
                assert tuple(w[4:9])==(0x2021000,0x5000,0x2040000,2,0x2022000),w
            assert tuple(w[9:16])==((1 if flag else 0),(0x2040000 if flag else 0),(26527232 if flag else 0),2 if flag else 1,0x2200100,3 if flag else 2,0x2200100),w
            assert w[17] == (77 if i == 4 else 0x700204 if i in (2,3) else 0),w
            rows.append(dict(compare_status=hex(w[17]),expected_descriptor=hex(0x2021800 if i in (3,4) else 0x2021000),flag=flag, mismatched_node=(i==2), gate_return=w[1],writer_order=w[9],writer_buffer=hex(w[10]),requested_bytes=w[11],push_order=w[12],pop_order=w[14],queue_handle=hex(w[13]),descriptor=hex(w[4]),data=hex(w[6]),node=hex(w[8]),descriptor_state=w[7],fragment_stop_r0=hex(w[16]),stack_preserved=True))
        trace=(out/'cases.trace').read_text()
        for addr in ('0x1b9292','0x1b93b0','0x18ee50','0x18e9fa','0x18efd8','0x18efea','0x18eff8','0x18f00c','0x1e2944'):
            assert any(line.startswith(addr+' ') for line in trace.splitlines()),addr
        (out/'cases.json').write_text(json.dumps(rows,indent=2)+'\n')
        (out/'fixture_patches.json').write_text(json.dumps(patches,indent=2)+'\n')
        (out/'verifier_snapshot.py').write_bytes(Path(__file__).read_bytes())
        r.results.update(status='PASS_SYNTHETIC_RAW_QUEUE_DESCRIPTOR_COMPARISON',scenarios=rows,
            assumptions=['Original 1B9292 through epilogue with synthetic caller frame and discriminator 0x0A; descriptor and frame-node are seeded directly.',
                         'Original 18EE50, 18E9D0, 18E8B4, 18E354, 18E310 and fragment 18EFC2..18F00C; queue, locks, writer and unrelated exit services are fixtures.',
                         'Lab-only stops replace code at 18F00E or 18F252 and return to the probe; image-preparation entry and later pipeline are not run.',
                         'GNU DSP v7 simulator is experimental; no actual image buffer is mapped or dereferenced.'],
            limits=['Caller comparison is entered manually with synthetic expected descriptor and r20 seeded to 0 or 77; its continuation is stopped after the comparison.',
                    'Manual fragment entry and seeded state do not establish runtime reachability, ownership, concurrency or same physical frame.',
                    'Writer is only an argument recorder; no file I/O, full JPEG worker or camera hardware.'])
        r.finish()
    except Exception as exc:
        r.results.update(status='FAIL',error=repr(exc))
        raise
    finally:
        r.save()
    print('PASS: synthetic RAW gate, queue, descriptor recovery and comparison;',out,flush=True)

if __name__=='__main__': main()
