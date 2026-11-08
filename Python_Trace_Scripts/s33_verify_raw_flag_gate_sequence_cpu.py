#!/usr/bin/env python3
"""Execute the original V1.1 marker and writer gates with synthetic services."""
from datetime import datetime, timezone
from pathlib import Path
from types import SimpleNamespace
import json
import struct
import sys
from s33_run_gnu_arc700 import ROOT, LEGACY, TOOLCHAIN, Runner, sha
from s33_verify_gnu_dsp_lab import compile_probe, LAB, BUILD
sys.path.insert(0, str(ROOT / 'S33-sections/analysis_codex'))
from static_common import BS, PS, EXPECTED, ORIGINAL, raw, locate, disasm, u32


def main():
    out = ROOT / 'Risultati/HiddenMenu_RAW' / datetime.now(timezone.utc).strftime('flag_gate_sequence_cpu_%Y%m%dT%H%M%SZ')
    r = Runner(SimpleNamespace(legacy_root=LEGACY, toolchain=TOOLCHAIN, output=out, action='raw-flag-gate-sequence'))
    print('Prove:', out, flush=True)
    try:
        r.prepare()
        assert sha(ORIGINAL) == EXPECTED
        dump = ROOT / 'DUMPS/MainCode.dmp'
        data = dump.read_bytes()
        r.input_hashes[str(dump)] = sha(dump)
        build = json.loads(BUILD.read_text())
        sim = LAB / 'install/bin/arc-elf32-run'
        assert sha(sim) == build['experimental_sha256']
        r.experimental_engine = LAB
        r.input_hashes[str(sim)] = sha(sim)
        r.input_hashes[str(BUILD)] = sha(BUILD)
        spans = [(0x1b91ec,0x1b9292),(0x1b9292,0x1b93cc),
                 (0x28d48c,0x28d494),(0xbc698,0xbc6a0),
                 (0x12be64,0x12be74),(0x14a2d8,0x14a2e0)]
        for a, b in spans:
            block, offset = locate(a, b-a)
            assert raw(a,b-a) == data[block['offset']+offset:block['offset']+offset+b-a]
        assert u32(0x1b92d4) == 0x368790
        (out/'gnu_windows.txt').write_text('\n'.join(disasm(a,b) for a,b in spans))
        images = {i:bytearray(PS[i]) for i in (0,1,2,3,4,5)}
        maps, patches = [], []
        def binary(name, asm):
            elf = compile_probe(r,name,asm)
            path = out/(name+'.bin')
            result = r.command(name+'_extract',[TOOLCHAIN/'arc-elf32-objcopy','-O','binary','--only-section=.text',elf,path])
            assert result.returncode == 0, result.stdout
            chunk = path.read_bytes()
            path.write_bytes(chunk+bytes(8+(-len(chunk))%8))
            return path
        def mapping(path, addr):
            return ['--memory-mapfile','/result/'+path.name,'--memory-region',f'{addr:#x},{path.stat().st_size}']
        common = ' mov r10,0x2000000\n ld r10,[r10]\n'
        services = [
            ('marker',0x28d5bc,common+''' ld r11,[r10,16]
 add r11,r11,1
 st r11,[r10,16]
 st r0,[r10,20]
 st r1,[r10,24]
 st r2,[r10,28]
 st r3,[r10,32]
 st r4,[r10,36]
 mov r0,0
 j_s [blink]
'''),
            ('intermediate_query',0x141ed8,common+''' ld r0,[r10,40]
 j_s [blink]
'''),
            ('intermediate_change',0x159bf0,common+''' ld r11,[r10,44]
 mov r12,0x36c26e
 stb r11,[r12]
 ld r11,[r10,48]
 add r11,r11,1
 st r11,[r10,48]
 mov r0,0
 j_s [blink]
'''),
            ('intermediate_end',0x141ebc,' mov r0,0\n j_s [blink]\n'),
            ('finish_a',0x12fd1c,' mov r0,0\n j_s [blink]\n'),
            ('finish_b',0xd01c0,' mov r0,0\n j_s [blink]\n'),
            ('writer',0x28d4d4,common+''' ld r11,[r10,64]
 asl r12,r11,4
 add r12,r12,r10
 st r2,[r12,68]
 st r3,[r12,72]
 st r4,[r12,76]
 add r11,r11,1
 st r11,[r10,64]
 ld r11,[r10,100]
 cmp r11,255
 bhi no_writer_change
 mov r12,0x36c26e
 stb r11,[r12]
no_writer_change:
 mov r0,0
 j_s [blink]
''')]
        for i,(name,addr,asm) in enumerate(services):
            target=0x2030000+i*0x400
            path=binary(name,asm)
            maps+=mapping(path,target)
            entry=binary('entry_'+name,f' mov_s r12,{target:#x}\n j_s [r12]\n').read_bytes()[:8]
            block,off=locate(addr,8)
            before=bytes(images[block['index']][off:off+8])
            assert before==raw(addr,8)
            images[block['index']][off:off+8]=entry
            patches.append(dict(name=name,address=hex(addr),original=before.hex(),fixture=entry.hex()))
        # No change case: the intermediate getter reports 0. Other cases inject a change in 159BF0.
        tests=[('zero',0,0,0,0),('one',1,0,0,0),('two',2,0,0,0),('ff',255,0,0,0),
               ('one_to_two',1,1,2,0),('two_to_zero',2,1,0,0),('two_to_one',2,1,1,0),
               ('two_two_buffers',2,0,0,1),('two_writer_to_zero',2,0,0,1)]
        asm=' mov r20,0x2000000\n'
        for i,(name,flag,query,changed,two) in enumerate(tests):
            a=0x2001000+i*192
            asm+=f''' mov r21,{a:#x}
 st r21,[r20]
 mov r1,0x36879c
 mov r0,0
 stb r0,[r1]
 mov r1,0x36c26e
 mov r0,{flag}
 stb r0,[r1]
 mov r1,0x366f90
 mov r0,3
 st r0,[r1]
 mov r0,{0 if name == "two_writer_to_zero" else 256}
 st r0,[r21,100]
 mov r0,{query}
 st r0,[r21,40]
 mov r0,{changed}
 st r0,[r21,44]
 mov r1,0x202100c
 mov r0,{0x2041000 if two else 0}
 st r0,[r1]
 st sp,[r21,52]
 bl capture_{i}
 st r0,[r21,12]
 st sp,[r21,56]
 mov r1,0x36c26e
 ldb r0,[r1]
 st r0,[r21,60]
 b after_{i}
 .align 4
 capture_{i}:
 push_s blink
 mov r12,0x334104
 jl [r12]
 st.aw fp,[sp,-4]
 mov fp,sp
 sub sp,sp,204
 mov r0,16
 st r0,[fp,-204]
 mov r0,123
 st r0,[fp,-188]
 mov r15,0x2020000
 mov r16,0x1234
 mov r12,0x1b91ec
 j [r12]
 after_{i}:
'''
        asm+=' mov r0,0\n mov r8,1\n trap_s 1\n'
        for i,image in images.items():
            path=out/f'block{i}_LAB_FIXTURE.bin'
            path.write_bytes(image)
            maps+=mapping(path,BS[i]['load_address_candidate'])
        cases=out/'cases.bin';cases.write_bytes(bytes(len(tests)*192));maps+=mapping(cases,0x2001000)
        current=out/'current.bin';current.write_bytes(bytes(8));maps+=mapping(current,0x2000000)
        outer=out/'outer.bin';outer.write_bytes(struct.pack('<I',0x2021000)+bytes(4));maps+=mapping(outer,0x2020000)
        desc=bytearray(128);struct.pack_into('<I',desc,4,0x2040000);struct.pack_into('<I',desc,0x48,0x2023000)
        descriptor=out/'descriptor.bin';descriptor.write_bytes(desc);maps+=mapping(descriptor,0x2021000)
        elf=compile_probe(r,'cases',asm)
        result,log=r.run('cases','/result/'+elf.name,maps,trace=True)
        assert result['exit_code']==0 and result['fault'] is None,log
        expected=[(0,0,0,0),(1,1,1,0),(2,0,1,0),(255,0,1,0),
                  (2,1,1,1),(0,0,0,1),(1,0,1,1),(2,0,2,0),(0,0,1,0)]
        rows=[]
        for i,(name,flag,query,changed,two) in enumerate(tests):
            w=struct.unpack_from('<33I',cases.read_bytes(),i*192)
            final, markers, writes, changes=expected[i]
            assert (w[15],w[4],w[16],w[12])==(final,markers,writes,changes),(name,w)
            assert w[13]==w[14] and w[3]==123,(name,w)
            if markers:
                assert tuple(w[5:10])==(0x2040000,0x1234,4208,3152,2),(name,w)
            for j in range(writes):
                off=17+j*4
                assert tuple(w[off:off+3])==((0x2040000 if j==0 else 0x2041000),26527232,111),(name,w)
            rows.append(dict(name=name,initial_flag=flag,query_result=query,fixture_change=changed if query else None, writer_flag_change=0 if name == 'two_writer_to_zero' else None,
                             final_flag=final,marker_calls=markers,writer_calls=writes,
                             requested_bytes=26527232 if writes else 0,stack_preserved=True))
        trace=(out/'cases.trace').read_text()
        for addr in ('0x1b91ec','0x1b923a','0x1b9292','0x1b933a','0x1b93c8'):
            assert any(line.startswith(addr+' ') for line in trace.splitlines()),addr
        (out/'cases.json').write_text(json.dumps(rows,indent=2)+'\n')
        (out/'fixture_patches.json').write_text(json.dumps(patches,indent=2)+'\n')
        (out/'verifier_snapshot.py').write_bytes(Path(__file__).read_bytes())
        r.results.update(status='PASS_RAW_FLAG_GATES_SYNTHETIC_SERVICES',scenarios=rows,
                         assumptions=['Original instructions 1B91EC to epilogue; descriptor, state, caller and stack synthetic.',
                                      'Intermediate query is fixture 0 or 1; when 1, fixture 159BF0 changes flag and 141EBC is stubbed.',
                                      'Marker and writer are call recorders and do not read/write buffer; no image memory mapped. One writer fixture injects flag zero.',
                                      'fp[-204] fixed to 16, skipping branch 4 and indirect callback; context+0C is 0, selector 3.',
                                      'GNU DSP v7 model experimental, not validated on hardware.'],
                         limits=['No sensor, task scheduling, actual service behavior, allocation, image contents, file I/O or hardware.',
                                 'Deliberate injected mutations demonstrate sensitivity, not actual intermediate-service behavior.',
                                 'No proof of RAW purity, same frame, JPEG or persistence.'])
        r.finish()
    except Exception as exc:
        r.results.update(status='FAIL',error=repr(exc))
        raise
    finally:
        r.save()
    print('PASS: original RAW gates with synthetic services;',out,flush=True)


if __name__=='__main__':
    main()
