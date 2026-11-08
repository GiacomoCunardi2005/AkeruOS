#!/usr/bin/env python3
"""Exercise shared RAW flags through the original IQDEBUG event wrapper."""
from datetime import datetime, timezone
from pathlib import Path
from types import SimpleNamespace
import json
import struct
import sys
from s33_run_gnu_arc700 import ROOT, LEGACY, TOOLCHAIN, Runner, sha
from s33_verify_gnu_dsp_lab import compile_probe, LAB, BUILD
sys.path.insert(0, str(ROOT / 'S33-sections/analysis_codex'))
from static_common import BS, PS, raw, locate, disasm, u32


def main():
    out = ROOT / 'Risultati/GUI_S33' / datetime.now(timezone.utc).strftime('raw_menu_capture_gate_cpu_%Y%m%dT%H%M%SZ')
    r = Runner(SimpleNamespace(legacy_root=LEGACY, toolchain=TOOLCHAIN, output=out, action='raw-menu-capture-gate'))
    print('Prove:', out, flush=True)
    try:
        r.prepare()
        dump = ROOT / 'DUMPS/MainCode.dmp'
        data = dump.read_bytes()
        r.input_hashes[str(dump)] = sha(dump)
        build=json.loads(BUILD.read_text());sim=LAB/'install/bin/arc-elf32-run'
        assert sha(sim)==build['experimental_sha256'];r.experimental_engine=LAB
        r.input_hashes[str(sim)]=sha(sim);r.input_hashes[str(BUILD)]=sha(BUILD)
        for a, n in [(0x1b9292,0x13c),(0x12be64,0x10),(0x14a2d8,8),(0x987000,28),(0x987020,0xb0),(0x7cf024,0x38),(0x7cf4c8,0x54),(0x7cf7c0,0x68),(0x28d48c,0x20),(0x14a2b8,0x28),(0x169f60,0x54)]:
            block, offset = locate(a, n)
            assert raw(a, n) == data[block['offset'] + offset:block['offset'] + offset + n]
        assert (u32(0x987050),u32(0x987054),u32(0x987098),u32(0x98709c))==(0x5003,0x7cf4c8,0x500c,0x7cf7c0)
        (out / 'gnu_windows.txt').write_text('\n'.join(disasm(a,b) for a,b in [(0x7cf024,0x7cf054),(0x7cf4c8,0x7cf51c),(0x7cf7c0,0x7cf828)]))
        images = {i: bytearray(PS[i]) for i in (0, 1, 2, 3, 4, 5)}
        maps, patches = [], []
        def binary(name, asm):
            elf = compile_probe(r, name, asm)
            path = out / (name + '.bin')
            result = r.command(name + '_extract', [TOOLCHAIN / 'arc-elf32-objcopy', '-O', 'binary', '--only-section=.text', elf, path])
            assert result.returncode == 0, result.stdout
            data = path.read_bytes()
            path.write_bytes(data + bytes(8 + (-len(data)) % 8))
            return path
        def mapping(path, addr):
            return ['--memory-mapfile', '/result/' + path.name, '--memory-region', f'{addr:#x},{path.stat().st_size}']
        common = ' mov r10,0x2000000\n ld r10,[r10]\n'
        services = [(name,addr,' mov r0,0\n j_s [blink]\n') for name,addr in
                    [('lookup',0x635bd8),('update',0x636040),('refresh',0x145150),('finish_a',0x12fd1c),('finish_b',0xd01c0)]]
        services += [('record_write',0x28d4d4,common+' ld r11,[r10,96]\n asl r12,r11,4\n add r12,r12,r10\n st r2,[r12,100]\n st r3,[r12,104]\n st r4,[r12,108]\n add r11,r11,1\n st r11,[r10,96]\n mov r0,0\n j_s [blink]\n')]
        for i, (name, addr, asm) in enumerate(services):
            target = 0x2030000 + i * 0x400
            path = binary(name, asm)
            maps += mapping(path, target)
            entry = binary('entry_' + name, f' mov_s r12,{target:#x}\n j_s [r12]\n').read_bytes()[:8]
            block, off = locate(addr, 8)
            before = bytes(images[block['index']][off:off + 8])
            assert before == raw(addr, 8)
            images[block['index']][off:off + 8] = entry
            patches.append({'name': name, 'address': hex(addr), 'original': before.hex(), 'fixture': entry.hex()})
        tests=[('off',()),('ordinary',(0x5003,)),('mode3',(0x500c,)),('off_stale3',(0x500c,0x5003)),('two_buffers',(0x500c,))]
        asm=' mov r20,0x2000000\n'
        for i,(name,sequence) in enumerate(tests):
            a=0x2001000+i*192
            asm+=f''' mov r21,{a:#x}
 st r21,[r20]
 mov r1,0x36c26e
 mov r0,0
 stb r0,[r1]
 mov r1,0x366f90
 st r0,[r1]
 st sp,[r21,48]
'''
            for event in sequence:
                asm+=f''' mov r0,0x987000
 mov r1,{event:#x}
 mov r2,0
 mov r12,0x7cf024
 jl [r12]
'''
            asm+=f''' mov r1,0x36c26e
 ldb r0,[r1]
 st r0,[r21]
 mov r1,0x366f90
 ld r0,[r1]
 st r0,[r21,4]
 mov r1,0x202100c
 mov r0,{0x2041000 if name=='two_buffers' else 0}
 st r0,[r1]
 bl capture_{i}
 st r0,[r21,12]
 st sp,[r21,52]
 b after_{i}
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
 mov r12,0x1b9292
 j [r12]
 after_{i}:
'''
        asm += ' mov r0,0\n mov r8,1\n trap_s 1\n'
        for i, image in images.items():
            path = out / f'block{i}_LAB_FIXTURE.bin'
            path.write_bytes(image)
            maps += mapping(path, BS[i]['load_address_candidate'])
        path = out / 'cases.bin'; path.write_bytes(bytes(len(tests) * 192)); maps += mapping(path, 0x2001000)
        current = out / 'current.bin'; current.write_bytes(bytes(8)); maps += mapping(current, 0x2000000)
        outer=out/'outer.bin';outer.write_bytes(struct.pack('<I',0x2021000)+bytes(4));maps+=mapping(outer,0x2020000)
        desc=bytearray(128);struct.pack_into('<I',desc,4,0x2040000);struct.pack_into('<I',desc,0x48,0x2023000)
        p=out/'descriptor.bin';p.write_bytes(desc);maps+=mapping(p,0x2021000)
        elf = compile_probe(r, 'cases', asm)
        result, log = r.run('cases', '/result/' + elf.name, maps, trace=True)
        assert result['exit_code'] == 0 and result['fault'] is None, log
        rows = []
        expected=[(0,0,0,0),(1,0,1,13263616),(1,3,1,26527232),(0,3,0,0),(1,3,2,26527232)]
        for i,(name,sequence) in enumerate(tests):
            w=struct.unpack_from('<33I',path.read_bytes(),i*192)
            flag,mode,n,length=expected[i]
            assert (w[0],w[1],w[24],w[12]==w[13],w[3])==(flag,mode,n,True,123),(name,w)
            for j in range(n):
                off=25+j*4
                assert (w[off],w[off+1],w[off+2])==((0x2040000 if j==0 else 0x2041000),length,111),(name,w)
            rows.append(dict(name=name,events=[hex(e) for e in sequence],flag=flag,selector=mode,recorded_writes=n,requested_bytes=length,stack_preserved=True))
        trace=(out/'cases.trace').read_text()
        for a in ('0x7cf024','0x7cf4c8','0x7cf7c0','0x1b9292','0x1b933a','0x1b93a0','0x1b93c8'):
            assert any(line.startswith(a+' ') for line in trace.splitlines()),a
        (out / 'cases.json').write_text(json.dumps(rows, indent=2) + '\n')
        (out / 'fixture_patches.json').write_text(json.dumps(patches, indent=2) + '\n')
        (out / 'verifier_snapshot.py').write_bytes(Path(__file__).read_bytes())
        r.results.update(status='PASS_RAW_MENU_CAPTURE_GATE_BOUNDED', scenarios=rows,
            assumptions=['Original IQDEBUG callbacks and capture gate from 1B9292 through original epilogue; synthetic frame and descriptors, UI and file write fixture.'],
            limits=['No actual capture, RAW data, allocation, file write, persistence or hardware; frame and pointers are synthetic and not physical RAM.'])
        r.finish()
    except Exception as exc:
        r.results.update(status='FAIL', error=repr(exc))
        raise
    finally:
        r.save()
    print('PASS: five RAW menu and bounded gate scenarios;', out, flush=True)

if __name__ == '__main__':
    main()
