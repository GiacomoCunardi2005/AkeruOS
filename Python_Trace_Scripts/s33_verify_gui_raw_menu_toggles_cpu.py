#!/usr/bin/env python3
"""Exercise shared RAW flags through the original IQDEBUG event wrapper."""
from datetime import datetime, timezone
from pathlib import Path
from types import SimpleNamespace
import json
import struct
import sys
from s33_run_gnu_arc700 import ROOT, LEGACY, TOOLCHAIN, Runner, sha
from s33_verify_gnu_dsp_lab import compile_probe
sys.path.insert(0, str(ROOT / 'S33-sections/analysis_codex'))
from static_common import BS, PS, raw, locate, disasm, u32


def main():
    out = ROOT / 'Risultati/GUI_S33' / datetime.now(timezone.utc).strftime('raw_menu_toggle_cpu_%Y%m%dT%H%M%SZ')
    r = Runner(SimpleNamespace(legacy_root=LEGACY, toolchain=TOOLCHAIN, output=out, action='raw-menu-toggle'))
    print('Prove:', out, flush=True)
    try:
        r.prepare()
        dump = ROOT / 'DUMPS/MainCode.dmp'
        data = dump.read_bytes()
        r.input_hashes[str(dump)] = sha(dump)
        for a, n in [(0x987000,28),(0x987020,0xb0),(0x7cf024,0x38),(0x7cf4c8,0x54),(0x7cf7c0,0x68),(0x28d48c,0x20),(0x14a2b8,0x28),(0x169f60,0x54)]:
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
                    [('lookup',0x635bd8),('update',0x636040),('refresh',0x145150)]]
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
        tests=[(0x5003,0x5003,0x500c,0x5003,0x5003,0x500c),
               (0x500c,0x5003,0x5003,0x500c,0x5003,0x500c)]
        asm=' mov r20,0x2000000\n'
        for i,sequence in enumerate(tests):
            a=0x2001000+i*128
            asm+=f''' mov r21,{a:#x}
 st r21,[r20]
 mov r1,0x36c26e
 mov r0,0
 stb r0,[r1]
 mov r1,0x366f90
 st r0,[r1]
 st sp,[r21,96]
'''
            for j,event in enumerate(sequence):
                asm+=f''' mov r0,0x987000
 mov r1,{event:#x}
 mov r2,0
 mov r12,0x7cf024
 jl [r12]
 mov r1,0x36c26e
 ldb r0,[r1]
 st r0,[r21,{j*8}]
 mov r1,0x366f90
 ld r0,[r1]
 st r0,[r21,{j*8+4}]
'''
            asm+=''' st sp,[r21,100]
'''
        asm += ' mov r0,0\n mov r8,1\n trap_s 1\n'
        for i, image in images.items():
            path = out / f'block{i}_LAB_FIXTURE.bin'
            path.write_bytes(image)
            maps += mapping(path, BS[i]['load_address_candidate'])
        path = out / 'cases.bin'; path.write_bytes(bytes(len(tests) * 128)); maps += mapping(path, 0x2001000)
        current = out / 'current.bin'; current.write_bytes(bytes(8)); maps += mapping(current, 0x2000000)
        elf = compile_probe(r, 'cases', asm)
        result, log = r.run('cases', '/result/' + elf.name, maps, trace=True)
        assert result['exit_code'] == 0 and result['fault'] is None, log
        rows = []
        expected=[[(1,0),(0,0),(1,3),(0,3),(1,3),(0,0)],[(1,3),(0,3),(1,3),(0,0),(1,0),(0,0)]]
        for i,sequence in enumerate(tests):
            w=struct.unpack_from('<26I',path.read_bytes(),i*128)
            got=[tuple(w[j*2:j*2+2]) for j in range(len(sequence))]
            assert got==expected[i] and w[24]==w[25],(i,got,w)
            rows.append(dict(events=[hex(x) for x in sequence],flag_selector=got,stack_preserved=True))
        trace=(out/'cases.trace').read_text()
        for a in ('0x7cf024','0x169f60','0x7cf4c8','0x7cf7c0','0x28d48c','0x28d498','0x14a2b8'):
            assert any(line.startswith(a+' ') for line in trace.splitlines()),a
        (out / 'cases.json').write_text(json.dumps(rows, indent=2) + '\n')
        (out / 'fixture_patches.json').write_text(json.dumps(patches, indent=2) + '\n')
        (out / 'verifier_snapshot.py').write_bytes(Path(__file__).read_bytes())
        r.results.update(status='PASS_RAW_MENU_TOGGLE_FIXTURES', scenarios=rows,
            assumptions=['Original IQDEBUG wrapper, event table, callbacks and RAW flag/selector getters and setters; UI services are fixtures.'],
            limits=['Events injected into wrapper; no RAW frame, real GUI, capture, file write, persistence or hardware.'])
        r.finish()
    except Exception as exc:
        r.results.update(status='FAIL', error=repr(exc))
        raise
    finally:
        r.save()
    print('PASS: two RAW menu toggle sequences;', out, flush=True)

if __name__ == '__main__':
    main()
