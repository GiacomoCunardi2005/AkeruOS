#!/usr/bin/env python3
"""Exercise original iris setter and wrapper with explicit service fixtures."""
from datetime import datetime, timezone
from pathlib import Path
from types import SimpleNamespace
import json
import struct
import sys
from s33_run_gnu_arc700 import ROOT, LEGACY, TOOLCHAIN, Runner, sha
from s33_verify_gnu_dsp_lab import compile_probe
sys.path.insert(0, str(ROOT / 'S33-sections/analysis_codex'))
from static_common import BS, PS, raw, locate, disasm


def main():
    out = ROOT / 'Risultati/GUI_S33' / datetime.now(timezone.utc).strftime('iris_panel_key_cpu_%Y%m%dT%H%M%SZ')
    r = Runner(SimpleNamespace(legacy_root=LEGACY, toolchain=TOOLCHAIN, output=out, action='iris-panel-key'))
    print('Prove:', out, flush=True)
    try:
        r.prepare()
        dump = ROOT / 'DUMPS/MainCode.dmp'
        data = dump.read_bytes()
        r.input_hashes[str(dump)] = sha(dump)
        for a, n in [(0x2c5074,0x13c), (0x406e05,43), (0x406e89,16), (0x406e9a,18), (0x149530, 0x16), (0x18b85c, 0x74), (0x18b788, 4), (0x149362, 0x10)]:
            block, offset = locate(a, n)
            assert raw(a, n) == data[block['offset'] + offset:block['offset'] + offset + n]
        (out / 'gnu_windows.txt').write_text('\n'.join(disasm(a, b) for a, b in [(0x149530, 0x149546), (0x18b85c, 0x18b8d0), (0x149362, 0x149372)]))
        images = {i: bytearray(PS[i]) for i in (0, 1, 4, 5)}
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
        services = [
            ('acquire', 0x235a1c, common + ' ld r11,[r10,32]\n add r11,r11,1\n st r11,[r10,32]\n mov r11,0x1234\n sth r11,[r1]\n ld r0,[r10,8]\n j_s [blink]\n'),
            ('guard', 0x235da0, common + ' ld r11,[r10,36]\n add r11,r11,1\n st r11,[r10,36]\n ld r0,[r10,12]\n j_s [blink]\n'),
            ('request', 0x235b0c, common + ' ld r11,[r10,40]\n add r11,r11,1\n st r11,[r10,40]\n st r0,[r10,48]\n st r1,[r10,52]\n st r2,[r10,56]\n st r3,[r10,60]\n ld r0,[r10,16]\n j_s [blink]\n'),
            ('release', 0x23524c, common + ' ld r11,[r10,44]\n add r11,r11,1\n st r11,[r10,44]\n mov r0,0\n j_s [blink]\n'),
            ('cleanup', 0x18b9d4, common + ' ld r11,[r10,64]\n add r11,r11,1\n st r11,[r10,64]\n mov r0,0\n j_s [blink]\n'),
        ]
        # shortcut: key getter replays a bounded sequence, not real electrical input.
        services += [
            ('key', 0x16f920, common + " cmp r0,4\n bne key_other\n ld r0,[r10,72]\n add r11,r0,1\n st r11,[r10,72]\n j_s [blink]\n key_other: ld r11,[r10,68]\n cmp r0,r11\n bne key_zero\n ld r0,[r10,76]\n add r11,r0,1\n st r11,[r10,76]\n cmp r0,0\n mov r0,0\n bne key_done\n mov r0,1\n key_done: j_s [blink]\n key_zero: mov r0,0\n j_s [blink]\n"),
            ('draw_text',0x1567f8,common+' st r2,[r10,80]\n mov r0,0\n j_s [blink]\n'),
        ] + [(name,addr,' mov r0,0\n j_s [blink]\n') for name,addr in
             [('init',0x14a7b0),('delay',0x145c3c),('setup',0x149f80),('clear',0x1564c0),('paint',0x1564a8)]]
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
        tests = [(9,1,9,1), (1,9,10,1), (9,1,9,0), (1,9,10,0)]
        asm = ' mov r20,0x2000000\n'
        for i, (initial, requested, key, accepted) in enumerate(tests):
            a = 0x2001000 + i * 96
            asm += f''' mov r21,{a:#x}
 st r21,[r20]
 mov r1,0x367fea
 mov r0,{initial}
 stb r0,[r1]
 mov r0,{accepted}
 st r0,[r21,16]
 mov r0,{key}
 st r0,[r21,68]
 st sp,[r21,24]
 mov r12,0x2c5074
 jl [r12]
 st r0,[r21]
 mov r1,0x367fea
 ldb r0,[r1]
 st r0,[r21,4]
 st sp,[r21,28]
'''
        asm += ' mov r0,0\n mov r8,1\n trap_s 1\n'
        for i, image in images.items():
            path = out / f'block{i}_LAB_FIXTURE.bin'
            path.write_bytes(image)
            maps += mapping(path, BS[i]['load_address_candidate'])
        path = out / 'cases.bin'; path.write_bytes(bytes(len(tests) * 96)); maps += mapping(path, 0x2001000)
        current = out / 'current.bin'; current.write_bytes(bytes(8)); maps += mapping(current, 0x2000000)
        elf = compile_probe(r, 'cases', asm)
        result, log = r.run('cases', '/result/' + elf.name, maps, trace=True)
        assert result['exit_code'] == 0 and result['fault'] is None, log
        rows = []
        for i, (initial, requested, key, accepted) in enumerate(tests):
            w = struct.unpack_from('<21I', path.read_bytes(), i * 96)
            assert (w[0],w[1],w[6]==w[7],tuple(w[8:11]),w[16]) == (1,requested if accepted else initial,True,(1,1,1),int(not accepted)),(i,w)
            assert tuple(w[12:16]) == (0x1234,requested,1,0x3a98),(i,w)
            assert w[18]==2 and w[19]==2,(i,w)
            assert w[20]==(0x406e89 if key==9 else 0x406e9a),(i,w)
            rows.append(dict(initial=initial,key=key,requested=requested,accepted=bool(accepted),state=w[1],display_string=hex(w[20]),request_arguments=list(w[12:16]),stack_preserved=True))
        trace=(out/'cases.trace').read_text()
        segments=trace.split('0x2c5074  push_s blink')
        assert len(segments)==5
        for segment,(_,_,key,_) in zip(segments[1:],tests):
            draw,call=('0x2c513c ','0x2c5140 ') if key==9 else ('0x2c516c ','0x2c5170 ')
            assert draw in segment and call in segment and segment.index(draw)<segment.index(call)
        for address in ('0x2c5074','0x2c513e','0x2c516e','0x18b85c'):
            assert any(line.startswith(address+' ') for line in trace.splitlines()),address
        (out / 'cases.json').write_text(json.dumps(rows, indent=2) + '\n')
        (out / 'fixture_patches.json').write_text(json.dumps(patches, indent=2) + '\n')
        (out / 'verifier_snapshot.py').write_bytes(Path(__file__).read_bytes())
        r.results.update(status='PASS_IRIS_PANEL_KEY_FIXTURES', scenarios=rows,
            assumptions=['Original V1.1 diagnostic loop and setter, simulated key query sequence and synthetic service return values.'],
            limits=['Text is sent before the setter outcome; no display, real keys, request, GPIO, scheduling or optical movement verified.'])
        r.finish()
    except Exception as exc:
        r.results.update(status='FAIL', error=repr(exc))
        raise
    finally:
        r.save()
    print('PASS: four diagnostic iris key sequences;', out, flush=True)

if __name__ == '__main__':
    main()
