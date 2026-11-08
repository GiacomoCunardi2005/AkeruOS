#!/usr/bin/env python3
"""Test the original GeneralSetup back handler with synthetic parent contexts."""
from datetime import datetime, timezone
from pathlib import Path
from types import SimpleNamespace
import json
import struct
import sys

from s33_run_gnu_arc700 import ROOT, LEGACY, TOOLCHAIN, Runner, sha
from s33_verify_gnu_dsp_lab import compile_probe

sys.path.insert(0, str(ROOT / 'S33-sections/analysis_codex'))
from static_common import BS, PS, locate, raw, u32


def main():
    out = ROOT / 'Risultati/GUI_S33' / datetime.now(timezone.utc).strftime('settings_back_context_cpu_%Y%m%dT%H%M%SZ')
    r = Runner(SimpleNamespace(legacy_root=LEGACY, toolchain=TOOLCHAIN, output=out, action='settings-back-context'))
    print('Prove:', out, flush=True)
    try:
        r.prepare()
        dump = ROOT / 'DUMPS/MainCode.dmp'
        data = dump.read_bytes()
        r.input_hashes[str(dump)] = sha(dump)
        r.input_hashes[str(Path(__file__))] = sha(Path(__file__))
        for addr, length in [(0x7eaad8, 0x40), (0x1453e4, 8), (0x3f5900 + 0x5e * 4, 4), (0x3f5900 + 0x87 * 4, 4)]:
            block, off = locate(addr, length)
            assert raw(addr, length) == data[block['offset'] + off:block['offset'] + off + length]
        assert u32(0x7eab14) == 0x89a050
        assert (u32(0x3f5900 + 0x5e * 4), u32(0x3f5900 + 0x87 * 4)) == (0x98e134, 0x783ae8)
        images = {i: bytearray(PS[i]) for i in (0, 1, 3, 4, 5)}
        def binary(name, asm):
            elf = compile_probe(r, name, asm)
            path = out / (name + '.bin')
            result = r.command(name + '_extract', [TOOLCHAIN / 'arc-elf32-objcopy', '-O', 'binary', '--only-section=.text', elf, path])
            assert result.returncode == 0, result.stdout
            contents = path.read_bytes()
            path.write_bytes(contents + bytes(8 + (-len(contents)) % 8))
            return path
        def mapping(path, address):
            return ['--memory-mapfile', '/result/' + path.name, '--memory-region', f'{address:#x},{path.stat().st_size}']
        recorder = binary('open_recorder', ' mov r10,0x2000000\n ld r10,[r10]\n st r0,[r10,0]\n st r1,[r10,4]\n ld r11,[r10,8]\n add r11,r11,1\n st r11,[r10,8]\n mov r0,1\n j_s [blink]\n')
        entry = binary('recorder_entry', ' mov_s r12,0x2030000\n j_s [r12]\n').read_bytes()[:8]
        block, off = locate(0x1453e4, 8)
        before = bytes(images[block['index']][off:off + 8])
        assert before == raw(0x1453e4, 8)
        images[block['index']][off:off + 8] = entry
        patches = [dict(address='0x1453e4', original=before.hex(), fixture=entry.hex())]
        values = (0, 1, 2, 3, 255)
        asm = ' mov r20,0x2000000\n'
        for i, value in enumerate(values):
            state = 0x2001000 + i * 32
            context = 0x2100000 + i * 128
            asm += f''' mov r21,{state:#x}
 st r21,[r20]
 mov r0,{context:#x}
 mov r1,0x89a050
 st r0,[r1]
 add r1,r0,64
 st r1,[r0,48]
 mov r0,{value}
 stb r0,[r1,16]
 st sp,[r21,12]
 mov r0,0
 mov r1,0x580
 mov r2,0
 mov r12,0x7eaad8
 jl [r12]
 st sp,[r21,16]
'''
        asm += ' mov r0,0\n mov r8,1\n trap_s 1\n'
        maps = mapping(recorder, 0x2030000)
        for index, image in images.items():
            path = out / f'block{index}_LAB_FIXTURE.bin'
            path.write_bytes(image)
            maps += mapping(path, BS[index]['load_address_candidate'])
        states = out / 'cases.bin'; states.write_bytes(bytes(len(values) * 32)); maps += mapping(states, 0x2001000)
        current = out / 'current.bin'; current.write_bytes(bytes(8)); maps += mapping(current, 0x2000000)
        contexts = out / 'contexts.bin'; contexts.write_bytes(bytes(len(values) * 128)); maps += mapping(contexts, 0x2100000)
        (out / 'fixture_patches.json').write_text(json.dumps(patches, indent=2) + '\n')
        (out / 'verifier_snapshot.py').write_bytes(Path(__file__).read_bytes())
        elf = compile_probe(r, 'cases', asm)
        case, log = r.run('cases', '/result/' + elf.name, maps, trace=True)
        assert case['exit_code'] == 0 and case['fault'] is None, log
        rows = []
        for i, value in enumerate(values):
            target, argument, count, before_sp, after_sp = struct.unpack_from('<5I', states.read_bytes(), i * 32)
            expected = 0x5e if value == 2 else 0x87
            assert (target, argument, count, before_sp == after_sp) == (expected, 0, 1, True)
            rows.append(dict(context_byte=value, requested_id=hex(target), argument=argument, stack_preserved=True))
        trace = (out / 'cases.trace').read_text()
        assert sum(line.startswith('0x7eaad8 ') for line in trace.splitlines()) == len(values)
        assert sha(dump) == r.input_hashes[str(dump)]
        (out / 'cases.json').write_text(json.dumps(rows, indent=2) + '\n')
        r.results.update(status='PASS_SETTINGS_BACK_CONTEXT_SYNTHETIC', scenarios=rows,
                         assumptions=['Original 7EAAD8 handler directly called with synthetic pointer chain and five context bytes; opening replaced by recorder.'],
                         limits=['No actual window transition, physical buttons, rendering, persistence, camera or verified physical context.'])
        r.finish()
    except Exception as exc:
        r.results.update(status='FAIL', error=repr(exc))
        raise
    finally:
        r.save()
    print('PASS: five synthetic settings-back contexts;', out, flush=True)


if __name__ == '__main__':
    main()
