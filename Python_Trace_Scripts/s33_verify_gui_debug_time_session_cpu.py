#!/usr/bin/env python3
"""Exercise edit-then-confirm of original diagnostic time handlers in one CPU run."""
from datetime import datetime, timezone
from pathlib import Path
from types import SimpleNamespace
import json
import struct
import sys
from s33_run_gnu_arc700 import ROOT, LEGACY, TOOLCHAIN, Runner, sha
from s33_verify_gnu_dsp_lab import compile_probe
sys.path.insert(0, str(ROOT / 'S33-sections/analysis_codex'))
from static_common import BS, PS, raw, locate, u32, disasm


def main():
    out = ROOT / 'Risultati/GUI_S33' / datetime.now(timezone.utc).strftime('debug_time_session_cpu_%Y%m%dT%H%M%SZ')
    r = Runner(SimpleNamespace(legacy_root=LEGACY, toolchain=TOOLCHAIN, output=out, action='gui-debug-time-session'))
    print('Prove:', out, flush=True)
    try:
        r.prepare()
        dump = ROOT / 'DUMPS/MainCode.dmp'
        data = dump.read_bytes()
        r.input_hashes[str(dump)] = sha(dump)
        for address, length in [(0x7d2394, 0xd0), (0x7d249c, 0x20), (0x7d24bc, 0x6a), (0x989cf8, 72), (0xd03e0, 0x28), (0xde7b4, 0x1c), (0x899ad4, 11)]:
            block, offset = locate(address, length)
            assert raw(address, length) == data[block['offset'] + offset:block['offset'] + offset + length]
        events = {u32(0x989cf8 + 8*i): u32(0x989cfc + 8*i) for i in range(9)}
        assert (events[0x380], events[0x400], events[0x580], events[0x480]) == (0x7d23c8, 0x7d241c, 0x7d2394, 0x7d249c)
        assert raw(0x899ad4, 11) == b'Auto\0%000d\0'
        (out / 'gnu_windows.txt').write_text('\n'.join(disasm(a, b) for a, b in [(0x7d2394, 0x7d23c4), (0x7d23c8, 0x7d241c), (0x7d241c, 0x7d2464), (0x7d249c, 0x7d24bc), (0x7d24bc, 0x7d2526), (0xd03e0, 0xd03fc), (0xde7b4, 0xde7d0)]))
        images = {i: bytearray(PS[i]) for i in (0, 1, 2, 4, 5)}
        maps, patches = [], []
        def binary(name, asm):
            elf = compile_probe(r, name, asm)
            path = out / (name + '.bin')
            result = r.command(name + '_extract', [TOOLCHAIN/'arc-elf32-objcopy', '-O', 'binary', '--only-section=.text', elf, path])
            assert result.returncode == 0, result.stdout
            content = path.read_bytes()
            path.write_bytes(content + bytes(8 + (-len(content)) % 8))
            return path
        def mapping(path, addr):
            return ['--memory-mapfile', '/result/' + path.name, '--memory-region', f'{addr:#x},{path.stat().st_size}']
        common = ' mov r10,0x2000000\n ld r10,[r10]\n'
        services = [
            ('format', 0x12ce54, common + ' st r1,[r10,52]\n st r2,[r10,56]\n ld r11,[r10,60]\n add r11,r11,1\n st r11,[r10,60]\n mov r0,0\n j_s [blink]\n'),
            ('resource', 0x145654, ' mov r0,0x2100000\n j_s [blink]\n'),
            ('set_text', 0x633020, ' mov r0,0\n j_s [blink]\n'),
            ('refresh', 0x145490, ' mov r0,0\n j_s [blink]\n'),
            ('timer', 0x14905c, common + ' ld r11,[r10,16]\n add r11,r11,1\n st r11,[r10,16]\n mov r0,0\n j_s [blink]\n'),
            ('open', 0x1453e4, common + ' st r0,[r10,20]\n st r1,[r10,24]\n ld r11,[r10,28]\n add r11,r11,1\n st r11,[r10,28]\n mov r0,0\n j_s [blink]\n')]
        for i, (name, addr, asm) in enumerate(services):
            target = 0x2030000 + i*0x400
            path = binary(name, asm)
            maps += mapping(path, target)
            entry = binary('entry_' + name, f' mov_s r12,{target:#x}\n j_s [r12]\n').read_bytes()[:8]
            block, offset = locate(addr, 8)
            before = bytes(images[block['index']][offset:offset+8])
            assert before == raw(addr, 8)
            images[block['index']][offset:offset+8] = entry
            patches.append(dict(name=name, address=hex(addr), original=before.hex(), fixture=entry.hex()))
        # Initial value, ordered edits, expected value after edits.
        tests = [(0, (0x380, 0x400), 119, True), (120, (0x380, 0x380), 122, True),
                 (3999, (0x380,), 0, True), (1, (0x400,), 0, True), (2, (0x400, 0x380), 2, True),
                 (120, (0x380,), 121, False), (1, (0x400,), 0, False)]
        asm = ' mov r20,0x2000000\n'
        for i, (initial, actions, expected, confirm) in enumerate(tests):
            address = 0x2001000 + i*96
            asm += f''' mov r21,{address:#x}
 st r21,[r20]
 mov r1,0x899ad0
 mov r0,{initial}
 st r0,[r1]
 mov r1,0x899ac0
 mov r0,0x2100000
 st r0,[r1]
 mov r1,0x365788
 mov r0,0x12345678
 st r0,[r1]
 mov r1,0x37fbf4
 st r0,[r1]
 st sp,[r21,32]
'''
            for event in actions:
                asm += f''' mov r0,0
 mov r1,{event:#x}
 mov r2,0
 mov r12,{events[event]:#x}
 jl [r12]
'''
            asm += f''' mov r1,0x899ad0
 ld r0,[r1]
 st r0,[r21]
 mov r1,0x365788
 ld r0,[r1]
 st r0,[r21,4]
 mov r1,0x37fbf4
 ld r0,[r1]
 st r0,[r21,8]
 mov r0,0
 mov r1,{0x580 if confirm else 0x480:#x}
 mov r2,0
 mov r12,{events[0x580 if confirm else 0x480]:#x}
 jl [r12]
 mov r1,0x365788
 ld r0,[r1]
 st r0,[r21,12]
 mov r1,0x37fbf4
 ld r0,[r1]
 st r0,[r21,36]
 st sp,[r21,40]
'''
        asm += ' mov r0,0\n mov r8,1\n trap_s 1\n'
        for i, content in images.items():
            path = out / f'block{i}_LAB_FIXTURE.bin'
            path.write_bytes(content)
            maps += mapping(path, BS[i]['load_address_candidate'])
        state = out / 'cases.bin'; state.write_bytes(bytes(len(tests)*96)); maps += mapping(state, 0x2001000)
        current = out / 'current.bin'; current.write_bytes(bytes(8)); maps += mapping(current, 0x2000000)
        context = out / 'context.bin'; context.write_bytes(bytes(256)); maps += mapping(context, 0x2100000)
        elf = compile_probe(r, 'cases', asm)
        case, log = r.run('cases', '/result/' + elf.name, maps, trace=True)
        assert case['exit_code'] == 0 and case['fault'] is None, log
        rows = []
        for i, (initial, actions, expected, confirm) in enumerate(tests):
            w = struct.unpack_from('<11I', state.read_bytes(), i*96)
            final = expected*1000 if confirm else 0x12345678
            assert (w[0], w[1], w[2], w[3], w[4], w[5], w[6], w[7], w[9], w[8] == w[10]) == (expected, 0x12345678, 0x12345678, final, len(actions), 0x36, 0, 1, final, True), (i, w)
            fmt, arg, count = struct.unpack_from('<3I', state.read_bytes(), i*96+52)
            assert fmt == (0x899ad4 if expected == 0 else 0x899ad9) and count == len(actions), (i, fmt, arg, count)
            if expected != 0: assert arg == expected, (i, arg, expected)
            rows.append(dict(initial=initial, events=[hex(e) for e in actions], action='confirm' if confirm else 'cancel', edited=w[0], before_finish=[w[1],w[2]], after_finish=[w[3],w[9]], timer_calls=w[4], format_pointer=hex(fmt), format_string='Auto' if expected == 0 else '%000d', format_argument=arg if expected else None, open_request=[w[5],w[6]], open_count=w[7], stack_preserved=True))
        (out/'cases.json').write_text(json.dumps(rows, indent=2) + '\n')
        (out/'fixture_patches.json').write_text(json.dumps(patches, indent=2) + '\n')
        (out/'verifier_snapshot.py').write_bytes(Path(__file__).read_bytes())
        r.results.update(status='PASS_DEBUG_TIME_EDIT_FINISH_BOUNDED', scenarios=rows,
            assumptions=['Original edit and confirm or cancel callbacks invoked directly in order with synthetic state.', 'Six services are explicit fixtures; open records request only.'],
            limits=['No timer repeat, event delivery, actual GUI, physical time, AE arbitration, persistence or sensor capture.'])
        r.finish()
    except Exception as exc:
        r.results.update(status='FAIL', error=repr(exc))
        raise
    finally:
        r.save()
    print('PASS: seven synthetic edit-then-confirm/cancel sessions;', out, flush=True)

if __name__ == '__main__':
    main()
