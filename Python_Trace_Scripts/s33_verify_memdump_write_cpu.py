#!/usr/bin/env python3
"""Run Nikon MEMDUMP and file wrappers on ARC CPU with explicitly modelled I/O."""
from datetime import datetime, timezone
from pathlib import Path
from types import SimpleNamespace
import json
import struct
import sys

from s33_run_gnu_arc700 import ROOT, LEGACY, TOOLCHAIN, Runner
from s33_verify_gnu_dsp_lab import compile_probe
sys.path.insert(0, str(ROOT / 'S33-sections/analysis_codex'))
from static_common import BS, PS, locate, raw


def main():
    out = ROOT / 'Risultati/Runtime_Kernel/MEMDUMP_CPU' / datetime.now(timezone.utc).strftime('%Y%m%dT%H%M%S%fZ')
    r = Runner(SimpleNamespace(legacy_root=LEGACY, toolchain=TOOLCHAIN, output=out, action='memdump-original-write-wrappers'))
    print('Prove:', out, flush=True)
    try:
        r.prepare()
        def binary(name, asm):
            elf = compile_probe(r, name, asm)
            dest = out / (name + '.bin')
            p = r.command(name + '_extract', [TOOLCHAIN / 'arc-elf32-objcopy', '-O', 'binary', '--only-section=.text', elf, dest])
            assert p.returncode == 0, p.stdout
            return dest.read_bytes()

        # All fixture state is synthetic. Distinct slots expose the sequence of calls.
        stubs = {
            0xcb5e4: 'j_s [blink]',
            0xcb5b0: 'j_s [blink]',
            0x12b0dc: 'j_s [blink]',
            0x32de00: 'j_s [blink]',
            0x1567f8: '''mov r10,0x2010000
 st r2,[r10,64]
 st r3,[r10,68]
 j_s [blink]''',
            0x18b45c: '''mov r10,0x2010000
 ld r11,[r10,0]
 stb r11,[r2]
 ld r11,[r10,4]
 add r11,r11,1
 st r11,[r10,4]
 mov r11,1
 st r11,[r10,0]
 mov r0,0
 j_s [blink]''',
            # Both open backends use (path, mode, pointer-to-handle).
            0x12dbfc: '''mov r10,0x2010000
 st r1,[r10,8]
 mov r11,0x1234
 st r11,[r2]
 mov r0,0
 j_s [blink]''',
            0x12ce8c: '''mov r10,0x2010000
 st r1,[r10,12]
 mov r11,0x1234
 st r11,[r2]
 mov r0,0
 j_s [blink]''',
            0x12d018: '''mov r10,0x2010000
 st r1,[r10,16]
 mov r0,0
 j_s [blink]''',
            0x12de3c: '''mov r10,0x2010000
 ld r11,[r10,20]
 cmp r11,0
 bne write_record
 mov r6,r1
 add r7,r10,256
 mov r8,64
copy_loop:
 ld r9,[r6]
 st r9,[r7]
 add r6,r6,4
 add r7,r7,4
 sub.f r8,r8,1
 bne copy_loop
write_record:
 add r12,r10,24
 asl r11,r11,4
 add r12,r12,r11
 st r1,[r12]
 st r2,[r12,4]
 st r3,[r12,8]
 ld r11,[r1]
 st r11,[r12,12]
 ld r11,[r10,20]
 add r11,r11,1
 st r11,[r10,20]
 ld r11,[r10,72]
 cmp r11,-1
 bne count_ready
 mov r11,r2
count_ready:
 st r11,[r4]
 ld r11,[r10,20]
 cmp r11,1
 bne second_error
 ld r0,[r10,76]
 j_s [blink]
second_error:
 ld r0,[r10,92]
 j_s [blink]''',
            0x12d604: '''mov r10,0x2010000
 ld r11,[r10,56]
 add r11,r11,1
 st r11,[r10,56]
 ld r0,[r10,88]
 j_s [blink]''',
        }
        image = bytearray(PS[0])
        services = []
        for i, (addr, asm) in enumerate(stubs.items()):
            target = 0x2030100 + i * 0x100
            data = binary('service_%02d' % i, asm + '\n')
            entry = binary('entry_%02d' % i, f' mov_s r12,{target:#x}\n j_s [r12]\n')
            block, offset = locate(addr, len(entry))
            assert block['index'] == 0 and len(entry) == 8
            assert image[offset:offset + 8] == raw(addr, 8)
            image[offset:offset + 8] = entry
            services.append((addr, target, data))
        specs = [('new_full', 0, 0xffffffff, 0, 0, 0, 2), ('existing_full', 1, 0xffffffff, 0, 0, 0, 2),
                 ('short_success', 0, 0, 0, 0, 0, 2), ('first_write_error', 0, 0, 77, 0, 0, 1),
                 ('second_write_error', 0, 0xffffffff, 0, 78, 0, 2), ('close_error', 0, 0xffffffff, 0, 0, 79, 2)]
        results = []
        for name, exists, count, first_error, second_error, close_error, writes in specs:
            maps = []
            def mmap(label, addr, data):
                path = out / (name + '_' + label + '.bin')
                path.write_bytes(bytes(addr % 8) + data)
                maps.extend(['--memory-mapfile', '/result/' + path.name, '--memory-region', f'{addr:#x},{len(data)}'])
                return path
            maps.extend(['--memory-fill', '0', '--memory-region', '0,0x80000'])
            mmap('main0', BS[0]['load_address_candidate'], image)
            state = bytearray(0x300)
            struct.pack_into('<I', state, 0x100, exists)
            struct.pack_into('<II', state, 0x100 + 72, count, first_error)
            struct.pack_into('<II', state, 0x100 + 88, close_error, second_error)
            state_file = mmap('state', 0x200ff00, state)
            service_image = bytearray(0x100 * (len(services) + 1))
            for _, target, data in services:
                offset = target - 0x2030000
                assert len(data) <= 0x100
                service_image[offset:offset + len(data)] = data
            mmap('services', 0x2030000, service_image)
            elf = compile_probe(r, name, '''mov r0,0
 mov r1,0x03020100
 mov r2,64
init_loop:
 st r1,[r0]
 add r0,r0,4
 add r1,r1,1
 sub.f r2,r2,1
 bne init_loop
 mov r0,256
 mov r1,0x03020100
 st r1,[r0]
 mov r20,0x2010000
 st sp,[r20,80]
 mov r12,0x16ed40
 jl [r12]
 st sp,[r20,84]
 mov r0,0
 mov r8,1
 trap_s 1
''')
            case, log = r.run(name, '/result/' + elf.name, maps, trace=True)
            assert case['exit_code'] == 0 and case['fault'] is None, log
            saved = state_file.read_bytes()[0x100:]
            w = struct.unpack_from('<24I', saved)
            assert struct.unpack_from('<64I', saved, 0x100) == tuple(0x03020100 + i for i in range(64)), name
            assert w[1] == writes and w[5] == writes and w[14] == writes, (name, w)
            assert w[20] == w[21], (name, w)
            assert w[7:10] == (256, 1, 0x03020100), (name, w)
            assert (w[2], w[3], w[4]) == ((0, 0x12, 3) if exists else (2, 0x12 if writes == 2 else 0, 3 if writes == 2 else 0)), (name, w)
            if writes == 2:
                assert w[10:14] == (0x100, 0x104064c, 1, 0x03020100), (name, w)
            assert w[16] == (0x39304e if first_error or second_error else 0x393044), (name, w)
            results.append(dict(name=name, initial_existing=exists, open_new_mode=w[2], open_existing_mode=w[3], seek_mode=w[4], writes=writes, first_pointer=hex(w[6]), first_size=w[7], first_sample=hex(w[9]), second_pointer=hex(w[10]) if writes == 2 else None, second_size=w[11] if writes == 2 else None, returned_count='requested' if count == 0xffffffff else count, close_error=close_error, log_string=hex(w[16]), stack_restored=w[20] == w[21]))
        hint_image = bytearray(image)
        block, offset = locate(0x18b45c, 8)
        hint_image[offset:offset + 8] = raw(0x18b45c, 8)
        extras = {
            0x26e6bc: '''mov r10,0x2010000
 st r0,[r10,40]
 ld r11,[r10,88]
 stb r11,[r1]
 ld r0,[r10,92]
 j_s [blink]''',
            0x156890: 'j_s [blink]',
        }
        for i, (addr, asm) in enumerate(extras.items(), start=len(services)):
            target = 0x2030100 + i * 0x100
            data = binary('hint_service_%02d' % i, asm + '\n')
            entry = binary('hint_entry_%02d' % i, f' mov_s r12,{target:#x}\n j_s [r12]\n')
            block, offset = locate(addr, len(entry))
            assert block['index'] == 0 and hint_image[offset:offset + 8] == raw(addr, 8)
            hint_image[offset:offset + 8] = entry
            services.append((addr, target, data))
        hints = []
        for name, attr, lookup_error, expected in [('hint_directory', 0x10, 0, 1), ('hint_file', 0, 0, 0),
                                                    ('hint_lookup_error', 0x10, 5, 0)]:
            maps = []
            def mmap_hint(label, addr, data):
                path = out / (name + '_' + label + '.bin')
                path.write_bytes(bytes(addr % 8) + data)
                maps.extend(['--memory-mapfile', '/result/' + path.name, '--memory-region', f'{addr:#x},{len(data)}'])
                return path
            mmap_hint('main0', BS[0]['load_address_candidate'], hint_image)
            main1 = bytearray(PS[1])
            flag_offset = 0x36726b - BS[1]['load_address_candidate']
            main1[flag_offset] = 0
            main1_file = mmap_hint('main1', BS[1]['load_address_candidate'], main1)
            state = bytearray(0x200)
            struct.pack_into('<II', state, 0x100 + 88, attr, lookup_error)
            state_file = mmap_hint('state', 0x200ff00, state)
            service_image = bytearray(0x100 * (len(services) + 1))
            for _, target, data in services:
                offset = target - 0x2030000
                assert len(data) <= 0x100
                service_image[offset:offset + len(data)] = data
            mmap_hint('services', 0x2030000, service_image)
            elf = compile_probe(r, name, '''mov r20,0x2010000
 st sp,[r20,80]
 mov r12,0x1592b0
 jl [r12]
 st sp,[r20,84]
 mov r0,0
 mov r8,1
 trap_s 1
''')
            case, log = r.run(name, '/result/' + elf.name, maps, trace=True)
            assert case['exit_code'] == 0 and case['fault'] is None, log
            state_after = state_file.read_bytes()[0x100:]
            w = struct.unpack_from('<24I', state_after)
            assert main1_file.read_bytes()[flag_offset] == expected and w[10] == 0x391ac1 and w[20] == w[21], (name, w)
            hints.append(dict(name=name, attribute=attr, lookup_status=lookup_error, flag=expected, lookup_name_pointer=hex(w[10])))
        (out / 'hint_cases.json').write_text(json.dumps(hints, indent=2) + '\n')
        (out / 'cases.json').write_text(json.dumps(results, indent=2) + '\n')
        (out / 'verifier_snapshot.py').write_bytes(Path(__file__).read_bytes())
        r.results.update(status='PASS_MEMDUMP_ORIGINAL_WRAPPERS_SYNTHETIC_IO', scenarios=results, hint_scenarios=hints,
            assumptions=['Original 16ED40, AD920, 12BD5C, 18B028, 18B0BC, 18B130 and 18B0FC execute; low memory, stack and all I/O fixtures synthetic.', 'Existence fixture reports file exists on second lookup, even after synthetic short success.'],
            limits=['The write fixture reads only the first word of the second range, does not write a file, and returns synthetic count/status.', 'Hint lookup is synthetic; execution does not establish that the function is reached at boot or identify a physical button.', 'No real filesystem, SD, physical RAM map, durability, concurrency or boot/launcher validated.'])
        r.finish()
    except Exception as exc:
        r.results.update(status='FAIL', error=repr(exc))
        raise
    finally:
        r.save()
    print('PASS MEMDUMP original wrappers with synthetic I/O:', out, flush=True)


if __name__ == '__main__':
    main()
