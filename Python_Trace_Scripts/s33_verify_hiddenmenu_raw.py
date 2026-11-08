#!/usr/bin/env python3
"""Bounded V1.1 HiddenMenu RAW evidence; original CPU accessors, no camera I/O."""
from datetime import datetime, timezone
from pathlib import Path
from types import SimpleNamespace
import json
import struct
import sys

from s33_run_gnu_arc700 import ROOT, LEGACY, TOOLCHAIN, Runner
from s33_verify_gnu_dsp_lab import compile_probe

sys.path.insert(0, str(ROOT / 'S33-sections/analysis_codex'))
from static_common import BS, PS, EXPECTED, ORIGINAL, raw, u32, sha, locate, disasm, cstring
from catalog_hiddenmenu import parse_lines


def main():
    out = ROOT / 'Risultati/HiddenMenu_RAW' / datetime.now(timezone.utc).strftime('%Y%m%dT%H%M%SZ')
    r = Runner(SimpleNamespace(legacy_root=LEGACY, toolchain=TOOLCHAIN,
                              output=out, action='hiddenmenu-raw-accessors'))
    try:
        r.prepare()
        assert sha(ORIGINAL.read_bytes()) == EXPECTED
        dump_path = ROOT / 'DUMPS/MainCode.dmp'
        dump = dump_path.read_bytes()
        r.input_hashes[str(dump_path)] = sha(dump)
        windows = [(0x7cf4c8, 0x7cf51c), (0x7cf51c, 0x7cf570),
                   (0x7cf7c0, 0x7cf828), (0x28d48c, 0x28d494),
                   (0x28d498, 0x28d4b0), (0x13af18, 0x13af28),
                   (0x14a2b8, 0x14a2d4), (0x14a2d8, 0x14a2e0),
                   (0x12be64, 0x12be74), (0x1b9292, 0x1b92ce),
                   (0x1b9310, 0x1b933a), (0x28d4d4, 0x28d5b8),
                   (0x7cf10a, 0x7cf160), (0x13aef4, 0x13af18)]
        listings, rows, spans = [], {}, []
        for start, end in windows:
            block, offset = locate(start, end-start)
            data = raw(start, end-start)
            assert dump[block['offset']+offset:block['offset']+offset+len(data)] == data
            spans.append(dict(start=hex(start), end_exclusive=hex(end), sha256=sha(data)))
            text = disasm(start, end)
            listings.append(text)
            rows.update({x['address']: x for x in parse_lines(text)})
        checks = [(0x7cf502, 'bl', ';0x28d498'), (0x7cf556, 'bl', ';0x13af20'),
                  (0x7cf7fa, 'bl', ';0x28d498'), (0x7cf818, 'mov_s', 'r0,0x3'),
                  (0x7cf81c, 'mov_s', 'r0,0'), (0x7cf81e, 'bl', ';0x14a2b8'),
                  (0x28d4a4, 'stb_s', 'r0,[r1,0]'), (0x13af24, 'stb_s', 'r0,[r1,0]'),
                  (0x14a2c4, 'st_s', 'r1,[r0,0]'), (0x1b92a6, 'cmp_s', 'r0,0x3'),
                  (0x1b9328, 'add', 'r3,r57,r57'), (0x1b9336, 'bl', ';0x28d4d4'),
                  (0x28d58c, 'bl', ';0x12bcc4'), (0x12be64, 'mov_s', 'r0,0x70'),
                  (0x12be66, 'bset_s', 'r0,r0,0xc'), (0x12be6c, 'mov_s', 'r0,0xc5'),
                  (0x12be6e, 'asl_s', 'r0,r0,0x4')]
        for pc, op, arg in checks:
            assert rows[pc]['op'] == op and arg in rows[pc]['args'], rows[pc]
        pools = {0x28d494: 0x36c26e, 0x13b250: 0x366c20, 0x14a2d4: 0x366f90,
                 0x13b24c: 0x366c18}
        for address, value in pools.items():
            assert u32(address) == value
        assert {2: cstring(u32(0x7cf2d0)), 1: cstring(u32(0x7cf2d4)),
                255: cstring(u32(0x7cf2d8))} == {
                    2: 'FullFormat:422', 1: 'FullFormat:420', 255: 'FullFormat:None'}
        assert u32(0x987050) == 0x5003 and u32(0x987054) == 0x7cf4c8
        assert u32(0x987058) == 0x5004 and u32(0x98705c) == 0x7cf51c
        assert u32(0x987098) == 0x500c and u32(0x98709c) == 0x7cf7c0
        (out / 'gnu_verified.txt').write_text('\n'.join(listings))

        # Execute original accessors only; capture, UI and file services are not called.
        asm = ' mov r20,0x2001000\n st sp,[r20,0]\n'
        expected = []
        def call(address):
            return f' mov r12,{address:#x}\n jl [r12]\n'
        def save(value):
            expected.append(value)
            return f' st r0,[r20,{len(expected)*4}]\n'
        asm += call(0x12be64) + save(4208)
        asm += call(0x12be6c) + save(3152)
        for value in (0, 1, 2, 255):
            asm += f' mov r0,{value}\n' + call(0x28d498) + call(0x28d48c) + save(value)
            asm += f' mov r0,{value}\n' + call(0x13af20) + call(0x13af18) + save(value)
        for value in (0, 3):
            asm += f' mov r0,{value}\n' + call(0x14a2b8) + call(0x14a2d8) + save(value)
        for value in (1, 2, 255, 3):
            asm += f' mov r0,{value}\n' + call(0x13aefc) + save(int(value != 3))
            asm += call(0x13aef4) + save(255 if value == 3 else value)
        asm += f' st sp,[r20,{(len(expected)+1)*4}]\n mov r0,0\n mov r8,1\n trap_s 1\n'
        main_file = out / 'main0.bin'
        main_file.write_bytes(PS[0])
        (out / 'main1.bin').write_bytes(PS[1])
        results_file = out / 'accessor_results.bin'
        results_file.write_bytes(bytes(128))
        elf = compile_probe(r, 'raw_accessors', asm)
        maps = ['--memory-mapfile', '/result/main0.bin', '--memory-region',
                f'{BS[0]["load_address_candidate"]:#x},{len(PS[0])}',
                '--memory-mapfile', '/result/main1.bin', '--memory-region',
                f'{BS[1]["load_address_candidate"]:#x},{len(PS[1])}',
                '--memory-mapfile', '/result/accessor_results.bin', '--memory-region', '0x2001000,128']
        case, log = r.run('raw_accessors', '/result/' + elf.name, maps, trace=True)
        assert case['exit_code'] == 0 and case['fault'] is None, log
        words = struct.unpack('<32I', results_file.read_bytes())
        assert list(words[1:1+len(expected)]) == expected
        assert words[0] == words[len(expected)+1], 'Stack was not restored'
        r.results.update(status='PASS_BOUNDED_RAW_ACCESSORS_AND_STATIC_PATH',
                         assumptions=['Original V1.1 accessors; synthetic caller, stack and RAM.'],
                         limits=['No UI callback execution, sensor/ISP capture, SD write or hardware test.',
                                 'Mode 3 name does not prove effective sensor precision or packing.',
                                 '4208x3152 are constants used by this export path, not measured buffer geometry.'],
                         checked_instructions=len(checks), source_spans=spans,
                         pools={hex(k): hex(v) for k, v in pools.items()},
                         cpu_observations=expected, stack_preserved=True,
                         export_geometry=dict(width=4208, height=3152,
                                              mode3_bytes=4208*3152*2, other_mode_bytes=4208*3152))
        (out / 'script.py.snapshot').write_bytes(Path(__file__).read_bytes())
        r.finish()
    except Exception as exc:
        r.results.update(status='FAIL', error=repr(exc))
        raise
    finally:
        r.save()
    print('PASS: original accessors on GNU, static menu/export path; evidence:', out)


if __name__ == '__main__':
    main()
