#!/usr/bin/env python3
"""Verify the original GUI packed-value lookup against an explicit fixture table."""
from datetime import datetime, timezone
from pathlib import Path
from types import SimpleNamespace
import hashlib
import json
import struct
import sys

from s33_run_gnu_arc700 import ROOT, LEGACY, TOOLCHAIN, Runner, sha
from s33_verify_gnu_dsp_lab import compile_probe

sys.path.insert(0, str(ROOT / 'S33-sections/analysis_codex'))
from static_common import BS, PS, disasm, locate, raw, u32


def key(value):
    first, second, third, fourth = value
    def reduced(x):
        return (x + (x <= 83) - (x >= 172)) >> 2
    last = ((255 - fourth) * 126 + 255) // 510
    return reduced(first) | (second << 8) | (reduced(third) << 16) | (last << 24)


def main():
    out = ROOT / 'Risultati/GUI_S33' / datetime.now(timezone.utc).strftime('color_lookup_cpu_%Y%m%dT%H%M%SZ')
    runner = Runner(SimpleNamespace(legacy_root=LEGACY, toolchain=TOOLCHAIN, output=out, action='gui-packed-value-lookup'))
    print('Prove:', out, flush=True)
    try:
        runner.prepare()
        dump_path = ROOT / 'DUMPS/MainCode.dmp'
        dump = dump_path.read_bytes()
        runner.input_hashes[str(dump_path)] = sha(dump_path)
        for address, size in ((0x17af2c, 0x9c), (0x17b164, 4), (0x335b34, 0x100), (0x3f6740, 1024)):
            block, offset = locate(address, size)
            assert raw(address, size) == dump[block['offset'] + offset:block['offset'] + offset + size]
        assert u32(0x17b164) == 0x47a448
        original_entries = [list(raw(0x3f6740 + 4 * i, 4)) for i in range(4)]
        boundary = [[x, i + 20, x, 100] for i, x in enumerate((83, 84, 85, 171, 172, 173))]
        values = original_entries + boundary
        slots = [0, 4, 7, 10, 20, 30, 40, 100, 200, 255]
        assert len(set(key(value) for value in values)) == len(values)
        table = [0xdeadbeef] * 258
        for slot, value in zip(slots, values):
            table[slot] = key(value)
        table[11] = key(values[1])
        cases = [(f'palette_prefix_{i}' if i < 4 else f'boundary_{value[0]}', value, slot)
                 for i, (value, slot) in enumerate(zip(values, slots))]
        cases += [('missing', [17, 239, 19, 21], 0)]
        assert key(cases[-1][1]) not in table[:256]
        table[256] = key(cases[-1][1])
        table_bytes = struct.pack('<258I', *table)
        state = bytearray(len(cases) * 16)
        asm = ''
        for i, (_, value, _) in enumerate(cases):
            packed = int.from_bytes(bytes(value), 'big')
            asm += f''' mov r20,{0x2000000 + i * 16:#x}
 st sp,[r20,4]
 mov r0,{packed:#x}
 mov r12,0x17af2c
 jl [r12]
 mov r20,{0x2000000 + i * 16:#x}
 st r0,[r20]
 st sp,[r20,8]
'''
        asm += ' mov r0,0\n mov r8,1\n trap_s 1\n'
        def mapped(name, data, address):
            path = out / name
            path.write_bytes(data)
            return ['--memory-mapfile', '/result/' + name, '--memory-region', f'{address:#x},{len(data)}']
        options = mapped('block0.bin', PS[0], BS[0]['load_address_candidate'])
        options += mapped('table.bin', table_bytes, 0x47a448)
        options += mapped('state.bin', state, 0x2000000)
        elf = compile_probe(runner, 'cases', asm)
        case, log = runner.run('cases', '/result/' + elf.name, options)
        assert case['exit_code'] == 0 and case['fault'] is None, log
        got = (out / 'state.bin').read_bytes()
        assert (out / 'table.bin').read_bytes() == table_bytes and (out / 'block0.bin').read_bytes() == PS[0]
        results = []
        for i, (name, value, expected) in enumerate(cases):
            actual, before, after = struct.unpack_from('<III', got, i * 16)
            assert actual == expected and before == after, (name, actual, expected)
            results.append({'name': name, 'input_bytes': value, 'key': hex(key(value)),
                            'result': actual, 'stack_preserved': True})
        (out / 'disassembly.txt').write_text(disasm(0x17af2c, 0x17af6c) +
                                              disasm(0x17af6c, 0x17afb8) +
                                              disasm(0x17afb8, 0x17afc8))
        runner.results.update(status='PASS_PACKED_VALUE_LOOKUP_BOUNDED', scenarios=results,
            original_palette_prefix=original_entries, table_sha256=hashlib.sha256(table_bytes).hexdigest(),
            assumptions=['Original lookup 0x17af2c and division helper; table at 0x47a448 is synthetic.',
                         'Fixture allocates two additional words; the unmatched key at index 256 is outside the 256 compared entries.'],
            limits=['Only eleven selected inputs, including four original resource-table entries; no full palette conversion.',
                    'Duplicate and absent-value results describe the fixture; runtime table and color interpretation are unverified.',
                    'No real display, camera execution, or claim that a zero result uniquely means absence.'])
        (out / 'verifier_snapshot.py').write_bytes(Path(__file__).read_bytes())
        runner.finish()
    except Exception as exc:
        runner.results.update(status='FAIL', error=repr(exc))
        raise
    finally:
        runner.save()
    print('PASS: eleven bounded packed-value lookup cases;', out, flush=True)


if __name__ == '__main__':
    main()
