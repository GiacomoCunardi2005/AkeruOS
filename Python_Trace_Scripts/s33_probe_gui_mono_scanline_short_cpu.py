#!/usr/bin/env python3
"""Verify the bounded indexed scanline helper using original ARC instructions."""
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
from static_common import BS, PS, disasm, locate, raw, u16, u32


def main():
    out = ROOT / 'Risultati/GUI_S33' / datetime.now(timezone.utc).strftime('mono_scanline_short_offset_probe_cpu_%Y%m%dT%H%M%SZ')
    runner = Runner(SimpleNamespace(legacy_root=LEGACY, toolchain=TOOLCHAIN, output=out, action='gui-indexed-scanline'))
    print('Prove:', out, flush=True)
    try:
        runner.prepare()
        dump_path = ROOT / 'DUMPS/MainCode.dmp'
        dump = dump_path.read_bytes()
        runner.input_hashes[str(dump_path)] = sha(dump_path)
        spans = [(0x23b530, 0x23b59a), (0x2c8380, 0x2c83ac), (0x2c83f0, 0x2c8408),
                 (0x21dc34, 0x21dc80), (0x21dc7e, 0x21dcbe), (0x2c81bc, 0x2c824c),
                 (0x2c9018, 0x2c9064)]
        windows = {}
        for start, end in spans:
            block, offset = locate(start, end - start)
            assert raw(start, end - start) == dump[block['offset'] + offset:block['offset'] + offset + end - start]
            windows[start] = disasm(start, end)
        for start, needles in {
            0x23b530: ['ld_s\tr15,[r13,0x8]', 'jl_s.d\t[r15]'],
            0x2c8380: ['ld_s\tr2,[r2,0]', 'ldw_s.x\tr1,[r2,0x6]', 'ldb.x\tr1,[r12,r1]', 'j_s\t[r12]'],
            0x2c83f0: ['ld_s\tr0,[r2,0xc]', '0x21dc34', 'mov\tr1,256', '0x2c8440'],
            0x21dc7e: ['ldb_s\tr0,[r14,0]', 'ldb_s\tr1,[r14,0x1]', 'ldb_s\tr0,[r14,0x3]', '0x17af2c', 'stb.ab\tr0,[r15,1]'],
            0x2c81bc: ['ld_s\tr3,[r0,0]', 'jl_s.d\t[r3]'],
            0x2c9018: ['ldb.ab\tr13,[r1,1]', 'ldb_s\tr0,[r0,0]', 'stb_s\tr0,[r3,0]', 'stb_s\tr2,[r0,0]'],
        }.items():
            for needle in needles:
                assert needle in windows[start], (hex(start), needle)
        for address, length in [(0x36a5e8, 4), (0x2c83ac, 24), (0x2c8440, 4), (0x3f6740, 256 * 4)]:
            block, offset = locate(address, length)
            assert raw(address, length) == dump[block['offset'] + offset:block['offset'] + offset + length]
        assert u32(0x36a5e8) == 0x2c8380
        assert 0x2c83ac + 2 * struct.unpack('b', raw(0x2c83ac + 7, 1))[0] == 0x2c83f0
        assert u32(0x2c8440) == 0x2c9018
        prior = json.loads((ROOT / 'Risultati/GUI_S33/graphic_table_init_20261027T180014Z/evidence.json').read_text())
        for descriptor in prior['descriptors']:
            address = int(descriptor['descriptor'], 16)
            block, offset = locate(address, 20)
            assert raw(address, 20) == dump[block['offset'] + offset:block['offset'] + offset + 20]
            assert u16(address + 6) == 8 and u32(address + 12) == 0x3f6740
        (out / 'original_disassembly.txt').write_text('\n'.join(windows.values()))
        cases = [('short_unaligned',[255]*16,3,1,True,[])]
        inputs = bytearray(len(cases) * 32)
        descriptors = bytearray(len(cases) * 32)
        destination = bytearray([0xa5]) * 8
        state = bytearray(len(cases) * 16)
        table = bytearray(256)
        table[0] = 0x7e
        asm = ''
        for i, (_, values, offset, count, mapping, _) in enumerate(cases):
            inputs[i * 32:i * 32 + len(values)] = bytes(values)
            struct.pack_into('<HHI', descriptors, i * 32, count, offset, 0)
            struct.pack_into('<I', descriptors, i * 32 + 8, 0x2400000 if mapping else 0)
            asm += f''' mov r20,{0x2000000 + i * 16:#x}
 st sp,[r20]
 mov r0,{0x2200000 + i * 32:#x}
 mov r1,{0x2300000 + i * 32:#x}
 mov r2,{0x2100000 + i * 32:#x}
 mov r12,0x2c8e4c
 jl [r12]
 mov r20,{0x2000000 + i * 16:#x}
 st sp,[r20,4]
'''
        asm += ' mov r0,0\n mov r8,1\n trap_s 1\n'
        def mapped(name, data, address):
            path = out / name
            path.write_bytes(data)
            return ['--memory-mapfile', '/result/' + name, '--memory-region', f'{address:#x},{len(data)}']
        options = mapped('block0.bin', PS[0], BS[0]['load_address_candidate'])
        options += mapped('inputs.bin', inputs, 0x2300000)
        options += mapped('descriptors.bin', descriptors, 0x2100000)
        options += mapped('destination.bin', destination, 0x2200000)
        options += mapped('table.bin', table, 0x2400000)
        options += mapped('state.bin', state, 0x2000000)
        elf = compile_probe(runner, 'cases', asm)
        case, log = runner.run('cases', '/result/' + elf.name, options, trace=True)
        assert case['fault'] is not None, (case,log)
        got = (out / 'destination.bin').read_bytes()
        state = (out / 'state.bin').read_bytes()
        assert (out / 'inputs.bin').read_bytes() == inputs and (out / 'table.bin').read_bytes() == table
        assert (out / 'block0.bin').read_bytes() == PS[0]
        assert got == bytes([0x7e])*8,got.hex()
        assert case['fault']['address'] == '0x2200008',case
        trace=(out/'cases.trace').read_text()
        assert sum(line.startswith('0x2c8e7c ') for line in trace.splitlines()) == 5
        results = [{'name':'short_unaligned','offset':3,'count':1,'bytes_written_in_8_byte_region':list(got),'fault':case['fault']}]
        runner.results.update(status='PASS_EXPECTED_FAULT_SYNTHETIC_UNALIGNED_SHORT', scenarios=results,
            candidate_color_table_sha256=hashlib.sha256(raw(0x3f6740, 256 * 4)).hexdigest(),
            assumptions=['Original helper 0x2c8e4c; synthetic source, output, per-call structures and mapping table.',
                         'Mapping table values and destination sentinel are explicitly chosen fixtures.'],
            limits=['Caller and 8-bit dispatch are static checks; only one intentionally short unaligned CPU scenario for isolated helper.',
                    'No original palette conversion, display hardware, runtime framebuffer or camera execution.'])
        (out / 'verifier_snapshot.py').write_bytes(Path(__file__).read_bytes())
        runner.finish()
    except Exception as exc:
        runner.results.update(status='FAIL', error=repr(exc))
        raise
    finally:
        runner.save()
    print('PASS: expected synthetic short unaligned fault;', out, flush=True)


if __name__ == '__main__':
    main()
