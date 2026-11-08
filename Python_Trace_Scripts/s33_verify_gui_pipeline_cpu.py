#!/usr/bin/env python3
"""Run an offline GUI resource pipeline on the existing GNU ARC700 simulator."""
from datetime import datetime, timezone
from pathlib import Path
from types import SimpleNamespace
import hashlib
import json
import struct
import sys

from s33_run_gnu_arc700 import ROOT, LEGACY, TOOLCHAIN, Runner, sha
from s33_verify_gnu_dsp_lab import BUILD, LAB, compile_probe
from s33_verify_gui_color_lookup_cpu import key

sys.path.insert(0, str(ROOT / 'S33-sections/analysis_codex'))
from static_common import BS, PS, locate, raw, u32


def main():
    source = ROOT / 'Risultati/GUI_S33/graphic_table_init_20261027T180014Z'
    descriptors = json.loads((source / 'evidence.json').read_text())['descriptors']
    assert len(descriptors) == 11
    out = ROOT / 'Risultati/GUI_S33' / datetime.now(timezone.utc).strftime('pipeline_cpu_%Y%m%dT%H%M%SZ')
    runner = Runner(SimpleNamespace(legacy_root=LEGACY, toolchain=TOOLCHAIN, output=out, action='gui-pipeline-dsp-lab'))
    print('Prove:', out, flush=True)
    try:
        runner.prepare()
        build = json.loads(BUILD.read_text())
        assert sha(LAB / 'install/bin/arc-elf32-run') == build['experimental_sha256']
        runner.experimental_engine = LAB
        runner.input_hashes[str(LAB / 'install/bin/arc-elf32-run')] = build['experimental_sha256']
        runner.input_hashes[str(BUILD)] = sha(BUILD)
        runner.input_hashes[str(source / 'evidence.json')] = sha(source / 'evidence.json')
        dump_path = ROOT / 'DUMPS/MainCode.dmp'
        dump = dump_path.read_bytes()
        runner.input_hashes[str(dump_path)] = sha(dump_path)
        for address, length in ((0x21dc34, 0x90), (0x17af2c, 0x9c), (0x23b234, 0xe8),
                                (0x2c9018, 0x4c), (0x3f6740, 1024)):
            block, offset = locate(address, length)
            assert raw(address, length) == dump[block['offset'] + offset:block['offset'] + offset + length]
        assert u32(0x367ba8) == 0 and raw(0x3699b8, 2) == bytes(2)
        palette = raw(0x3f6740, 1024)
        keys = [key(palette[i:i + 4]) for i in range(0, len(palette), 4)]
        inputs = bytearray(len(descriptors) * 0x1000)
        fixtures = bytearray(len(descriptors) * 0x20)
        asm = ''' mov r20,0x2000000
 st sp,[r20,4]
 mov r0,0x3f6740
 mov r1,256
 mov r12,0x21dc34
 jl [r12]
 mov r20,0x2000000
 st r0,[r20]
 st sp,[r20,8]
'''
        for i, desc in enumerate(descriptors):
            assert (desc['width'], desc['height']) == (72, 72)
            data = raw(int(desc['source'], 16), desc['compressed_bytes'])
            assert hashlib.sha256(data).hexdigest() == desc['compressed_sha256'] and len(data) <= 0x1000
            block, offset = locate(int(desc['source'], 16), len(data))
            assert data == dump[block['offset'] + offset:block['offset'] + offset + len(data)]
            inputs[i * 0x1000:i * 0x1000 + len(data)] = data
            fixture = bytearray.fromhex(desc['descriptor_hex'])
            assert fixture == raw(int(desc['descriptor'], 16), 20)
            struct.pack_into('<I', fixture, 16, 0x2400000 + i * 0x1000)
            fixtures[i * 0x20:i * 0x20 + 20] = fixture
            result = 0x2000100 + i * 0x20
            asm += f''' mov r1,0x36a5f4
 mov r0,{0x2200000 + i * 0x2000:#x}
 st r0,[r1]
 mov r0,5184
 st r0,[r1,4]
 mov r20,{result:#x}
 st sp,[r20,8]
 mov r0,{0x2100000 + i * 0x20:#x}
 mov r1,r20
 add r2,r20,2
 mov r12,0x23b234
 jl [r12]
 mov r20,{result:#x}
 st r0,[r20,4]
 mov r21,0
 mov r22,{0x2600000 + i * 0x2000:#x}
 mov r23,{0x2200000 + i * 0x2000:#x}
row_{i}:
 mov r0,r22
 mov r1,r23
 mov r2,0x2500000
 mov r12,0x2c9018
 jl [r12]
 add r22,r22,72
 add r23,r23,72
 add r21,r21,1
 cmp r21,72
 blt row_{i}
 mov r20,{result:#x}
 st sp,[r20,12]
'''
        asm += ' mov r0,0\n mov r8,1\n trap_s 1\n'
        elf = compile_probe(runner, 'pipeline', asm)
        def mapped(name, data, address):
            path = out / name
            path.write_bytes(data)
            return ['--memory-mapfile', '/result/' + name, '--memory-region', f'{address:#x},{len(data)}']
        results = []
        for scenario, entries in (('forward', keys), ('reverse', list(reversed(keys)))):
            expected_map = bytes(entries.index(value) for value in keys)
            table = struct.pack('<258I', *entries, 0xdeadbeef, 0xdeadbeef)
            row = struct.pack('<HHII', 72, 0, 0, 0x4bd2b0) + bytes(4)
            options = mapped(scenario + '_block0.bin', PS[0], BS[0]['load_address_candidate'])
            options += mapped(scenario + '_block1.bin', PS[1], BS[1]['load_address_candidate'])
            options += mapped(scenario + '_source.bin', inputs, 0x2400000)
            options += mapped(scenario + '_descriptors.bin', fixtures, 0x2100000)
            options += mapped(scenario + '_decoded.bin', bytes([0xa5]) * (len(descriptors) * 0x2000), 0x2200000)
            options += mapped(scenario + '_output.bin', bytes([0xa5]) * (len(descriptors) * 0x2000), 0x2600000)
            options += mapped(scenario + '_state.bin', bytes(0x100 + len(descriptors) * 0x20), 0x2000000)
            options += mapped(scenario + '_table.bin', table, 0x47a448)
            options += mapped(scenario + '_mapping.bin', bytes(256), 0x4bd2b0)
            options += mapped(scenario + '_row.bin', row, 0x2500000)
            case, log = runner.run(scenario, '/result/' + elf.name, options)
            assert case['exit_code'] == 0 and case['fault'] is None, log
            assert log.count('S33_DSP_LAB pc=0023b262 word=290c00be left=00000048 right=00000048 r56=00000000 r57=00001440 provisional=1') == len(descriptors)
            assert 'S33_DSP_GUARD' not in log
            assert (out / (scenario + '_mapping.bin')).read_bytes() == expected_map
            assert (out / (scenario + '_block0.bin')).read_bytes() == PS[0]
            assert (out / (scenario + '_source.bin')).read_bytes() == inputs
            assert (out / (scenario + '_table.bin')).read_bytes() == table
            state = (out / (scenario + '_state.bin')).read_bytes()
            table_pointer, before, after = struct.unpack_from('<III', state)
            assert table_pointer == 0x4bd2b0 and before == after
            decoded = (out / (scenario + '_decoded.bin')).read_bytes()
            rendered = (out / (scenario + '_output.bin')).read_bytes()
            changed_descriptors = (out / (scenario + '_descriptors.bin')).read_bytes()
            for i, desc in enumerate(descriptors):
                reference = (source / f"{desc['id']:03}.indices").read_bytes()
                runner.input_hashes[str(source / f"{desc['id']:03}.indices")] = hashlib.sha256(reference).hexdigest()
                assert decoded[i * 0x2000:i * 0x2000 + 5184] == reference
                assert decoded[i * 0x2000 + 5184:(i + 1) * 0x2000] == bytes([0xa5]) * (0x2000 - 5184)
                assert changed_descriptors[i * 0x20 + 8] == 0
                assert struct.unpack_from('<I', changed_descriptors, i * 0x20 + 16)[0] == 0x2200000 + i * 0x2000
                expected = bytes(expected_map[value] or 0xa5 for value in reference)
                actual = rendered[i * 0x2000:i * 0x2000 + 5184]
                assert actual == expected
                assert rendered[i * 0x2000 + 5184:(i + 1) * 0x2000] == bytes([0xa5]) * (0x2000 - 5184)
                x, y, status, before, after = struct.unpack_from('<HHIII', state, 0x100 + i * 0x20)
                assert (x, y, status) == (0, 0, 0) and before == after
                results.append({'scenario': scenario, 'resource_id': desc['id'], 'rows': 72,
                                'output_sha256': hashlib.sha256(actual).hexdigest(), 'stack_preserved': True})
        assert (out / 'forward_mapping.bin').read_bytes() != (out / 'reverse_mapping.bin').read_bytes()
        assert (out / 'forward_output.bin').read_bytes() != (out / 'reverse_output.bin').read_bytes()
        runner.results.update(status='PASS_GUI_PIPELINE_EXPERIMENTAL_DSP', scenarios=results,
            assumptions=['Original 21DC34, 17AF2C, 23B234 and 2C9018; synthetic caller, RAM and lookup tables.',
                         'Table fixtures are generated from original palette keys in forward and reverse order.',
                         'GNU DSP v7 MULDW 72×72 remains provisional and is not verified on hardware.'],
            limits=['This is not the original event, loading, clipping or display pipeline.',
                    'Output bytes are synthetic indices, not verified colors, pixels or physical framebuffer.',
                    'Two extra lookup words are mapped; no claim about real table bounds or physical RAM.'])
        (out / 'verifier_snapshot.py').write_bytes(Path(__file__).read_bytes())
        runner.finish()
    except Exception as exc:
        runner.results.update(status='FAIL', error=repr(exc))
        raise
    finally:
        runner.save()
    print('PASS: GUI pipeline, 11 resources × 2 synthetic lookup tables;', out, flush=True)


if __name__ == '__main__':
    main()
