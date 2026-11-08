#!/usr/bin/env python3
"""Compare the original GUI RLE routine with original resource data offline."""
from datetime import datetime, timezone
from pathlib import Path
from types import SimpleNamespace
import hashlib
import json
import struct
import sys

from s33_run_gnu_arc700 import ROOT, LEGACY, TOOLCHAIN, Runner, sha
from s33_verify_gnu_dsp_lab import BUILD, LAB, compile_probe

sys.path.insert(0, str(ROOT / 'S33-sections/analysis_codex'))
from static_common import BS, PS, locate, raw


def main():
    source = ROOT / 'Risultati/GUI_S33/graphic_table_init_20261027T180014Z'
    evidence = json.loads((source / 'evidence.json').read_text())
    out = ROOT / 'Risultati/GUI_S33' / datetime.now(timezone.utc).strftime('rle_original_cpu_%Y%m%dT%H%M%SZ')
    runner = Runner(SimpleNamespace(legacy_root=LEGACY, toolchain=TOOLCHAIN, output=out, action='gui-original-rle-dsp-lab'))
    print('Prove:', out, flush=True)
    try:
        runner.prepare()
        build = json.loads(BUILD.read_text())
        assert sha(LAB / 'install/bin/arc-elf32-run') == build['experimental_sha256']
        runner.experimental_engine = LAB
        runner.input_hashes[str(LAB / 'install/bin/arc-elf32-run')] = build['experimental_sha256']
        runner.input_hashes[str(BUILD)] = sha(BUILD)
        runner.input_hashes[str(source / 'evidence.json')] = sha(source / 'evidence.json')
        dump = (ROOT / 'DUMPS/MainCode.dmp').read_bytes()
        runner.input_hashes[str(ROOT / 'DUMPS/MainCode.dmp')] = hashlib.sha256(dump).hexdigest()
        for address, size in ((0x23b234, 0xe8), (0x23b4d0, 4)):
            block, offset = locate(address, size)
            assert raw(address, size) == dump[block['offset'] + offset:block['offset'] + offset + size]
        descriptors = evidence['descriptors']
        inputs = bytearray(len(descriptors) * 0x1000)
        fixtures = bytearray(len(descriptors) * 0x20)
        output = bytearray([0xa5]) * (len(descriptors) * 0x2000)
        state = bytearray(len(descriptors) * 0x40)
        asm = ''
        for index, desc in enumerate(descriptors):
            assert (desc['width'], desc['height']) == (72, 72)
            data = raw(int(desc['source'], 16), desc['compressed_bytes'])
            assert hashlib.sha256(data).hexdigest() == desc['compressed_sha256'] and len(data) <= 0x1000
            block, offset = locate(int(desc['source'], 16), len(data))
            assert data == dump[block['offset'] + offset:block['offset'] + offset + len(data)]
            inputs[index * 0x1000:index * 0x1000 + len(data)] = data
            fixture = bytearray.fromhex(desc['descriptor_hex'])
            assert fixture == raw(int(desc['descriptor'], 16), 20)
            struct.pack_into('<I', fixture, 16, 0x2400000 + index * 0x1000)
            fixtures[index * 0x20:index * 0x20 + 20] = fixture
            result = 0x2000000 + index * 0x40
            asm += f''' mov r1,0x36a5f4
 mov r0,{0x2200000 + index * 0x2000:#x}
 st r0,[r1]
 mov r0,5184
 st r0,[r1,4]
 mov r20,{result:#x}
 st sp,[r20,8]
 mov r0,{0x2100000 + index * 0x20:#x}
 mov r1,r20
 add r2,r20,2
 mov r12,0x23b234
 jl [r12]
 mov r20,{result:#x}
 st r0,[r20,4]
 st sp,[r20,12]
'''
        asm += ' mov r0,0\n mov r8,1\n trap_s 1\n'
        def mapped(name, data, address):
            path = out / name
            path.write_bytes(data)
            return ['--memory-mapfile', '/result/' + name, '--memory-region', f'{address:#x},{len(data)}']
        options = mapped('block0.bin', PS[0], BS[0]['load_address_candidate'])
        options += mapped('context.bin', bytes(32), 0x36a5e0)
        options += mapped('source.bin', inputs, 0x2400000)
        options += mapped('descriptors.bin', fixtures, 0x2100000)
        options += mapped('output.bin', output, 0x2200000)
        options += mapped('state.bin', state, 0x2000000)
        elf = compile_probe(runner, 'cases', asm)
        case, log = runner.run('cases', '/result/' + elf.name, options)
        assert case['exit_code'] == 0 and case['fault'] is None, log
        assert log.count('S33_DSP_LAB pc=0023b262 word=290c00be left=00000048 right=00000048 r56=00000000 r57=00001440 provisional=1') == len(descriptors)
        assert 'S33_DSP_GUARD' not in log
        assert (out / 'source.bin').read_bytes() == inputs and (out / 'block0.bin').read_bytes() == PS[0]
        got = (out / 'output.bin').read_bytes()
        state = (out / 'state.bin').read_bytes()
        modified = (out / 'descriptors.bin').read_bytes()
        results = []
        for index, desc in enumerate(descriptors):
            pixels = got[index * 0x2000:index * 0x2000 + 5184]
            reference = (source / f"{desc['id']:03}.indices").read_bytes()
            runner.input_hashes[str(source / f"{desc['id']:03}.indices")] = hashlib.sha256(reference).hexdigest()
            assert pixels == reference and hashlib.sha256(pixels).hexdigest() == desc['indices_sha256']
            assert got[index * 0x2000 + 5184:(index + 1) * 0x2000] == bytes([0xa5]) * (0x2000 - 5184)
            x, y, status, sp_before, sp_after = struct.unpack_from('<HHIII', state, index * 0x40)
            assert (x, y, status) == (0, 0, 0) and sp_before == sp_after
            assert modified[index * 0x20 + 8] == 0
            assert struct.unpack_from('<I', modified, index * 0x20 + 16)[0] == 0x2200000 + index * 0x2000
            results.append({'id': desc['id'], 'bytes': len(pixels), 'sha256': hashlib.sha256(pixels).hexdigest(),
                            'return': status, 'stack_preserved': True, 'output_guard_preserved': True})
        runner.results.update(status='PASS_GUI_RLE_EXPERIMENTAL_DSP', scenarios=results,
            assumptions=['Original 0x23b234 and compressed data; descriptor source pointers and RAM buffers are synthetic.',
                         'GNU DSP laboratory v7 provides provisional MULDW semantics for 72×72; not hardware verified.'],
            limits=['No original resource loading, GUI event handling, palette, renderer or camera hardware.',
                    'Only type 1, dimensions 72×72 and eleven existing image streams tested.',
                    'Host reference and CPU share original bytes; this is not an independent hardware test.'])
        (out / 'verifier_snapshot.py').write_bytes(Path(__file__).read_bytes())
        runner.finish()
    except Exception as exc:
        runner.results.update(status='FAIL', error=repr(exc))
        raise
    finally:
        runner.save()
    print('PASS: original RLE routine on eleven resources with provisional DSP;', out, flush=True)


if __name__ == '__main__':
    main()
