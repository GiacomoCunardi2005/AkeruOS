#!/usr/bin/env python3
"""Exercise the original diagnostic dispatch with a substituted iris entry."""
from datetime import datetime, timezone
from pathlib import Path
from types import SimpleNamespace
import json
import struct
import sys

from s33_run_gnu_arc700 import ROOT, LEGACY, TOOLCHAIN, Runner, sha
from s33_verify_gnu_dsp_lab import BUILD, LAB, compile_probe

sys.path.insert(0, str(ROOT / 'S33-sections/analysis_codex'))
from static_common import BS, PS, raw, locate, u32


def main():
    out = ROOT / 'Risultati/GUI_S33' / datetime.now(timezone.utc).strftime('iris_diagnostic_dispatch_cpu_%Y%m%dT%H%M%SZ')
    r = Runner(SimpleNamespace(legacy_root=LEGACY, toolchain=TOOLCHAIN, output=out, action='iris-diagnostic-dispatch'))
    print('Prove:', out, flush=True)
    try:
        r.prepare()
        build = json.loads(BUILD.read_text())
        sim = LAB / 'install/bin/arc-elf32-run'
        assert sha(sim) == build['experimental_sha256']
        r.experimental_engine = LAB
        r.input_hashes[str(sim)] = sha(sim)
        dump = ROOT / 'DUMPS/MainCode.dmp'
        data = dump.read_bytes()
        r.input_hashes[str(dump)] = sha(dump)
        for address, size in ((0x2c4fac, 0x9c), (0x406c68, 47 * 8)):
            block, offset = locate(address, size)
            assert raw(address, size) == data[block['offset'] + offset:block['offset'] + offset + size]
        assert u32(0x2c5044) == 0x406c68
        assert (u32(0x406cf0), u32(0x406cf4)) == (0x50, 0x2c5074)
        assert u32(0x406dd8) == 0x7fffffff
        images = {i: bytearray(PS[i]) for i in range(6)}
        maps = []
        patches = []

        def binary(name, asm):
            elf = compile_probe(r, name, asm)
            path = out / (name + '.bin')
            cmd = r.command(name + '_extract', [TOOLCHAIN / 'arc-elf32-objcopy', '-O', 'binary', '--only-section=.text', elf, path])
            assert cmd.returncode == 0
            value = path.read_bytes()
            path.write_bytes(value + bytes(8 + (-len(value)) % 8))
            return path

        def mapping(path, address, size):
            return ['--memory-mapfile', '/result/' + path.name, '--memory-region', f'{address:#x},{size}']

        stub = ' mov r0,0\n j_s [blink]\n'
        recorder = ' mov r12,0x2000000\n ld r12,[r12]\n' + ''.join(f' st r{i},[r12,{4*i}]\n' for i in range(6)) + ' mov r0,0\n j_s [blink]\n'
        services = [(f'init{i}', a, stub) for i, a in enumerate((0xca404, 0xdecd4, 0x12df54, 0x1453f4, 0x1490fc, 0x1487e8, 0x148e14, 0x1567f8))]
        services.append(('iris_entry', 0x2c5074, recorder))
        for i, (name, address, asm) in enumerate(services):
            dst = 0x2030000 + i * 0x400
            path = binary(name, asm)
            maps += mapping(path, dst, path.stat().st_size)
            entry = binary('entry_' + name, f' mov_s r12,{dst:#x}\n j_s [r12]\n').read_bytes()[:8]
            block, offset = locate(address, 8)
            before = bytes(images[block['index']][offset:offset + 8])
            assert before == raw(address, 8)
            images[block['index']][offset:offset + 8] = entry
            patches.append(dict(name=name, address=hex(address), original=before.hex(), fixture=entry.hex()))

        asm = ' mov r20,0x2000000\n'
        for i, selector in enumerate((0x50, 0x12345678)):
            addr = 0x2001000 + i * 64
            asm += f''' mov r21,{addr:#x}
 st r21,[r20]
 st sp,[r21,32]
 mov r0,{selector:#x}
 mov r1,11
 mov r2,22
 mov r3,33
 mov r4,44
 mov r5,55
 mov r6,66
 mov r12,0x2c4fac
 jl [r12]
 st r0,[r21,24]
 st sp,[r21,36]
'''
        asm += ' mov r0,0\n mov r8,1\n trap_s 1\n'
        for i, image in images.items():
            path = out / f'block{i}_LAB_FIXTURE.bin'
            path.write_bytes(image)
            maps += mapping(path, BS[i]['load_address_candidate'], len(image))
        path = out / 'cases.bin'
        path.write_bytes(bytes(128))
        maps += mapping(path, 0x2001000, 128)
        current = out / 'current.bin'
        current.write_bytes(bytes(8))
        maps += mapping(current, 0x2000000, 8)
        elf = compile_probe(r, 'cases', asm)
        case, log = r.run('cases', '/result/' + elf.name, maps, trace=True)
        assert case['exit_code'] == 0 and case['fault'] is None, log
        values = path.read_bytes()
        yes = struct.unpack_from('<10I', values, 0)
        no = struct.unpack_from('<10I', values, 64)
        assert yes[:7] == (11, 22, 33, 44, 55, 66, 1) and yes[8] == yes[9], yes
        assert no[:7] == (0, 0, 0, 0, 0, 0, 0) and no[8] == no[9], no
        trace = (out / 'cases.trace').read_text().splitlines()
        assert sum(line.startswith('0x2c5034 ') for line in trace) == 1
        assert sum(line.startswith('0x2c501e ') for line in trace) == 1
        (out / 'fixture_patches.json').write_text(json.dumps(patches, indent=2) + '\n')
        (out / 'verifier_snapshot.py').write_bytes(Path(__file__).read_bytes())
        r.results.update(status='PASS_IRIS_DIAGNOSTIC_DISPATCH_FIXTURE', scenarios=[
            {'selector': '0x50', 'target': '0x2c5074', 'forwarded': [11, 22, 33, 44, 55, 66], 'return': 1},
            {'selector': '0x12345678', 'target': None, 'return': 0}],
            limits=['Direct dispatcher invocation with initialization and iris entry replaced by fixtures; no panel execution, optical movement, physical keys or display.',
                    'Synthetic RAM and experimental GNU DSP; no hardware or installability claim.'])
        r.finish()
    except Exception as e:
        r.results.update(status='FAIL', error=repr(e))
        raise
    finally:
        r.save()
    print('PASS: diagnostic dispatch fixture;', out, flush=True)


if __name__ == '__main__':
    main()
