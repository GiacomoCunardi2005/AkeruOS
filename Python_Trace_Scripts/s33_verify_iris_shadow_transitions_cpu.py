#!/usr/bin/env python3
"""Check original snapshot-to-shadow transitions read by the iris panel."""
from datetime import datetime, timezone
from pathlib import Path
from types import SimpleNamespace
import json
import struct
import sys

from s33_run_gnu_arc700 import ROOT, LEGACY, TOOLCHAIN, Runner, sha
from s33_verify_gnu_dsp_lab import BUILD, LAB, compile_probe

sys.path.insert(0, str(ROOT / 'S33-sections/analysis_codex'))
from static_common import BS, PS, raw, locate


def main():
    out = ROOT / 'Risultati/GUI_S33' / datetime.now(timezone.utc).strftime('iris_shadow_transitions_cpu_%Y%m%dT%H%M%SZ')
    r = Runner(SimpleNamespace(legacy_root=LEGACY, toolchain=TOOLCHAIN, output=out, action='iris-shadow-transitions'))
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
        for a, n in ((0x1406d0, 0x30), (0x16ec38, 0x4e), (0x16e6e0, 0x150),
                     (0x16f86c, 0x80), (0x16f72c, 0x13c), (0x16f920, 8), (0x392f04, 320)):
            b, o = locate(a, n)
            assert raw(a, n) == data[b['offset'] + o:b['offset'] + o + n]
        records = raw(0x392f04, 320)
        cases = [(7, 20), (8, 16), (9, 21), (10, 15)]
        for key, bit in cases:
            assert any(records[i * 20 + 8:i * 20 + 10] == bytes((bit, key)) and
                       struct.unpack_from('<I', records, i * 20)[0] == 1 << bit for i in range(16))
        images = {i: bytearray(PS[i]) for i in range(6)}
        maps, patches = [], []

        def mapping(p, a, n):
            return ['--memory-mapfile', '/result/' + p.name, '--memory-region', f'{a:#x},{n}']

        def binary(name, asm):
            elf = compile_probe(r, name, asm)
            p = out / (name + '.bin')
            result = r.command(name + '_extract', [TOOLCHAIN / 'arc-elf32-objcopy', '-O', 'binary', '--only-section=.text', elf, p])
            assert result.returncode == 0
            data = p.read_bytes()
            p.write_bytes(data + bytes(8 + (-len(data)) % 8))
            return p

        for i, (name, a) in enumerate((('lock', 0x1593ac), ('unlock', 0x1594a4),
                                       ('queue_lock', 0x1786e8), ('queue_unlock', 0x179354),
                                       ('notify', 0x158cbc), ('filter', 0x17c150))):
            dst = 0x2030000 + i * 0x400
            p = binary(name, ' mov r0,0\n j_s [blink]\n')
            maps += mapping(p, dst, p.stat().st_size)
            entry = binary('entry_' + name, f' mov_s r12,{dst:#x}\n j_s [r12]\n').read_bytes()[:8]
            b, o = locate(a, 8)
            before = bytes(images[b['index']][o:o + 8])
            assert before == raw(a, 8)
            images[b['index']][o:o + 8] = entry
            patches.append(dict(name=name, address=hex(a), original=before.hex(), fixture=entry.hex()))

        asm = ''
        for i, (key, bit) in enumerate(cases):
            state = 0x2001000 + i * 32
            asm += f''' mov r21,{state:#x}
 st sp,[r21,16]
 mov r1,0x3678e8
 mov r0,0x392f04
 st r0,[r1]
 mov r0,16
 sth r0,[r1,4]
 mov r0,1
 stb r0,[r1,6]
 mov r0,0
 st r0,[r1,8]
 st r0,[r1,12]
 mov r1,0x3678a2
 stb r0,[r1]
 mov r1,0x366de8
 mov r0,0x16ec38
 st r0,[r1]
 mov r1,0x3678f9
 mov r0,1
 stb r0,[r1]
 mov r1,{0x446808 + key * 4 + 2:#x}
 sth r0,[r1]
 mov r1,{0x446808 + 4 * 4:#x}
 mov r0,0x5a
 stb r0,[r1]
 mov r0,{(0xffffffff ^ (1 << bit)):#x}
 mov r12,0x1406d0
 jl [r12]
 mov r0,{key}
 mov r12,0x16f920
 jl [r12]
 st r0,[r21]
 mov r0,-1
 mov r12,0x1406d0
 jl [r12]
 mov r0,{key}
 mov r12,0x16f920
 jl [r12]
 st r0,[r21,4]
 mov r0,4
 mov r12,0x16f920
 jl [r12]
 st r0,[r21,8]
 st sp,[r21,20]
'''
        asm += ' mov r0,0\n mov r8,1\n trap_s 1\n'
        for i, image in images.items():
            p = out / f'block{i}_LAB_FIXTURE.bin'
            p.write_bytes(image)
            maps += mapping(p, BS[i]['load_address_candidate'], len(image))
        p = out / 'cases.bin'
        p.write_bytes(bytes(32 * len(cases)))
        maps += mapping(p, 0x2001000, 32 * len(cases))
        for name, addr in (('key_state', 0x446000), ('queue', 0x47a000)):
            region = out / (name + '.bin')
            region.write_bytes(bytes(0x2000))
            maps += mapping(region, addr, 0x2000)
        elf = compile_probe(r, 'cases', asm)
        result, log = r.run('cases', '/result/' + elf.name, maps, trace=True)
        assert result['exit_code'] == 0 and result['fault'] is None, log
        assert 'S33_DSP_GUARD' not in log
        rows = []
        for i, (key, bit) in enumerate(cases):
            active, released, exit_key, _, sp0, sp1 = struct.unpack_from('<6I', p.read_bytes(), i * 32)
            assert (active, released, exit_key, sp0 == sp1) == (1, 0, 0x5a, True), (key, active, released, exit_key)
            rows.append(dict(key=key, bit=bit, active=active, released=released, key4_control=exit_key))
        trace = (out / 'cases.trace').read_text().splitlines()
        for addr in (0x1406d0, 0x16ec38, 0x16e6e0, 0x16f86c, 0x16f72c, 0x16f920):
            assert any(line.startswith(f'{addr:#x} ') for line in trace), hex(addr)
        (out / 'cases.json').write_text(json.dumps(rows, indent=2) + '\n')
        (out / 'fixture_patches.json').write_text(json.dumps(patches, indent=2) + '\n')
        (out / 'verifier_snapshot.py').write_bytes(Path(__file__).read_bytes())
        r.results.update(status='PASS_IRIS_SHADOW_TRANSITIONS_FIXTURES', scenarios=rows,
                         assumptions=['Original V1.1 callback, normalization, record transition, writer and getter; snapshot arguments injected directly.',
                                      'Synthetic previous state, gates, shadow table, scheduler and service fixtures; experimental DSP.'],
                         limits=['No original monitor, MMIO reader, physical buttons, concurrent task, display or optical movement.',
                                 'Index 4 is a synthetic control, not its real producer.'])
        r.finish()
    except Exception as exc:
        r.results.update(status='FAIL', error=repr(exc))
        raise
    finally:
        r.save()
    print('PASS: four iris shadow transitions;', out, flush=True)


if __name__ == '__main__':
    main()
