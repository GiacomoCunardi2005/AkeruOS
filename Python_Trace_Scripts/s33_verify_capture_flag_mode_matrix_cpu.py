#!/usr/bin/env python3
"""Original CaptureMenu flag update 0x7CB1B4 with original getters 0xCAD30/0xCA310.

Matrix of shooting-mode byte (RAM 0xC8E80C, pool 0xCAAC4 of the ld.as in 0xCAD30)
and guard byte (RAM 0x365751, pool 0xCA30C of 0xCA310) against the flag bit 1
written on the records of the two CaptureMenu lists
(controls 0x9801C0/ID 0x4800 and 0x980268/ID 0x4801). The update entry, the
record helper 0x631E98 and both byte getters execute original code from the
V1.1 dump; only 0x1457D4 (current resource id) is a lab fixture reading the
same current-control cell used by the update itself ([0x89985C], pool
0x7CB1AC -> 0x899858).
"""
from datetime import datetime, timezone
from pathlib import Path
from types import SimpleNamespace
import hashlib, json, struct, sys
from s33_run_gnu_arc700 import ROOT, LEGACY, TOOLCHAIN, Runner, sha
from s33_verify_gnu_dsp_lab import BUILD, LAB, compile_probe
sys.path.insert(0, str(ROOT / 'S33-sections/analysis_codex'))
from static_common import BS, PS, locate, raw, u16, u32

CTRL = {0x4800: (0x9801C0, 0x98016C, 3), 0x4801: (0x980268, 0x9801F8, 4)}
SENTINEL = 0x13572468  # bit 1 clear on both lists' inactive records

# (resource, mode, guard, seed_active, expected_flags, cad30, ca310, idgetter, reads)
CASES = [
    (0x4801, 0x46, 0, 0x08, [0x8, 0x8, 0xA, 0xA], 2, 0, 1, [8] * 6),
    (0x4801, 0x2C, 0, 0x08, [0x8, 0x8, 0x8, 0x8], 2, 2, 1, [8] * 4),
    (0x4801, 0x2C, 7, 0x08, [0x8, 0x8, 0xA, 0xA], 2, 2, 1, [8] * 6),
    (0x4801, 0x2C, 6, 0x08, [0x8, 0x8, 0x8, 0x8], 2, 2, 1, [8] * 4),
    (0x4801, 0x2B, 0, 0x08, [0x8, 0x8, 0xA, 0xA], 2, 0, 1, [8] * 6),
    (0x4801, 0x46, 0, 0x0A, [0x8, 0x8, 0xA, 0xA], 2, 0, 1, [0xA] * 4 + [8] * 2),
    (0x4801, 0x2C, 0, 0x0A, [0x8, 0x8, 0x8, 0x8], 2, 2, 1, [0xA] * 4),
    (0x4800, 0x46, 0, 0x08, [0x8, 0x8, 0x8], 10, 0, 2, [8] * 3),
    (0x4800, 0x14, 0, 0x08, [0x8, 0xA, 0xA], 2, 0, 2, [8] * 5),
    (0x4800, 0x68, 0, 0x08, [0x8, 0xA, 0x8], 8, 0, 2, [8] * 4),
    (0x4800, 0x15, 0, 0x08, [0x8, 0x8, 0xA], 9, 0, 2, [8] * 4),
    (0x4800, 0x0A, 0, 0x08, [0x8, 0x8, 0x8], 10, 0, 2, [8] * 3),
    (0x4800, 0x14, 0, 0x0A, [0x8, 0xA, 0xA], 2, 0, 2, [0xA] * 3 + [8] * 2),
    (0x4800, 0x2C, 7, 0x0A, [0x8, 0x8, 0x8], 10, 0, 2, [0xA] * 3),
]


def main():
    out = ROOT / 'Risultati/GUI_S33' / datetime.now(timezone.utc).strftime(
        'capture_flag_mode_matrix_cpu_%Y%m%dT%H%M%S%fZ')
    r = Runner(SimpleNamespace(legacy_root=LEGACY, toolchain=TOOLCHAIN, output=out,
                               action='capture-flag-mode-matrix'))
    print('Prove:', out, flush=True)
    try:
        r.prepare()
        build = json.loads(BUILD.read_text())
        sim = LAB / 'install/bin/arc-elf32-run'
        assert sha(sim) == build['experimental_sha256']
        r.experimental_engine = LAB
        r.input_hashes[str(sim)] = sha(sim)
        r.input_hashes[str(BUILD)] = sha(BUILD)
        dump = ROOT / 'DUMPS/MainCode.dmp'
        data = dump.read_bytes()
        r.input_hashes[str(dump)] = sha(dump)

        # --- static decode, byte-verified on the dump -------------------
        for a, n in [(0x7cb1b4, 0x130), (0x7cb03c, 0x68), (0x631e98, 0x30),
                     (0xcad30, 0x28), (0xcad38, 0x28), (0xca310, 0x18),
                     (0x1457d4, 0x18), (0x334128, 0x10), (0x33418c, 0x10),
                     (0x98016c, 84), (0x9801f8, 112), (0x9801c0, 56),
                     (0x980268, 56), (0x899858, 16), (0xcad58, 4), (0xca30c, 4),
                     (0x1457d0, 4), (0x7cb1ac, 4), (0x7cb2e4, 4)]:
            b, o = locate(a, n)
            assert raw(a, n) == data[b['offset'] + o:b['offset'] + o + n], hex(a)
        window_hashes = {f'{a:#x}+{n:#x}': hashlib.sha256(raw(a, n)).hexdigest()
                         for a, n in [(0x7cb1b4, 0x130), (0x631e98, 0x30), (0xcad30, 0x28),
                                     (0xca310, 0x18), (0x1457d4, 0x18)]}
        assert u32(0x7cb1ac) == 0x899858 and u32(0x7cb1b0) == 0x4801 and u32(0x7cb2e4) == 0xCAD30
        assert u32(0x1457d0) == 0x366EAC       # original current-resource getter reads active control cell
        assert BS[8]['load_address_candidate'] <= 0xC8E80C < BS[8]['load_address_candidate'] + BS[8]['size']
        assert u32(0xcaac4) == 0xC8E80C       # ld.as pool of getter 0xCAD30 -> mode byte cell
        assert u32(0xcad58) == 0x365753       # pool shared by setter 0xCAD38 and stub 0xCAD5C
        assert u32(0xca30c) == 0x365751       # guard getter pool
        for rid, (c, recs, n) in CTRL.items():
            assert u16(c + 4) == rid and u16(c + 6) == 0x15
            assert u32(c + 0x30) == recs and u16(c + 0x34) == n
        assert [u16(0x98016C + 28 * k + 0x14) for k in range(3)] == [0x87, 0x9D, 0x9D]
        assert [raw(0x98016C + 28 * k + 0x10, 1)[0] for k in range(3)] == [0, 2, 3]
        assert [u16(0x9801F8 + 28 * k + 0x14) for k in range(4)] == [0x87, 0x07, 0x0A, 0xBB]
        assert [raw(0x9801F8 + 28 * k + 0x10, 1)[0] for k in range(4)] == [0, 0, 0, 0]

        images = {i: bytearray(PS[i]) for i in (0, 1, 2, 3, 4, 5, 8)}  # 8 = 0xC8E800 bank with the mode cell
        maps = []
        patches = []

        def binary(name, asm):
            elf = compile_probe(r, name, asm)
            p = out / (name + '.bin')
            assert r.command(name + '_extract', [TOOLCHAIN / 'arc-elf32-objcopy', '-O', 'binary',
                                                 '--only-section=.text', elf, p]).returncode == 0
            d = p.read_bytes()
            p.write_bytes(d + bytes(8 + (-len(d)) % 8))
            return p

        def mapping(p, a):
            return ['--memory-mapfile', '/result/' + p.name, '--memory-region', f'{a:#x},{p.stat().st_size}']

        # fixture: current resource id reads the same current-control cell as the update
        dst = 0x2030000
        p = binary('current_resource_id',
                   ' mov r0,0x89985c\n ld r0,[r0]\n ldh r0,[r0,4]\n j_s [blink]\n')
        maps += mapping(p, dst)
        entry = binary('entry_current_resource_id',
                       f' mov_s r12,{dst:#x}\n j_s [r12]\n').read_bytes()[:8]
        b, o = locate(0x1457d4, 8)
        before = bytes(images[b['index']][o:o + 8])
        assert before == raw(0x1457d4, 8)
        images[b['index']][o:o + 8] = entry
        patches.append(dict(name='current_resource_id', address='0x1457d4',
                            original=before.hex(), fixture=entry.hex()))

        asm = ' mov r10,0\n'
        for i, (rid, mode, guard, seed, _exp, _c1, _c2, _c3, _rd) in enumerate(CASES):
            ctrl, recs, count = CTRL[rid]
            other, orecs, ocount = CTRL[0x4801 if rid == 0x4800 else 0x4800]
            cell = 0x2001000 + i * 128
            asm += f''' mov r21,{cell:#x}
 st sp,[r21,52]
 mov r1,0x89985c
 mov r0,{ctrl:#x}
 st r0,[r1]
 mov r1,0xc8e80c
 mov r0,{mode:#x}
 stb r0,[r1]
 mov r1,0x365751
 mov r0,{guard:#x}
 stb r0,[r1]
'''
            for k in range(count):
                asm += f' mov r1,{recs + 28 * k + 0x18:#x}\n mov r0,{seed:#x}\n st r0,[r1]\n'
            for k in range(ocount):
                asm += f' mov r1,{orecs + 28 * k + 0x18:#x}\n mov r0,{SENTINEL:#x}\n st r0,[r1]\n'
            asm += f''' mov r0,{0x9802ac:#x}
 mov r12,0x7cb1b4
 jl [r12]
 st r0,[r21]
 st sp,[r21,56]
 mov r1,0x89985c
 ld r0,[r1]
 st r0,[r21,4]
 mov r1,0xc8e80c
 ldb r0,[r1]
 st r0,[r21,8]
 mov r1,0x365751
 ldb r0,[r1]
 st r0,[r21,12]
'''
            for k in range(count):
                asm += (f' mov r1,{recs + 28 * k + 0x18:#x}\n ld r0,[r1]\n'
                        f' st r0,[r21,{16 + 4 * k}]\n')
            for k in range(ocount):
                asm += (f' mov r1,{orecs + 28 * k + 0x18:#x}\n ld r0,[r1]\n'
                        f' st r0,[r21,{16 + 4 * (count + k)}]\n')
        asm += ' mov r0,0\n mov r8,1\n trap_s 1\n'

        for i, img in images.items():
            p = out / f'block{i}_LAB_FIXTURE.bin'
            p.write_bytes(img)
            maps += mapping(p, BS[i]['load_address_candidate'])
        cases = out / 'cases.bin'
        cases.write_bytes(bytes(128 * len(CASES)))
        maps += mapping(cases, 0x2001000)

        elf = compile_probe(r, 'cases', asm)
        result, log = r.run('cases', '/result/' + elf.name, maps, trace=True)
        assert result['exit_code'] == 0 and result['fault'] is None, log

        rows = []
        blob = cases.read_bytes()
        for i, (rid, mode, guard, seed, exp, n_cad30, n_ca310, n_id, reads) in enumerate(CASES):
            ctrl, recs, count = CTRL[rid]
            other, orecs, ocount = CTRL[0x4801 if rid == 0x4800 else 0x4800]
            w = struct.unpack_from('<16I', blob, i * 128)
            assert w[1] == ctrl, (i, w)
            assert w[2] == mode and w[3] == guard, (i, w)
            assert w[13] == w[14], ('stack', i, w)
            active = list(w[4:4 + count])
            inactive = list(w[4 + count:4 + count + ocount])
            assert active == exp, (i, active, exp)
            assert inactive == [SENTINEL] * ocount, (i, inactive)
            rows.append(dict(case=i, resource=f'{rid:#x}', control=f'{ctrl:#x}', mode=mode,
                             guard=guard, seed=f'{seed:#x}', flags_after=[f'{v:#x}' for v in active],
                             inactive_records_untouched=True, cad30_calls=n_cad30,
                             ca310_calls=n_ca310, id_getter_calls=n_id, stack_preserved=True))
            # 0x4801: one 0xCAD30 call per consulted record (dest 0xBB/0x0A);
            # 0x4800: one 0xCAD30 call per comparison, up to 6 (cat 2) / 4 (cat 3).

        trace = (out / 'cases.trace').read_text()
        lines = trace.splitlines()
        for pc, n in [('0x7cb1b4 ', len(CASES)),
                      ('0x631e98 ', sum(len(c[8]) for c in CASES)),
                      ('0x0cad30 ', sum(c[5] for c in CASES)),
                      ('0x0ca310 ', sum(c[6] for c in CASES)),
                      ('0x1457d4 ', sum(c[7] for c in CASES))]:
            got = sum(line.startswith(pc) for line in lines)
            assert got == n, (pc, got, n)
        got_reads = [line.split('<- ')[-1] for line in lines if line.startswith('0x631ea2 ')]
        want_reads = [f'{v:#x}' for c in CASES for v in c[8]]
        assert got_reads == want_reads, (got_reads, want_reads)

        (out / 'cases.json').write_text(json.dumps(rows, indent=2) + '\n')
        (out / 'fixture_patches.json').write_text(json.dumps(patches, indent=2) + '\n')
        (out / 'verifier_snapshot.py').write_bytes(Path(__file__).read_bytes())
        assert sha(dump) == r.input_hashes[str(dump)]
        r.results.update(
            status='PASS_CAPTURE_FLAG_MODE_MATRIX',
            window_sha256=window_hashes,
            scenarios=rows,
            assumptions=[
                'Original code from the V1.1 dump: update entry 0x7CB1B4, record helper 0x631E98, '
                'mode getter 0xCAD30 (ld.as pool 0xCAAC4 -> RAM 0xC8E80C), guard getter 0xCA310 '
                '(pool 0xCA30C -> RAM 0x365751). Only 0x1457D4 is a lab fixture reading '
                '[0x89985C]+4, the same '
                'current-control cell the update itself enumerates (pool 0x7CB1AC -> 0x899858).',
                'Mode byte, guard byte, current control cell and record flags are seeded synthetic RAM '
                'values; the record base flags in the dump are 0x08/0x00.',
            ],
            limits=[
                'No full AutoScene/manager chain in this run: the update is entered directly, as the '
                'single call site 0x7CB076 does during class-15 init. Real producers of the mode/guard '
                'bytes, physical meaning of the modes, rendering, physical keys and camera behavior '
                'are not established. 0x631E98 is a generic helper with 128 call sites; other menus '
                'may write bit 1 of their own records. NON_INSTALLARE.',
            ])
        r.finish()
    except Exception as e:
        r.results.update(status='FAIL', error=repr(e))
        raise
    finally:
        r.save()
    print('PASS:', len(CASES), 'original flag-update matrix cases;', out, flush=True)


if __name__ == '__main__':
    main()
