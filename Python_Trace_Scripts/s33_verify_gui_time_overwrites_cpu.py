#!/usr/bin/env python3
"""Test competing original setters for the S33 debug exposure word."""
from datetime import datetime, timezone
from types import SimpleNamespace
import json, struct, sys
from s33_run_gnu_arc700 import ROOT, LEGACY, TOOLCHAIN, Runner, sha
from s33_verify_gnu_dsp_lab import compile_probe
sys.path.insert(0, str(ROOT / 'S33-sections/analysis_codex'))
from static_common import BS, PS, raw, locate, u32, disasm


def main():
    out = ROOT / 'Risultati/GUI_S33' / datetime.now(timezone.utc).strftime('time_overwrites_cpu_%Y%m%dT%H%M%SZ')
    r = Runner(SimpleNamespace(legacy_root=LEGACY, toolchain=TOOLCHAIN, output=out, action='gui-time-overwrites'))
    print('Prove:', out, flush=True)
    try:
        r.prepare()
        dump = ROOT / 'DUMPS/MainCode.dmp'
        data = dump.read_bytes()
        r.input_hashes[str(dump)] = sha(dump)
        for address, size in [(0xc9f08, 0x0a), (0xca5dc, 0x11e), (0xd5a80, 0x32), (0xdbcc0, 0x10), (0xdbdc0, 0x56), (0xde730, 0x30), (0xdf47c, 0xa0), (0x17c480, 0x1c), (0x323e5a, 0x26), (0xd03e0, 0x28), (0xde548, 0x30), (0xde7b4, 0x1c), (0xf6f0c, 8), (0x17c49c, 0x90), (0x1e1dc4, 0x28)]:
            block, offset = locate(address, size)
            assert raw(address, size) == data[block['offset'] + offset:block['offset'] + offset + size]
        assert u32(0xf6f10) == 0x37fbd0 and u32(0xf6f18) == 0x380574 and u32(0xd03fc) == 0x365788
        windows = [(0xc9f08, 0xc9f12), (0xca5dc, 0xca6f6), (0xd5a80, 0xd5ab2), (0xdbdc0, 0xdbe16), (0xde730, 0xde760), (0xde7b4, 0xde7dc), (0xdf47c, 0xdf51c), (0x1e1dc4, 0x1e1dec), (0x323e5a, 0x323e80)]
        (out / 'gnu_windows.txt').write_text('\n'.join(disasm(a, b) for a, b in windows))
        assert [u32(a) for a in range(0x17c508, 0x17c528, 4)] == [500000, 1000000, 1500000, 2000000, 3000000, 4000000, 6000000, 8000000]
        cases = [('table', i) for i in range(10)] + [('bounded', i) for i in (0, 1000000, 1000001, 0xffffffff)]
        state = bytearray(len(cases) * 32)
        asm = ' mov r20,0x2001000\n'
        for i, (kind, value) in enumerate(cases):
            asm += f''' mov r21,{0x2001000 + i * 32:#x}
 mov r0,42000
 mov r12,0xd03e0
 jl [r12]
 mov r0,{value:#x}
 mov r12,{0x17c49c if kind == 'table' else 0x1e1dc4:#x}
 jl [r12]
 st r0,[r21,0]
 mov r1,0x37fbf4
 ld r0,[r1]
 st r0,[r21,4]
 mov r1,0x365788
 ld r0,[r1]
 st r0,[r21,8]
'''
        asm += ' mov r0,0\n mov r8,1\n trap_s 1\n'
        maps = []
        for i in (0, 1, 4, 5):
            image = out / f'block{i}_LAB_FIXTURE.bin'
            image.write_bytes(bytes(PS[i]))
            maps += ['--memory-mapfile', '/result/' + image.name, '--memory-region', f'{BS[i]["load_address_candidate"]:#x},{len(PS[i])}']
        statefile = out / 'cases.bin'
        statefile.write_bytes(state)
        maps += ['--memory-mapfile', '/result/' + statefile.name, '--memory-region', f'0x2001000,{len(state)}']
        elf = compile_probe(r, 'cases', asm)
        result, log = r.run('cases', '/result/' + elf.name, maps, trace=True)
        assert result['exit_code'] == 0 and result['fault'] is None, log
        values = [0, 500000, 1000000, 1500000, 2000000, 3000000, 4000000, 6000000, 8000000]
        rows = []
        for i, (kind, value) in enumerate(cases):
            ret, field, debug = struct.unpack_from('<3I', statefile.read_bytes(), i * 32)
            expected = values[value] if kind == 'table' and value < 9 else (value if kind == 'bounded' and value <= 1000000 else 42000)
            expected_ret = int((kind == 'table' and value >= 9) or (kind == 'bounded' and value > 1000000))
            assert (ret, field, debug) == (expected_ret, expected, 42000), (kind, value, ret, field, debug)
            rows.append(dict(kind=kind, input=value, ret=ret, field=field, debug_word=debug))
        (out / 'cases.json').write_text(json.dumps(rows, indent=2) + '\n')
        (out / 'verifier_snapshot.py').write_bytes(__import__('pathlib').Path(__file__).read_bytes())
        r.results.update(status='PASS_TIME_OVERWRITES', scenarios=rows, assumptions=['Original functions and synthetic memory; paths are invoked directly in sequence.'], limits=['No runtime scheduling, hardware, unit or capture effect established.'])
        r.finish()
    except Exception as e:
        r.results.update(status='FAIL', error=repr(e))
        raise
    finally:
        r.save()
    print('PASS: 14 competing-setter cases;', out, flush=True)

if __name__ == '__main__':
    main()
