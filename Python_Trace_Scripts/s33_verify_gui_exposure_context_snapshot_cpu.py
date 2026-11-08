#!/usr/bin/env python3
"""Execute original exposure setters and snapshot copy with synthetic RAM."""
from datetime import datetime, timezone
from pathlib import Path
from types import SimpleNamespace
import json, struct, sys
from s33_run_gnu_arc700 import ROOT, LEGACY, TOOLCHAIN, Runner, sha
from s33_verify_gnu_dsp_lab import compile_probe
sys.path.insert(0, str(ROOT/'S33-sections/analysis_codex'))
from static_common import BS, PS, raw, locate, u32


def main():
    out = ROOT/'Risultati/GUI_S33'/datetime.now(timezone.utc).strftime('exposure_context_snapshot_cpu_%Y%m%dT%H%M%SZ')
    r = Runner(SimpleNamespace(legacy_root=LEGACY, toolchain=TOOLCHAIN, output=out, action='exposure-context-snapshot'))
    print('Prove:', out, flush=True)
    try:
        r.prepare()
        dump = ROOT/'DUMPS/MainCode.dmp'; data = dump.read_bytes(); r.input_hashes[str(dump)] = sha(dump)
        for addr, size in ((0xf6f54, 0x34), (0xad920, 0x20), (0xd03b8, 0x44), (0x17c320, 0xc8), (0xde78c, 0x40)):
            b, off = locate(addr, size)
            assert raw(addr, size) == data[b['offset']+off:b['offset']+off+size]
        assert u32(0xf6f10) == 0x37fbd0 and u32(0xf6f08) == 0x380a24
        cases = [(6, 125, 42000, 19, 1600, 121000), (0, 0, 0, 6, 125, 1000), (19, 1600, 4000000, 0, 0, 0)]
        maps = []
        def mapping(p, addr):
            return ['--memory-mapfile', '/result/'+p.name, '--memory-region', f'{addr:#x},{p.stat().st_size}']
        for i in (0, 1):
            p = out/f'block{i}.bin'; p.write_bytes(PS[i]); maps += mapping(p, BS[i]['load_address_candidate'])
        p = out/'cases.bin'; p.write_bytes(bytes([0xa5])*(len(cases)*160)); maps += mapping(p, 0x2001000)
        asm = ''
        for i, (idx, val, time, idx2, val2, time2) in enumerate(cases):
            base = 0x2001000+i*160
            asm += f''' mov r21,{base:#x}
 st sp,[r21,128]
 mov r1,0x37fbd0
 mov r2,0
 mov r3,64
seed_{i}:
 add r0,r2,0x31
 add r4,r1,r2
 stb r0,[r4]
 add r2,r2,1
 cmp r2,r3
 blt seed_{i}
 mov r0,{idx}
 mov r12,0xd03b8
 jl [r12]
 mov r0,{time}
 mov r12,0xd03e0
 jl [r12]
 mov r1,0x37fbd0
 mov r2,0
copy_{i}:
 ldb r0,[r1,r2]
 add r4,r21,r2
 stb r0,[r4]
 add r2,r2,1
 cmp r2,64
 blt copy_{i}
 add r0,r21,64
 mov r12,0xf6f54
 jl [r12]
 mov r0,{idx2}
 mov r12,0xd03b8
 jl [r12]
 mov r0,{time2}
 mov r12,0xd03e0
 jl [r12]
 mov r1,0x37fbf2
 ldh r0,[r1]
 st r0,[r21,132]
 mov r1,0x37fbf4
 ld r0,[r1]
 st r0,[r21,136]
 mov r1,0x380a35
 ldb r0,[r1]
 st r0,[r21,140]
 st sp,[r21,144]
'''
        asm += ' mov r0,0\n mov r8,1\n trap_s 1\n'
        elf = compile_probe(r, 'cases', asm)
        case, log = r.run('cases', '/result/'+elf.name, maps, trace=True)
        assert case['exit_code'] == 0 and case['fault'] is None, log
        blob = p.read_bytes(); rows = []
        for i, (idx, val, time, idx2, val2, time2) in enumerate(cases):
            chunk = blob[i*160:(i+1)*160]
            assert chunk[:64] == chunk[64:128], (i, chunk[:64].hex(), chunk[64:128].hex())
            assert struct.unpack_from('<HI', chunk, 0x22) == (val, time)
            stack, current_iso, current_time, flag, stack_end = struct.unpack_from('<5I', chunk, 128)
            assert (current_iso, current_time, flag, stack_end) == (val2, time2, 0, stack)
            assert chunk[148:160] == bytes([0xa5])*12
            rows.append(dict(index=idx, iso_software=val, time_field=time, new_index=idx2, new_iso_software=current_iso, new_time_field=current_time, copied_64_bytes_equal=True, snapshot_retains_prechange=True, flag_after=flag, stack_preserved=True))
        trace = (out/'cases.trace').read_text()
        for addr in ('0x0d03b8', '0x0d03e0', '0x0f6f54', '0x0ad920'):
            assert any(line.startswith(addr+' ') for line in trace.splitlines()), addr
        assert sum(line.startswith('0x0f6f70 ') and '0x1' in line for line in trace.splitlines()) == len(cases)
        assert sum(line.startswith('0x0f6f7a ') and '0x0' in line for line in trace.splitlines()) == len(cases)
        (out/'cases.json').write_text(json.dumps(rows, indent=2)+'\n')
        (out/'verifier_snapshot.py').write_bytes(Path(__file__).read_bytes())
        r.results.update(status='PASS_EXPOSURE_CONTEXT_SNAPSHOT', cases=rows, assumptions=['Direct calls to original setters and snapshot helper; synthetic RAM and sequential calls.'], limits=['Does not execute the D8CA4 caller, AE, capture, sensor, concurrency or camera.', 'Field values and physical ISO/exposure units are not calibrated.'], hardware_tested=False, installable=False)
        r.finish()
    except Exception as exc:
        r.results.update(status='FAIL', error=repr(exc)); raise
    finally:
        r.save()
    print('PASS: original sequential exposure context snapshot;', out, flush=True)

if __name__ == '__main__': main()
