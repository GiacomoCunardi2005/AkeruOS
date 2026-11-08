#!/usr/bin/env python3
"""Verify an original CFA AWB-record population fragment with synthetic RAM."""
from datetime import datetime, timezone
from pathlib import Path
from types import SimpleNamespace
import json, struct, sys

from s33_run_gnu_arc700 import ROOT, LEGACY, TOOLCHAIN, Runner, sha
from s33_verify_gnu_dsp_lab import compile_probe
sys.path.insert(0, str(ROOT / 'S33-sections/analysis_codex'))
from static_common import BS, PS, locate, raw, u32


def main():
    writer = '--writer' in sys.argv
    out = ROOT / 'Risultati/Mono_RAW' / datetime.now(timezone.utc).strftime(('cfa_awb_writer_cpu_' if writer else 'cfa_awb_triplet_cpu_') + '%Y%m%dT%H%M%SZ')
    r = Runner(SimpleNamespace(legacy_root=LEGACY, toolchain=TOOLCHAIN, output=out, action='cfa-awb-triplet'))
    print('Prove:', out, flush=True)
    try:
        r.prepare()
        dump = ROOT / 'DUMPS/MainCode.dmp'
        data = dump.read_bytes()
        for p in (dump, Path(__file__)):
            r.input_hashes[str(p)] = sha(p)
        for a, n in ((0xe767a, 0x28), (0xe4264, 0x58), (0xad920, 8), (0xe793c, 0x28), (0x32e180, 0x14), (0x128c20, 8), (0xe5448, 0x1c)):
            block, off = locate(a, n)
            assert raw(a, n) == data[block['offset'] + off:block['offset'] + off + n]
        assert (u32(0xe42b4), u32(0xe42b8), u32(0xe7984)) == (0x365d18, 0x365d20, 0x3451ec)
        assert raw(0x3451ec, 15) == b'awb_debug_info\0'
        images = {i: bytearray(PS[i]) for i in (0, 1)}
        def binary(name, asm):
            elf = compile_probe(r, name, asm)
            path = out / (name + '.bin')
            result = r.command(name + '_extract', [TOOLCHAIN / 'arc-elf32-objcopy', '-O', 'binary', '--only-section=.text', elf, path])
            assert result.returncode == 0, result.stdout
            b = path.read_bytes(); path.write_bytes(b + bytes(8 + (-len(b)) % 8))
            return path
        def mapping(p, addr):
            return ['--memory-mapfile', '/result/' + p.name, '--memory-region', f'{addr:#x},{p.stat().st_size}']
        exit_stub = binary('fragment_exit', ' j [r19]\n')
        entry = binary('exit_entry', ' mov_s r12,0x2030000\n j_s [r12]\n').read_bytes()[:8]
        patches = []
        for addr in ((0xe76a2, 0xe795c, 0xe5464) if writer else (0xe76a2, 0xe795c)):
            block, off = locate(addr, 8)
            before = bytes(images[block['index']][off:off + 8])
            assert before == raw(addr, 8)
            images[block['index']][off:off + 8] = entry
            patches.append({'address': hex(addr), 'original': before.hex(), 'fixture': entry.hex(), 'reason': 'stop fragment before continuation'})
        cases = [(162, 128, 113), (0, 1, 65535), (4369, 8738, 13107), (0, 0, 0)]
        enabled = [(1, 1), (1, 0), (0, 1), (0, 0)]
        asm = ' mov r20,0x2001000\n'
        for i, values in enumerate(cases):
            asm += f''' mov r21,0x{0x2001000 + i*32:x}
 st sp,[r21,16]
 mov r1,0x365d18
 mov r0,{0xaaaa if writer else values[0]}
 sth r0,[r1]
 mov r0,{0xaaaa if writer else values[1]}
 sth r0,[r1,2]
 mov r0,{0xaaaa if writer else values[2]}
 sth r0,[r1,4]
{f''' mov r1,0x365d20
 mov r0,0xbbbb
 sth r0,[r1]
 sth r0,[r1,2]
 sth r0,[r1,4]
 mov r13,{0x2004000+i*16 if enabled[i][0] else 0}
 mov r18,{0x2004008+i*16 if enabled[i][1] else 0}
 mov r19,writer_return_{i}
 mov r12,0xe5448
 j [r12]
writer_return_{i}:
 mov r1,0x365d20
 mov r2,{0x2005000+i*16}
 ldh r0,[r1]
 st r0,[r2]
 ldh r0,[r1,2]
 st r0,[r2,4]
 ldh r0,[r1,4]
 st r0,[r2,8]''' if writer else ''}
 mov fp,0x2002800
 mov r0,0xa55a
 sth r0,[fp,-160]
 sth r0,[fp,-152]
 mov r19,return_{i}
 mov r12,0xe767a
 j [r12]
return_{i}:
 ldh r0,[fp,-158]
 st r0,[r21]
 ldh r0,[fp,-156]
 st r0,[r21,4]
 ldh r0,[fp,-154]
 st r0,[r21,8]
 ldh r0,[fp,-160]
 st r0,[r21,12]
 ldh r0,[fp,-152]
 st r0,[r21,20]
 mov r16,0x{0x2003000 + i*160:x}
 mov r19,copy_return_{i}
 mov r12,0xe793c
 j [r12]
copy_return_{i}:
 st sp,[r21,24]
'''
        asm += ' mov r0,0\n mov r8,1\n trap_s 1\n'
        maps = mapping(exit_stub, 0x2030000)
        for i, image in images.items():
            p = out / f'block{i}_LAB_FIXTURE.bin'; p.write_bytes(image)
            maps += mapping(p, BS[i]['load_address_candidate'])
        state = out / 'cases.bin'; state.write_bytes(bytes(len(cases)*32)); maps += mapping(state, 0x2001000)
        frame = out / 'frame.bin'; frame.write_bytes(bytes(4096)); maps += mapping(frame, 0x2002000)
        output = out / 'records.bin'; output.write_bytes(bytes(len(cases)*160)); maps += mapping(output, 0x2003000)
        if writer:
            input_data = b''.join(struct.pack('<3H2x3H2x', *values, 11, 22, 33) for values in cases)
            inputs = out / 'inputs.bin'; inputs.write_bytes(input_data); maps += mapping(inputs, 0x2004000)
            writes = out / 'writes.bin'; writes.write_bytes(bytes(len(cases)*16)); maps += mapping(writes, 0x2005000)
        elf = compile_probe(r, 'cases', asm)
        result, log = r.run('cases', '/result/' + elf.name, maps, trace=True)
        assert result['exit_code'] == 0 and result['fault'] is None, log
        rows = []
        for i, values in enumerate(cases):
            w = struct.unpack_from('<8I', state.read_bytes(), i*32)
            expected = values if not writer or enabled[i][0] else (0xaaaa,)*3
            assert tuple(w[:3]) == expected and w[3] == w[5] == 0xa55a and w[4] == w[6], (i, w)
            record = output.read_bytes()[i*160:(i+1)*160]
            assert record[:14] == b'awb_debug_info' and struct.unpack_from('<3H', record, 16+54) == expected, (i, record[:80].hex())
            row = {'input_halfwords': values, 'output_halfwords': list(w[:3]), 'guard_before': w[3], 'guard_after': w[5], 'stack_preserved': True}
            if writer:
                second = struct.unpack_from('<3I', writes.read_bytes(), i*16)
                assert second == ((11,22,33) if enabled[i][1] else (0xbbbb,)*3), (i, second)
                row.update(first_pointer_present=bool(enabled[i][0]), second_pointer_present=bool(enabled[i][1]), second_triplet=second)
            rows.append(row)
        trace = (out / 'cases.trace').read_text()
        for addr in ('0x0e767a', '0x0e4264', '0x0e768e', '0x0e7696', '0x0e769e', '0x0e76a2'):
            assert sum(line.startswith(addr + ' ') for line in trace.splitlines()) == len(cases), addr
        assert sum(line.startswith('0x0ad920 ') for line in trace.splitlines()) >= 3 * len(cases)
        for addr in ('0x0e793c', '0x0e7958', '0x0e795c'):
            assert sum(line.startswith(addr + ' ') for line in trace.splitlines()) == len(cases), addr
        if writer:
            assert sum(line.startswith('0x0e5448 ') for line in trace.splitlines()) == len(cases)
            assert sum(line.startswith('0x0e5464 ') for line in trace.splitlines()) == len(cases)
        assert all(sha(Path(p)) == h for p, h in r.input_hashes.items())
        (out / 'cases.json').write_text(json.dumps(rows, indent=2) + '\n')
        (out / 'fixture_patches.json').write_text(json.dumps(patches, indent=2) + '\n')
        (out / 'verifier_snapshot.py').write_bytes(Path(__file__).read_bytes())
        r.results.update(status='PASS_CFA_AWB_TRIPLET_SYNTHETIC', scenarios=rows,
            assumptions=['Direct entry to original fragments 0xE767A and 0xE793C with synthetic fp and global triplet; intermediate code is skipped; original E4264, AD920 and 128C20 execute.', 'Writer mode directly enters original E5448 after synthetic input setup, skipping E5408 preamble.' if writer else 'Global triplet injected directly.'],
            limits=['No continuous full producer, real CFA file write, concurrent writers, calibration, channel identity or optical white balance verified.'])
        r.finish()
    except Exception as exc:
        r.results.update(status='FAIL', error=repr(exc)); raise
    finally:
        r.save()
    print('PASS:', len(cases), 'triplets', out, flush=True)


if __name__ == '__main__':
    main()
