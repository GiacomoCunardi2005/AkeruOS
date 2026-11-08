#!/usr/bin/env python3
"""Execute the special-region copy branches 0x32F410/0x32F4C0/0x32F570 of the guarded memcpy.

These are the paths 0x128C20 dispatches to when source or destination touch
[0x423900,0x428600): plain copies with .di (cache-inhibit) loads/stores. Original
payload0 bytes, mapfile fixtures, extension sentinel A5: no candidate code, no
firmware modification, no hardware.
"""
from datetime import datetime, timezone
from pathlib import Path
from types import SimpleNamespace
import json, sys

from s33_run_gnu_arc700 import ROOT, LEGACY, TOOLCHAIN, Runner, sha
from s33_verify_gnu_dsp_lab import compile_probe
sys.path.insert(0, str(ROOT/'S33-sections/analysis_codex'))
from static_common import BS, PS, disasm

MEMCPY = 0x128c20
DEST_SPECIAL = 0x32f4c0    # .di stores: destination in the special region
SRC_SPECIAL = 0x32f410     # .di loads: source in the special region
BOTH_SPECIAL = 0x32f570    # .di loads and stores
SPECIAL_LO, SPECIAL_HI = 0x423900, 0x428600
EXTENSION = (0x35bc00, 0x35ce00)
SCRATCH, SOURCE = 0x35d000, 0x35e000
SPECIAL_SCRATCH, SPECIAL_SOURCE = 0x423900, 0x424000
PATTERN = bytes((0x10+i*7) & 0xff for i in range(64))
EVIDENCE = ROOT/'Risultati/USB_SCSI/Accesso_NAND_PC'


def main():
    out = EVIDENCE/datetime.now(timezone.utc).strftime('memcpy_special_cpu_%Y%m%dT%H%M%SZ')
    runner = Runner(SimpleNamespace(legacy_root=LEGACY, toolchain=TOOLCHAIN, output=out,
                                    action='original-memcpy-special-region-branches'))
    runner.prepare()
    try:
        payload0 = bytes(PS[0])
        base0 = BS[0]['load_address_candidate']
        assert base0 == 0xAD800 and len(payload0) == 0x2AE400

        def mmap(options, name, address, data):
            path = out/name; path.write_bytes(bytes(address % 8)+data)
            options.extend(['--memory-mapfile', '/result/'+name, '--memory-region', f'{address:#x},{len(data)}'])
            return path

        def execute(name, target, dst_offset, src_offset, length, *, dst_zone='special', src_zone='normal'):
            """dst_offset/src_offset are offsets inside the zone buffers; returns the case row."""
            options = []
            # Ascending mapfile order: payload0, extension, gap scratch/source, special fixtures.
            p0_path = mmap(options, name+'_payload0.bin', base0, payload0)
            extension = mmap(options, name+'_extension.bin', EXTENSION[0], b'\xa5'*(EXTENSION[1]-EXTENSION[0]))
            scratch = mmap(options, name+'_scratch.bin', SCRATCH, b'\xc3'*0x1000) if dst_zone == 'gap' else None
            if src_zone == 'normal':
                mmap(options, name+'_source.bin', SOURCE, PATTERN+bytes(0x100))
            special_dst = mmap(options, name+'_special_dst.bin', SPECIAL_SCRATCH, b'\x5c'*0x200) if dst_zone == 'special' else None
            special_src = mmap(options, name+'_special_src.bin', SPECIAL_SOURCE, PATTERN+bytes(0x100)) if src_zone == 'special' else None
            dst = (SPECIAL_SCRATCH if dst_zone == 'special' else SCRATCH)+dst_offset
            src = (SPECIAL_SOURCE if src_zone == 'special' else SOURCE)+src_offset
            assembly = (f' mov r0,{dst:#x}\n mov r1,{src:#x}\n mov r2,{length}\n'
                        f' mov r12,{target:#x}\n jl [r12]\n mov r0,0\n mov r8,1\n trap_s 1\n')
            elf = compile_probe(runner, name, assembly)
            case, log = runner.run(name, '/result/'+elf.name, options, trace=False)
            assert case['exit_code'] == 0 and case['fault'] is None, log
            assert p0_path.read_bytes()[base0 % 8:] == payload0, name+': payload0 alterato'
            assert extension.read_bytes()[EXTENSION[0] % 8:] == b'\xa5'*(EXTENSION[1]-EXTENSION[0]), name+': estensione alterata'
            expected = bytearray(b'\x5c'*0x200) if dst_zone == 'special' else bytearray(b'\xc3'*0x1000)
            expected[dst_offset:dst_offset+length] = PATTERN[:length]
            observed = (special_dst if dst_zone == 'special' else scratch).read_bytes()
            observed = observed[(SPECIAL_SCRATCH if dst_zone == 'special' else SCRATCH) % 8:]
            assert observed == bytes(expected), name+': copia non delimitata'
            if src_zone == 'special':
                assert special_src.read_bytes()[SPECIAL_SOURCE % 8:] == PATTERN+bytes(0x100), name+': sorgente speciale alterato'
            return dict(name=name, target=hex(target), dest=hex(dst), src=hex(src), length=length,
                        exit_code=case['exit_code'], instructions=case['instructions'],
                        extension='intact', bounded_copy=True)

        rows = []
        # Direct branch executions.
        rows.append(execute('special_dest_copy_16', DEST_SPECIAL, 0, 0, 16))
        rows.append(execute('special_dest_copy_3', DEST_SPECIAL, 0x10, 0, 3))
        rows.append(execute('special_dest_copy_0', DEST_SPECIAL, 0x20, 0, 0))
        rows.append(execute('special_src_copy_16', SRC_SPECIAL, 0, 0, 16, dst_zone='gap', src_zone='special'))
        rows.append(execute('special_both_copy_16', BOTH_SPECIAL, 0x40, 0, 16))
        rows.append(execute('special_src_unaligned', SRC_SPECIAL, 8, 0, 5, dst_zone='gap', src_zone='special'))
        # Integration: the full guarded service dispatches into the special branch.
        rows.append(execute('integration_memcpy_special_dest', MEMCPY, 0x80, 0, 16))
        rows.append(execute('integration_memcpy_special_src', MEMCPY, 0, 0, 16, dst_zone='gap', src_zone='special'))

        from s33_sweep_extension_writers import raw_disasm, parse_listing as _
        from s33_trace_state_dispatch import parse_listing, window
        listing, oob = raw_disasm(payload0, base0, tolerate_oob=True)
        addresses, lines = parse_listing(listing)
        windows_out = ['# S33 - rami speciali del memcpy: finestre GNU lineari (supporto, non CFG)']
        for label, center in [('src_special', SRC_SPECIAL), ('dest_special', DEST_SPECIAL),
                              ('both_special', BOTH_SPECIAL), ('memcpy_guard', MEMCPY)]:
            windows_out.append(f'====== {label} 0x{center:x} ======')
            windows_out.append(window(addresses, lines, center, 8, 160))
        (out/'gnu_verified.txt').write_text('\n'.join(windows_out)+'\n')
        assert all(sha(Path(path)) == digest for path, digest in runner.input_hashes.items())
        result = dict(status='PASS_ORIGINAL_MEMCPY_SPECIAL_REGION_BRANCHES',
                      branches=dict(dest_special=hex(DEST_SPECIAL), src_special=hex(SRC_SPECIAL),
                                    both_special=hex(BOTH_SPECIAL),
                                    region=[hex(SPECIAL_LO), hex(SPECIAL_HI)],
                                    semantics='.di (cache-inhibit) loads/stores; plain bounded copies, no MMIO'),
                      cases=rows,
                      sources={str(p): sha(p) for p in [Path(__file__), ROOT/'OriginalSoftware_NikonS33_V1.1/firmware.bin']},
                      assumptions=['Original payload0 mapped at 0xAD800; fixtures are mapfiles only',
                                   'The simulator executes .di accesses as ordinary RAM accesses',
                                   'Integration cases call the full 0x128C20 which dispatches to the branch'],
                      limits=['Only the copy bodies executed: their runtime cache effect is not modelled',
                              'No proof that no other code path writes the special region',
                              'No DMA, no hardware; candidate NON_INSTALLARE unchanged'])
        runner.results.update(**{k: v for k, v in result.items() if k != 'status'})
        runner.results['status'] = result['status']
        (out/'verified_evidence.json').write_text(json.dumps(runner.results, indent=2, ensure_ascii=False)+'\n')
        (EVIDENCE/'memcpy_special_latest.json').write_text(json.dumps(
            dict(evidence=str((out/'verified_evidence.json').relative_to(ROOT))), indent=2)+'\n')
        print('PASS', out)
        for r in rows:
            print(' ', r['name'], r['target'], 'len', r['length'], 'insn', r['instructions'])
    except BaseException as exc:
        runner.results.update(status='FAIL', error=repr(exc))
        (out/'verified_evidence.json').write_text(json.dumps(runner.results, indent=2)+'\n')
        raise


if __name__ == '__main__':
    main()
