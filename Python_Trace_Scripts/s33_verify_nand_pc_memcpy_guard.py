#!/usr/bin/env python3
"""Execute the original guarded memcpy 0x128C20 with the GNU engine; template 0x35BB04 and extension canaries.

Refines the earlier "pool 333B78" reading: 0x35BB04 is a 16-byte all-zero template
inside payload0's tail, copied to caller destinations by the tratto at 0x333968.
0x128C20 validates the destination range ((r0+len<=0xAD800) or r0>=0xBB534),
self-loops on the forbidden zone, flags ranges touching [0x423900,0x428600).
Original bytes only; fixtures are mapfiles. No firmware or GNU modification.
"""
from datetime import datetime, timezone
from pathlib import Path
from types import SimpleNamespace
import json, struct, sys

from s33_run_gnu_arc700 import ROOT, LEGACY, TOOLCHAIN, Runner, sha
from s33_verify_gnu_dsp_lab import compile_probe
sys.path.insert(0, str(ROOT/'S33-sections/analysis_codex'))
from static_common import BS, PS, disasm

MEMCPY = 0x128c20
TEMPLATE = 0x35bb04
CALLER = 0x333968
EXTENSION = (0x35bc00, 0x35ce00)
FORBIDDEN_LO, WRITABLE_FLOOR = 0xad800, 0xbb534
SPECIAL_LO, SPECIAL_HI = 0x423900, 0x428600
SCRATCH, SOURCE = 0x35d000, 0x35e000
PATTERN = bytes((0x10+i*7) & 0xff for i in range(64))
EVIDENCE = ROOT/'Risultati/USB_SCSI/Accesso_NAND_PC'


def main():
    out = EVIDENCE/datetime.now(timezone.utc).strftime('memcpy_guard_cpu_%Y%m%dT%H%M%SZ')
    runner = Runner(SimpleNamespace(legacy_root=LEGACY, toolchain=TOOLCHAIN, output=out,
                                    action='original-guarded-memcpy-and-extension-canaries'))
    runner.prepare()
    try:
        payload0 = bytes(PS[0])
        base0 = BS[0]['load_address_candidate']
        assert base0 == 0xAD800 and len(payload0) == 0x2AE400
        assert payload0[TEMPLATE-base0:TEMPLATE-base0+16] == bytes(16), 'template non azzero inatteso'
        # The simulator attaches mapfiles in insertion order: keep regions ascending.

        def mmap(options, name, address, data):
            path = out/name; path.write_bytes(bytes(address % 8)+data)
            options.extend(['--memory-mapfile', '/result/'+name, '--memory-region', f'{address:#x},{len(data)}'])
            return path

        def execute(name, dst, src, length, content, *, low_region=False, fresh_payload=False,
                    extension_mode='intact'):
            """Run one case; returns its row. low_region maps [0xad700,0xad800) below payload0 first."""
            options = []
            low_path = None
            if low_region:
                low_path = mmap(options, name+'_low.bin', 0xad700, b'\xc3'*0x100)
            p0_path = mmap(options, name+'_payload0.bin', base0, payload0)
            extension = mmap(options, name+'_extension.bin', EXTENSION[0], b'\xa5'*(EXTENSION[1]-EXTENSION[0]))
            scratch = mmap(options, name+'_scratch.bin', SCRATCH, b'\xc3'*0x1000)
            mmap(options, name+'_source.bin', SOURCE, PATTERN+bytes(0x100))
            assembly = (f' mov r0,{dst:#x}\n mov r1,{src:#x}\n mov r2,{length}\n'
                        f' mov r12,{MEMCPY:#x}\n jl [r12]\n mov r0,0\n mov r8,1\n trap_s 1\n')
            elf = compile_probe(runner, name, assembly)
            case, log = runner.run(name, '/result/'+elf.name, options, trace=False)
            assert case['exit_code'] == 0 and case['fault'] is None, log
            into_payload0 = base0 <= dst < base0+len(payload0)
            if not into_payload0:
                assert p0_path.read_bytes()[base0 % 8:] == payload0, name+': immagine payload0 alterata da una lettura'
            ext = extension.read_bytes()[EXTENSION[0] % 8:]
            if extension_mode == 'intact':
                assert ext == b'\xa5'*(EXTENSION[1]-EXTENSION[0]), name+': estensione alterata'
                ext_result = 'intact'
            else:
                want = bytearray(b'\xa5'*(EXTENSION[1]-EXTENSION[0]))
                want[dst-EXTENSION[0]:dst-EXTENSION[0]+length] = content[:length]
                assert ext == bytes(want), name+': scrittura estensione non delimitata'
                ext_result = f'exactly {length} bytes inside'
            if into_payload0:  # destination inside the payload0 image itself (0xBB534 boundary)
                observed = p0_path.read_bytes()[base0 % 8:]
                want = bytearray(payload0)
                want[dst-base0:dst-base0+length] = content[:length]
                assert observed == bytes(want), name+': copia dentro payload0 non delimitata'
                dest_result = 'exactly-16-bytes-inside-payload0-image'
            elif EXTENSION[0] <= dst < EXTENSION[1]:
                observed = scratch.read_bytes()[SCRATCH % 8:]
                assert observed == b'\xc3'*0x1000, name+': scratch toccata con destinazione in estensione'
                dest_result = 'inside-extension-already-validated'
            elif low_region:
                observed = low_path.read_bytes()[0xad700 % 8:]
                want = bytearray(b'\xc3'*0x100)
                want[dst-0xad700:dst-0xad700+length] = content[:length]
                assert observed == bytes(want), name+': copia regione bassa non delimitata'
                dest_result = 'exactly-copied-below-payload0'
            else:
                observed = scratch.read_bytes()[SCRATCH % 8:]
                want = bytearray(b'\xc3'*0x1000)
                want[dst-SCRATCH:dst-SCRATCH+length] = content[:length]
                assert observed == bytes(want), name+': copia scratch non delimitata'
                dest_result = 'exactly-copied-bounded'
            return dict(name=name, dest=hex(dst), src=hex(src), length=length,
                        exit_code=case['exit_code'], instructions=case['instructions'],
                        extension=ext_result, destination=dest_result)

        rows = []
        # 1. The real neighborhood call: 16 zero bytes from the original template.
        rows.append(execute('template_copy_16', SCRATCH, TEMPLATE, 16, bytes(16)))
        # 2. Non-zero pattern proves real transport (aligned and unaligned destinations).
        rows.append(execute('pattern_copy_16', SCRATCH+4, SOURCE, 16, PATTERN))
        rows.append(execute('pattern_copy_3', SCRATCH+2, SOURCE, 3, PATTERN[:3]))
        # 3. Upper guard boundary: first writable destination at 0xBB534 (inside payload0 image).
        rows.append(execute('boundary_bb534', WRITABLE_FLOOR, SOURCE, 16, PATTERN))
        # 4. Lower guard boundary, inclusive: r0+len == 0xAD800 is still allowed.
        rows.append(execute('boundary_last_below', 0xad800-16, SOURCE, 16, PATTERN, low_region=True))
        # 5. Honest negative: the guard ALLOWS the extension as destination (exactly 16 bytes).
        rows.append(execute('copy_into_extension', 0x35bd00, SOURCE, 16, PATTERN, extension_mode='write'))
        # 6. Forbidden destination inside the payload0 image: self-loop at 0x128c3c, no progress.
        options = []
        p0_path = mmap(options, 'guard_forbidden_payload0.bin', base0, payload0)
        mmap(options, 'guard_forbidden_extension.bin', EXTENSION[0], b'\xa5'*(EXTENSION[1]-EXTENSION[0]))
        mmap(options, 'guard_forbidden_source.bin', SOURCE, PATTERN+bytes(0x100))
        assembly = (f' mov r0,{FORBIDDEN_LO+0x200:#x}\n mov r1,{SOURCE:#x}\n mov r2,16\n'
                    f' mov r12,{MEMCPY:#x}\n jl [r12]\n mov r0,0\n mov r8,1\n trap_s 1\n')
        elf = compile_probe(runner, 'guard_forbidden_low', assembly)
        cmd = ['podman', 'run', '--rm', '--network', 'none', '--memory', '2g',
               '--volume', f'{LEGACY}:/work:ro', '--volume', f'{out}:/result:rw',
               'localhost/arc700-legacy:gcc10', 'timeout', '10s', '/work/install/bin/arc-elf32-run']
        p = runner.command('guard_forbidden_low', cmd+options+['-v', '/result/'+elf.name])
        assert p.returncode == 124, (p.returncode, p.stdout[-400:])
        assert p0_path.read_bytes()[base0 % 8:] == payload0, 'destinazione vietata: payload0 modificato'
        assert (out/'guard_forbidden_extension.bin').read_bytes()[EXTENSION[0] % 8:] == b'\xa5'*(EXTENSION[1]-EXTENSION[0])
        rows.append(dict(name='guard_forbidden_low', dest=hex(FORBIDDEN_LO+0x200), src=hex(SOURCE), length=16,
                         exit_code=124, outcome='self-loop non-progress, zero byte scritti',
                         note='il codice originale si blocca intenzionalmente su destinazione vietata'))

        windows = [(MEMCPY, 0x128dac), (CALLER, 0x333980), (0x32f410, 0x32f428), (0x32f4c0, 0x32f4d8), (0x32f570, 0x32f588)]
        (out/'gnu_verified.txt').write_text('\n'.join(disasm(a, b) for a, b in windows))
        assert all(sha(Path(path)) == digest for path, digest in runner.input_hashes.items())
        result = dict(status='PASS_ORIGINAL_GUARDED_MEMCPY_TEMPLATE_EXTENSION',
                      memcpy_cpu=hex(MEMCPY), template_cpu=hex(TEMPLATE), caller_cpu=hex(CALLER),
                      template_bytes=payload0[TEMPLATE-base0:TEMPLATE-base0+16].hex(),
                      guard=dict(allowed='(r0+len <= 0xAD800) or (r0 >= 0xBB534)',
                                 forbidden='0xAD800 <= r0 < 0xBB534, or r0 < 0xAD800 with r0+len > 0xAD800',
                                 forbidden_behavior='self-loop at 0x128c3c (deliberate non-progress, timeout 124)',
                                 special_flag_region=[hex(SPECIAL_LO), hex(SPECIAL_HI)],
                                 extension_is_allowed_destination=True),
                      cases=rows,
                      reinterpretation=('0x333B78 -> 0x35BB04 e un template di 16 byte a zero nella coda di payload0, '
                                        'copiato come sorgente dalla routine 0x333968 (r2=16): non un pool che cresce verso l\'estensione'),
                      sources={str(p): sha(p) for p in [Path(__file__), ROOT/'OriginalSoftware_NikonS33_V1.1/firmware.bin']},
                      assumptions=['Original payload0 image mapped at 0xAD800; scratch/source/extension are mapfiles',
                                   'The driver calls the original 0x128C20 bytes; no candidate code executed',
                                   'Scratch 0x35D000 and source 0x35E000 are inside the payload0..payload1 gap above the extension'],
                      limits=['Only 0x128C20 and the shown caller executed; not all copy services or callers',
                              'Special-region branches 0x32F410/0x32F4C0/0x32F570 are static windows, not executed',
                              'The guard permits extension destinations: it bounds each copy, does not reserve the area',
                              'No DMA, cache or computed-pointer proof; candidate NON_INSTALLARE unchanged'])
        runner.results.update(**{k: v for k, v in result.items() if k != 'status'})
        runner.results['status'] = result['status']
        (out/'verified_evidence.json').write_text(json.dumps(runner.results, indent=2, ensure_ascii=False)+'\n')
        (EVIDENCE/'memcpy_guard_latest.json').write_text(json.dumps(
            dict(evidence=str((out/'verified_evidence.json').relative_to(ROOT))), indent=2)+'\n')
        print('PASS', out)
        for r in rows:
            print(' ', r['name'], r.get('destination', r.get('outcome')), 'ext:', r['extension'] if 'extension' in r else '-')
    except BaseException as exc:
        runner.results.update(status='FAIL', error=repr(exc))
        (out/'verified_evidence.json').write_text(json.dumps(runner.results, indent=2)+'\n')
        raise


if __name__ == '__main__':
    main()
