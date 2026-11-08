#!/usr/bin/env python3
"""Verify supplied BootNAND DDR-ID arithmetic and BFN checksum, entirely offline.

GNU/source trees are read only. No boot, MMIO response or memory capacity test
is executed: the CPU probe runs six relocated original arithmetic/load
instructions and the original checksum helper against laboratory data.
"""
from pathlib import Path
from types import SimpleNamespace
from datetime import datetime, timezone
import hashlib
import json
import re
import struct

from s33_run_gnu_arc700 import ROOT, LEGACY, TOOLCHAIN, Runner, sha
from s33_verify_gnu_dsp_lab import compile_probe

BASE = 0x0f800000  # candidate supported by internal absolute self references
WINDOWS = [(0, 0x108), (0x350, 0x37a), (0x478, 0x4d4),
           (0xa54, 0xb12), (0x1018, 0x1140), (0x15dc, 0x1678), (0x1d20, 0x1d24)]
IDS = [0, 1, 0x10, 0x20, 0x80, 0xff, 0x100, 0x110, 0x120, 0x180, 0x1ff, 0xffffffff]


def digest(data):
    return hashlib.sha256(data).hexdigest()


def memory_test_sites(bound):
    """Static projection of the verified loop, for positive bounds only."""
    assert bound > 0
    address = 0
    result = []
    while True:
        if address != 0x08000000:
            result.append(address)
            if address == 0x0f700000:
                break
        address += 0x100000
        if address >= bound:
            break
    return result


def main():
    out = ROOT / 'Risultati/Dump_fotocamera/BootNAND_ID' / datetime.now(timezone.utc).strftime('%Y%m%dT%H%M%SZ')
    r = Runner(SimpleNamespace(legacy_root=LEGACY, toolchain=TOOLCHAIN, output=out,
                              action='supplied-bootnand-ddr-id-and-checksum'))
    print('Evidence:', r.out, flush=True)
    try:
        r.prepare()  # existing read-only input/tool validation, outputs only under r.out
        r.results['assumptions'] = ['Candidate BootNAND base 0x0F800000 from internal absolute references',
            'Six original instructions relocated to laboratory caller; data pointer initialized by test',
            'GNU default RAM supplies laboratory stack; no physical reset context assumed']
        r.results['limits'] = ['No full BootNAND/DDR/MMIO execution or hardware access',
            '256 MiB is the configured test bound for ID0x120, not certified usable physical RAM',
            'Sparse memory-test sites are a static loop projection; no real RAM write performed',
            'No NAND ECC, selection of copies, ROM loading or recovery validation']
        previous = json.loads((ROOT / 'Risultati/Dump_fotocamera/BFN_NAND/latest.json').read_text())
        bfn_evidence = ROOT / previous['evidence']
        verified = json.loads(bfn_evidence.read_text())
        assert verified['status'] == 'PASS_BFN_NAND_EXPORT_STATIC_CORRELATION'
        for name, info in verified['unchanged_inputs'].items():
            p = ROOT / 'DUMPS' / name
            assert sha(p) == info['sha256'], name
            r.input_hashes[str(p)] = info['sha256']
        r.input_hashes[str(bfn_evidence)] = sha(bfn_evidence)
        boot_path = ROOT / 'DUMPS/BootNANDBase.dmp'
        boot = boot_path.read_bytes()
        assert len(boot) == 8192
        assert digest(boot) == '44c849a4ab69d9e9e010602887293eda1fb19dfcfa22d1f7f4bcfba7a166bd65'
        nand = (ROOT / 'DUMPS/NANDP1.dmp').read_bytes()
        assert boot == b''.join(nand[i:i + 512] for i in range(0, 16 * 528, 528))
        page = nand[0x2100:0x2300]
        assert len(page) == 512
        expected_sum = sum(struct.unpack_from('<108I', page, 80)) & 0xffffffff
        assert expected_sum == struct.unpack_from('<I', page, 76)[0] == 0x5a97d
        assert struct.unpack_from('<I', page, 196)[0] == 0x120
        mapped = r.out / 'bootnand_mmap.bin'
        config = r.out / 'configuration_mmap.bin'
        mapped.write_bytes(boot)
        config.write_bytes(page)
        (r.out / 'configuration_input.bin').write_bytes(page)
        tools = ROOT / 'work/build-arc/binutils'
        for name in ('objcopy', 'objdump'):
            r.input_hashes[str(tools / name)] = sha(tools / name)
        elf, back = r.out / 'bootnand_candidate_base.elf', r.out / 'bootnand_roundtrip.bin'
        p = r.command('bootnand_elf', [tools / 'objcopy', '-I', 'binary', '-O', 'elf32-littlearc', '-B', 'arc',
            '--rename-section', '.data=.text,alloc,load,readonly,code,contents',
            '--change-section-vma', f'.data={BASE:#x}', '--strip-all', boot_path, elf])
        assert p.returncode == 0
        p = r.command('bootnand_roundtrip', [tools / 'objcopy', '--dump-section', f'.text={back}', elf])
        assert p.returncode == 0 and back.read_bytes() == boot
        instructions = {}
        listings = []
        for i, (a, b) in enumerate(WINDOWS):
            p = r.command(f'gnu_window_{i}', [tools / 'objdump', '-d', '-m', 'arc:ARC700', '-EL',
                f'--start-address={BASE + a:#x}', f'--stop-address={BASE + b:#x}', elf])
            assert p.returncode == 0 and 'out of bounds' not in p.stdout.lower()
            listings.append(p.stdout.replace(str(elf), 'bootnand_candidate_base.elf'))
            for line in p.stdout.splitlines():
                m = re.match(r'\s*([0-9a-f]+):\t([^\t]+)\t(\S+)(?:\t(.*))?$', line)
                if m:
                    instructions[int(m[1], 16) - BASE] = (m[3], (m[4] or '').strip())
        (r.out / 'gnu_verified.txt').write_text('\n'.join(listings))

        def ins(pc, mnemonic, operand):
            actual = instructions[pc]
            assert actual[0] == mnemonic and actual[1].split('\t;')[0] == operand, (hex(pc), actual)

        # Candidate base: verify actual absolute references, not a guessed file load address.
        ins(0x20, 'mov', 'gp,0xf801e3c')
        assert boot[0x1fe0:0x1fed] == b'BootFromNAND\0'
        # Runtime pointer is read from AUX18, NOT hard-coded to candidate_base + 0x2000.
        ins(0x15e8, 'lr', 'r14,[0x18]')
        ins(0x1636, 'mov_s', 'r0,r14')
        ins(0x1652, 'mov_s', 'r0,r14')
        assert instructions[0x1632][1].endswith(f';{hex(BASE + 0x478)}')
        assert instructions[0x164e][1].endswith(f';{hex(BASE + 0x109c)}')
        ins(0x1d20, 'j_s.d', '[blink]')
        ins(0x1d22, 'mov_s', 'r0,0x1')
        # Reader: 256 halfwords; checksum word at +76, sum of 432 bytes from +80.
        ins(0x480, 'mov', 'lp_count,256')
        ins(0x49a, 'mov_s', 'r0,0xffca010')
        ins(0x4a0, 'ldh.di', 'r0,[r0]')
        ins(0x4a4, 'sth.ab', 'r0,[r14,2]')
        ins(0x4a8, 'ld_s', 'r14,[r13,0x4c]')
        ins(0x4aa, 'add3', 'r0,r13,0xa')
        ins(0x4b2, 'mov', 'r1,432')
        ins(0x4b6, 'breq', 'r14,r0,22')
        assert instructions[0x4b6][1].endswith(f';{hex(BASE + 0x4ca)}')
        # ID uses: low byte gives test bound, bit8 selects a controller branch.
        for pc, mn, op in [(0x10a4, 'ld', 'r13,[r0,196]'), (0x10ea, 'extb_s', 'r13,r13'),
            (0x10f2, 'asl_s', 'r13,r13,0x17'), (0x1104, 'mov_s', 'r0,r13'),
            (0xa6a, 'ld', 'r0,[r0,196]'), (0xa74, 'and', 'r0,r0,256'),
            (0xa78, 'lsr', 'r17,r0,0x8'), (0xae8, 'mov_s', 'r0,r17'),
            (0xaea, 'sth.di', 'r0,[r1]')]:
            ins(pc, mn, op)
        assert instructions[0x1100][1].endswith(f';{hex(BASE + 0x1018)}')
        ins(0x1038, 'mov_s', 'r13,0')
        ins(0x104e, 'st_s', 'r1,[r13,0]')
        ins(0x1050, 'st_s', 'r0,[r13,0x4]')
        ins(0x108a, 'add_s', 'r13,r13,0x100000')
        assert instructions[0x103a][1].endswith(f';{hex(BASE + 0x108a)}')
        assert 'r13,0x8000000,' in instructions[0x103a][1]
        assert 'r13,0xf700000,' in instructions[0x1082][1]
        assert instructions[0x1082][1].endswith(f';{hex(BASE + 0x1094)}')
        assert instructions[0x1090][1].endswith(f';{hex(BASE + 0x103a)}')
        assert instructions[0x1090][1].startswith('r13,r14,')

        # Execute exact original bytes for arithmetic; surrounding setup/assertions are synthetic.
        size_bytes = boot[0x10a4:0x10a8] + boot[0x10ea:0x10ec] + boot[0x10f2:0x10f4]
        mode_bytes = boot[0xa6a:0xa6e] + boot[0xa74:0xa7c]
        byte_line = lambda data: ' .byte ' + ','.join(f'0x{v:02x}' for v in data) + '\n'
        asm = ' mov r20,0\n'
        arithmetic = []
        for i, ident in enumerate(IDS):
            bound, mode = ((ident & 255) << 23) & 0xffffffff, (ident >> 8) & 1
            asm += (f' mov r0,0x18000\n mov r1,{ident:#x}\n st r1,[r0,196]\n' + byte_line(size_bytes)
                + f' mov r2,{bound:#x}\n cmp r13,r2\n bne fail\n mov r0,0x18000\n'
                + byte_line(mode_bytes) + f' cmp r17,{mode}\n bne fail\n add r20,r20,1\n')
            arithmetic.append(dict(id=hex(ident), configured_test_bound=hex(bound), controller_bit8=mode))
        # Original word has been changed by arithmetic probes; restore it before summing.
        asm += (' mov r0,0x18000\n mov r1,0x120\n st r1,[r0,196]\n'
                ' mov r0,0x18050\n mov r1,432\n mov r12,0xf800350\n jl [r12]\n'
                f' cmp r0,{expected_sum:#x}\n bne fail\n add r20,r20,1\n'
                ' mov r0,0x180a0\n ld r1,[r0]\n add r1,r1,1\n st r1,[r0]\n'
                ' mov r0,0x18050\n mov r1,432\n mov r12,0xf800350\n jl [r12]\n'
                f' cmp r0,{expected_sum + 1:#x}\n bne fail\n add r20,r20,1\n'
                f' cmp r20,{len(IDS) + 2}\n bne fail\n mov r0,0\n b finish\n'
                'fail:\n mov r0,7\nfinish:\n mov r8,1\n trap_s 1\n')
        probe = compile_probe(r, 'ddr_id_and_checksum', asm)
        case, log = r.run('ddr_id_and_checksum', f'/result/{probe.name}',
            ['--memory-mapfile', '/result/bootnand_mmap.bin', '--memory-region', f'{BASE:#x},0x2000',
             '--memory-mapfile', '/result/configuration_mmap.bin', '--memory-region', '0x18000,512'],
            trace=True, extract=True)
        assert case['exit_code'] == 0 and case['fault'] is None, log
        assert 'runtime error:' not in log
        trace = (r.out / 'ddr_id_and_checksum.trace').read_text()
        assert f'0x{BASE + 0x350:x}' in trace
        assert not re.search(r'\b(?:ld|st)\w*\.di\b', trace), 'Probe must not execute MMIO loads/stores'
        case.update(arithmetic_id_cases=len(IDS), original_checksum_cases=2, original_checksum_helper=hex(BASE + 0x350),
                    mmio_executed=False, complete_boot_executed=False)
        sites = memory_test_sites(0x10000000)
        assert len(sites) == 247 and sites[0] == 0 and sites[-1] == 0xf700000
        assert 0x08000000 not in sites and 0x08100000 in sites
        assert len(memory_test_sites(0x08000000)) == 128
        assert len(memory_test_sites(0x00100000)) == 1
        (r.out / 'memory_test_static_sites.json').write_text(json.dumps(dict(
            configured_bound=hex(0x10000000), method='Static control-flow projection; NOT CPU/hardware memory test',
            stride=hex(0x100000), skipped_site=hex(0x8000000), stop_after_site=hex(0xf700000),
            sites=[dict(address=hex(a), word_addresses=[hex(a), hex(a+4)]) for a in sites],
            bytes_per_site=8, total_sparse_bytes=1976), indent=2) + '\n')
        (r.out / 'arithmetic_cases.json').write_text(json.dumps(arithmetic, indent=2) + '\n')
        (r.out / 'verifier_snapshot.py').write_bytes(Path(__file__).read_bytes())
        (r.out / 'probe_builder_snapshot.py').write_bytes((ROOT / 'Python_Trace_Scripts/s33_verify_gnu_dsp_lab.py').read_bytes())
        # GNU mapfiles are shared mappings: guest stores update this laboratory
        # copy. The camera dump and preserved input copy remain read only.
        changed_page = bytearray(page)
        struct.pack_into('<I', changed_page, 0xa0, struct.unpack_from('<I', page, 0xa0)[0] + 1)
        assert mapped.read_bytes() == boot and config.read_bytes() == bytes(changed_page)
        assert (r.out / 'configuration_input.bin').read_bytes() == page
        r.results.update(status='PASS_BOOTNAND_ID_ARITHMETIC_AND_CHECKSUM',
            bootnand_sha256=digest(boot), previous_bfn_evidence=str(bfn_evidence.relative_to(ROOT)),
            candidate_boot_base=hex(BASE), runtime_configuration_pointer='AUX18, value not observed',
            gnu_windows=len(WINDOWS), original_bfn_checksum=hex(expected_sum),
            bfn_checksum_scope=dict(offset=80, bytes=432, stored_at=76, algorithm='sum of108 little-endian u32 modulo2^32'),
            ddr_id=hex(0x120), capacity_field_low8=32, configured_bound_bytes=268435456,
            configured_bound_mib=256, controller_mode_bit8=1, arithmetic_cases=len(IDS),
            checksum_cpu_cases=2, physical_capacity_certified=False, usable_ram_certified=False,
            memory_test_static_sites=247, memory_test_static_sparse_bytes=1976,
            laboratory_shared_map_mutation=dict(file='configuration_mmap.bin', offset=160, added_to_u32=1,
                preserved_input_file='configuration_input.bin', camera_dump_changed=False))
        r.finish()
    except Exception as exc:
        r.results.update(status='FAIL', error=repr(exc))
        raise
    finally:
        r.save()
    (out.parent / 'latest.json').write_text(json.dumps(dict(evidence=str((out / 'verified_evidence.json').relative_to(ROOT))), indent=2) + '\n')
    print('PASS: 12 CPU arithmetic cases, 2 original checksum executions; configured bound256MiB, hardware capacity not certified;', out)


if __name__ == '__main__':
    main()
