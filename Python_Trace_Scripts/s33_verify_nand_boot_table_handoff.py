#!/usr/bin/env python3
"""Reconstruct supplied NAND boot blocks and verify the P1IDSTR -> TBIB contract.

NAND transfers are reconstructed from files, not executed against a fake NAND
controller. Separate CPU cases run original helper code and the original
post-transfer checksum/handoff tail with explicitly supplied laboratory state.
"""
from pathlib import Path
from types import SimpleNamespace
from datetime import datetime, timezone
import json
import re
import struct

from s33_run_gnu_arc700 import ROOT, LEGACY, TOOLCHAIN, Runner, sha
from s33_verify_gnu_dsp_lab import compile_probe

BASE = 0xf800000
WINDOWS = [(0x350, 0x37a), (0x6ac, 0x7ec), (0x1140, 0x1258),
           (0x127c, 0x12be), (0x13c8, 0x14b0), (0x1d24, 0x1e3c)]


def main():
    out = ROOT / 'Risultati/Dump_fotocamera/NAND_Loader' / datetime.now(timezone.utc).strftime('%Y%m%dT%H%M%SZ')
    r = Runner(SimpleNamespace(legacy_root=LEGACY, toolchain=TOOLCHAIN, output=out,
                              action='nand-p1idstr-boot-blocks-and-post-transfer-handoff'))
    print('Evidence:', r.out, flush=True)
    try:
        r.prepare()
        r.results['assumptions'] = ['BootNAND base0F800000 candidate from internal absolute references',
            'Post-transfer memory image reconstructed from supplied NANDP1, not NAND-controller emulation',
            'Synthetic caller/stack and P1IDSTR pointer, direct entry after transfer at0F801444',
            'Helpers use original GNU engine; no laboratory MMIO return values supplied']
        r.results['limits'] = ['Not a full NAND/ROM/BootNAND boot, ECC/remap or hardware capacity test',
            '24 table copies in the export are not proof of24 independently recoverable NAND copies',
            'Only selected BootCode blocks are reconstructed; complete MainCode/Reserved NAND mapping remains open',
            'Handoff CPU case starts after transfer and stops on the first unprovided TBIB stack write']
        previous = ROOT / json.loads((ROOT / 'Risultati/Dump_fotocamera/BootNAND_ID/latest.json').read_text())['evidence']
        evidence = json.loads(previous.read_text())
        assert evidence['status'] == 'PASS_BOOTNAND_ID_ARITHMETIC_AND_CHECKSUM'
        for path, checksum in evidence['input_hashes'].items():
            assert sha(Path(path)) == checksum, path
            r.input_hashes[path] = checksum
        r.input_hashes[str(previous)] = sha(previous)
        boot = (ROOT / 'DUMPS/BootNANDBase.dmp').read_bytes()
        nand = (ROOT / 'DUMPS/NANDP1.dmp').read_bytes()
        boot_export = (ROOT / 'DUMPS/BootCode.dmp').read_bytes()
        config = nand[0x2100:0x2300]
        table_offsets = [b + j * 528 + 10 + k * 256
            for b in [0x2100, 0x2940, 0x3180, 0x39c0] for j in (1, 2, 3) for k in (0, 1)]
        table = nand[table_offsets[0]:table_offsets[0] + 244]
        assert table[:8] == table[-8:] == b'P1IDSTR\0'
        assert all(nand[o:o + 244] == table for o in table_offsets)
        assert len(set(table_offsets)) == 24
        page_shift = struct.unpack_from('<I', config, 88)[0]
        block_bytes = struct.unpack_from('<I', config, 92)[0]
        assert (page_shift, block_bytes) == (6, 0x20000)
        assert struct.unpack_from('<I', config, 84)[0] == 1 << page_shift == 64
        load, length, checksum, entry = struct.unpack_from('<4I', table, 180)
        assert (load, length, checksum, entry) == struct.unpack_from('<4I', boot_export)
        assert (load, length, checksum, entry) == (0x1000000, 0x44bbc, 0xf3f78173, 0x1000000)
        block_count = (length + 32 + block_bytes - 1) // block_bytes
        assert block_count == 3
        block_ids = list(struct.unpack_from(f'<{block_count}H', table, 8))
        assert block_ids == [1, 2, 3]
        segments = []
        loaded = bytearray()
        for block_id in block_ids:
            first_record = block_id << page_shift
            data = b''.join(nand[i * 2112:i * 2112 + 2048]
                            for i in range(first_record, first_record + (1 << page_shift)))
            assert len(data) == block_bytes
            segments.append(dict(block_id=block_id, first_record=first_record,
                raw_file_offset=hex(first_record * 2112), records=1 << page_shift,
                guest_destination=hex(load - 16 + len(loaded)), bytes=len(data)))
            loaded.extend(data)
        assert bytes(loaded) == boot_export
        assert sum(struct.unpack_from(f'<{length // 4}I', loaded, 16)) & 0xffffffff == checksum
        assert load - 16 == 0xfffff0 and len(loaded) == 0x60000
        (out / 'bootnand_mmap.bin').write_bytes(boot)
        (out / 'bootcode_reconstructed.bin').write_bytes(loaded)
        (out / 'p1idstr_mmap.bin').write_bytes(table)
        (out / 'bfn_input.bin').write_bytes(config)
        (out / 'expected_signature.bin').write_bytes(b'P1IDSTR\0')
        tools = ROOT / 'work/build-arc/binutils'
        for name in ('objcopy', 'objdump'):
            r.input_hashes[str(tools / name)] = sha(tools / name)
        elf = out / 'bootnand_candidate_base.elf'
        p = r.command('bootnand_elf', [tools / 'objcopy', '-I', 'binary', '-O', 'elf32-littlearc', '-B', 'arc',
            '--rename-section', '.data=.text,alloc,load,readonly,code,contents',
            '--change-section-vma', f'.data={BASE:#x}', '--strip-all', out / 'bootnand_mmap.bin', elf])
        assert p.returncode == 0
        listings = []
        instructions = {}
        for i, (a, b) in enumerate(WINDOWS):
            p = r.command(f'gnu_window_{i}', [tools / 'objdump', '-d', '-m', 'arc:ARC700', '-EL',
                f'--start-address={BASE+a:#x}', f'--stop-address={BASE+b:#x}', elf])
            assert p.returncode == 0 and 'out of bounds' not in p.stdout.lower()
            listings.append(p.stdout.replace(str(elf), 'bootnand_candidate_base.elf'))
            for line in p.stdout.splitlines():
                m = re.match(r'\s*([0-9a-f]+):\t([^\t]+)\t(\S+)(?:\t(.*))?$', line)
                if m:
                    instructions[int(m[1], 16)-BASE] = (m[3], (m[4] or '').strip())
        (out / 'gnu_verified.txt').write_text('\n'.join(listings))

        def ins(pc, mn, op):
            actual = instructions[pc]
            assert actual[0] == mn and actual[1].split('\t;')[0] == op, (hex(pc), actual)

        # The stored string guards a244-byte table, not a raw NAND-wide checksum.
        ins(0x744, 'mov', 'lp_count,0x5')
        ins(0x76c, 'mov', 'lp_count,122')
        ins(0x790, 'sth.ab', 'r0,[r13,2]')
        ins(0x7a0, 'add2', 'r0,r14,0x3b')  # table +236 for final signature
        ins(0x11a8, 'ld', 'r16,[r13,88]')
        ins(0x11ac, 'ld', 'r24,[r13,92]')
        ins(0x1224, 'ld', 'r15,[r23,180]')
        ins(0x1228, 'sub_s', 'r15,r15,0x10')
        ins(0x1230, 'ld', 'r1,[r23,184]')
        ins(0x1234, 'sub', 'r0,r24,0x1')
        ins(0x123e, 'add_s', 'r1,r1,0x20')
        ins(0x1240, 'add_s', 'r0,r0,r1')
        ins(0x127c, 'add', 'r1,r23,0x8')
        ins(0x1280, 'ldh.as', 'r1,[r1,r17]')
        ins(0x1284, 'asl', 'r1,r1,r16')
        ins(0x1422, 'asl', 'r0,r21,0xb')
        ins(0x142a, 'add_s', 'r15,r15,r0')
        ins(0x1444, 'ld', 'r0,[r23,180]')
        ins(0x1448, 'ld', 'r1,[r23,184]')
        ins(0x144c, 'ld', 'r14,[r23,188]')
        ins(0x1454, 'ld', 'r13,[r23,192]')
        ins(0x14a4, 'sr', '0xfc00000,[0x18]')
        ins(0x14ac, 'j', '[r13]')
        assert instructions[0x1450][1].endswith(f';{hex(BASE+0x148c)}')
        assert instructions[0x148c][1].endswith(f';{hex(BASE+0x350)}')
        assert instructions[0x1490][1].endswith(f';{hex(BASE+0x14a4)}')
        byte_line = lambda data: ' .byte ' + ','.join(f'0x{v:02x}' for v in data) + '\n'
        # Copy only non-PC-relative original field loads/arithmetic to a synthetic caller.
        fields = boot[0x1444:0x1450] + boot[0x1454:0x1458]
        arithmetic = boot[0x1230:0x1238] + boot[0x123e:0x1242] + boot[0x1246:0x1248]
        asm = ' mov r20,0\n mov r23,0x18000\n'
        for pointer, good in [(0x18000, True), (0x180ec, True), (0x18000, False), (0x180ec, False)]:
            if not good:
                asm += f' mov r0,{pointer:#x}\n mov r1,0x51\n stb r1,[r0]\n'
            asm += (f' mov r0,{pointer:#x}\n mov r1,0x1a000\n mov r12,0xf8006ac\n jl [r12]\n'
                    + ' cmp r0,0\n' + (' bne fail\n' if good else ' beq fail\n')
                    + ' add r20,r20,1\n')
            if not good:
                asm += f' mov r0,{pointer:#x}\n mov r1,0x50\n stb r1,[r0]\n'
        asm += (' mov r0,0x19000\n ld r24,[r0,92]\n' + byte_line(arithmetic)
                + ' mov r12,0xf801d24\n jl [r12]\n cmp r0,3\n bne fail\n add r20,r20,1\n')
        asm += byte_line(fields)
        asm += (' cmp r0,0x1000000\n bne fail\n cmp r1,0x44bbc\n bne fail\n'
                ' cmp r14,0xf3f78173\n bne fail\n cmp r13,0x1000000\n bne fail\n'
                ' mov r12,0xf800350\n jl [r12]\n cmp r0,r14\n bne fail\n'
                ' add r20,r20,1\n cmp r20,6\n bne fail\n mov r0,0\n b finish\n'
                'fail:\n mov r0,7\nfinish:\n mov r8,1\n trap_s 1\n')
        options = ['--memory-mapfile', '/result/bootnand_mmap.bin', '--memory-region', '0xf800000,0x2000',
            '--memory-mapfile', '/result/bootcode_reconstructed.bin', '--memory-region', '0xfffff0,0x60000',
            '--memory-mapfile', '/result/p1idstr_mmap.bin', '--memory-region', '0x18000,244',
            '--memory-mapfile', '/result/bfn_input.bin', '--memory-region', '0x19000,512',
            '--memory-mapfile', '/result/expected_signature.bin', '--memory-region', '0x1a000,8']
        helper_elf = compile_probe(r, 'table_helpers', asm)
        case, log = r.run('table_helpers', f'/result/{helper_elf.name}', options, trace=True)
        assert case['exit_code'] == 0 and case['fault'] is None, log
        trace = (out/'table_helpers.trace').read_text()
        for target in (0xf8006ac, 0xf801d24, 0xf800350):
            assert f'0x{target:x}' in trace
        assert not re.search(r'\b(?:ld|st)\w*\.di\b', trace)
        case.update(signature_cases=4, loader_block_count_cases=1, complete_tbib_checksum_cases=1, mmio_executed=False)
        # Execute the real post-transfer tail through its real TBIB entry. All
        # earlier controller/clock/DDR/ROM work is explicitly outside this case.
        handoff_elf = compile_probe(r, 'post_transfer_handoff',
            ' mov r23,0x18000\n mov r25,0\n mov r12,0xf801444\n j [r12]\n')
        handoff, log = r.run('post_transfer_handoff', f'/result/{handoff_elf.name}', options, trace=True)
        assert handoff['exit_code'] == 11 and handoff['fault'] is not None, log
        trace = (out/'post_transfer_handoff.trace').read_text()
        for target in (0xf801444, 0xf80148c, 0xf8014a4, 0xf8014ac, 0x1000000):
            assert f'0x{target:x}' in trace
        assert not re.search(r'\b(?:ld|st)\w*\.di\b', trace)
        assert handoff['fault'] == dict(size=4, operation='write', address='0x10d7158', pc='0x103ae88'), handoff
        handoff.update(started_after_nand_transfer=True, original_tbib_entry_reached=True,
                       full_boot=False, physical_handoff_observed=False)
        print('Handoff stop:', handoff['fault'], flush=True)
        for name, data in [('bootnand_mmap.bin', boot), ('bootcode_reconstructed.bin', bytes(loaded)),
            ('p1idstr_mmap.bin', table), ('bfn_input.bin', config), ('expected_signature.bin', b'P1IDSTR\0')]:
            assert (out/name).read_bytes() == data, name
        (out/'verifier_snapshot.py').write_bytes(Path(__file__).read_bytes())
        (out/'block_mapping.json').write_text(json.dumps(dict(segments=segments,
            metadata=dict(load=hex(load), bytes=length, checksum=hex(checksum), entry=hex(entry)),
            pages_per_block=64, data_bytes_per_page=2048, exported_record_stride=2112,
            formula_block_count='ceil((body_length+32)/block_bytes)', load_including_header=hex(load-16),
            table_copies=[hex(o) for o in table_offsets], table_bytes=244,
            complete_bootcode_match=True),indent=2)+'\n')
        r.results.update(status='PASS_NAND_BOOT_TABLE_AND_CONDITIONAL_HANDOFF',
            previous_evidence=str(previous.relative_to(ROOT)), table_copies=24, table_bytes=244,
            signature_checks='P1IDSTR at offsets0 and236', gnu_windows=len(WINDOWS),
            blocks=block_ids, reconstructed_bytes=len(loaded), matches_entire_bootcode_export=True,
            tbib_body_bytes=length, tbib_load_address=hex(load), tbib_entry=hex(entry),
            tbib_checksum=hex(checksum), conditional_handoff_reached_tbib=True,
            transfer_execution_simulated=False, full_boot=False)
        r.finish()
    except Exception as exc:
        r.results.update(status='FAIL', error=repr(exc))
        raise
    finally:
        r.save()
    (out.parent/'latest.json').write_text(json.dumps(dict(evidence=str((out/'verified_evidence.json').relative_to(ROOT))),indent=2)+'\n')
    print('PASS:24 P1IDSTR copies;3 NAND blocks reconstruct all BootCode bytes; conditional original tail reaches TBIB;',out)


if __name__ == '__main__':
    main()
