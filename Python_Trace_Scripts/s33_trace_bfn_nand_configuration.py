#!/usr/bin/env python3
"""Correlate BFN text, supplied NAND records and verified V1.1 exporter code.

Read only inputs/GNU tools; write timestamped evidence outside GNU trees.
This is static analysis, not execution of the NAND reader or DDR initialization.
"""
from pathlib import Path
from datetime import datetime, timezone
import hashlib
import json
import re
import struct
import sys

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / 'S33-sections/analysis_codex'))
from static_common import BS, ORIGINAL, EXPECTED, raw, u32, locate, disasm

WINDOWS = [(0x1ed440, 0x1ed5e4), (0x301f14, 0x301fcc),
           (0x300554, 0x300934), (0x3009d8, 0x300c9c)]
DDR_REG_OFFSETS = [0x18, 0x20, 0x80, 0x84, 0xf4, 0xf8, 0x100, 0x104, 0x134]
CLOCK_EXPORT_LOADS = [0x30083a, 0x30086a, 0x30089a, 0x3008ca,
                      0x3008fa, 0x30092a, 0x300a00, 0x300a30,
                      0x300a60, 0x300a90, 0x300ac0, 0x300aee,
                      0x300b1c, 0x300b4a, 0x300b78, 0x300ba6]


def sha(b):
    return hashlib.sha256(b).hexdigest()


def occurrences(data, needle):
    result = []
    start = 0
    while (i := data.find(needle, start)) >= 0:
        result.append(i)
        start = i + 1
    return result


def main():
    out = ROOT / 'Risultati/Dump_fotocamera/BFN_NAND' / datetime.now(timezone.utc).strftime('%Y%m%dT%H%M%SZ')
    out.mkdir(parents=True, exist_ok=False)
    latest = json.loads((ROOT / 'Risultati/Dump_fotocamera/latest.json').read_text())
    previous = ROOT / latest['evidence']
    catalog = json.loads(previous.read_text())
    inputs = {}
    for row in catalog['files']:
        p = ROOT / 'DUMPS' / row['file']
        b = p.read_bytes()
        assert sha(b) == row['sha256'], row['file']
        inputs[row['file']] = dict(bytes=len(b), sha256=sha(b))
    assert len(inputs) == 14 and sha(ORIGINAL.read_bytes()) == EXPECTED
    tools = {ROOT / 'work/build-arc/binutils' / n: sha((ROOT / 'work/build-arc/binutils' / n).read_bytes())
             for n in ('objcopy', 'objdump')}
    supplied = (ROOT / 'DUMPS/MainCode.dmp').read_bytes()
    spans = []

    def check_span(a, n):
        block, offset = locate(a, n)
        b = raw(a, n)
        assert supplied[block['offset'] + offset:block['offset'] + offset + n] == b
        spans.append(dict(address=hex(a), bytes=n, sha256=sha(b)))
        return b

    def pool(a):
        check_span(a, 4)
        return u32(a)

    def cstr(a):
        b = raw(a, 256).split(b'\0')[0]
        check_span(a, len(b) + 1)
        return b.decode('ascii')

    listings = []
    instructions = {}
    for a, b in WINDOWS:
        check_span(a, b - a)
        text = disasm(a, b)
        listings.append(text)
        for line in text.splitlines():
            m = re.match(r'\s*([0-9a-f]+):\t([^\t]+)\t(\S+)(?:\t(.*))?$', line)
            if m:
                instructions[int(m[1], 16)] = (m[3], (m[4] or '').strip())
    (out / 'gnu_verified.txt').write_text('\n'.join(listings))

    def instruction(pc, mnemonic, operand):
        actual = instructions[pc]
        assert actual[0] == mnemonic and actual[1].split('\t;')[0] == operand, (hex(pc), actual, operand)

    # Calls/delay slots and bases: establish the reader -> unpacker -> exporter chain.
    assert instructions[0x30056c][0] == 'bl' and instructions[0x30056c][1].endswith(';0x1ed440')
    assert instructions[0x30058a][0] == 'bl' and instructions[0x30058a][1].endswith(';0x301f14')
    instruction(0x300566, 'sub3', 'r13,fp,0x35')  # descriptor at fp-424, 296 bytes
    instruction(0x30057e, 'sub', 'r0,r0,508')
    instruction(0x300584, 'add', 'r1,r1,380')     # unpacked view at fp-128
    instruction(0x1ed49a, 'mov', 'r1,296')       # delay slot of clear helper
    instruction(0x1ed506, 'add2', 'r0,r13,0x1f') # descriptor +124
    instruction(0x1ed540, 'add3', 'r13,r13,0x1f')# descriptor +248
    instruction(0x1ed4fe, 'mov_s', 'r0,0x9')
    instruction(0x1ed500, 'st_s', 'r0,[r13,0x4c]')
    assert pool(0x1ed774) == 0x50e140
    assert pool(0x1ed7a0) == 0x50e33c == pool(0x1ed774) + 0x1fc

    text = (ROOT / 'DUMPS/BFNSetting.txt').read_bytes()
    pairs = [(k.decode(), int(v, 16)) for k, v in re.findall(rb'^(\w+)\s*=\s*(0x[0-9a-fA-F]+)\r?$', text, re.M)]
    assert len(pairs) == 28 and len(set(k for k, _ in pairs)) == 28
    ddr, clocks, versions = pairs[:10], pairs[10:26], pairs[26:]
    assert versions == [('BFN_Setting_Version', 0x10001), ('System_FormatVersion', 0x10000)]
    nand = (ROOT / 'DUMPS/NANDP1.dmp').read_bytes()
    ddr_hits = occurrences(nand, struct.pack('<10I', *(v for _, v in ddr)))
    clock_hits = occurrences(nand, struct.pack('<16I', *(v for _, v in clocks)))
    record_bases = [0x2100, 0x2940, 0x3180, 0x39c0]
    assert ddr_hits == [b + 0xa0 for b in record_bases]
    assert clock_hits == [b + 0x180 for b in record_bases]
    assert occurrences(nand, nand[0x2100:0x2940]) == record_bases
    assert all(nand[b:b + 2112] == nand[0x2100:0x2940] for b in record_bases)
    page = nand[0x2100:0x2300]

    rows = []
    for i, (name, value) in enumerate(ddr):
        source = 0xa0 + 4 * i
        descriptor = 8 * i + 4 if i < 9 else 0xdc
        packed = 4 * i if i < 9 else 0x34
        export_pc = 0x300602 + 0x30 * i
        key_pc = export_pc - 4
        key_pool = 0x30094c + 8 * i
        instruction(export_pc, 'ld', f'r3,[fp,{packed - 128}]')
        assert instructions[key_pc][1].endswith(f';{hex(key_pool)}')
        assert cstr(pool(key_pool)) == name
        assert cstr(pool(key_pool - 4)) == '%-40s = 0x%08x\r\n'
        if i < 9:
            load_pc = 0x1ed49e if i == 0 else 0x1ed4a8 + 6 * (i - 1)
            instruction(load_pc, 'ld', f'r0,[r14,{source}]')
            store_pc = load_pc + (8 if i == 0 else 6 if i == 8 else 4)
            instruction(store_pc, 'st_s', f'r0,[r13,{hex(descriptor)}]')
            instruction(0x301f2a + 4 * i, 'ld_s', f'r0,[r2,{hex(descriptor)}]')
            dst = '0' if packed == 0 else hex(packed)
            instruction(0x301f2c + 4 * i, 'st_s', f'r0,[r1,{dst}]')
            register = pool(0x1ed778 + 4 * i)
            assert register == 0xfe20000 + DDR_REG_OFFSETS[i]
            assert instructions[0x1ed4da + 4 * i][0] == 'ld_s'
            assert instructions[0x1ed4da + 4 * i][1].endswith(f';{hex(0x1ed778 + 4 * i)}')
            address_slot = hex(8 * i) if i else '0'
            instruction(0x1ed4dc + 4 * i, 'st_s', f'r0,[r13,{address_slot}]')
        else:
            instruction(0x1ed502, 'ld', 'r2,[r14,196]')
            instruction(0x1ed50a, 'st', 'r2,[r13,220]')
            instruction(0x301f4e, 'ld', 'r0,[r2,220]')
            instruction(0x301f52, 'st_s', 'r0,[r1,0x34]')
            register = None
        rows.append(dict(name=name, value=value, nand_relative_offset=source,
                         descriptor_offset=descriptor, unpacked_offset=packed,
                         exporter_value_load=hex(export_pc), register_address=hex(register) if register else None))

    for i, ((name, value), export_pc) in enumerate(zip(clocks, CLOCK_EXPORT_LOADS)):
        source, descriptor, packed = 0x180 + i * 4, 0xe0 + i * 4, 0x38 + i * 4
        load_pc = 0x1ed56a + 6 * i
        instruction(load_pc, 'ld', f'{"r2" if i < 6 else "r0"},[r1,{source - 0x1fc}]')
        dest_base, dest_off = ('r0', descriptor - 124) if i < 6 else ('r13', descriptor - 248)
        instruction(load_pc + 4, 'st_s', f'{"r2" if i < 6 else "r0"},[{dest_base},{hex(dest_off) if dest_off else "0"}]')
        unpack_pc = 0x301f54 + 6 * i
        if descriptor < 256:
            instruction(unpack_pc, 'ld', f'r0,[r2,{descriptor}]')
        else:
            instruction(unpack_pc, 'ld.as', f'r0,[r2,{descriptor // 4}]')
        instruction(unpack_pc + 4, 'st_s', f'r0,[r1,{hex(packed)}]')
        instruction(export_pc, 'ld', f'r3,[fp,{packed - 128}]')
        key_pc = export_pc - 4
        key_pool = int(instructions[key_pc][1].split(';')[1], 16)
        assert cstr(pool(key_pool)) == name
        assert cstr(pool(key_pool - 4)) == '%-40s = 0x%08x\r\n'
        rows.append(dict(name=name, value=value, nand_relative_offset=source,
                         descriptor_offset=descriptor, unpacked_offset=packed,
                         exporter_value_load=hex(export_pc), register_address=None))

    # Version path selected by raw System_FormatVersion; only this supplied branch is reconstructed.
    assert struct.unpack_from('<I', page, 0x1fc)[0] == 0x10000
    instruction(0x1ed53a, 'cmp_s', 'r2,0x10000')
    instruction(0x1ed548, 'bset_s', 'r2,r2,0x10')
    instruction(0x1ed54a, 'st_s', 'r2,[r13,0x28]')
    instruction(0x1ed5ca, 'ld', 'r0,[r1,-4]')
    instruction(0x1ed5ce, 'st_s', 'r0,[r13,0x2c]')
    for name, value, source, descriptor, packed, unpack_pc, export_pc, key_pool in [
        ('BFN_Setting_Version', 0x10001, 0x1f8, 0x124, 0x7c, 0x301fb4, 0x300c2c, 0x300d00),
        ('System_FormatVersion', 0x10000, 0x1fc, 0x120, 0x78, 0x301fba, 0x300c5e, 0x300d08)]:
        instruction(unpack_pc, 'ld.as', f'r0,[r2,{descriptor // 4}]')
        instruction(unpack_pc + 4, 'st_s', f'r0,[r1,{hex(packed)}]')
        instruction(export_pc - 10, 'add3', 'r3,fp,0x3e')
        instruction(export_pc, 'ld.as', f'r3,[r3,{(packed - 128 - 496) // 4}]')
        assert cstr(pool(key_pool)) == name
        rows.append(dict(name=name, value=value, nand_relative_offset=source,
                         descriptor_offset=descriptor, unpacked_offset=packed,
                         exporter_value_load=hex(export_pc), register_address=None))
    for row in rows:
        assert struct.unpack_from('<I', page, row['nand_relative_offset'])[0] == row['value']

    # Reproduce all original bytes from the 28 NAND words, labels and format, including CRLF.
    rendered = '[DDR_Setting]\r\n'
    rendered += ''.join(f'{k:<40s} = 0x{v:08x}\r\n' for k, v in ddr)
    rendered += '[DDR_Setting_End]\r\n[CLOCK_Setting]\r\n'
    rendered += ''.join(f'{k:<40s} = 0x{v:08x}\r\n' for k, v in clocks)
    rendered += '[CLOCK_Setting_End]\r\n[Version_Setting]\r\n'
    rendered += ''.join(f'{k:<40s} = 0x{v:08x}\r\n' for k, v in versions)
    assert rendered.encode('ascii') == text
    (out / 'BFNSetting.original.txt').write_bytes(text)
    (out / 'configuration_first_512.bin').write_bytes(page)
    (out / 'field_mapping.json').write_text(json.dumps(rows, indent=2) + '\n')
    (out / 'analyzer.py.snapshot').write_bytes(Path(__file__).read_bytes())
    assert all(sha((ROOT / 'DUMPS' / n).read_bytes()) == v['sha256'] for n, v in inputs.items())
    assert sha(ORIGINAL.read_bytes()) == EXPECTED
    assert all(sha(p.read_bytes()) == v for p, v in tools.items())
    evidence = dict(status='PASS_BFN_NAND_EXPORT_STATIC_CORRELATION',
        original_firmware_sha256=EXPECTED, original_payloads_verified=len(BS),
        previous_classification=str(previous.relative_to(ROOT)), unchanged_inputs=inputs,
        readonly_gnu_tools={str(p.relative_to(ROOT)):v for p, v in tools.items()},
        gnu_windows=len(WINDOWS), installed_main_spans=spans,
        nand_records=[dict(file_offset=hex(b), index_at_stride_2112=b // 2112,
            bytes=2112, sha256=sha(nand[b:b+2112])) for b in record_bases],
        exact_record_occurrences_only_in_supplied_NANDP1=record_bases,
        ddr_sequence_occurrences=ddr_hits, clock_sequence_occurrences=clock_hits,
        field_count=len(rows), whole_bfn_text_reconstructed_byte_exact=True,
        configuration_buffer_candidate=hex(0x50e140), descriptor_bytes=296,
        nand_relative_ddr_block=hex(0xa0), nand_relative_size_id=hex(0xc4),
        nand_relative_clock_block=hex(0x180), nand_relative_bfn_version=hex(0x1f8),
        nand_relative_system_version=hex(0x1fc),
        ddr_register_pairs=9, size_id_is_separate_field=True,
        limits=['Static reader/unpacker/exporter correlation, not CPU execution or hardware tracing',
                'Four identical exported records do not prove four independent physical recovery copies',
                'Offsets are positions in NANDP1.dmp, not CPU addresses or validated NAND geometry',
                'DDR_SIZE_ID=0x120 capacity encoding and early boot consumer remain unresolved',
                'Stored clock settings do not measure active frequencies or explain the zero CSV table',
                'No NAND ECC/remap reconstruction, free RAM, AkeruOS boot, photo or recovery proven'])
    evidence['files'] = {str(p.relative_to(out)):sha(p.read_bytes()) for p in sorted(out.iterdir()) if p.is_file()}
    (out / 'verified_evidence.json').write_text(json.dumps(evidence, indent=2) + '\n')
    (out.parent / 'latest.json').write_text(json.dumps(dict(
        evidence=str((out / 'verified_evidence.json').relative_to(ROOT)),
        fields=str((out / 'field_mapping.json').relative_to(ROOT))), indent=2) + '\n')
    print('PASS: 28 fields, 4 identical 2112-byte records, exact BFN text, 9 DDR register pairs;', out)


if __name__ == '__main__':
    main()
