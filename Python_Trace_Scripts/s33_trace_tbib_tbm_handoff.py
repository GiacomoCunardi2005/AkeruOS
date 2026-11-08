#!/usr/bin/env python3
"""Offline TBIB type2 handoff, TBM CPU entry and startup clearing evidence."""
import json
import random
import re
import struct
import tempfile
from pathlib import Path
from s33_trace_state_dispatch import verified_payloads, run, sha

ROOT = Path(__file__).resolve().parents[1]
FIRMWARE_SHA = '1d34e990a8f99019ffa53ca5de785399df863e942739a667ceb314ec6ce62a39'
TBIB_SHA = 'dffbb06318214881d85e10a68d0a3d25001cfb6a1d6802deaf1b7571cfff306e'
WINDOWS = [
    ('TBIB', 0x10000C4, 0x10000E6, 'IndirectMainFirmwareEntry'),
    ('TBIB', 0x1000C10, 0x1000C18, 'RegisteredHandoffCallback'),
    ('TBIB', 0x1001048, 0x10010BA, 'SectorDescriptorType1And2'),
    ('TBIB', 0x10011BC, 0x100125A, 'FileDescriptorType1And2'),
    ('TBIB', 0x10010F8, 0x100110E, 'RHIRMagicCheck'),
    ('TBIB', 0x100114A, 0x10011A8, 'DescriptorIteration'),
    ('TBIB', 0x103FE30, 0x103FE3E, 'HandoffCallbackRegistration'),
    ('TBIB', 0x103E028, 0x103E03A, 'CallbackListSelection'),
    ('TBIB', 0x103DFE0, 0x103E018, 'CallbackRecordLinking'),
    ('TBIB', 0x103E06C, 0x103E090, 'SelectedCallbackListConsumer'),
    ('TBIB', 0x103FE68, 0x103FE78, 'CallbackListConsumerWrapper'),
    ('TBM00', 0xBB540, 0xBB5D8, 'MainFirmwareCPUEntry'),
    ('TBM00', 0xBB5D8, 0xBB5DC, 'MainFirmwareRuntimeReturnBranch'),
    ('TBM00', 0xBB5E0, 0xBB5F8, 'MainFirmwareRuntimeReturnLoop'),
    ('TBM00', 0xAD890, 0xAD8C4, 'RuntimeClearingAndKernelCall'),
    ('TBM00', 0xAD90C, 0xAD920, 'ZeroFillWrapper'),
]
CHECKS = {
    0x10000D6: 'ld_s\tr14,[r0,0]', 0x10000D8: 'jl_s\t[r14]',
    0x1000C10: 'mov_s\tr0,0', 0x1000C12: ';0x10000c4',
    0x100105A: 'ldw_s\tr0,[r0,0]', 0x100105E: ';0x100109e',
    0x1001070: 'ld_s\tr15,[r13,0x8]', 0x1001082: 'asl\tr1,r16,0x9',
    0x100109E: 'cmp_s\tr0,0x2', 0x10010A0: ';0x10010ac',
    0x10010A2: 'ld_s\tr1,[r13,0x4]', 0x10010A6: 'st_s\tr1,[r0,0]',
    0x100123C: 'cmp_s\tr0,0x2', 0x1001240: 'ld_s\tr1,[r14,0x4]',
    0x1001242: 'ld.as\tr0,[pcl,-97]', 0x1001246: 'st_s\tr1,[r0,0]',
    0x1001102: 'cmp_s\tr0,0x52494852', 0x1001154: ';0x10011a6',
    0x1001194: ';0x1001048', 0x100119E: 'add_s\tr13,r13,0x10',
    0x103FE34: 'mov_s\tr0,0x1042610', 0x103FE3A: ';0x103e028',
    0x103E02C: 'add_s\tr1,r1,0x2', 0x103E032: ';0x103dfe0',
    0x103DFE8: 'add2_s\tr3,r3,r1', 0x103E008: 'st_s\tr13,[r0,0x8]',
    0x103E00C: 'st_s\tr0,[r3,0]',
    0x103E07C: 'ld_s\tr13,[r1,0x8]', 0x103E084: 'ld_s\tr0,[r13,0x4]',
    0x103E086: 'jl_s\t[r0]', 0x103FE6C: ';0x103e06c',
    0xBB5A8: 'mov\tlp_count,0', 0xBB5AC: 'sr\t0,[lp_start]',
    0xBB5B4: 'sr\t0,[lp_end]', 0xBB5BC: 'mov\tsp,0x5daddc',
    0xBB5C4: 'sub\tsp,sp,0x10', 0xBB5C8: 'mov\tgp,0x423844',
    0xBB5D0: ';0xad890', 0xBB5D4: 'mov\tfp,0',
    0xBB5D8: ';0xbb5e0', 0xBB5E0: 'flag\t0x1', 0xBB5F0: ';0xbb5e0',
    0xAD89C: ';0xad8b4', 0xAD8A2: ';0xad90c', 0xAD8A6: 'sub_s\tr1,r1,r0',
    0xAD8B6: ';0x333d7c', 0xAD90E: ';0x13a954', 0xAD912: 'mov_s\tr1,0',
}


def main():
    blocks, payloads, block_dir = verified_payloads(ROOT)
    info = {b['index']: b for b in blocks}
    firmware = (ROOT / 'OriginalSoftware_NikonS33_V1.1/firmware.bin').read_bytes()
    assert sha(firmware) == FIRMWARE_SHA
    tbib = (ROOT / 'S33-sections/01_TBIB_SK501_payload.bin').read_bytes()
    tbm = (ROOT / 'S33-sections/02_TBM_SK501_payload.bin').read_bytes()
    assert sha(tbib) == TBIB_SHA and firmware[0x6C:0x6C + len(tbib)] == tbib
    assert firmware[0x480B8:0x480B8 + len(tbm)] == tbm
    base, length, checksum, entry = struct.unpack_from('<4I', tbib)
    assert (base, length, checksum, entry) == (0x1000000, 0x44BBC, 0xF3F78173, 0x1000000)
    body = tbib[16:16 + length]
    assert sum(struct.unpack(f'<{length // 4}I', body)) & 0xFFFFFFFF == checksum
    assert tbm[:4] == b'RHIR' and tbm[6] == 17
    records = [struct.unpack_from('<HHHHII', tbm, 0x10 + i * 16) for i in range(17)]
    for b in blocks:
        typ, _, sector, count, dest, record_sum = records[b['index']]
        assert (typ, sector * 512, count * 512, dest) == (
            b['type'], b['offset'], b['size'], b['load_address_candidate'])
        assert tbm[sector * 512:(sector + count) * 512] == payloads[b['index']]
    assert [i for i, r in enumerate(records) if r[0] == 1] == [0, 1, 8]
    assert records[16][0] == 2
    handoff = struct.unpack_from('<I', tbm, 0x10 + 16 * 16 + 4)[0]
    assert handoff == 0xBB540 and info[0]['load_address_candidate'] <= handoff < info[0]['load_address_candidate'] + info[0]['size']
    def word(address):
        for origin, data in [(base, body)] + [(info[i]['load_address_candidate'], payloads[i]) for i in (0, 1)]:
            if origin <= address <= origin + len(data) - 4:
                return struct.unpack_from('<I', data, address - origin)[0]
        raise AssertionError(hex(address))
    literals = {0x10000E8: 0x1041100, 0x10010BC: 0x1041100,
                0x1042610: 1, 0x1042614: 0x1000C10, 0x1042618: 0,
                0x103E0AC: 0x1044BA0, 0xAD8C8: 0x3707B4,
                0xAD8CC: 0x42D140, 0xAD8D0: 0x5DA5DC,
                0xAD8D4: 0x423844, 0xAD8D8: 0x423844, 0x3707B8: 1}
    for address, expected in literals.items():
        assert word(address) == expected
    assert (0x1001242 & ~3) - 97 * 4 == 0x10010BC
    tools = ROOT / 'work/build-arc/binutils'
    listings = []
    with tempfile.TemporaryDirectory(prefix='s33-tbib-handoff-') as td:
        elfs = {}
        for label, data, origin in [('TBIB', body, base), ('TBM00', payloads[0], info[0]['load_address_candidate'])]:
            src, elf, back = [Path(td) / (label + suffix) for suffix in ('.bin', '.elf', '.back')]
            src.write_bytes(data)
            run([tools / 'objcopy', '-I', 'binary', '-O', 'elf32-littlearc', '-B', 'arc',
                 '--rename-section', '.data=.text,alloc,load,readonly,code,contents',
                 '--change-section-vma', f'.data={origin:#x}', '--strip-all', src, elf])
            run([tools / 'objcopy', '--dump-section', f'.text={back}', elf])
            assert back.read_bytes() == data
            elfs[label] = elf
        for label, start, end, name in WINDOWS:
            text = run([tools / 'objdump', '-d', '-m', 'arc:ARC700', '-EL',
                        f'--start-address={start:#x}', f'--stop-address={end:#x}', elfs[label]])
            assert 'out of bounds' not in text.lower(), name
            listings.append('WINDOW ' + name + '\n' + text.replace(str(elfs[label]), label + '.elf'))
    listing = '\n'.join(listings)
    decoded = {}
    for line in listing.splitlines():
        match = re.match(r'^\s*([0-9a-f]+):\t([^\t]+)\t(\S+)\t?(.*)$', line)
        if match:
            decoded[int(match[1], 16)] = (len(match[2].split()) * 2, match[3], match[4], line)
    for address, expected in CHECKS.items():
        assert expected in decoded[address][3], decoded[address]
    for reg in range(26):
        assert f'mov\tr{reg},0' in decoded[0xBB540 + 4 * reg][3]

    def transfer_slice(start, end, regs, memory):
        pc = start
        while pc < end:
            size, op, args, _ = decoded[pc]
            args = args.split(';')[0].strip()
            if op in ('ld_s', 'ld.as', 'st_s'):
                reg, basereg, off = re.fullmatch(r'(r\d+),\[(r\d+|pcl),(0x[0-9a-f]+|-?\d+)\]', args).groups()
                address = ((pc & ~3) if basereg == 'pcl' else regs[basereg]) + int(off, 0) * (4 if op == 'ld.as' else 1)
                if op == 'st_s': memory[address] = regs[reg]
                else: regs[reg] = word(address) if basereg == 'pcl' else memory[address]
            elif op == 'mov_s':
                reg, value = args.split(','); regs[reg] = int(value, 0)
            else:
                raise AssertionError((hex(pc), op, args))
            pc += size
        assert pc == end

    rng = random.Random(3306)
    entries = [handoff, 0, 1, 0xFFFFFFFF] + [rng.getrandbits(32) for _ in range(252)]
    cases = 0
    for target in entries:
        for start, end, descriptor_reg in [(0x10010A2, 0x10010AA, 'r13'), (0x1001240, 0x100124A, 'r14')]:
            regs = {descriptor_reg: 0x2000}
            memory = {0x2004: target, 0x1041100: 0xDEADBEEF}
            transfer_slice(start, end, regs, memory)
            assert memory[0x1041100] == target and regs['r0'] == 0
            transfer_slice(0x10000D4, 0x10000D8, regs, memory)
            assert regs['r14'] == target
            cases += 1
    output = ROOT / 'Ghidra_Results/ghidra_reports/tbib_tbm_handoff'
    output.mkdir(parents=True, exist_ok=True)
    result = dict(firmware='S33 V1.1 static only', firmware_sha256=sha(firmware),
        tbib_payload_sha256=sha(tbib), tbib_body_sha256=sha(body), tbm_payload_sha256=sha(tbm),
        block_sha256={str(b['index']): b['sha256'] for b in blocks},
        script_sha256=sha(Path(__file__).read_bytes()), verified_blocks=16,
        tbib_header=dict(base=hex(base), length=hex(length), checksum=hex(checksum), entry=hex(entry)),
        elf_roundtrips=['TBIB body', 'TBM block00'],
        windows=[dict(image=l, start=hex(a), end=hex(b), label=n) for l, a, b, n in WINDOWS],
        checked_instructions=len(CHECKS), checked_zeroed_registers=26,
        checked_literals={hex(a): hex(v) for a, v in literals.items()},
        immediate_type1_records=[0, 1, 8], type2_record=16, type2_value=hex(handoff),
        handoff_cell='0x01041100', handoff_instruction='0x010000d8',
        decoded_transfer_cases=cases, tbm_startup=dict(entry=hex(handoff), sp='0x005dadcc', gp='0x00423844', call='0x000ad890'),
        startup_clear=dict(start='0x0042d140', end_exclusive='0x005da5dc', bytes=0x5DA5DC - 0x42D140, guard='word[0x3707b8]!=0; original payload value1'),
        observations=['Record16 type2 reads word+4 as entry, not two sector halfwords; both selected loaders write0x1041100',
            'If the TBM runtime returns normally, the startup prefix enters the local0xbb5e0 loop instead of returning to TBIB',
            'Registered callback0x1000c10 reaches indirect call through0x1041100, holding0xbb540 for the supplied image',
            'TBM entry initializes r0..r25, loop registers, stack and gp then calls the known runtime bridge0xad890',
            'Selected runtime startup clears0x42d140..0x5da5dc under the original nonzero guard',
            'Selected type1 loader handles initial records0,1,8; other record types require their own semantics'],
        limits=['Conditional static handoff, not proof of execution or all boot success/cleanup guards',
            'Transfer models data propagation only; arbitrary synthetic targets are never executed or accepted as safe',
            'ROM entry, full hardware/cache/interrupt shutdown, package acceptance and recovery remain unresolved',
            'Startup clearing region and startup stack are not evidence of free memory or physical RAM capacity',
            'V1.1 addresses are not automatically valid on the V1.0 device'])
    (output / 'gnu_verified.txt').write_text(listing)
    (output / 'verified_evidence.json').write_text(json.dumps(result, indent=2) + '\n')
    print(f'PASS: original container identity, TBIB checksum,16 exact blocks,2 ELF roundtrips, '
          f'{len(WINDOWS)} windows,{len(CHECKS)} instructions,26 initial registers,'
          f'{len(literals)} literals,{cases} transfer cases; entry={handoff:#x}')


if __name__ == '__main__':
    main()
