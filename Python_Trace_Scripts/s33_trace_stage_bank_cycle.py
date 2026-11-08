#!/usr/bin/env python3
"""Static S33 stage-bank layout and selected index updates; no firmware execution."""
import json
import random
import re
import struct
import tempfile
from pathlib import Path
from s33_trace_state_dispatch import verified_payloads, run, sha

ROOT = Path(__file__).resolve().parents[1]
C, BANK, INDEX = 0x367490, 0x392288, 0x3674E1
WINDOWS = [
    (0x15D02C, 0x15D030, 'TaskContextBinding'),
    (0x15D0DC, 0x15D0FA, 'IndexAdvanceModeDispatch'),
    (0x15D100, 0x15D116, 'IndexAdvanceBeforeProcessing'),
    (0x15DA1A, 0x15DA4E, 'IndexAdvanceSelectorZero'),
    (0x15DA98, 0x15DABC, 'IndexAdvanceOtherPath'),
    (0x15F09A, 0x15F0B0, 'SuccessfulSetupIndexReset'),
    (0x15EAEA, 0x15EB4E, 'FourTriplesBuilder'),
    (0x15EB4E, 0x15EB84, 'OptionalAllocationBeforeCapacityGuard'),
    (0x15EB84, 0x15EB9C, 'PostConstructionCapacityGuard'),
    (0x15D3BE, 0x15D3EE, 'UncheckedBankSelection'),
]
LITERALS = {0x15CFA8: C, 0x15D32C: C + 0x38, 0x15DA94: C + 0x38,
            0x15F284: C + 0x38, 0x15EDAC: BANK, 0x15EDA4: C, 0x15D6A8: BANK}
UPDATES = [(0x15D106, 0x15D112), (0x15DA3E, 0x15DA4A), (0x15DAA8, 0x15DAB4)]
CHECKS = {
    0x15D0E0: 'cmp_s\tr0,0x1', 0x15D0EA: ';0x15d1a4',
    0x15D0F2: 'ldb.x\tr0,[r12,r0]', 0x15D0F6: 'add1_s\tr12,r12,r0',
    0x15D100: 'ldb\tr0,[r14,81]', 0x15D112: 'stb_s\tr0,[r1,0x19]',
    0x15DA1A: 'ldb\tr0,[r14,253]', 0x15DA30: 'ld.as\tr0,[r14,65]',
    0x15DA38: 'ldb\tr0,[r14,81]', 0x15DA4A: 'stb_s\tr0,[r1,0x19]',
    0x15DA98: 'ldb\tr0,[r14,100]', 0x15DAA0: 'ldb\tr0,[r14,81]',
    0x15DAB4: 'stb_s\tr0,[r1,0x19]', 0x15F0A4: 'mov_s\tr0,0',
    0x15F0AC: 'stb_s\tr0,[r1,0x19]', 0x15EAF0: 'cmp_s\tr0,0',
    0x15EAF2: ';0x15eb4e', 0x15EAFC: 'mov_s\tr15,0x4',
    0x15EB0E: 'muludw\t0,r0,r5', 0x15EB20: 'asr\tr1,r5',
    0x15EB24: ';0x3342a8', 0x15EB28: 'asr_s\tr0,r0',
    0x15EB40: 'sub_s\tr15,r15,0x1', 0x15EB42: 'cmp_s\tr15,0',
    0x15EB44: 'bhi.d', 0x15EB48: 'add_s\tr13,r13,0xc',
    0x15EB4A: 'st\tr2,[sp,180]', 0x15EB8E: 'ld\tr1,[r16,8]',
    0x15EB50: 'ldb\tr0,[r0,84]', 0x15EB62: ';0x15ba8c',
    0x15EB94: 'bls_s', 0x15D3C6: 'ldb\tr0,[r14,81]',
    0x15D3CE: 'asl_s\tr0,r0,0x2', 0x15D3D0: 'add1_s\tr0,r0,r0',
    0x15D3D2: 'ld.aw\tr2,[r0,r12]',
}


def main():
    blocks, payloads, block_dir = verified_payloads(ROOT)
    block = next(b for b in blocks if b['index'] == 0)
    def raw(address, size):
        offset = address - block['load_address_candidate']
        assert 0 <= offset <= len(payloads[0]) - size
        return payloads[0][offset:offset + size]
    def word(address):
        return struct.unpack('<I', raw(address, 4))[0]
    for address, expected in LITERALS.items():
        assert word(address) == expected
    assert C + 0x38 + 0x19 == C + 0x51 == INDEX
    table = struct.unpack('6b', raw(0x15D0FA, 6))
    targets = [0x15D0FA + 2 * entry for entry in table]
    assert targets == [0x15D100, 0x15D1A4, 0x15D1A4, 0x15D100, 0x15D100, 0x15D116]
    tools = ROOT / 'work/build-arc/binutils'
    listings = []
    with tempfile.TemporaryDirectory(prefix='s33-stage-bank-') as td:
        elf, back = Path(td) / '0.elf', Path(td) / '0.bin'
        run([tools / 'objcopy', '-I', 'binary', '-O', 'elf32-littlearc', '-B', 'arc',
             '--rename-section', '.data=.text,alloc,load,readonly,code,contents',
             '--change-section-vma', f'.data={block["load_address_candidate"]:#x}',
             '--strip-all', block_dir / block['file'], elf])
        run([tools / 'objcopy', '--dump-section', f'.text={back}', elf])
        assert back.read_bytes() == payloads[0]
        for start, end, label in WINDOWS:
            text = run([tools / 'objdump', '-d', '-m', 'arc:ARC700', '-EL',
                        f'--start-address={start:#x}', f'--stop-address={end:#x}', elf])
            assert 'out of bounds' not in text.lower()
            listings.append('WINDOW ' + label + '\n' + text.replace(str(elf), 'verified-block0.elf'))
    listing = '\n'.join(listings)
    decoded = {}
    for line in listing.splitlines():
        match = re.match(r'^\s*([0-9a-f]+):\t([^\t]+)\t(\S+)\t?(.*)$', line)
        if match:
            decoded[int(match[1], 16)] = (len(match[2].split()) * 2, match[3], match[4], line)
    for address, expected in CHECKS.items():
        assert expected in decoded[address][3], decoded[address]
    for site, expected in [(0x15D02C, C), (0x15D104, C + 0x38),
                           (0x15DA3C, C + 0x38), (0x15DAA4, C + 0x38),
                           (0x15F09C, C + 0x38), (0x15EAFE, BANK), (0x15D3CA, BANK)]:
        args = decoded[site][2]
        offset = int(re.search(r'\[pcl,([^\]]+)\]', args)[1], 0)
        assert word((site & ~3) + offset) == expected

    def arithmetic(start, end, regs, stores):
        """Selected straight-line arithmetic only; supplied U/V replace size calculations."""
        pc = start
        def val(s):
            return regs[s] if s in regs else int(s, 0)
        while pc < end:
            size, op, args, _ = decoded[pc]
            args = args.split(';')[0].strip()
            if op == 'st_s':
                src, base, off = re.fullmatch(r'(r\d+),\[(r\d+),(0x[0-9a-f]+|\d+)\]', args).groups()
                stores[val(base) + int(off, 0)] = val(src)
            else:
                parts = args.split(','); a = val(parts[1])
                b = val(parts[2]) if len(parts) == 3 else 1
                if op in ('add_s', 'add'): result = a + b
                elif op == 'add1_s': result = a + 2 * b
                elif op in ('sub_s', 'sub'): result = a - b
                elif op in ('lsr_s', 'lsr'): result = a >> b
                elif op == 'asl_s': result = a << b
                elif op == 'asr_s': result = ((a & 0x7FFFFFFF) - (a & 0x80000000)) >> b
                elif op == 'bmsk_s': result = a & ((1 << (b + 1)) - 1)
                elif op == 'mov_s': result = a
                else: raise AssertionError((hex(pc), op, args))
                regs[parts[0]] = result & 0xFFFFFFFF
            pc += size
        assert pc == end

    index_cases = 0
    for start, end in UPDATES:
        for old in range(256):
            regs = dict(r0=old, r12=0)
            arithmetic(start, end, regs, {})
            assert regs['r0'] == (old + 1) % 4
            index_cases += 1
    rng = random.Random(3305)
    quantities = [(0, 0), (1, 1), (7, 7), (8, 8), (65535, 65535)] + [
        (rng.randrange(0x100000), rng.randrange(0x100000)) for _ in range(512)]
    align = lambda n: (n + 7) & ~7
    layout_cases = 0
    for u, v in quantities:
        start = 0x1000000
        regs = dict(r2=start, r13=BANK, r0=0, r57=u)
        stores = {}
        expected = {}
        cursor = start
        for slot in range(4):
            arithmetic(0x15EB0C, 0x15EB0E, regs, stores)
            arithmetic(0x15EB12, 0x15EB20, regs, stores)
            regs['r0'] = v
            arithmetic(0x15EB2A, 0x15EB40, regs, stores)
            p1 = align(cursor + u); p2 = align(p1 + v)
            expected.update({BANK + slot * 12: cursor,
                             BANK + slot * 12 + 4: p1, BANK + slot * 12 + 8: p2})
            cursor = align(p2 + v)
            assert regs['r2'] == cursor
            arithmetic(0x15EB48, 0x15EB4A, regs, stores)  # branch delay slot, including last iteration
            layout_cases += 1
        assert stores == expected and regs['r13'] == BANK + 48
    addresses = [BANK + 12 * i for i in range(256)]
    assert [i for i, address in enumerate(addresses) if BANK <= address and address + 12 <= BANK + 48] == list(range(4))
    output = ROOT / 'Ghidra_Results/ghidra_reports/stage_bank_cycle'
    output.mkdir(parents=True, exist_ok=True)
    result = dict(firmware='S33 V1.1 static only', verified_blocks=16,
        elf_roundtrip_blocks=[0], block_sha256={str(b['index']): b['sha256'] for b in blocks},
        script_sha256=sha(Path(__file__).read_bytes()),
        windows=[dict(start=hex(a), end=hex(b), label=l) for a, b, l in WINDOWS],
        checked_instructions=len(CHECKS), checked_literals={hex(a): hex(v) for a, v in LITERALS.items()},
        jump_table_targets=[hex(t) for t in targets],
        index_cell=hex(INDEX), update_stores=[hex(end) for _, end in UPDATES],
        reset_store='0x15f0ac', decoded_index_cases=index_cases,
        synthetic_quantity_pairs=len(quantities), decoded_slot_layouts=layout_cases,
        valid_byte_indices=[0, 1, 2, 3], bank_span=[hex(BANK), hex(BANK + 48)],
        observations=['Three selected index updates normalize all byte inputs to0..3; setup reset writes0',
            'Signed-byte mode table dispatches values0,3,4 to the first update, under prior guards',
            'Builder produces4 triples with pointers cursor,align8(cursor+U),align8(previous+V),then align8(previous+V)',
            'Builder skipped when C+0x72!=0; capacity comparison follows writes',
            'Selected bank reader uses raw byte index without a local index<4 guard'],
        limits=['Only selected writers and branch windows are covered; no global absence-of-other-writers proof',
            'U/V supplied at arithmetic boundaries; dimension calculations and helper0x3342a8 not emulated',
            'Layout comparisons use nonwrapping aligned starting addresses and bounded synthetic quantities',
            'Memory ordering, concurrent accesses, stale initialization and final physical buffer use remain unknown'])
    (output / 'gnu_verified.txt').write_text(listing)
    (output / 'verified_evidence.json').write_text(json.dumps(result, indent=2) + '\n')
    print(f'PASS:16 hashes, block0 roundtrip, {len(WINDOWS)} windows, {len(CHECKS)} instructions, '
          f'{len(LITERALS)} pools, 6 jump cases, {index_cases} index updates, '
          f'{layout_cases} slot layouts, all256 selector bytes')


if __name__ == '__main__':
    main()
