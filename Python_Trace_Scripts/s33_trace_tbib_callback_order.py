#!/usr/bin/env python3
"""Offline sorted TBIB callback lists and conditional handoff precedence."""
import json
import random
import re
import struct
import tempfile
from pathlib import Path
from s33_trace_state_dispatch import run, sha
from s33_trace_tbib_tbm_handoff import ROOT, TBIB_SHA, FIRMWARE_SHA

HEADS, GUARD = 0x1044BA0, 0x10417B8
RECORDS = [(0x1042610, 1, 0x1000C10, 2),
           (0x1043AE4, 121, 0x103B4D0, 0),
           (0x104444C, 120, 0x103BE1C, 2),
           (0x1044458, 120, 0x103BE48, 0)]
WINDOWS = [(0x103FE30, 0x103FE68, 'FourOriginalRegistrations'),
    (0x103E018, 0x103E03C, 'ListAndSortPolicySelection'),
    (0x103DFE0, 0x103E018, 'SortedInsertion'),
    (0x103E090, 0x103E0AA, 'InitialListConsumer'),
    (0x103E06C, 0x103E090, 'FinalListGuardDetachAndConsumer'),
    (0x103B4D0, 0x103B4D8, 'InitialCallbackFirst'),
    (0x103BE48, 0x103BE68, 'InitialCallbackSecond'),
    (0x103BE1C, 0x103BE48, 'FinalResourceCleanup'),
    (0x103DF0C, 0x103DF44, 'CleanupServiceBoundary'),
    (0x1000C10, 0x1000C18, 'HandoffCallback'),
    (0x10000D4, 0x10000DA, 'HandoffCellConsumer')]
CHECKS = {0x103FE3A: ';0x103e028', 0x103FE44: ';0x103e018',
    0x103FE4E: ';0x103e028', 0x103FE58: ';0x103e018', 0x103FE5C: ';0x103e090',
    0x103E01A: 'ld_s\tr1,[r0,0x8]', 0x103E01E: 'mov_s\tr2,0',
    0x103E02C: 'add_s\tr1,r1,0x2', 0x103E030: 'mov_s\tr2,0x1',
    0x103DFFE: 'brlo\tr1,r15,-10', 0x103E004: 'brlo\tr15,r1,-18',
    0x103E008: 'st_s\tr13,[r0,0x8]', 0x103E010: 'st_s\tr0,[r14,0x8]',
    0x103E096: 'ld_s\tr13,[r1,0]', 0x103E09A: 'st_s\tr0,[r1,0]',
    0x103E074: 'brne_s\tr0,0,24', 0x103E078: 'st_s\tr0,[r1,0]',
    0x103E07C: 'ld_s\tr13,[r1,0x8]', 0x103E080: 'st_s\tr0,[r1,0x8]',
    0x103E084: 'ld_s\tr0,[r13,0x4]', 0x103E086: 'jl_s\t[r0]',
    0x103B4D0: ';0x103decc', 0x103BE4E: ';0x103decc',
    0x103BE54: ';0x103decc', 0x103BE5A: ';0x103decc',
    0x103BE26: ';0x103df0c', 0x103BE30: ';0x103df0c', 0x103BE3C: ';0x103df0c',
    0x1000C12: ';0x10000c4', 0x10000D8: 'jl_s\t[r14]'}


def main():
    firmware = (ROOT / 'OriginalSoftware_NikonS33_V1.1/firmware.bin').read_bytes()
    payload = (ROOT / 'S33-sections/01_TBIB_SK501_payload.bin').read_bytes()
    assert sha(firmware) == FIRMWARE_SHA and sha(payload) == TBIB_SHA
    assert firmware[0x6C:0x6C + len(payload)] == payload
    base, length, checksum, entry = struct.unpack_from('<4I', payload)
    assert base == entry == 0x1000000 and length == 0x44BBC
    body = payload[16:16 + length]
    assert sum(struct.unpack(f'<{length // 4}I', body)) & 0xFFFFFFFF == checksum
    def word(address):
        offset = address - base; assert 0 <= offset <= len(body) - 4
        return struct.unpack_from('<I', body, offset)[0]
    for address, key, callback, group in RECORDS:
        assert (word(address), word(address + 4), word(address + 8)) == (key, callback, 0)
    literals = {0x103E0AC: HEADS, 0x103E0B0: GUARD,
        HEADS: 0, HEADS + 4: 0, HEADS + 8: 0, HEADS + 12: 0, GUARD: 0,
        0x103BE6C: 0x10967A0, 0x103BE70: 0x10967A4, 0x103BE78: 0x10967A8}
    for address, expected in literals.items(): assert word(address) == expected
    tools = ROOT / 'work/build-arc/binutils'; listings = []
    with tempfile.TemporaryDirectory(prefix='s33-tbib-callback-order-') as td:
        src, elf, back = [Path(td) / name for name in ('body.bin', 'body.elf', 'back.bin')]
        src.write_bytes(body)
        run([tools / 'objcopy', '-I', 'binary', '-O', 'elf32-littlearc', '-B', 'arc',
             '--rename-section', '.data=.text,alloc,load,readonly,code,contents',
             '--change-section-vma', f'.data={base:#x}', '--strip-all', src, elf])
        run([tools / 'objcopy', '--dump-section', f'.text={back}', elf]); assert back.read_bytes() == body
        for start, end, label in WINDOWS:
            text = run([tools / 'objdump', '-d', '-m', 'arc:ARC700', '-EL',
                        f'--start-address={start:#x}', f'--stop-address={end:#x}', elf])
            assert 'out of bounds' not in text.lower(), label
            listings.append('WINDOW ' + label + '\n' + text.replace(str(elf), 'TBIB.elf'))
    listing = '\n'.join(listings); decoded = {}
    for line in listing.splitlines():
        match = re.match(r'^\s*([0-9a-f]+):\t([^\t]+)\t(\S+)\t?(.*)$', line)
        if match: decoded[int(match[1], 16)] = (len(match[2].split()) * 2, match[3], match[4], line)
    for address, expected in CHECKS.items(): assert expected in decoded[address][3], decoded[address]

    def execute(start, stop, regs, memory, stop_callback=None):
        """Insertion/consumer slices only; callback stubs return without side effects."""
        pc, calls = start, []
        def value(s): return regs[s] if s in regs else int(s, 0)
        for _ in range(2048):
            if pc == stop: return calls
            size, op, raw, _ = decoded[pc]; args = raw.split(';')[0].strip()
            parts = args.split(',')
            if op in ('ld_s', 'st_s'):
                reg, basereg, offset = re.fullmatch(r'(r\d+),\[(r\d+|pcl)(?:,(0x[0-9a-f]+|\d+))?\]', args).groups()
                address = ((pc & ~3) if basereg == 'pcl' else value(basereg)) + int(offset or '0', 0)
                if op == 'st_s': memory[address] = value(reg)
                else: regs[reg] = word(address) if basereg == 'pcl' else memory[address]
            elif op == 'add2_s': regs[parts[0]] = (value(parts[1]) + 4 * value(parts[2])) & 0xFFFFFFFF
            elif op == 'mov_s': regs[parts[0]] = value(parts[1])
            elif op in ('b_s', 'breq_s', 'brne_s', 'brlo'):
                take = (op == 'b_s' or
                    op == 'breq_s' and value(parts[0]) == value(parts[1]) or
                    op == 'brne_s' and value(parts[0]) != value(parts[1]) or
                    op == 'brlo' and value(parts[0]) < value(parts[1]))
                if take:
                    pc = int(re.search(r';0x([0-9a-f]+)', raw)[1], 16); continue
            elif op == 'jl_s':
                callback = value(args.strip('[]')); calls.append(callback)
                if callback == stop_callback: return calls
            else: raise AssertionError((hex(pc), op, args))
            pc += size
        raise AssertionError('Slice did not terminate')

    def linked(memory, group):
        nodes = []; ptr = memory[HEADS + 4 * group]
        while ptr:
            assert ptr not in nodes, 'cyclic host list'; nodes.append(ptr); ptr = memory[ptr + 8]
        return nodes

    def insert(memory, address, group):
        assert memory[address + 8] == 0
        execute(0x103DFE6, 0x103E012,
                dict(r0=address, r1=group, r2=int(group == 2)), memory)

    original = {HEADS + 4 * i: 0 for i in range(4)} | {GUARD: 0}
    for address, key, callback, group in RECORDS:
        original.update({address: key, address + 4: callback, address + 8: 0})
        insert(original, address, group)
    initial_order = linked(original, 0); final_order = linked(original, 2)
    assert initial_order == [0x1043AE4, 0x1044458]
    assert final_order == [0x1042610, 0x104444C]
    all_return = original.copy()
    assert execute(0x103E070, 0x103E08C, {}, all_return) == [0x1000C10, 0x103BE1C]
    assert all_return[GUARD] == 1 and all_return[HEADS + 8] == 0
    assert execute(0x103E070, 0x103E08C, {}, all_return) == []
    handoff = original.copy()
    assert execute(0x103E070, 0x103E08C, {}, handoff, 0x1000C10) == [0x1000C10]
    assert handoff[GUARD] == 1 and handoff[HEADS + 8] == 0

    rng = random.Random(3308); cases = 0
    for group in (0, 2):
        for iteration in range(256):
            count = iteration % 17
            keys = [rng.choice((0, 1, 120, 121, 0x7FFFFFFF, 0xFFFFFFFF, rng.getrandbits(32))) for _ in range(count)]
            memory = {HEADS + 4 * i: 0 for i in range(4)}; addresses = []
            for i, key in enumerate(keys):
                address = 0x20000 + 16 * i; addresses.append(address)
                memory.update({address: key, address + 4: 0x30000 + i * 4, address + 8: 0})
                insert(memory, address, group)
            expected_indices = sorted(range(count), key=lambda i: (keys[i] if group == 2 else -keys[i], -i))
            assert linked(memory, group) == [addresses[i] for i in expected_indices]
            cases += 1
    output = ROOT / 'Ghidra_Results/ghidra_reports/tbib_callback_order'; output.mkdir(parents=True, exist_ok=True)
    result = dict(firmware='S33 V1.1 static only', firmware_sha256=sha(firmware), tbib_payload_sha256=sha(payload),
        script_sha256=sha(Path(__file__).read_bytes()), tbib_checksum=hex(checksum), elf_roundtrip='TBIB body',
        windows=[dict(start=hex(a), end=hex(b), label=l) for a, b, l in WINDOWS],
        checked_instructions=len(CHECKS), checked_literals={hex(a): hex(v) for a, v in literals.items()},
        records=[dict(address=hex(a), key=k, callback=hex(c), group=g) for a, k, c, g in RECORDS],
        decoded_sort_cases=cases, initial_order=[hex(a) for a in initial_order], final_order=[hex(a) for a in final_order],
        all_return_callbacks=['0x01000c10', '0x0103be1c'], nonreturn_handoff_callbacks=['0x01000c10'],
        observations=['Original constructor inserts four records into lists0(descending key) and2(ascending key)',
            'Within the two known final-list records, handoff key1 precedes resource cleanup key120',
            'Equal keys insert before existing records; comparisons are unsigned',
            'Final consumer sets guard and detaches head before calling handoff',
            'Resource cleanup callback is reached only if prior handoff returns in this two-record list'],
        limits=['Four original registrations only; later registrations and indirect writers are not excluded',
            'Insertion and consumer models use host memory; callbacks are stubs or a synthetic nonreturn stop',
            'No identification of all resource types, hardware quiescence, cache completion or device execution',
            'No modified boot, recovery or V1.0 address compatibility established'])
    (output / 'gnu_verified.txt').write_text(listing)
    (output / 'verified_evidence.json').write_text(json.dumps(result, indent=2) + '\n')
    print(f'PASS: firmware/TBIB identity,checksum,roundtrip,{len(WINDOWS)} windows,'
          f'{len(CHECKS)} instructions,{len(literals)} literals,4 original records,'
          f'{cases} decoded sort cases,return/nonreturn/reentry consumers')


if __name__ == '__main__': main()
