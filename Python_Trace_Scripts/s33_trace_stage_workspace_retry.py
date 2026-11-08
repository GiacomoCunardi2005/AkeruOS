#!/usr/bin/env python3
"""Verify local workspace allocation/retry slices, without running firmware or USB."""
import json
import random
import re
import struct
import tempfile
from pathlib import Path
from s33_trace_state_dispatch import verified_payloads, run, sha

ROOT = Path(__file__).resolve().parents[1]
WINDOWS = [
    (0x243F48, 0x244032, 'AdmissionRegionQueriesAndFirstConfig'),
    (0x24405C, 0x2440F8, 'NormalWorkspaceAllocation'),
    (0x2440F8, 0x244234, 'AlternateAllocationAndRetryTail'),
    (0x15F014, 0x15F032, 'TaskCallerStackArgument'),
    (0x24C30A, 0x24C344, 'OtherDirectCaller'),
    (0x334104, 0x33413C, 'RegisterSaveAndStackAccounting'),
    (0x3341AE, 0x3341E4, 'RegisterRestore'),
    (0x24BBCE, 0x24BBF0, 'NormalQuantityHelperFactor'),
    (0x24BC5E, 0x24BC80, 'OtherQuantityHelperFactor'),
]
EDGES = {0x15F024: 0x243F48, 0x24C33C: 0x243F48,
         0x243FA8: 0x1774C8, 0x243FBE: 0x1774C8,
         0x244024: 0x24AF64, 0x244068: 0x24BB60,
         0x2440C6: 0x24B6F8, 0x2440DE: 0x24BBF0,
         0x244146: 0x24B6F8, 0x24415A: 0x24BBF0,
         0x2441B6: 0x24B6F8, 0x2441C6: 0x24BBF0,
         0x24BBDE: 0x3342A8, 0x24BBE4: 0x3342A8,
         0x24BC6E: 0x3342A8, 0x24BC74: 0x3342A8}
CHECKS = {0x243F4E: 'sub_s\tsp,sp,0x24',
          0x243FA6: 'mov_s\tr0,0x3', 0x243FA8: 'bl.d',
          0x243FAC: 'mov_s\tr21,r0', 0x243FD6: 'sub\tr21,r0,0x1',
          0x24400E: 'st\tr21,[r15,48]', 0x2440A8: 'st\tr21,[r14,60]',
          0x244126: 'st\tr21,[r14,60]', 0x2441B2: 'st\tr21,[r14,60]',
          0x244210: 'ld_s\tr0,[sp,0x5c]', 0x244214: ';0x24422c',
          0x24421E: 'bhs_s', 0x244224: ';0x243fd6',
          0x2441E0: 'ld.as\tr0,[pcl,-105]',
          0x15F01C: 'ld\tr0,[r0,144]', 0x15F020: 'st_s\tr0,[sp,0]',
          0x334114: 'st.aw\tr21,[sp,-4]', 0x3341BE: 'ld\tr21,[sp,32]',
          0x24BBE2: 'ld_s\tr0,[r14,0x30]', 0x24BC72: 'ld_s\tr0,[r14,0x3c]'}


def main():
    blocks, payloads, block_dir = verified_payloads(ROOT)
    block = next(b for b in blocks if b['index'] == 0)
    def word(address):
        offset = address - block['load_address_candidate']
        assert 0 <= offset <= len(payloads[0]) - 4
        return struct.unpack_from('<I', payloads[0], offset)[0]
    literals = {0x24403C: 0x08200001, 0x244054: 0x0820000C, 0x2444B0: 0x08200008}
    for address, expected in literals.items():
        assert word(address) == expected
    assert (0x2441E0 & ~3) - 105 * 4 == 0x24403C
    # push blink + r25..r13 + local0x24: caller SP is current SP+0x5c.
    assert 4 + 13 * 4 + 0x24 == 0x5C
    tools = ROOT / 'work/build-arc/binutils'
    listings = []
    with tempfile.TemporaryDirectory(prefix='s33-workspace-retry-') as td:
        elf, back = Path(td) / '0.elf', Path(td) / '0.bin'
        run([tools / 'objcopy', '-I', 'binary', '-O', 'elf32-littlearc', '-B', 'arc',
             '--rename-section', '.data=.text,alloc,load,readonly,code,contents',
             '--change-section-vma', f'.data={block["load_address_candidate"]:#x}',
             '--strip-all', block_dir / block['file'], elf])
        run([tools / 'objcopy', '--dump-section', f'.text={back}', elf])
        assert back.read_bytes() == payloads[0]
        for start, end, label in WINDOWS:
            listing = run([tools / 'objdump', '-d', '-m', 'arc:ARC700', '-EL',
                           f'--start-address={start:#x}', f'--stop-address={end:#x}', elf])
            assert 'out of bounds' not in listing.lower()
            listings.append('WINDOW ' + label + '\n' + listing.replace(str(elf), 'verified-block0.elf'))
    listing = '\n'.join(listings)
    decoded = {}
    for line in listing.splitlines():
        match = re.match(r'^\s*([0-9a-f]+):\t([^\t]+)\t(\S+)\t?(.*)$', line)
        if match:
            decoded[int(match[1], 16)] = (len(match[2].split()) * 2, match[3], match[4], line)
    for address, expected in CHECKS.items():
        assert expected in decoded[address][3], decoded[address]
    for site, target in EDGES.items():
        assert f';0x{target:x}' in decoded[site][3], decoded[site]
    for index, reg in enumerate(range(25, 12, -1)):
        assert f'st.aw\tr{reg},[sp,-4]' in decoded[0x334104 + index * 4][3]

    def execute(start, stops, regs, mem):
        """Only arithmetic, memory and branches in the selected allocation/tail slices."""
        pc, comparison = start, None
        for _ in range(100):
            if pc in stops:
                return pc
            size, op, args, _ = decoded[pc]
            args = args.split(';')[0].strip()
            parts = args.split(',')
            def val(s):
                return regs[s] if s in regs else int(s, 0)
            if op in ('ld_s', 'st_s', 'ld', 'st'):
                match = re.fullmatch(r'(r\d+),\[(r\d+|sp),(0x[0-9a-f]+|\d+)\]', args)
                assert match, (hex(pc), args)
                reg, base, off = match.groups()
                address = (regs[base] + int(off, 0)) & 0xFFFFFFFF
                if op in ('ld_s', 'ld'):
                    regs[reg] = mem[address]
                else:
                    mem[address] = regs[reg]
            elif op == 'cmp_s':
                comparison = (val(parts[0]), val(parts[1]))
            elif op in ('b_s', 'beq_s', 'bne', 'bls_s', 'bhs_s'):
                take = op == 'b_s' or {
                    'beq_s': lambda a, b: a == b, 'bne': lambda a, b: a != b,
                    'bls_s': lambda a, b: a <= b, 'bhs_s': lambda a, b: a >= b,
                }.get(op, lambda a, b: False)(*(comparison or (0, 0)))
                if take:
                    pc = int(re.search(r';0x([0-9a-f]+)', decoded[pc][2])[1], 16)
                    continue
            elif op == 'mov_s':
                regs[parts[0]] = val(parts[1])
            elif op in ('add_s', 'add1_s', 'add1', 'add2_s', 'add2', 'add3', 'sub_s', 'sub', 'lsr_s', 'lsr', 'asl_s'):
                a = val(parts[1]); b = val(parts[2])
                if op.startswith('add'):
                    result = a + (b << {'add1_s': 1, 'add1': 1, 'add2_s': 2, 'add2': 2, 'add3': 3}.get(op, 0))
                elif op.startswith('sub'):
                    result = a - b
                elif op.startswith('lsr'):
                    result = a >> b
                else:
                    result = a << b
                regs[parts[0]] = result & 0xFFFFFFFF
            else:
                raise AssertionError((hex(pc), op, args))
            pc += size
        raise AssertionError('Slice did not terminate')

    base, workspace, stack = 0x0F79B180, 0x4453DC, 0x10000
    align = lambda n: (n + 7) & ~7
    rng = random.Random(3304)
    allocation_cases = 0
    for q0, q1, d0, d1 in [(1, 1, 1, 1), (8, 16, 32, 16),
                           (65535, 65535, 65535, 65535)] + [
            tuple(rng.randrange(1, 65536) for _ in range(4)) for _ in range(2048)]:
        for alternate in (False, True):
            regs = dict(r0=q0, r1=0, r2=0, r3=0, r13=workspace, r18=base, sp=stack)
            mem = {workspace + 8: d0, workspace + 12: d1,
                   stack + 0x1C: q0, stack + 0x20: q1}
            if alternate:
                regs['r0'] = d1
                execute(0x2441D2, {0x244210}, regs, mem)
                p0 = base + align(max(q0, q1))
                expected_end = align(p0 + 2 * max(d0, 2 * d1))
                expected = [p0, p0, p0 + 2 * d1]
            else:
                execute(0x24405C, {0x244068}, regs, mem)
                regs['r0'] = d0
                execute(0x24406E, {0x24407C}, regs, mem)
                regs['r0'] = q1
                execute(0x2440D2, {0x2440DE}, regs, mem)
                regs['r0'] = d1
                execute(0x2440E4, {0x244210}, regs, mem)
                p0 = base + align(q0)
                p1 = p0 + 2 * d0 + align(q1)
                expected, expected_end = [p0, p1, p1 + 2 * d1], p1 + 4 * d1
            assert [mem[workspace + off] for off in (0x10, 0x14, 0x18)] == expected
            assert regs['r1'] == expected_end
            allocation_cases += 1

    # bl.d executes the next instruction before the callee overwrites r0.
    regs = dict(r0=0, r21=0)
    execute(0x243FA6, {0x243FA8}, regs, {})
    execute(0x243FAC, {0x243FAE}, regs, {})
    regs['r0'] = 0  # successful region-query return, after the delay slot
    assert regs['r21'] == 3
    tail_cases = 0
    for bypass in (0, 1, 2, 0xFFFFFFFF):
        for required in (0, 0x3FFF, 0x4000, 0x4001, 0x10000):
            for k in (3, 2, 1):
                regs = dict(r0=0, r1=base + required, r21=k, sp=stack)
                mem = {stack + 0x5C: bypass, stack + 8: base,
                       stack + 0x10: 0x4000, stack + 4: 0}
                stop = execute(0x244210, {0x24422C, 0x243FDA, 0x244228}, regs, mem)
                expected = (0x24422C if bypass == 1 or required <= 0x4000 else
                            0x243FDA if k > 1 else 0x244228)
                assert stop == expected
                if stop == 0x243FDA:
                    assert regs['r21'] == k - 1
                tail_cases += 1
    output = ROOT / 'Ghidra_Results/ghidra_reports/stage_workspace_retry'
    output.mkdir(parents=True, exist_ok=True)
    result = dict(firmware='S33 V1.1 static only', verified_blocks=16,
        block_sha256={str(b['index']): b['sha256'] for b in blocks},
        script_sha256=sha(Path(__file__).read_bytes()), elf_roundtrip_blocks=[0],
        windows=[dict(start=hex(a), end=hex(b), label=l) for a, b, l in WINDOWS],
        checked_edges={hex(a): hex(b) for a, b in EDGES.items()},
        checked_instructions=len(CHECKS), checked_stack_saves=13,
        checked_literals={hex(a): hex(b) for a, b in literals.items()},
        allocation_cases=allocation_cases, tail_cases=tail_cases,
        retry_parameters=[3, 2, 1], capacity_bytes=0x4000,
        stack_argument_offset='0x5c', capacity_bypass_value=1,
        error_codes=dict(admission='0x0820000c', zero_quantity='0x08200001', exhausted='0x08200008'),
        observations=['Counter3 is captured before query3 returns, in its call delay slot',
            'Normal allocation reserves Q0 rounded8,2*D0,Q1 rounded8,4*D1',
            'Alternate allocation overlays P0/P1 after rounded8 max(Q0,Q1), then reserves2*max(D0,2*D1) rounded8',
            'Only incoming stack argument exactly1 bypasses capacity comparison',
            'Over-capacity branch retries at2,1 then returns exhausted; descriptors were already written'],
        limits=['Quantities are supplied at helper boundaries, not calculated by a hardware emulator',
            'Allocation tests use nonzero uint16 helper results and nonwrapping addresses',
            'Tail tests cover listed boundary values; no proof of arbitrary address overflow safety',
            'Three-pass bound assumes returning callees obey the register-preservation ABI',
            'No device execution, direction, last physical access or global bank-index proof'])
    (output / 'gnu_verified.txt').write_text(listing)
    (output / 'verified_evidence.json').write_text(json.dumps(result, indent=2) + '\n')
    print(f'PASS:16 hashes, block0 roundtrip, {len(WINDOWS)} windows, {len(EDGES)} edges, '
          f'{len(CHECKS)} instructions, {len(literals)} pools, '
          f'{allocation_cases} decoded allocations, {tail_cases} tail decisions, delay-slot counter=3')


if __name__ == '__main__':
    main()
