#!/usr/bin/env python3
"""Bounded decoded ARC slices: event wait, context switch, wake and resume."""
import json
from pathlib import Path
import random
import re
import struct
import tempfile

from s33_trace_state_dispatch import verified_payloads, run, sha

ROOT = Path(__file__).resolve().parents[1]
WINDOWS = [
    (0x158D90, 0x158E1E, 'EventWrapperDeadlineAndStatus'),
    (0x23C938, 0x23C940, 'WaitTrampoline'),
    (0x2C9994, 0x2C9AE0, 'WaitPredicateQueueAndResume'),
    (0xB2C74, 0xB2D0C, 'BlockingContextSaveAndUnlink'),
    (0xB2D34, 0xB2D50, 'ConditionalRescheduleGate'),
    (0xB2DD8, 0xB2E40, 'ReadySelectionAndIdle'),
    (0xB2E40, 0xB2F38, 'OrdinaryContextRestore'),
    (0x23C674, 0x23C6A2, 'EventQueueInitialization'),
    (0x23C758, 0x23C8AC, 'EventSignalAndReadyInsertion'),
    (0x15968C, 0x1596B8, 'OriginalAuxWorkerWait'),
    (0x3371C0, 0x3371D0, 'BareCpuSleepHelper'),
    (0x17B790, 0x17B794, 'StatusZeroBranch'),
    (0x17B858, 0x17B85C, 'StatusZeroReturnDelaySlot'),
]
CHECKS = {
    0x158DB4: 'mov_s\tr3,0', 0x158DBC: 'mov_s\tr2,r16',
    0x23C93C: 'mov\tr4,0', 0x2C99B2: 'bset_s\tr0,r0,0xc',
    0x2C9A2C: 'st\tr1,[r15,196]', 0x2C9A6A: 'st_s\tr2,[r15,0x8]',
    0x2C9A6C: 'st_s\tr0,[r15,0x30]', 0x2C9AC2: ';0xb2c74',
    0xB2C74: 'sub\tsp,sp,164', 0xB2C7E: 'st\tblink,[sp,52]',
    0xB2C82: 'st\tblink,[sp,44]', 0xB2CC4: 'st\tgp,[sp,132]',
    0xB2CC8: 'st\tfp,[sp,136]', 0xB2CE2: 'st\tsp,[r3,20]',
    0xB2D04: 'st_s\tr3,[r0,0]', 0xB2D0A: 'st_s\tr0,[r3,0x4]',
    0xB2E08: 'sleep\t0', 0xB2E22: 'ld\tsp,[r3,20]',
    0xB2E28: 'st_s\tr3,[r2,0x1c]', 0xB2E92: 'ld\tgp,[sp,132]',
    0xB2E9A: 'ld\tfp,[sp,136]', 0xB2F2A: 'ld_s\tr0,[sp,0x34]',
    0xB2F30: 'add\tsp,sp,164', 0xB2F34: 'j.f\t[r30]',
    0x23C812: 'st\tr7,[r4,48]', 0x23C826: 'st\tr11,[r4,8]',
    0x23C842: 'st\tr4,[r1,4]', 0x23C854: ';0x23c862',
    0x23C866: 'bic_s\tr3,r3,r2', 0x159698: ';0x158d04',
    0x15969C: 'mov_s\tr3,r2', 0x3371C0: 'sleep\t0',
    0x158DF2: ';0x17b770', 0x158DF6: 'mov_s\tr0,r16',
    0x17B792: ';0x17b858', 0x17B858: 'j_s.d\t[blink]', 0x17B85A: 'mov_s\tr0,0',
}


def read(memory, address, size=4):
    assert all(address+i in memory for i in range(size)), hex(address)
    return int.from_bytes(bytes(memory[address+i] for i in range(size)), 'little')


def write(memory, address, value, size=4):
    assert all(address+i in memory for i in range(size)), hex(address)
    for i, byte in enumerate((value & ((1 << (size*8))-1)).to_bytes(size, 'little')):
        memory[address+i] = byte


def execute(lines, pc, stops, registers, memory, auxiliary):
    # shortcut: decoded slices below only; CPU flags/interrupt effects are not emulated.
    zero = False

    def value(item):
        if item == 'lp_count': return auxiliary[item]
        return registers[item] if item in registers else int(item, 0)

    def data(site):
        nonlocal zero
        op, args, size = lines[site]
        parts = args.split(',')
        if op.startswith(('ld', 'st')):
            match = re.fullmatch(r'(\w+),\[([^,\]]+)(?:,([^\]]+))?\]', args)
            assert match, (op, args)
            reg, base, offset = match.groups()
            address = (value(base) + (value(offset) if offset else 0)) & 0xffffffff
            width = 2 if op in ('ldw_s', 'stw_s', 'ldh', 'sth') else 4
            if op.startswith('ld'):
                registers[reg] = read(memory, address, width)
            else:
                write(memory, address, value(reg), width)
        elif op in ('lr', 'sr'):
            reg, aux = parts
            key = aux.strip('[]')
            if op == 'lr':
                registers[reg] = auxiliary[key]
            else:
                auxiliary[key] = value(reg)
        elif op == 'flag':
            auxiliary.setdefault('flag_requests', []).append(value(args))
        elif op in ('nop', 'nop_s'):
            pass
        elif op in ('tst', 'tst_s'):
            zero = not value(parts[0]) & value(parts[1])
        else:
            assert len(parts) >= 2, (hex(site), op, args)
            baseop = op.removesuffix('.f').removesuffix('_s')
            a = value(parts[1])
            b = value(parts[2]) if len(parts) == 3 else None
            if baseop == 'mov': result = a
            elif baseop == 'add': result = a+b
            elif baseop == 'add2': result = a+4*b
            elif baseop == 'sub': result = a-b
            elif baseop == 'sub2': result = a-4*b
            elif baseop == 'sub3': result = a-8*b
            elif baseop == 'and': result = a & b
            elif baseop == 'or': result = a | b
            elif baseop == 'bic': result = a & ~b
            elif baseop == 'bset': result = a | 1 << b
            else: raise AssertionError((hex(site), op, args))
            result &= 0xffffffff
            if parts[0] == 'lp_count': auxiliary['lp_count'] = result
            elif parts[0] != '0': registers[parts[0]] = result
            if op.endswith('.f'): zero = result == 0
        return size

    for _ in range(500):
        if pc in stops:
            return pc
        op, args, size = lines[pc]
        parts = args.split(',')
        condition = None
        if op in ('breq_s', 'breq', 'brne_s', 'brne', 'brhs'):
            a, b = value(parts[0]), value(parts[1])
            condition = (a >= b) if op == 'brhs' else ((a != b) if 'brne' in op else (a == b))
        elif op in ('bbit0', 'bbit1'):
            condition = bool(value(parts[0]) & 1 << value(parts[1])) == (op == 'bbit1')
        elif op in ('beq', 'beq_s', 'beq.d', 'jeq', 'bne', 'bne_s', 'bne.d'):
            condition = not zero if op.startswith('bne') else zero
        elif op in ('b_s', 'b.d'):
            condition = True
        elif op == 'j.f':
            pc = value(args.strip('[]'))
            continue
        if condition is None:
            pc += data(pc)
        else:
            match = re.search(r';0x([0-9a-f]+)', args)
            target = int(match[1], 16) if match else int(args, 0)
            following = pc+size
            if op.endswith('.d'):
                following += data(following)
            pc = target if condition else following
    raise AssertionError('slice did not terminate')


def main():
    blocks, payloads, directory = verified_payloads(ROOT)
    info = {b['index']: b for b in blocks}

    def word(i, address):
        return struct.unpack_from('<I', payloads[i], address-info[i]['load_address_candidate'])[0]

    literals = {0x159990: 0x04700004, 0x36B2B8: 0, 0x36B2B4: 0}
    for address, expected in literals.items():
        assert word(0 if address < 0x360800 else 1, address) == expected
    event_record = [word(1, 0x372AB8+4*i) for i in range(14)]
    assert event_record == [0x45564E4C, 0x04700004, 2]+[0]*11
    listings, lines = [], {}
    tools = ROOT/'work/build-arc/binutils'
    with tempfile.TemporaryDirectory(prefix='s33-task-wait-') as temporary:
        elf, back = Path(temporary)/'0.elf', Path(temporary)/'0.bin'
        run([tools/'objcopy', '-I', 'binary', '-O', 'elf32-littlearc', '-B', 'arc',
             '--rename-section', '.data=.text,alloc,load,readonly,code,contents',
             '--change-section-vma', f'.data={info[0]["load_address_candidate"]:#x}',
             '--strip-all', directory/info[0]['file'], elf])
        run([tools/'objcopy', '--dump-section', f'.text={back}', elf])
        assert back.read_bytes() == payloads[0]
        for start, end, name in WINDOWS:
            text = run([tools/'objdump', '-d', '-m', 'arc:ARC700', '-EL',
                        f'--start-address={start:#x}', f'--stop-address={end:#x}', elf])
            assert 'out of bounds' not in text.lower(), name
            listings.append('WINDOW '+name+'\n'+text.replace(str(elf), 'verified-block0.elf'))
    listing = '\n'.join(listings)
    for line in listing.splitlines():
        match = re.match(r'^\s*([0-9a-f]+):\t([^\t]+)\t(\S+)\t?(.*)$', line)
        if match:
            address = int(match[1], 16)
            lines[address] = (match[3], match[4].split(';')[0].strip(), len(match[2].replace(' ', ''))//2)
            # Preserve branch targets while dropping objdump's unscaled pool comments elsewhere.
            if ';0x' in match[4] and match[3].startswith(('b', 'j')):
                lines[address] = (match[3], match[4], lines[address][2])
    for address, fragment in CHECKS.items():
        line = next(l for l in listing.splitlines() if re.match(rf'^\s*{address:x}:', l))
        assert fragment in line, line
    # Model addresses are synthetic and separate from firmware placement claims.
    K, E, D, QA, QB, T, STACK = 0x10000, 0x20000, 0x30000, 0x50000, 0x50020, 0x60000, 0xA0000
    rng = random.Random(0x533A17)
    outcomes = {'other_task_selected': 0, 'idle_selected': 0, 'resumed': 0}
    for case in range(512):
        memory = {}
        for start, size in ((K, 0x400), (E, 0x38), (D, 0xEC), (QA, 0x10), (QB, 0x10),
                            (T, 0xEC), (STACK-512, 512), (0, 4), (0x369348, 4), (0x36B2B4, 8)):
            memory.update({address: 0 for address in range(start, start+size)})
        write(memory, 0, rng.getrandbits(32))  # Idle scan delay slot reads this word; value is discarded.
        for address, val in ((0x369348, K), (K+0x1C, D), (K+0x2C, QA), (K+0x60, 0xC0000),
                             (D, QA), (D+4, QA), (D+8, 2), (D+0x1C, QA), (D+0x68, 1),
                             (QA, D), (QA+4, D), (QA+8, QB),
                             (E+8, E+8), (E+12, E+8), (E+0x14, 1),
                             (T+0x14, 0xB0000), (T+0x1C, QB)):
            write(memory, address, val)
        idle = bool(case & 1)
        for address, val in ((QB, QB if idle else T), (QB+4, QB if idle else T),
                             (T, QB), (T+4, QB)):
            write(memory, address, val)
        option, auto = (case >> 1) & 1, (case >> 2) & 1
        mask = rng.getrandbits(32) or 1
        write(memory, E+0x1C, auto)
        regs = {f'r{i}': rng.getrandbits(32) for i in range(31)}
        regs.update(r13=E, r14=K, r15=D, r1=mask, r2=option, r3=0, r4=0,
                    sp=STACK, gp=rng.getrandbits(32), fp=rng.getrandbits(32), blink=0x2C9AC6)
        aux = {name: rng.getrandbits(32) for name in ('status32', 'lp_start', 'lp_end', 'lp_count')}
        assert execute(lines, 0x2C99E0, {0x2C99FA, 0x2C9A28}, regs, memory, aux) == 0x2C9A28
        regs.update(r1=mask, r2=option)
        assert execute(lines, 0x2C9A28, {0x2C9AC2}, regs, memory, aux) == 0x2C9AC2
        assert read(memory, E+0x10, 2) == 1 and read(memory, E+8) == D+0xBC
        assert read(memory, D+0xC4) == mask and read(memory, D+8) == 0x42D
        assert read(memory, D+0x30) == E+8
        assert bool(read(memory, D+0x6C) & 128) == bool(option)
        saved = regs.copy()
        saved_aux = aux.copy()
        assert execute(lines, 0xB2C74, {0xB2DD8}, regs, memory, aux) == 0xB2DD8
        frame = STACK-0xA4
        assert read(memory, D+0x14) == frame
        slots = {0x14: saved['r13'], 0x18: saved['r14'], 0x1C: saved['r15'],
                 0x20: saved_aux['lp_count'], 0x24: saved_aux['lp_start'], 0x28: saved_aux['lp_end'],
                 0x2C: 0x2C9AC6, 0x30: saved_aux['status32'], 0x34: 0x2C9AC6,
                 0x84: saved['gp'], 0x88: saved['fp']}
        slots.update({0x5C+4*(i-16): saved[f'r{i}'] for i in range(16, 26)})
        assert all(read(memory, frame+offset) == val for offset, val in slots.items())
        assert read(memory, QA) == read(memory, QA+4) == QA
        selected = execute(lines, 0xB2DD8, {0xB2E2C, 0xB2E08}, regs, memory, aux)
        if idle:
            assert selected == 0xB2E08 and regs['sp'] == 0xC0000 and read(memory, K+0x1C) == K+0x360
            outcomes['idle_selected'] += 1
        else:
            assert selected == 0xB2E2C and regs['sp'] == 0xB0000 and read(memory, K+0x1C) == T
            outcomes['other_task_selected'] += 1
        # Signal path starts after the service has entered its critical region.
        regs.update(r0=E, r1=mask, r6=K, r7=0)
        assert execute(lines, 0x23C782, {0x23C86A}, regs, memory, aux) == 0x23C86A
        assert read(memory, E+0x10, 2) == 0 and read(memory, E+8) == read(memory, E+12) == E+8
        assert read(memory, D+0x30) == 0 and read(memory, D+8) == 2
        assert read(memory, QA) == read(memory, QA+4) == D
        assert read(memory, E+0x18) == (0 if auto else mask)
        assert all(read(memory, D+offset) == 0 for offset in (0x7C, 0x80, 0x84))
        # A later scan from QA is a precondition here, not a fairness/preemption claim.
        regs.update(r1=QA, r2=K)
        assert execute(lines, 0xB2DD8, {0xB2E2C}, regs, memory, aux) == 0xB2E2C
        assert read(memory, K+0x1C) == D and regs['sp'] == read(memory, D+0x14)
        assert execute(lines, 0xB2E2C, {0x2C9AC6}, regs, memory, aux) == 0x2C9AC6
        assert regs['sp'] == STACK and regs['gp'] == saved['gp'] and regs['fp'] == saved['fp']
        assert all(regs[f'r{i}'] == saved[f'r{i}'] for i in range(13, 26))
        assert all(aux[key] == saved_aux[key] for key in ('lp_start', 'lp_end', 'lp_count'))
        assert aux['status32_l2'] == saved_aux['status32']
        assert execute(lines, 0x2C9A84, {0x2C9AA4}, regs, memory, aux) == 0x2C9AA4
        assert regs['r0'] == 0 and read(memory, D+0x68) == 0
        outcomes['resumed'] += 1
    predicate_cases = []
    for mask in (0, 1):
        for bits in (0, 1):
            for option in (0, 1):
                write(memory, E+0x18, bits)
                regs.update(r13=E, r1=mask, r2=option)
                pc = execute(lines, 0x2C99E0, {0x2C99FA, 0x2C9A28}, regs, memory, aux)
                matched = (bits & mask) == mask if option else bool(bits & mask)
                assert (pc == 0x2C99FA) == matched
                predicate_cases.append(dict(mask=mask, bits=bits, option=option, immediate=matched))
    for nesting in (0, 1, 0xFFFF):
        write(memory, K+0x18, nesting, 2)
        regs.update(r14=K)
        pc = execute(lines, 0x2C99A8, {0x2C99B4, 0x2C99C4}, regs, memory, aux)
        assert pc == (0x2C99C4 if nesting == 0 else 0x2C99B4)
        if nesting: assert regs['r0'] == 0x100D
    write(memory, E+0x14, 0)
    write(memory, D+0x68, 1)
    regs.update(r13=E, r14=K)
    assert execute(lines, 0x2C9A84, {0x2C9AA4}, regs, memory, aux) == 0x2C9AA4
    assert regs['r0'] == 0x1039
    multiple = []
    for auto in (0, 1):
        memory = {}
        second = D+0x100
        for start, size in ((K, 0x400), (E, 0x38), (D, 0x200), (QA, 0x10)):
            memory.update({address: 0 for address in range(start, start+size)})
        for address, val in ((K+0x2C, QA), (QA, QA), (QA+4, QA),
                             (E+8, D+0xBC), (E+12, second+0xBC), (E+0x1C, auto)):
            write(memory, address, val)
        write(memory, E+0x10, 2, 2)
        for task, mask, following, previous in ((D, 1, second+0xBC, E+8),
                                               (second, 2, E+8, D+0xBC)):
            for offset, val in ((8, 0x42D), (0x1C, QA), (0x30, E+8), (0x6C, 128),
                                (0xBC, following), (0xC0, previous), (0xC4, mask)):
                write(memory, task+offset, val)
        regs.update(r0=E, r1=3, r6=K, r7=0)
        execute(lines, 0x23C782, {0x23C86A}, regs, memory, aux)
        assert read(memory, D+8) == 2
        assert read(memory, E+0x10, 2) == auto
        assert read(memory, second+8) == (0x42D if auto else 2)
        assert read(memory, E+0x18) == (2 if auto else 3)
        multiple.append(dict(auto_clear=auto, after_signal_3=dict(waiters_remaining=auto,
                             bits=read(memory, E+0x18), second_ready=not bool(auto))))
        if auto:
            regs.update(r0=E, r1=0, r6=K, r7=0)
            execute(lines, 0x23C782, {0x23C86A}, regs, memory, aux)
            assert read(memory, second+8) == 2 and read(memory, E+0x10, 2) == 0
            assert read(memory, E+0x18) == 0
            multiple[-1]['after_second_signal_0'] = dict(waiters_remaining=0, bits=0, second_ready=True)
    out = ROOT/'Ghidra_Results/ghidra_reports/task_wait_switch'
    out.mkdir(parents=True, exist_ok=True)
    result = dict(firmware='S33 V1.1 static only', script_sha256=sha(Path(__file__).read_bytes()),
                  verified_blocks=16, block_sha256={str(b['index']): b['sha256'] for b in blocks},
                  elf_roundtrip_blocks=[0], windows=[dict(start=hex(a), end=hex(b), label=n) for a,b,n in WINDOWS],
                  checked_instructions=len(CHECKS), literals={hex(a): hex(v) for a,v in literals.items()},
                  event_record=dict(address='0x372ab8', words=event_record), cases=512, outcomes=outcomes,
                  boundary_predicates=predicate_cases, entry_guard_cases=3,
                  resumed_invalid_object_status='0x1039', multi_waiter_cases=multiple,
                  limits=['Decoded bounded slices, not a full CPU/RTOS emulator or target execution.',
                          'Model requires valid lists, task context, no deadline, initially missing nonzero mask, zero switch hooks, ordinary task flags.',
                          'FLAG requests are recorded, not executed; interrupt/cache/atomicity and all callers are not proven.',
                          'Idle slice models a readable word at address0 for the unconditional branch delay-slot load; no hardware mapping proof.',
                          'Wake and later selection of resumed task are separate modeled phases; no elapsed-time or fairness claim.',
                          'No Nikon event or RAM assigned to AkeruOS; no device operation.'])
    (out/'gnu_verified.txt').write_text(listing)
    (out/'verified_evidence.json').write_text(json.dumps(result, indent=2)+'\n')
    print(f'PASS: 16 hashes, block00 roundtrip, {len(WINDOWS)} windows, {len(CHECKS)} instructions, 512 cycles, 8 predicates, 3 entry guards, invalid-object return, 2 multi-waiter cases')


if __name__ == '__main__':
    main()
