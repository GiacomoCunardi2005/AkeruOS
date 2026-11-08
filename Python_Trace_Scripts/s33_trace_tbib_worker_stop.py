#!/usr/bin/env python3
"""Static pre-handoff worker request/ack and six-pair boot-info copy."""
import json
import random
import re
import struct
import tempfile
from pathlib import Path
from s33_trace_state_dispatch import run, sha
from s33_trace_tbib_tbm_handoff import ROOT, TBIB_SHA, FIRMWARE_SHA

WINDOWS = [(0x1000414, 0x100042A, 'SuccessPathBeforeKernelExit'),
    (0x1002314, 0x100233E, 'WorkerStopRequestAndAckWait'),
    (0x10021A4, 0x10021C0, 'WorkerWaitAndExplicitClear'),
    (0x10021EC, 0x100221A, 'WorkerStopBitTimerCancelAndAck'),
    (0x10038B8, 0x10038C8, 'TimerCancelWrapper'),
    (0x100C158, 0x100C170, 'ConditionalPreparationCall'),
    (0x101611C, 0x1016120, 'PreparationLeafStub'),
    (0x100BFA8, 0x100BFAC, 'SecondPreparationStub'),
    (0x10006EC, 0x1000712, 'CopySixPairsToBootInfo'),
    (0x100029E, 0x10002A4, 'BootInfoPointerBinding'),
    (0x100062A, 0x1000638, 'BootInfoMagic'),
    (0x100691E, 0x1006946, 'EventCreateFlags'),
    (0x101ED54, 0x101ED6A, 'EventInitialBitsAndAutoClearField'),
    (0x1006998, 0x10069BC, 'SetEventWrapper'),
    (0x10069BC, 0x10069E0, 'ClearEventWrapper'),
    (0x1006A82, 0x1006AA4, 'WaitWrapperLowerCall'),
    (0x102D9C0, 0x102D9E8, 'AllAnyAndConditionalClear'),
    (0x101EE4A, 0x101EE54, 'SetEventUsesOr'),
    (0x101EF94, 0x101EF9A, 'ExplicitClearUsesBic')]
CHECKS = {0x100041A: ';0x1002314', 0x100041E: ';0x10006ec', 0x1000424: ';0x1006d20',
    0x1002316: ';0x100c158', 0x100231A: ';0x100bfa8',
    0x1002324: ';0x1006998', 0x1002328: 'bset_s\tr1,r1,0x1e',
    0x100232C: 'ror\tr1,0x1', 0x1002330: 'mov_s\tr2,0x1',
    0x1002332: ';0x10069e0', 0x1002336: 'mov_s\tr3,0', 0x100233C: 'mov_s\tr0,0',
    0x10021AA: ';0x10069e0', 0x10021BA: ';0x10069bc',
    0x10021FC: 'btst_s\tr0,0x1e', 0x10021FE: ';0x10021a4',
    0x1002200: ';0x10038b8', 0x1002208: ';0x1006998',
    0x100220C: 'ror\tr1,0x1', 0x1002210: ';0x100b5b0',
    0x10038BA: ';0x1013ad8', 0x100C164: ';0x101611c',
    0x101611C: 'j_s\t[blink]', 0x100BFaa: 'mov_s\tr0,0',
    0x10006EE: 'ld.as\tr3,[pcl,-133]', 0x1000706: 'st_s\tr2,[r0,0x3c]',
    0x100070A: 'st_s\tr13,[r0,0x40]', 0x100070C: ';0x10006f4',
    0x10002A2: 'st_s\tr1,[r0,0x20]', 0x1000634: 'st_s\tr1,[r0,0]',
    0x100692C: 'bmsk_s\tr14,r14,0', 0x100693E: ';0x101ed3c',
    0x101ED62: 'st_s\tr15,[r0,0x18]', 0x101ED68: 'st_s\tr1,[r0,0x1c]',
    0x102D9C6: 'and\tr6,r5,r1', 0x102D9CA: ';0x102d9da',
    0x102D9DC: 'bbit0\tr2,0,12', 0x101EE4E: 'or_s\tr3,r3,r1',
    0x101EF96: 'bic_s\tr2,r2,r1', 0x10069AC: ';0x101ee20',
    0x10069D0: ';0x101ef74', 0x1006A94: ';0x101f000'}


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
    literals = {0x1002354: 0x03200002, 0x1002358: 0x60F7F773,
        0x1006B24: 0x1041864, 0x1002364: 0x1041180,
        0x10004D8: 0x1090000, 0x1000714: 0x1041120,
        0x1000468: 0x900, 0x1000450: 0x1041100, 0x10006E0: 0x4F464E49}
    for address, expected in literals.items(): assert word(address) == expected
    event = struct.unpack_from('<14I', body, 0x4189C)
    assert event == (0x45564E4C, 0x03200002, 2) + (0,) * 11
    assert 0x1041864 + 0x38 == 0x104189C
    assert (0x10006EE & ~3) - 133 * 4 == 0x10004D8
    tools = ROOT / 'work/build-arc/binutils'; listings = []
    with tempfile.TemporaryDirectory(prefix='s33-tbib-worker-stop-') as td:
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

    def trace(start, end, regs, memory, returns):
        """Dataflow/call slices only. Frames are abstract; callees return supplied values."""
        calls, writes, comparison = [], [], (0, 0)
        def value(s): return regs[s] if s in regs else int(s, 0)
        def step(pc):
            nonlocal comparison
            size, op, raw, _ = decoded[pc]; args = raw.split(';')[0].strip(); parts = args.split(',')
            if op in ('ld_s', 'ld.as', 'st_s'):
                reg, br, off = re.fullmatch(r'(r\d+),\[(r\d+|pcl),(0x[0-9a-f]+|-?\d+)\]', args).groups()
                address = ((pc & ~3) if br == 'pcl' else value(br)) + int(off, 0) * (4 if op == 'ld.as' else 1)
                if op == 'st_s': memory[address] = value(reg); writes.append(address)
                else: regs[reg] = word(address) if br == 'pcl' else memory[address]
            elif op in ('mov_s', 'mov'): regs[parts[0]] = value(parts[1])
            elif op == 'bset_s': regs[parts[0]] = value(parts[1]) | (1 << value(parts[2]))
            elif op == 'ror':
                x = value(parts[1]); regs[parts[0]] = ((x >> 1) | (x << 31)) & 0xFFFFFFFF
            elif op in ('add3', 'add3_s'): regs[parts[0]] = (value(parts[1]) + 8 * value(parts[2])) & 0xFFFFFFFF
            elif op == 'add_s': regs[parts[0]] = (value(parts[1]) + value(parts[2])) & 0xFFFFFFFF
            elif op == 'extb_s': regs[parts[0]] = value(parts[1]) & 255
            elif op == 'cmp_s': comparison = (value(parts[0]), value(parts[1]))
            elif op in ('push_s', 'pop_s'): pass
            else: raise AssertionError((hex(pc), op, args))
            return pc + size
        pc = start
        for _ in range(256):
            if pc == end: return calls, writes
            size, op, args, _ = decoded[pc]
            if op in ('bl', 'bl.d'):
                target = int(re.search(r';0x([0-9a-f]+)', args)[1], 16)
                pc += size
                if op == 'bl.d': pc = step(pc)
                calls.append((target, tuple(regs[f'r{i}'] for i in range(4))))
                regs['r0'] = returns.get(target, 0)
            elif op == 'blo_s':
                pc = int(re.search(r';0x([0-9a-f]+)', args)[1], 16) if comparison[0] < comparison[1] else pc + size
            elif op in ('j_s', 'j_s.d'):
                if op == 'j_s.d': pc = step(pc + size)
                else: pc += size
                assert pc == end
                return calls, writes
            else: pc = step(pc)
        raise AssertionError('Slice did not terminate')

    rng = random.Random(3309); stop_cases = copy_cases = 0
    for i in range(256):
        rc = [0, 1, 0xFFFFFFFF][i] if i < 3 else rng.getrandbits(32)
        regs = {f'r{r}': 0 for r in range(16)}
        calls, _ = trace(0x1002314, 0x100233E, regs, {}, {0x10069E0: rc, 0x1006998: rc})
        assert [(t, a[:2]) for t, a in calls[-2:]] == [(0x1006998, (0x03200002, 0x40000000)), (0x10069E0, (0x03200002, 0x80000000))]
        assert calls[-1][1][2:] == (1, 0) and regs['r0'] == 0
        regs = {f'r{r}': 0 for r in range(16)}; regs['r14'] = 0x1041180
        calls, _ = trace(0x1002200, 0x1002210, regs, {0x1041180: 0x12345678}, {0x10038B8: rc})
        assert calls[0] == (0x10038B8, (0x12345678, 0, 0, 0))
        assert calls[1][0] == 0x1006998 and calls[1][1][:2] == (0x03200002, 0x80000000)
        stop_cases += 1
        values = [rng.getrandbits(32) for _ in range(12)]
        memory = {0x1090000 + 4 * j: v for j, v in enumerate(values)} | {0x1041120: 0x900}
        regs = {f'r{r}': 0 for r in range(16)}
        calls, writes = trace(0x10006EC, 0x1000712, regs, memory, {})
        assert calls == [] and writes == list(range(0x93C, 0x96C, 4))
        assert [memory[0x93C + 4 * j] for j in range(12)] == values
        copy_cases += 1
    output = ROOT / 'Ghidra_Results/ghidra_reports/tbib_worker_stop'; output.mkdir(parents=True, exist_ok=True)
    result = dict(firmware='S33 V1.1 static only', firmware_sha256=sha(firmware), tbib_payload_sha256=sha(payload),
        script_sha256=sha(Path(__file__).read_bytes()), tbib_checksum=hex(checksum), elf_roundtrip='TBIB body',
        windows=[dict(start=hex(a), end=hex(b), label=l) for a, b, l in WINDOWS], checked_instructions=len(CHECKS),
        checked_literals={hex(a): hex(v) for a, v in literals.items()}, event_record='0x0104189c', event_id='0x03200002',
        request_mask='0x40000000', ack_mask='0x80000000', event_initial_flags=2, auto_clear_argument=event[2] & 1,
        decoded_stop_scenarios=stop_cases, decoded_six_pair_copies=copy_cases,
        boot_info=dict(pointer_cell='0x01041120', bound_base='0x900', source='0x01090000', copied_span=['0x93c','0x96c'], bytes=48),
        observations=['Caller sets request bit30 then waits for ack bit31 with options1 and zero timeout argument',
            'Worker sees request bit30, calls timer cancellation, sets ack bit31 without comparing cancellation return, then reaches scheduler call',
            'Stop wrapper overwrites returned wait status with0; event initialized with no auto-clear',
            'Second success-path call copies six raw word pairs into boot INFO rather than stopping a controller'],
        limits=['Calls are stubs returning synthetic codes, not firmware execution or real timing tests',
            'Event initialization/registration and successful scheduling are prerequisites; no global freshness proof for ack',
            'Timer cancellation internals, DMA/controller quiescence and final physical use are not proven',
            'Copied word values are runtime data; host model does not assign physical meanings to the six pairs',
            'No modified boot, recovery or V1.0 compatibility established'])
    (output / 'gnu_verified.txt').write_text(listing)
    (output / 'verified_evidence.json').write_text(json.dumps(result, indent=2) + '\n')
    print(f'PASS: firmware/TBIB identity,checksum,roundtrip,{len(WINDOWS)} windows,'
          f'{len(CHECKS)} instructions,{len(literals)} literals,event record,'
          f'{stop_cases} stop scenarios,{copy_cases} six-pair copies')


if __name__ == '__main__': main()
