#!/usr/bin/env python3
"""Verify TBIB shutdown continuation and bounded save/restore context semantics."""
import json
import random
import re
import struct
import tempfile
from pathlib import Path
from s33_trace_state_dispatch import run, sha
from s33_trace_tbib_tbm_handoff import ROOT, TBIB_SHA, FIRMWARE_SHA

WINDOWS = [
    (0x1000414, 0x100042A, 'BootSuccessShutdownCall'),
    (0x1006B5C, 0x1006BBC, 'BootstrapContextAndResumeBranch'),
    (0x1006D20, 0x1006D60, 'ShutdownCallbackStatusAndNonlocalReturn'),
    (0x103AF08, 0x103AF78, 'SaveContext'),
    (0x103AF78, 0x103AFF4, 'RestoreContext'),
    (0x101F096, 0x101F0B4, 'SaveOriginalVectorBase'),
    (0x101F028, 0x101F048, 'VectorBaseGetSet'),
    (0x101F52A, 0x101F546, 'InstallShutdownCallbackInDelaySlot'),
    (0x10139D8, 0x10139E2, 'KernelContextGetter'),
    (0x101F6F4, 0x101F70A, 'ShutdownCPURequests'),
    (0x1029C40, 0x1029C4C, 'DataCacheFlushRequest'),
    (0x1029BFC, 0x1029C08, 'DataCacheInvalidateRequest'),
    (0x103DE54, 0x103DE60, 'KernelBridgeThenExit'),
    (0x103B51C, 0x103B540, 'RuntimeExitOnceGuard'),
    (0x103BB88, 0x103BBA8, 'TwoExitHooks'),
    (0x103B478, 0x103B4B4, 'ExitArrayRegistration'),
    (0x103B4B4, 0x103B4D0, 'ExitArrayReverseDispatch'),
    (0x103ADF8, 0x103AE08, 'RegisterFinalizationAndHandoffRecord'),
    (0x101F614, 0x101F61C, 'ConstructorsDuringKernelSetup'),
    (0x103FE68, 0x103FE78, 'FinalizationListWrapper'),
]
CHECKS = {
    0x1000422: 'mov_s\tr0,r17', 0x1000424: ';0x1006d20',
    0x1006B78: 'mov_s\tr0,0x1090988', 0x1006B7E: ';0x103af08',
    0x1006B82: 'sub_s\tsp,sp,0x14', 0x1006B8A: ';0x1006bbc',
    0x1006B92: ';0x101f034', 0x1006B96: 'ld.as\tr0,[r13,94]',
    0x1006B9A: 'ld.as\tr14,[r13,95]', 0x1006BA0: 'mov\tblink,r17',
    0x1006D42: 'ld.as\tr2,[r0,76]', 0x1006D4A: 'st.as\tr13,[r0,95]',
    0x1006D50: 'jl_s\t[r2]', 0x1006D52: 'mov_s\tr0,0x1090988',
    0x1006D58: ';0x103af78', 0x1006D5C: 'mov_s\tr1,0x1',
    0x101F096: ';0x101f028', 0x101F0A8: 'st.as\tr0,[r15,94]',
    0x101F02E: 'and\tr0,r0,-1024', 0x101F040: 'sr\tr0,[int_vector_base]',
    0x101F538: 'mov_s\tr0,0x101f6f4', 0x101F53E: 'bl.d',
    0x101F542: 'st.as\tr0,[r13,76]', 0x10139D8: 'ld\tr0,[0x104126c]',
    0x101F6F6: ';0x1029c40', 0x101F6FA: ';0x1029bfc',
    0x101F6FE: 'sr\t0x3,[aux_irq_lv12]',
    0x1029C40: 'sr\t0x1,[dc_flsh]', 0x1029BFC: 'sr\t0x1,[dc_ivdc]',
    0x103DE56: ';0x1006b5c', 0x103DE5A: ';0x103de60', 0x103DE5C: ';0x103b51c',
    0x103B528: 'brne_s\tr0,0,10', 0x103B52C: ';0x103bb88',
    0x103B530: 'st_s\tr0,[r1,0]', 0x103BB8C: ';0x103bbb0',
    0x103BB92: 'jlne\t[r0]', 0x103BBA0: 'jlne\t[r0]',
    0x103B49A: 'st_s\tr2,[r1,0]', 0x103B4A0: 'st_s\tr13,[r1,0]',
    0x103B4BE: 'sub_s\tr13,r13,0x1', 0x103B4C2: 'ld.as\tr0,[r0,r13]',
    0x103B4C6: 'jl_s\t[r0]', 0x103B4C8: 'brne_s\tr13,0,-10',
    0x103ADFA: 'bl.d', 0x103ADFE: ';0x103aebc', 0x103AE00: ';0x103fe30',
    0x101F618: ';0x103adf8', 0x103FE6C: ';0x103e06c',
}


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
        offset = address - base
        assert 0 <= offset <= len(body) - 4
        return struct.unpack_from('<I', body, offset)[0]
    literals = {0x103DE60: 0x1044B68, 0x103AEBC: 0x103FE68,
        0x103B4D8: 0x1041748, 0x103B4DC: 0x103B4B4,
        0x103B4E0: 0x1041768, 0x103B4E4: 0x1096710,
        0x103B540: 0x1041750, 0x103BBB0: 0x1041768, 0x103BBB4: 0x104176C,
        0x1041748: 0, 0x1041750: 0, 0x1041768: 0, 0x104176C: 0}
    for address, expected in literals.items(): assert word(address) == expected
    tools = ROOT / 'work/build-arc/binutils'
    listings = []
    with tempfile.TemporaryDirectory(prefix='s33-tbib-shutdown-') as td:
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
    names = [f'r{i}' for i in range(13, 26)] + ['gp', 'fp', 'sp', 'ilink', 'r30', 'blink', 'lp_count']
    frame = {i * 4: name for i, name in enumerate(names)}
    frame.update({80: 'lp_start', 84: 'lp_end', 88: 'status32'})
    for i, name in enumerate(names):
        assert f'st\t{name},[r0' in decoded[0x103AF08 + i * 4][3]
    assert set(frame) == set(range(0, 92, 4))

    def execute(start, end, regs, memory, aux):
        """Only decoded save/restore register transfers; flag stores the requested word."""
        pc, zero, target = start, False, None
        def val(s): return regs[s] if s in regs else int(s, 0)
        while pc < end:
            size, op, args, _ = decoded[pc]; args = args.split(';')[0].strip()
            if op in ('st', 'ld'):
                reg, off = re.fullmatch(r'([^,]+),\[r0(?:,(\d+))?\]', args).groups()
                address = regs['r0'] + int(off or '0')
                if op == 'st': memory[address] = regs[reg]
                else: regs[reg] = memory[address]
            elif op in ('lr', 'sr'):
                reg, name = re.fullmatch(r'([^,]+),\[([^\]]+)\]', args).groups()
                if op == 'lr': regs[reg] = aux[name]
                else: aux[name] = val(reg)
            elif op in ('mov', 'mov.eq'):
                dst, src = args.split(',')
                if op == 'mov' or zero: regs[dst] = val(src)
            elif op == 'sub.f':
                dst, a, b = args.split(','); assert dst == '0'; zero = val(a) == val(b)
            elif op == 'flag': aux['status32'] = val(args)
            elif op == 'j.d': assert args == '[blink]'; target = regs['blink']
            else: raise AssertionError((hex(pc), op, args))
            pc += size
        assert pc == end and target is not None
        return target

    rng = random.Random(3307); cases = 0
    for resume in [0, 1, 2, 0xFFFFFFFF] + [rng.getrandbits(32) for _ in range(508)]:
        original = {name: rng.getrandbits(32) for name in names}
        original['blink'] = 0x1006B84
        aux = {name: rng.getrandbits(32) for name in ('lp_start', 'lp_end', 'status32')}
        original_aux = aux.copy(); regs = original | dict(r0=0x1090988, r1=0, r2=0, r3=0); memory = {}
        assert execute(0x103AF08, 0x103AF78, regs, memory, aux) == original['blink']
        assert regs['r0'] == 0 and len(memory) == 23
        assert memory == {0x1090988 + off: (original[name] if name in original else original_aux[name]) for off, name in frame.items()}
        regs = {name: rng.getrandbits(32) for name in names} | dict(r0=0x1090988, r1=resume, r2=0, r3=0)
        aux = dict(lp_start=0, lp_end=0, status32=0)
        assert execute(0x103AF78, 0x103AFF4, regs, memory, aux) == original['blink']
        assert all(regs[name] == value for name, value in original.items())
        assert aux == original_aux and regs['r0'] == (resume or 1)
        cases += 1
    output = ROOT / 'Ghidra_Results/ghidra_reports/tbib_shutdown_context'; output.mkdir(parents=True, exist_ok=True)
    result = dict(firmware='S33 V1.1 static only', firmware_sha256=sha(firmware), tbib_payload_sha256=sha(payload),
        script_sha256=sha(Path(__file__).read_bytes()), tbib_checksum=hex(checksum), elf_roundtrip='TBIB body',
        windows=[dict(start=hex(a), end=hex(b), label=l) for a, b, l in WINDOWS],
        checked_instructions=len(CHECKS), checked_literals={hex(a): hex(v) for a, v in literals.items()},
        context_buffer='0x01090988', context_bytes=92, frame={hex(off): name for off, name in frame.items()},
        decoded_context_roundtrips=cases, saved_return='0x01006b84', shutdown_resume_value=1,
        kernel_fields={'0x130': 'shutdown callback0x0101f6f4', '0x178': 'original vector base', '0x17c': 'shutdown status'},
        exit_hooks=['0x01041768 -> reverse callback array', '0x0104176c -> secondary hook'],
        observations=['Shutdown stores caller status, invokes optional K+0x130, then restores saved bootstrap context with return1',
            'Resume path restores original vector base before returning status to runtime exit',
            'K+0x130 receives0x101f6f4 in a call delay slot before the callee can change r0',
            'CPU callback writes1 to dc_flsh,1 to dc_ivdc,3 to aux_irq_lv12 without local polling',
            'First runtime-exit hook traverses registered callbacks in reverse order, including finalization wrapper0x103fe68'],
        limits=['Context model validates transfers and requested status word, not silicon flag/interrupt behavior',
            'Full callbacks, cache completion, DMA/controller quiescence and all error exits remain unverified',
            'Optional K fields and exit hooks can have other writers; no global immutability proof',
            'No hardware execution, modified firmware acceptance, recovery or V1.0 address validity established'])
    (output / 'gnu_verified.txt').write_text(listing)
    (output / 'verified_evidence.json').write_text(json.dumps(result, indent=2) + '\n')
    print(f'PASS: original firmware/TBIB identity,checksum,ELF roundtrip,{len(WINDOWS)} windows,'
          f'{len(CHECKS)} instructions,{len(literals)} literals,23 context words,{cases} decoded roundtrips')


if __name__ == '__main__': main()
