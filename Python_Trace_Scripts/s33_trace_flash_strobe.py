#!/usr/bin/env python3
"""Offline S33 V1.1: flash/strobe subsystem, static dossier.

FlashChargerTask (0x165c84), its mailbox protocol, the strobe command/fire
services and the MMIO registers 0x0FED18A0/0x0FED18AC/0x0FED18B0. Never
executes firmware, never accesses the camera or USB.
"""
import json
import struct
import tempfile
from pathlib import Path

from s33_trace_state_dispatch import run, sha, verified_payloads


def main():
    root = Path(__file__).resolve().parent
    project = root.parent
    blocks, payloads, block_dir = verified_payloads(project)
    info = {b['index']: b for b in blocks}
    out = project / 'Ghidra_Results' / 'ghidra_reports' / 'flash_strobe'
    out.mkdir(parents=True, exist_ok=True)

    def raw(index, address, size):
        offset = address - info[index]['load_address_candidate']
        if not 0 <= offset <= len(payloads[index]) - size:
            raise ValueError(f'Out-of-bounds read: block {index} {address:#x}')
        return payloads[index][offset:offset + size]

    def word(index, address):
        return struct.unpack('<I', raw(index, address, 4))[0]

    # --- FlashChargerTask record in the task table 0x372388 (block 1) ---
    assert word(1, 0x372988) == 0x5800001
    assert word(1, 0x372988 + 4) == 0x165C84
    assert word(1, 0x372988 + 8) == 0x1000     # stack size
    assert word(1, 0x372988 + 12) == 0x2        # priority
    assert word(1, 0x372988 + 16) == 0x3766B2   # name pointer
    assert raw(1, 0x3766B2, 17) == b'FlashChargerTask\0'

    # --- Task literal pool (block 0) ---
    pool = {
        0x165D80: 0x5800002,   # event/mailbox source id used by the task
        0x165D84: 0x36778C,    # strobe context base
        0x165D88: 0x3928B4,    # reply argument (empty string in image)
        0x165D8C: 0x3677B4,    # status cell for the 0x10 branch
        0x165D90: 0x3677B8,    # status cell for the 0x20 branch
        0x165D94: 0x5800003,   # second mailbox id (lock context)
        0x16596C: 0x0FED18A0,  # strobe MMIO register
        0x1659A4: 0x0FED18AC,  # strobe MMIO register (time field bits 8..11)
        0x165C30: 0x0FED18A0,
        0x1660B8: 0x0FED18B0,  # third strobe MMIO register
        0x1661A8: 0x0FED18A0,
        0x166190: 0x36778C,
        0x166194: 0x445AC0,
        0x165C24: 0x5800003,
    }
    for addr, value in pool.items():
        assert word(0, addr) == value, hex(addr)

    # --- Strobe-related strings, byte-verified ---
    strings = {
        (5, 0x98AB87): b'Strobe Fire!\0',
        (5, 0x98AAEB): b'Strobe Charge:Enabled\0',
        (5, 0x98AB2E): b'Strobe Charge Status:XXX\0',
        (5, 0x98B60B): b'Strobe Type : PKI\0',
        (5, 0x98B61D): b'Strobe Type : NK\0',
        (5, 0x98B62E): b'Strobe Type : 3rd Party\0',
        (5, 0x98B677): b'Save strobe type to calibration fail\0',
        (5, 0x98CB56): b'Fire full strobe.(ENABLE)\0',
        (1, 0x4217AB): b'-----Flash Charger Cali-----',
        (1, 0x421458): b'B:\\StrobeCaliData.csv',
        (1, 0x3851A2): b'flash time(us): redeye:%d pf1:%d pf2:%d',
        (3, 0x781637): b'Flash Time : %d us\0',
    }
    for (index, addr), text in strings.items():
        assert raw(index, addr, len(text)) == text, (index, hex(addr))

    # --- Service-script dictionary entries containing flash/strobe keywords ---
    keywords = [b'FlashFire\0', b'StrobeReady\0', b'ImgCap_SetFlashTime\0',
                b'KeyFlash\0', b'FE_FlashFire\0', b'FE_SetFlashMode4Script\0',
                b'FE_WriteStrobeTypeToNANDCali\0', b'FlashChargerCalibration\0',
                b'SetFlashTime\0', b'RedEyePreflash\0', b'Flash_CheckCover\0',
                b'StrobeScript_SetType\0']
    keyword_hits = {}
    for kw in keywords:
        found = None
        for index, data in payloads.items():
            base = info[index]['load_address_candidate']
            pos = data.find(kw)
            if pos >= 0:
                found = (index, base + pos)
                break
        assert found, kw
        keyword_hits[kw.decode().rstrip('\0')] = f'block {found[0]} {found[1]:#x}'

    # --- Rooted GNU windows ---
    windows = [
        (0, 0x165C84, 0x165D40, 'FlashChargerTask'),
        (0, 0x165D40, 0x165D70, 'StrobeCommandDispatch6'),
        (0, 0x165C0C, 0x165C84, 'StrobeBit3Control'),
        (0, 0x165640, 0x1656B0, 'FireService165640'),
        (0, 0x16589C, 0x165930, 'CommandService16589C'),
    ]
    listings = []
    tool = project / 'work/build-arc/binutils'
    with tempfile.TemporaryDirectory(prefix='s33-flash-strobe-') as td:
        elf = Path(td) / 'b0.elf'
        back = Path(td) / 'b0.bin'
        run([tool / 'objcopy', '-I', 'binary', '-O', 'elf32-littlearc', '-B', 'arc',
             '--rename-section', '.data=.text,alloc,load,readonly,code,contents',
             '--change-section-vma', f'.data={info[0]["load_address_candidate"]:#x}',
             '--strip-all', block_dir / info[0]['file'], elf])
        run([tool / 'objcopy', '--dump-section', f'.text={back}', elf])
        assert back.read_bytes() == payloads[0]

        def listing(start, end, name):
            for extra in (0, 2, 4, 6):
                text = run([tool / 'objdump', '-d', '-m', 'arc:ARC700', '-EL',
                            f'--start-address={start:#x}',
                            f'--stop-address={end + extra:#x}', elf])
                if 'out of bounds' not in text.lower():
                    return f'WINDOW BLOCK 0 {name} {start:#x}..{end + extra:#x}\n' + \
                        text.replace(str(elf), 'verified-block0.elf')
            raise ValueError(f'Truncated instruction in {name}')

        for wi, s, e, n in windows:
            listings.append(listing(s, e, n))

    def window_text(name):
        return next(t for t in listings if name in t.splitlines()[0])

    def line_of(name, address):
        text = window_text(name)
        return next(l for l in text.splitlines() if l.strip().startswith(f'{address:x}:'))

    def requires(name, address, *fragments):
        line = line_of(name, address)
        for fragment in fragments:
            if fragment.startswith('\t0x'):
                fragment = '\t;' + fragment[1:]
            assert fragment in line, f'{name} {address:#x}: {line}'

    # Task protocol: register source, request 0x30, wait, dispatch bits 0x10/0x20/0x06.
    requires('FlashChargerTask', 0x165C8C, 'bl.d', '0x158ce0')
    requires('FlashChargerTask', 0x165C9C, 'bl.d', '0x158d04')
    requires('FlashChargerTask', 0x165CA4, 'bl.d', '0x158e28')
    requires('FlashChargerTask', 0x165CBA, 'and.f\tr1,r0,0x10')
    requires('FlashChargerTask', 0x165CC0, 'btst_s\tr0,0x5')
    requires('FlashChargerTask', 0x165CCA, 'bl.d', '0x16589c')
    requires('FlashChargerTask', 0x165CE2, '\tbl\t', '\t0x165bc4')
    requires('FlashChargerTask', 0x165CD8, '\tbl\t', '\t0x158cbc')
    requires('FlashChargerTask', 0x165D28, 'btst_s\tr0,0x6')
    requires('FlashChargerTask', 0x165D34, '\tbl\t', '\t0xb2c74')
    # Six-case strobe command dispatcher on the context byte.
    requires('StrobeCommandDispatch6', 0x165D58, 'ldb_s\tr0,[r15,0]')
    requires('StrobeCommandDispatch6', 0x165D62, 'add\tr12,pcl,0xe')
    requires('StrobeCommandDispatch6', 0x165D66, 'ldh.as.x\tr0,[r12,r0]')
    # GPIO-style bit 3 set/clear on 0x0FED18A0 plus strobe services.
    requires('StrobeBit3Control', 0x165C0C, 'bl.d', '0x145c2c')
    requires('StrobeBit3Control', 0x165C12, '\tbl\t', '\t0x1786e8')
    requires('StrobeBit3Control', 0x165C48, 'ldh.di')
    requires('StrobeBit3Control', 0x165C4C, 'bclr\tr10,r10,r14')
    requires('StrobeBit3Control', 0x165C5A, 'bset\tr10,r10,r14')
    requires('StrobeBit3Control', 0x165C6E, '\tbl\t', '\t0x179354')
    requires('StrobeBit3Control', 0x165C78, 'bl.d', '0x179354')
    # Command service locks, dispatches and calls the fire service.
    requires('CommandService16589C', 0x1658BA, 'bl.d', '0x1593ac')
    requires('CommandService16589C', 0x165918, 'bl.d', '0x165640')
    requires('CommandService16589C', 0x16592E, 'bl.d', '0x165640')
    requires('FireService165640', 0x165640, 'push_s')

    evidence = {
        'analysis': 'STATIC flash/strobe subsystem dossier; no firmware executed',
        'firmware_reference': 'Nikon S33 V1.1; camera observed V1.0; offsets not portable without proof',
        'verified_blocks': 16,
        'script_sha256': sha(Path(__file__).read_bytes()),
        'block_sha256': {str(b['index']): b['sha256'] for b in blocks},
        'explicit_windows': [dict(block=0, start=hex(s), end_exclusive=hex(e), name=n)
                             for _, s, e, n in windows],
        'flash_charger_task': {
            'task_table_record': '0x372988 (block 1): id 0x5800001, entry 0x165c84, '
                                 'stack 0x1000, priority 2, name "FlashChargerTask" at 0x3766b2',
            'protocol': 'registers event source 0x5800002 via 0x158ce0 (mask 1023), '
                        'requests 0x30 via 0x158d04, waits via 0x158e28; '
                        'bits 0x10/0x20 -> services 0x16589c/0x165bc4, replies 256/512 '
                        'via 0x158cbc; bit 0x06 -> 0x158cbc, 0xb2c74(0x80) and exit',
            'context': '0x36778c (+0x24 state, +0x28/+0x2c results); status cells 0x3677b4/0x3677b8',
            'second_mailbox': '0x5800003 used by the six-case dispatcher 0x165d40 and locks',
        },
        'strobe_services': {
            'command_service': '0x16589c: lock 0x1593ac, case table, calls fire service '
                               '0x165640 with context fields (times at ctx+80/100/0x54/0x58/0x5c/0x60)',
            'fire_service': '0x165640: register save/restore via 0x335b34/0x3341e4; '
                            'parameter-heavy entry, body not fully reconstructed',
            'bit3_control': '0x165c0c..0x165c82: read-modify-write of halfword 0x0fed18a0 '
                             'with bclr/bset bit 3 (ldh.di/sth.di), services 0x1786e8/0x179354, '
                             'then stb 1 to the context byte',
            'time_field': '0x165982..0x16599a builds (x & 0xfffff0ff) | ((t<<8) & 0xf00) '
                          'and writes halfword 0x0fed18ac: a 4-bit strobe time field at bits 8..11',
        },
        'strobe_mmio': ['0x0FED18A0 (bit 3 toggled)', '0x0FED18AC (time field bits 8..11)',
                        '0x0FED18B0'],
        'script_dictionary_commands': keyword_hits,
        'calibration_persistence': 'strobe type saved to calibration (strings "Save strobe '
                                   'type to calibration fail", "Strobe Type : PKI/NK/3rd Party", '
                                   '"-----Flash Charger Cali-----", "B:\\StrobeCaliData.csv")',
        'limits': [
            'Static V1.1 only; no execution, no hardware, no V1.0 proof.',
            'MMIO 0x0FED18A0/AC/B0 attributed only by pool use in strobe code; exact bit '
            'semantics (charge vs fire) unresolved.',
            'Fire service 0x165640 body not reconstructed; flash times provenance '
            '(calibration tables) not traced.',
            'Task activation at runtime not proven; the record exists in the task table.',
            'No link reconstructed yet between the S1/S2 shutter path and the strobe '
            'command service; preflash/redeye/main-flash sequencing is string evidence only '
            '("flash time(us): redeye:%d pf1:%d pf2:%d").',
            'ARC objdump is linear; windows rooted, branches not executed.',
        ],
    }
    (out / 'verified_evidence.json').write_text(json.dumps(evidence, indent=2) + '\n')
    (out / 'gnu_verified.txt').write_text('\n\n'.join(listings) + '\n')
    print(f'16 blocks verified; {len(windows)} rooted windows; {len(keywords)} script '
          f'keywords; 3 strobe MMIO registers; evidence in {out}')


if __name__ == '__main__':
    main()
