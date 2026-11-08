#!/usr/bin/env python3
"""Offline S33 V1.1: hardware button/key input backend feeding logical keys.

Reconstructs, statically and with rooted GNU windows, the input subsystem that
turns physical level sources into logical key states (table 0x446808) and key
events. Never executes firmware, never accesses the camera or USB.
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
    out = project / 'Ghidra_Results' / 'ghidra_reports' / 'button_input'
    out.mkdir(parents=True, exist_ok=True)

    def raw(index, address, size):
        offset = address - info[index]['load_address_candidate']
        if not 0 <= offset <= len(payloads[index]) - size:
            raise ValueError(f'Out-of-bounds read: block {index} {address:#x}')
        return payloads[index][offset:offset + size]

    def word(index, address):
        return struct.unpack('<I', raw(index, address, 4))[0]

    # --- Literal pool of the key subsystem init (block 0) ---
    pool = {
        0x16E834: 0x367898,   # shared key context base
        0x16E90C: 0x16EE30,   # timer callback A (period 100, key 0x62 path)
        0x16E910: 0x16EAF8,   # timer callback B (period 50, diff scan)
        0x16E914: 0x16E988,   # key 1 front callback
        0x16E918: 0xFFFF800C, # key 1 event source id (backend row idx 11)
        0x16E91C: 0x3678B4,   # key context base for level bytes
        0x16E920: 0x16E9E8,   # key 2 front callback
        0x16E924: 0xFFFF800D, # key 2 event source id (backend row idx 12)
        0x16E928: 0x16F124,   # timer callback C (period 500, key 0x77)
        0x16E92C: 0xFFFF9007, # timer id for callback C
        0x16E930: 0x16F0EC,
        0x16E934: 0xA18,      # dispatch source id -> reader 0x137774 -> key 0x63
        0x16E974: 0xA16,      # dispatch source id -> reader 0x210BC8 -> key 0x65
        0x16E9E0: 0x16EA3C,   # key 1 deferred verify callback
        0x16E9E4: 0x4E20,     # deferred verify timer value 20000
        0x16EA34: 0x16EAAC,   # key 2 deferred verify callback
        0x16EA38: 0x3678C1,   # key 2 level byte
        0x16EAF4: 0x3678DA,
        0x16EB78: 0x3678B4,   # level storage base (+0x18: source 0x210BC8)
        0x16EB7C: 0x3678D0,   # level storage base (+0: 0x137774, +1: 0x1784F4)
        0x16EE2C: 0x367898,   # combined-state context base
        0x16EE74: 0x36789B,
        0x16EE78: 0x3101,     # direct event id emitted by callback A
        0x16F118: 0x9007,
        0x16F11C: 0xFFFF9007,
        0x16F120: 0x3678DB,
        0x16FA34: 0x446808,   # logical key state table base
        0x16E394: 0x16ECB4,   # input-manager init registration (slot 4)
        0x16E398: 0x16EC88,   # input-manager init registration (slot 2, key 0x0C producer)
    }
    for addr, value in pool.items():
        assert word(0, addr) == value, hex(addr)

    # --- Level reader literals ---
    assert word(0, 0x17B5DC) == 0x0FF04020  # key 1 halfword register
    assert word(0, 0x17B5F4) == 0x0FF04024  # key 2 halfword register
    assert word(0, 0x210BD0) == 0x0FF04020  # bit 0 reader (dispatch 0xA16)
    assert word(0, 0x180A98) == 0xFFEF037C  # key 0x77 halfword register, bit 6
    assert word(0, 0x137794) == 0x366B24
    assert word(0, 0x17B570) == 0x367BB4

    # --- Event backend table 0x424F00 (block 1): header + 16 rows ---
    assert word(1, 0x424F00) == 0x0FEF0048
    assert word(1, 0x424F04) == 0x0FEF0324
    assert word(1, 0x424F08) == 16
    rows = []
    for k in range(16):
        base = 0x424F0C + 8 * k
        w0, callback = word(1, base), word(1, base + 4)
        source_id = w0 & 0xFFFF
        idx_pending, idx_enable = (w0 >> 16) & 0xFF, (w0 >> 24) & 0xFF
        assert source_id == 0x8010 - k
        assert idx_pending == idx_enable == 15 - k
        assert callback == 0, hex(base)
        rows.append(dict(row=hex(base), source_id=hex(source_id),
                        pending_bit=idx_pending, enable_bit=idx_enable,
                        registered_callback='null in image, filled at runtime'))

    # --- Rooted GNU windows ---
    windows = [
        (0x16E340, 0x16E354, 'InputManagerInitCaller'),
        (0x16E838, 0x16E8FA, 'KeySubsystemInit'),
        (0x16E988, 0x16E9DC, 'Key1FrontCallback'),
        (0x16EA3C, 0x16EAA8, 'Key1DeferredVerify'),
        (0x16E9E8, 0x16EA2E, 'Key2FrontCallback'),
        (0x16EAAC, 0x16EAE8, 'Key2DeferredVerify'),
        (0x16EAF8, 0x16EB78, 'DiffScanTimerCallback'),
        (0x16EB80, 0x16EC34, 'KeyScanDispatch'),
        (0x16EED8, 0x16F050, 'CombinedState65_66_77'),
        (0x16EE30, 0x16EE74, 'TimerCallbackKey62'),
        (0x16F124, 0x16F17C, 'TimerCallbackKey77'),
        (0x16F72C, 0x16F866, 'UpdateKeyState'),
        (0x16F920, 0x16F932, 'GetKeyState'),
        (0x17B53C, 0x17B606, 'LevelReaderFamily'),
        (0x210BC8, 0x210BE4, 'LevelReaderBit0'),
        (0x210BE4, 0x210C08, 'Key77ReaderThunk'),
        (0x180A68, 0x180AA8, 'Key77LevelReader'),
        (0x16EC88, 0x16ECB0, 'Key0CProducer'),
        (0x16EDDC, 0x16EE28, 'Key62Producer'),
        (0x16E938, 0x16E990, 'ChangeHelpers'),
        (0x144A52, 0x144A88, 'Key77ProducerWindowMgr'),
        (0x137774, 0x137794, 'Key63Source'),
        (0x18AAB4, 0x18ABC0, 'Key66SourceAndRegister'),
        (0x1784F4, 0x1784F8, 'DiffSource4'),
    ]
    listings = []
    tool = project / 'work/build-arc/binutils'
    with tempfile.TemporaryDirectory(prefix='s33-button-input-') as td:
        elf = Path(td) / 'block0.elf'
        back = Path(td) / 'block0.bin'
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

        for start, end, name in windows:
            listings.append(listing(start, end, name))

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

    # Registration of the two hardware event sources and of the timers.
    requires('KeySubsystemInit', 0x16E886, '\tbl.d\t', '\t0x16d898')
    requires('KeySubsystemInit', 0x16E8AC, '\tbl.d\t', '\t0x16d898')
    requires('KeySubsystemInit', 0x16E894, '\tbl\t', '\t0x17b5d4')
    requires('KeySubsystemInit', 0x16E8BA, '\tbl\t', '\t0x17b5ec')
    requires('KeySubsystemInit', 0x16E8EA, '\tbl\t', '\t0x210be4')
    requires('KeySubsystemInit', 0x16E8A6, '\tbl\t', '\t0x16f72c')
    requires('KeySubsystemInit', 0x16E8CA, '\tbl\t', '\t0x16f72c')
    requires('KeySubsystemInit', 0x16E8F6, '\tbl\t', '\t0x16f72c')
    requires('KeySubsystemInit', 0x16E856, '\tbl\t', '\t0x14905c')
    requires('KeySubsystemInit', 0x16E8DE, '\tbl\t', '\t0x14905c')
    requires('KeySubsystemInit', 0x16E876, '\tbl\t', '\t0x14905c')
    requires('KeySubsystemInit', 0x16E85E, '\tbl\t', '\t0x1491b8')
    requires('InputManagerInitCaller', 0x16E344, '\tbl\t', '\t0x1405f8')
    requires('InputManagerInitCaller', 0x16E34C, '\tbl\t', '\t0x1405f8')
    requires('InputManagerInitCaller', 0x16E350, '\tbl\t', '\t0x16e838')

    # Front and deferred-verify callbacks for keys 1 and 2.
    requires('Key1FrontCallback', 0x16E992, '\tbl\t', '\t0x16d840')
    requires('Key1FrontCallback', 0x16E9C2, '\tbl\t', '\t0x145f28')
    requires('Key1FrontCallback', 0x16E9D8, '\tbl\t', '\t0x16f72c')
    requires('Key2FrontCallback', 0x16EA0A, '\tbl\t', '\t0x145f28')
    requires('Key2FrontCallback', 0x16EA2A, '\tbl\t', '\t0x16f72c')
    requires('Key1DeferredVerify', 0x16EA42, '\tbl\t', '\t0x17b5d4')
    requires('Key1DeferredVerify', 0x16EA68, '\tbl\t', '\t0x16f920')
    requires('Key2DeferredVerify', 0x16EAB2, '\tbl\t', '\t0x17b5ec')
    requires('Key2DeferredVerify', 0x16EAD4, '\tbl\t', '\t0x16f72c')

    # Periodic diff scan over four level sources and its change helpers.
    for address, target in ((0x16EB0A, '0x210bc8'), (0x16EB26, '0x137774'),
                            (0x16EB3C, '0x18aab4'), (0x16EB56, '0x1784f4')):
        requires('DiffScanTimerCallback', address, '\tbl\t', f'\t{target}')
    for address in (0x16EB1E, 0x16EB36, 0x16EB4E, 0x16EB72):
        requires('DiffScanTimerCallback', address, 'bl_s', '0x16e960' if address == 0x16EB1E
                 else '0x16e94c' if address == 0x16EB36
                 else '0x16e938' if address == 0x16EB4E else '0x16e978')
    requires('DiffScanTimerCallback', 0x16EB6E, '\tbl\t', '\t0xd10fc')

    # Dispatch of level sources to logical keys.
    requires('KeyScanDispatch', 0x16EBB6, '\tbl\t', '\t0x210bc8')
    requires('KeyScanDispatch', 0x16EBC0, '\tbl\t', '\t0x18aab4')
    requires('KeyScanDispatch', 0x16EBCC, '\tbl\t', '\t0x137774')
    requires('KeyScanDispatch', 0x16EBFA, '\tbl\t', '\t0x210be4')
    requires('KeyScanDispatch', 0x16EBE8, '\tbl\t', '\t0x268ea0')
    requires('KeyScanDispatch', 0x16EBF4, '\tbl\t', '\t0x144cc4')
    requires('KeyScanDispatch', 0x16EC18, '\tbl\t', '\t0x16f920')
    requires('KeyScanDispatch', 0x16EC10, '\tbl\t', '\t0x16eed8')
    requires('KeyScanDispatch', 0x16EC28, '\tbl\t', '\t0x16f72c')
    requires('KeyScanDispatch', 0x16EB92, '0xa16')
    requires('KeyScanDispatch', 0x16EBA4, '0xa18')
    requires('KeyScanDispatch', 0x16EBAC, '0x9007')
    requires('KeyScanDispatch', 0x16EBBC, 'mov_s\tr13,0x65')
    requires('KeyScanDispatch', 0x16EBC6, 'mov_s\tr13,0x66')
    requires('KeyScanDispatch', 0x16EBD2, 'mov_s\tr13,0x63')
    requires('KeyScanDispatch', 0x16EC00, 'mov_s\tr13,0x77')

    # Combined 0x65/0x66/0x77 state machine and its producers.
    requires('CombinedState65_66_77', 0x16EEE8, '\tbl\t', '\t0x18aab4')
    requires('CombinedState65_66_77', 0x16EEF0, '\tbl\t', '\t0x210bc8')
    requires('CombinedState65_66_77', 0x16EEF6, '\tbl\t', '\t0x210be4')
    for address in (0x16EF64, 0x16EF7A, 0x16EFC8, 0x16EFEC, 0x16F00E):
        requires('CombinedState65_66_77', address, '\tbl\t', '\t0x16f72c')
    requires('TimerCallbackKey62', 0x16EE4C, '\tbl\t', '\t0x16f920')
    requires('TimerCallbackKey62', 0x16EE5E, 'bl_s', '0x16eddc')
    requires('TimerCallbackKey77', 0x16F148, 'bl_s', '0x16eb80')
    requires('TimerCallbackKey77', 0x16F176, '\tbl\t', '\t0x16f72c')
    requires('TimerCallbackKey77', 0x16F15A, '\tbl\t', '\t0x210be4')
    requires('Key0CProducer', 0x16EC96, '\tbl\t', '\t0x17b5bc')
    requires('Key0CProducer', 0x16ECA2, '\tbl\t', '\t0x16f72c')
    requires('Key62Producer', 0x16EDEC, '\tbl\t', '\t0x17b53c')
    requires('Key62Producer', 0x16EDFE, '\tbl\t', '\t0x16f72c')
    requires('Key77ProducerWindowMgr', 0x144A70, '\tbl\t', '\t0x210be4')
    requires('Key77ProducerWindowMgr', 0x144A82, '\tbl\t', '\t0x16f72c')

    # State table write, ID formula and threshold between small and large keys.
    requires('UpdateKeyState', 0x16F736, '0x16fa34')
    requires('UpdateKeyState', 0x16F76C, 'asl_s\tr1,r1,0x7')
    requires('UpdateKeyState', 0x16F76E, 'cmp_s\tr13,0x61')
    requires('UpdateKeyState', 0x16F770, 'bge.d')
    requires('UpdateKeyState', 0x16F792, '\tbl.d\t', '\t0x17c150')
    requires('UpdateKeyState', 0x16F7EA, 'bl_s', '0x16f6b0')
    requires('UpdateKeyState', 0x16F80E, 'bl_s', '0x16f6b0')
    requires('GetKeyState', 0x16F920, '0x16fa34')
    requires('GetKeyState', 0x16F928, 'cmp_s\tr0,0x61')
    requires('GetKeyState', 0x16F930, 'ldb_s\tr0,[r1,0x1]')

    # Level reader shapes: bypassed-cache halfword reads with single-bit extraction.
    requires('LevelReaderFamily', 0x17B5E0, 'ldh.di')
    requires('LevelReaderFamily', 0x17B5F8, 'ldh.di')
    requires('LevelReaderBit0', 0x210BD4, 'ldh.di')
    requires('Key77LevelReader', 0x180A9C, 'ldh.di')
    requires('Key77LevelReader', 0x180AA0, 'btst_s\tr0,0x6')
    requires('LevelReaderFamily', 0x17B5C2, 'btst_s\tr0,0x1')

    evidence = {
        'analysis': 'STATIC hardware button/key input backend; no firmware executed',
        'firmware_reference': 'Nikon S33 V1.1; camera observed V1.0; offsets not portable without proof',
        'verified_blocks': 16,
        'script_sha256': sha(Path(__file__).read_bytes()),
        'block_sha256': {str(b['index']): b['sha256'] for b in blocks},
        'explicit_windows': [dict(block=0, start=hex(s), end_exclusive=hex(e), name=n)
                             for s, e, n in windows],
        'event_backend_table': dict(base='0x424f00', pending_register='0x0fef0048',
                                    enable_register='0x0fef0324', count=16, rows=rows),
        'input_subsystem': {
            'init': '0x16e838 (called by 0x16e350 inside the input-manager init that also registers 0x16ecb4 and 0x16ec88 via 0x1405f8)',
            'context_bases': ['0x367898', '0x3678b4', '0x3678d0'],
            'state_table': '0x446808 + 4*key, byte 0 level; keys >= 0x61 also expose byte +1 via 0x16f920',
            'update_entry': '0x16f72c', 'getter_entry': '0x16f920',
            'sources': [
                dict(logical_key='1', level='0x0ff04020 halfword bit 15 via 0x17b5d4',
                     event_source_id='0xffff800c (row 0x424f2c, pending/enable bit 11)',
                     front_callback='0x16e988', deferred_verify='0x16ea3c',
                     verify_timer='0x4e20 (20000) via 0x145f28',
                     level_byte='0x3678c0', ids='0x80 (nonzero state) / 0x81 (zero state)'),
                dict(logical_key='2', level='0x0ff04024 halfword bit 0 via 0x17b5ec',
                     event_source_id='0xffff800d (row 0x424f24, pending/enable bit 12)',
                     front_callback='0x16e9e8', deferred_verify='0x16eaac',
                     verify_timer='0x4e20 (20000) via 0x145f28',
                     level_byte='0x3678c1', ids='0x100 / 0x101',
                     note='chain to WindowMgr and CaptureLiveview already documented in S33_S2_MMIO_e_Coda_Eventi'),
                dict(logical_key='0x0c', level='0x17b5bc -> 0x16ad38 result bit 1',
                     producer='0x16ec88 (registered by input-manager init via 0x1405f8 slot 2)'),
                dict(logical_key='0x62', level='0x17b53c (0x18ac58 + 0x17b5bc + state checks)',
                     producer='0x16eddc, called at init and by timer callback 0x16ee30 (period 100)',
                     direct_event='0x3101 via 0x169eb4 in callback 0x16ee30'),
                dict(logical_key='0x63', level='0x137774 (compares byte at 0x366b24-deref; indirect)',
                     dispatch_source='0xa18', diff_scan='[0x3678b4+56] vs current',
                     level_storage='0x3678d0+0'),
                dict(logical_key='0x65', level='0x0ff04020 halfword bit 0 via 0x210bc8',
                     dispatch_source='0xa16', diff_scan='[0x3678b4+52] vs current',
                     level_storage='0x3678b4+0x18'),
                dict(logical_key='0x66', level='0x18aab4 (jumps to 0x263ddc; indirect)',
                     dispatch_source='-6 (0xfffffffa)', diff_scan='[0x3678b4+53] vs current',
                     level_storage='0x3678b4+25', also='combined handler 0x16eed8 and bulk emitter 0x16ef00 region'),
                dict(logical_key='0x77', level='0xffef037c halfword bit 6 via 0x210be4 -> 0x180a68',
                     dispatch_source='0x9007', timer='0xffff9007 period 500 via 0x14905c, callback 0x16f124',
                     diff_scan='none; polled by timer and by 0x16eed8',
                     also='producers 0x144a52 region (WindowMgr area) and combined handler'),
                dict(logical_key='none', level='0x1784f4 returns constant 0',
                     diff_scan='[0x3678b4+57] vs current', side_effect='0xd10fc + direct event 0x7ce9 via 0x169eb4 from helper 0x16e978'),
            ],
            'timers': [
                dict(context='0x3678b6', kind_arg=2, period=100, callback='0x16ee30'),
                dict(context='0x3678b5', kind_arg=3, period=50, callback='0x16eaf8 (diff scan)'),
                dict(context='0x3678f7', kind_arg='0xffff9007', period=500, callback='0x16f124 (key 0x77 poll)'),
            ],
            'deferred_verify': 'front callback toggles the level byte and schedules a verify timer; the deferred callback re-reads the level and corrects the state; semantics of the 20000 timer unit unresolved',
            'id_formula': 'small keys (<0x61): state nonzero -> key<<7, zero -> (key<<7)|1; keys >= 0x61 emit key<<7 and (key<<7)|1 conditioned on the halfword at state entry +12 (not fully reconstructed)',
        },
        'limits': [
            'Static V1.1 analysis only; physical button identity, polarity, debounce and V1.0 equivalence unresolved.',
            'Readers 0x137774, 0x18aab4, 0x16ad38 and the 0x1784f4 family are indirect; their ultimate peripheral registers were not traced here.',
            'Backend rows 0x8001, 0x8008, 0x800b, 0x800f have literals elsewhere in block 0 (0xf666c, 0x2331ac, 0x238b68, 0x32e10c/0x3311cc/0x331248) and belong to other subsystems; not attributed.',
            'No proof of which sources are enabled at runtime: enable register 0x0fef0324 and timer activation are dynamic.',
            'Key state table writers exist outside this subsystem (bulk emitters 0x16f86c and 0x16f8a4 loop); list not exhaustive.',
            'Logical keys 9 and 11 (diagnostics gate) have no identified producer in this subsystem; feeder unknown.',
            'ARC objdump is linear; windows are rooted at entries but branch outcomes were not executed.',
            'No firmware, camera command, RAM or flash was executed or written.',
        ],
    }
    (out / 'verified_evidence.json').write_text(json.dumps(evidence, indent=2) + '\n')
    (out / 'gnu_verified.txt').write_text('\n\n'.join(listings) + '\n')
    print(f'16 blocks verified; {len(windows)} rooted windows; backend table rows {len(rows)}; '
          f'evidence in {out}')


if __name__ == '__main__':
    main()
