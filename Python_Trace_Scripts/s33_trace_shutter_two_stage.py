#!/usr/bin/env python3
"""Offline S33 V1.1: two-stage shutter (S1/S2) event model, static.

CaptureLiveview consumes key 1 (S1 half-press) events 0x80/0x81 and key 2
(S2 full-press) event 0x100. This script verifies the event table, the S1
handlers, the S1->state-prepare call and the S1/AE/AF marker family.
Never executes firmware, never accesses the camera or USB.
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
    out = project / 'Ghidra_Results' / 'ghidra_reports' / 'shutter_two_stage'
    out.mkdir(parents=True, exist_ok=True)

    def raw(index, address, size):
        offset = address - info[index]['load_address_candidate']
        if not 0 <= offset <= len(payloads[index]) - size:
            raise ValueError(f'Out-of-bounds read: block {index} {address:#x}')
        return payloads[index][offset:offset + size]

    def word(index, address):
        return struct.unpack('<I', raw(index, address, 4))[0]

    def half(index, address):
        return struct.unpack('<H', raw(index, address, 2))[0]

    # --- CaptureLiveview event table 0x7833EC (block 3) ---
    table_base = 0x7833EC
    entries = []
    a = table_base
    for _ in range(64):
        event = half(3, a)
        handler = word(3, a + 4)
        entries.append(dict(address=hex(a), event=hex(event), handler=hex(handler)))
        if event == 0 and handler == 0x20E814:
            break
        a += 8
    by_event = {e['event']: e['handler'] for e in entries if e['event'] != '0x0'}
    assert by_event['0x80'] == '0x654fe8', 'S1 pressed handler'
    assert by_event['0x81'] == '0x655b68', 'S1 released handler'
    assert by_event['0x100'] == '0x654cd4', 'S2 handler (already documented)'
    assert by_event['0x4401'] == '0x652758'
    assert by_event['0x4405'] == '0x652794'
    # Other key events present in the same table (key index = event >> 7).
    for event, key in (('0x180', 3), ('0x480', 9), ('0x500', 10), ('0x580', 11)):
        assert event in by_event, event

    # --- S1 handler literal pool (block 2) ---
    pool = {
        0x655374: 0xB00100,   # S1 event marker logged at 0x655000
        0x655378: 0x2600001,  # request constant for 0x158d04
        0x65537C: 0x681E74,   # CaptureLiveview context
        0x655380: 0x681F00,   # second context (byte +17 written)
        0x655EC4: 0x681E74,   # context in S1 released handler
        0x655EC8: 0x3101,
        0x655ECC: 0x681F11,
        0x655ED0: 0xCAD30,    # mode-code getter used by S1 released
    }
    for addr, value in pool.items():
        assert word(2, addr) == value, hex(addr)

    # --- S1/AE/AF marker family, aligned literal inventory ---
    expected_markers = {
        0xB00100: [(0, 0x1DCCE4), (0, 0x1DD238), (2, 0x655374), (2, 0x65AFF4),
                   (4, 0x7F7E2C), (4, 0x7FA53C), (9, 0xCECEA4)],
        0xB00101: [(0, 0xDB4C4)],
        0xB00102: [(0, 0xDB7AC), (12, 0x105EA10)],
        0xB00103: [(0, 0xDB4D8)],
        0xB00104: [(0, 0xDB4E0), (9, 0xCCF768)],
        0xB00105: [(2, 0x655B5C), (2, 0x65B004)],
        0xB00106: [(0, 0x1DCCE8), (0, 0x1DD5F8), (2, 0x654FE4), (2, 0x65B3A4),
                   (4, 0x7F7F74), (4, 0x7FA544)],
        0xB00107: [(0, 0x1502F0), (0, 0x1B7FD0)],
    }
    marker_sites = {}
    for code, expected in expected_markers.items():
        pat = struct.pack('<I', code)
        sites = []
        for index, data in payloads.items():
            base = info[index]['load_address_candidate']
            ofs = 0
            while True:
                j = data.find(pat, ofs)
                if j < 0:
                    break
                if j % 4 == 0:
                    sites.append((index, base + j))
                ofs = j + 1
        assert sorted(sites) == sorted(expected), (hex(code), sites)
        marker_sites[hex(code)] = [f'block {i} {a:#x}' for i, a in sites]

    # --- Rooted GNU windows ---
    windows = [
        (2, 0x654FE8, 0x655040, 'S1PressedHead'),
        (2, 0x655050, 0x6550F0, 'S1InterlockAndModes'),
        (2, 0x655150, 0x6551A0, 'S1OpenObject'),
        (2, 0x6556D0, 0x655710, 'S1StatePrepare'),
        (2, 0x655B68, 0x655C40, 'S1Released'),
        (2, 0x654CD4, 0x654D28, 'S2HandlerHead'),
        (0, 0xDB470, 0xDB4AC, 'AeAfControlMarkers'),
    ]
    listings = []
    tool = project / 'work/build-arc/binutils'
    with tempfile.TemporaryDirectory(prefix='s33-shutter-') as td:
        for bidx in sorted({w[0] for w in windows}):
            elf = Path(td) / f'b{bidx}.elf'
            back = Path(td) / f'b{bidx}.bin'
            run([tool / 'objcopy', '-I', 'binary', '-O', 'elf32-littlearc', '-B', 'arc',
                 '--rename-section', '.data=.text,alloc,load,readonly,code,contents',
                 '--change-section-vma', f'.data={info[bidx]["load_address_candidate"]:#x}',
                 '--strip-all', block_dir / info[bidx]['file'], elf])
            run([tool / 'objcopy', '--dump-section', f'.text={back}', elf])
            assert back.read_bytes() == payloads[bidx]

            def listing(start, end, name, bidx=bidx, elf=elf):
                for extra in (0, 2, 4, 6):
                    text = run([tool / 'objdump', '-d', '-m', 'arc:ARC700', '-EL',
                                f'--start-address={start:#x}',
                                f'--stop-address={end + extra:#x}', elf])
                    if 'out of bounds' not in text.lower():
                        return f'WINDOW BLOCK {bidx} {name} {start:#x}..{end + extra:#x}\n' + \
                            text.replace(str(elf), f'verified-block{bidx}.elf')
                raise ValueError(f'Truncated instruction in {name}')

            for wi, s, e, n in [w for w in windows if w[0] == bidx]:
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

    # S1 pressed: marker, request 0x158d04 with constant 0x2600001 and 2000.
    requires('S1PressedHead', 0x655000, 'bl.d', '0x12cad4')
    requires('S1PressedHead', 0x655026, '\tbl\t', '\t0x158d04')
    requires('S1PressedHead', 0x655032, '\tbl\t', '\t0x17be18')
    # S1/S2 interlock and mode branches.
    requires('S1InterlockAndModes', 0x65505A, '\tbl\t', '\t0x16f920')
    requires('S1InterlockAndModes', 0x655064, '\tbl\t', '\t0x16f920')
    requires('S1InterlockAndModes', 0x6550A4, '\tbl\t', '\t0x16f920')
    requires('S1InterlockAndModes', 0x6550CE, '\tbl\t', '\t0xcad30')
    requires('S1InterlockAndModes', 0x6550E4, '\tbl\t', '\t0xcf554')
    # S1 can re-open an object by id (0x1453e4) and forwards event 0x80 (0x17bd98).
    requires('S1OpenObject', 0x655172, '\tbl\t', '\t0x1453e4')
    requires('S1OpenObject', 0x655196, '\tbl\t', '\t0x17bd98')
    # S1 prepares the capture state byte via 0x0cbaf0 into context+59 = 0x681eaf.
    requires('S1StatePrepare', 0x6556DA, '\tbl\t', '\t0xca310')
    requires('S1StatePrepare', 0x6556E4, '\tbl\t', '\t0xca38c')
    requires('S1StatePrepare', 0x6556F2, 'add\tr3,r13,0x3b')
    requires('S1StatePrepare', 0x6556F6, '\tbl\t', '\t0xcbaf0')
    # S2 handler head reads the same context (known chain, boundary anchor).
    requires('S2HandlerHead', 0x654CD4, 'push_s')
    # S1 released handler services.
    requires('S1Released', 0x655B7E, '\tbl\t', '\t0x17083c')
    requires('S1Released', 0x655B90, '\tbl\t', '\t0xcb5b0')
    requires('S1Released', 0x655BC4, '\tbl\t', '\t0xdebf0')
    requires('S1Released', 0x655BE0, '\tbl\t', '\t0xcd558')
    # AE/AF control tratto logs a family marker via 0x12cad4 (literal 0xb00104 at 0xdb4e0).
    requires('AeAfControlMarkers', 0xDB494, '\tbl\t', '\t0xf6f4c')
    requires('AeAfControlMarkers', 0xDB4A0, 'bl.d', '0x12cad4')

    evidence = {
        'analysis': 'STATIC two-stage shutter S1/S2 model; no firmware executed',
        'firmware_reference': 'Nikon S33 V1.1; camera observed V1.0; offsets not portable without proof',
        'verified_blocks': 16,
        'script_sha256': sha(Path(__file__).read_bytes()),
        'block_sha256': {str(b['index']): b['sha256'] for b in blocks},
        'explicit_windows': [dict(block=wi, start=hex(s), end_exclusive=hex(e), name=n)
                             for wi, s, e, n in windows],
        'capture_liveview_event_table': dict(base='0x7833ec', block=3, entries=entries),
        'two_stage_model': {
            's1_pressed': dict(event='0x80 (key 1, id 1<<7)', handler='0x654fe8',
                               marker='0xb00100 S1 event logged at 0x655000',
                               request='0x158d04(0x2600001, 8, 0, 2000) at 0x655026',
                               interlock='key-state getter 0x16f920 on keys 1 and 2; '
                                        'mode getter 0xcad30 with branches 0x46/0x6c',
                               reopens='0x1453e4(1, 0) at 0x655172 after 0x1439d4(0x15)',
                               state_prepare='0x0cbaf0(first, second, [fp-70], ctx+59) '
                                             'at 0x6556f6 writes 0x681eaf (same byte S2 reads)'),
            's1_released': dict(event='0x81 (key 1 released)', handler='0x655b68',
                                services=['0x17083c(1)', '0xcb5b0', '0xdebf0', '0x177484',
                                          '0x149df4', '0xdecd4', '0xcd558(1)'],
                                marker_literal='0xb00105 S1 display at 0x655b5c (pool of the region)'),
            's2_pressed': dict(event='0x100 (key 2, id 2<<7)', handler='0x654cd4',
                               chain='reads 0x681eaf, opens CaptureImage index 4 via '
                                     '0x1453e4, events 0x4401/0x4405 -> state 0x68200d -> '
                                     'CapMgr 0x1b9ea8 (documented in S33_S2_Stato_CaptureImage)'),
            'note': 'the state byte consumed by S2 is prepared inside the S1 pressed handler; '
                    'static links only, no proof of runtime ordering',
        },
        'marker_family_sites': marker_sites,
        'marker_names': {hex(c): n for c, n in (
            (0xB00100, 'S1 event'), (0xB00101, 'AE start'), (0xB00102, 'AE lock'),
            (0xB00103, 'AF start'), (0xB00104, 'AF lock'), (0xB00105, 'S1 display'),
            (0xB00106, 'S2 event'), (0xB00107, 'Expo start'))},
        'limits': [
            'Static V1.1 only; no execution, no hardware, no V1.0 proof.',
            'Physical button identity/polarity of key 1/key 2 as half/full press is inferential '
            '(marker names and interlock checks support it, no measurement).',
            'The S1 handler is long and mode-dependent: most branches (0x6c modes, 0xd0270, '
            '0xcf554, 0x17bd98 forwarding) are not reconstructed.',
            'Runtime ordering S1-then-S2 is assumed from design, not executed.',
            'AE start/AF start/AF lock markers are pool literals of a block-0 function around '
            '0xdb470..; the AE/AF service itself is not traced to hardware.',
            'ARC objdump is linear; windows rooted, branches not executed.',
        ],
    }
    (out / 'verified_evidence.json').write_text(json.dumps(evidence, indent=2) + '\n')
    (out / 'gnu_verified.txt').write_text('\n\n'.join(listings) + '\n')
    print(f'16 blocks verified; {len(windows)} rooted windows; '
          f'{len(entries)} table entries; 8 marker codes; evidence in {out}')


if __name__ == '__main__':
    main()
