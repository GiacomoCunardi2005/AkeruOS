#!/usr/bin/env python3
"""Offline S33 V1.1: display/screen output chain, first static dossier.

Static evidence for the layers that turn software state into pixels on the
LCD: graphics font/context library, LCD driver timing logs, panel type table,
TV/LCD mode test, service-script keywords (LCDOn/LCDOff/ClearOSD) and the BCIP
command layer. Never executes firmware, never accesses the camera or USB.
"""
import json
import re
import struct
import tempfile
from pathlib import Path

from s33_trace_state_dispatch import run, sha, verified_payloads


def main():
    root = Path(__file__).resolve().parent
    project = root.parent
    blocks, payloads, block_dir = verified_payloads(project)
    info = {b['index']: b for b in blocks}
    out = project / 'Ghidra_Results' / 'ghidra_reports' / 'display_output'
    out.mkdir(parents=True, exist_ok=True)

    def raw(index, address, size):
        offset = address - info[index]['load_address_candidate']
        if not 0 <= offset <= len(payloads[index]) - size:
            raise ValueError(f'Out-of-bounds read: block {index} {address:#x}')
        return payloads[index][offset:offset + size]

    def word(index, address):
        return struct.unpack('<I', raw(index, address, 4))[0]

    # --- Literal pools tying code to display strings ---
    pools = {
        (0, 0x1EB3A8): 0x3BB256,   # "hfFontCreate Fail"
        (0, 0x1EB3B0): 0x3BB280,   # "hfContextBindFont Fail"
        (0, 0x1DF3AC): 0x3BA713,   # "LCD V_COM = 1 %d"
        (0, 0x1DF3B0): 0x3BA725,   # "LCD V_COM = 0 %d"
        (0, 0x16C3F4): 0x392CBF,   # "Set LCD Mode : OK"
        (0, 0x16C40C): 0x0FEB1000, # MMIO used by the TV/LCD mode test
        (0, 0x16C410): 0x90A1100,  # second literal of the same test pool
        (0, 0x1226E8): 0x385067,   # "LCD Will be turn off"
        (2, 0x651F1C): 0x782172,   # "Load LCD TG CLK OK"
        (4, 0x7CCE1C): 0x982E9F,   # "LCD : GPT 640x480 3.0" label table pointer
    }
    for (index, addr), value in pools.items():
        assert word(index, addr) == value, (index, hex(addr))

    # --- Display-related strings, byte-verified ---
    strings = {
        (1, 0x3BB256): b'hfFontCreate Fail\0',
        (1, 0x3BB280): b'hfContextBindFont Fail\0',
        (1, 0x3BA713): b'LCD V_COM = 1 %d\n\0',
        (1, 0x3BA725): b'LCD V_COM = 0 %d\n\0',
        (1, 0x392CBF): b'Set LCD Mode : OK\0',
        (1, 0x385067): b'LCD Will be turn off\0',
        (1, 0x38F824): b'Display start\0',
        (1, 0x38F9E8): b'REV display\0',
        (3, 0x782172): b'Load LCD TG CLK OK\0',
        (5, 0x982E9F): b'LCD : GPT 640x480 3.0\0',
        (5, 0x982FA7): b'LCD : Default\0',
        (5, 0x988799): b'save LCD type in calibration fail\0',
    }
    for (index, addr), text in strings.items():
        assert raw(index, addr, len(text)) == text, (index, hex(addr))

    # --- Service-script keyword dictionary (block 5) ---
    dictionary_region = (0x9A0C00, 0x9A2000)
    d5 = payloads[5]
    lo = dictionary_region[0] - info[5]['load_address_candidate']
    hi = dictionary_region[1] - info[5]['load_address_candidate']
    region = d5[lo:hi]
    keywords = [b'ClearOSD', b'LCDOff', b'LCDOn', b'LCDRedrawEnable',
                b'LCD_TypeSelect', b'LCD_TypeSetup', b'LCD_TypeGet',
                b'LCDScript_SetFixedBrightness', b'SetBrightnessValue',
                b'ResetLCDPwrSave', b'SetFontColor', b'VFSetFontColor']
    keyword_hits = {}
    for kw in keywords:
        pos = region.find(kw + b'\0')
        assert pos >= 0, kw
        addr = dictionary_region[0] + pos
        # record tail: the byte run after the name NULs contains 0x07 + flag
        tail = region[pos + len(kw):pos + len(kw) + 6]
        assert b'\x07' in tail, (kw, tail)
        keyword_hits[kw.decode()] = dict(address=hex(addr), tail=tail.hex(' '))
    key_commands = sorted(set(re.findall(rb'Key[A-Z][A-Za-z]{2,18}\0', region)))
    assert len(key_commands) >= 20

    # --- BCIP command inventory (block 1) ---
    d1 = payloads[1]
    bcip = sorted(set(m.group().decode() for m in re.finditer(rb'BCIP_[A-Za-z_]{2,40}', d1)))
    assert 'BCIP_LCD_PLAY_IMAGE' in bcip
    assert 'BCIP_SET_LCD_BACK_LIGHT' in bcip
    assert len(bcip) >= 28

    # --- Rooted GNU windows ---
    windows = [
        (0, 0x1EB2C0, 0x1EB3C0, 'FontContextSequence'),
        (0, 0x1EB3B8, 0x1EB418, 'FontContextFail'),
        (0, 0x1DF300, 0x1DF3C0, 'LcdVcomTest'),
        (0, 0x16C380, 0x16C420, 'TvLcdModeTestUser'),
        (0, 0x1226A0, 0x122710, 'LcdTurnOffUser'),
        (2, 0x651EC0, 0x651F40, 'LcdTgClkLoad'),
        (5, 0x9A1210, 0x9A1280, 'ScriptKeywordLcdEntries'),
        (4, 0x7CCDF0, 0x7CCE30, 'LcdTypeLabelTable'),
    ]
    listings = []
    tool = project / 'work/build-arc/binutils'
    with tempfile.TemporaryDirectory(prefix='s33-display-output-') as td:
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

    # Graphics font/context library call sequence and failure logging.
    requires('FontContextSequence', 0x1EB2C2, '\tbl\t', '\t0x2981a4')
    requires('FontContextSequence', 0x1EB304, '\tbl\t', '\t0x29af40')
    requires('FontContextSequence', 0x1EB316, '\tbl\t', '\t0x156890')
    requires('FontContextSequence', 0x1EB326, '\tbl\t', '\t0x2983dc')
    requires('FontContextSequence', 0x1EB33E, '\tbl\t', '\t0x2986b0')
    requires('FontContextSequence', 0x1EB356, '\tbl\t', '\t0x298740')
    requires('FontContextSequence', 0x1EB36E, '\tbl\t', '\t0x298408')
    requires('FontContextSequence', 0x1EB37E, '\tbl\t', '\t0x298dc8')
    requires('FontContextSequence', 0x1EB38A, '\tbl\t', '\t0xad90c')
    requires('FontContextFail', 0x1EB3C8, '\tbl\t', '\t0xc588c')
    requires('FontContextFail', 0x1EB3D0, '\tbl\t', '\t0xc7e04')
    requires('FontContextFail', 0x1EB3EC, '\tbl\t', '\t0x32de80')
    requires('FontContextFail', 0x1EB3F4, '\tbl\t', '\t0x1ebde0')
    requires('FontContextFail', 0x1EB406, '\tbl\t', '\t0x1ebe20')

    # TV/LCD mode test uses the key-state getter and MMIO 0x0FEB1000.
    requires('TvLcdModeTestUser', 0x16C392, '\tbl\t', '\t0x210bc8')
    requires('TvLcdModeTestUser', 0x16C38C, 'bl.d', '0x145c3c')
    requires('TvLcdModeTestUser', 0x16C3A6, '\tbl\t', '\t0x1564a8')
    requires('TvLcdModeTestUser', 0x16C3CE, '\tbl\t', '\t0x175a24')
    requires('TvLcdModeTestUser', 0x16C3D2, '\tbl\t', '\t0x17fc48')

    # LCD timing/clock load with readiness predicates and logger 0x1567f8.
    requires('LcdTgClkLoad', 0x651EC4, '\tbl\t', '\t0x1567f8')
    requires('LcdTgClkLoad', 0x651ED2, '\tbl\t', '\t0x65208c')
    requires('LcdTgClkLoad', 0x651EF2, '\tbl\t', '\t0x6520a8')

    # VCOM test tratto: iteration over halfword parameter table plus service calls.
    requires('LcdVcomTest', 0x1DF316, '\tbl\t', '\t0x32e180')
    requires('LcdVcomTest', 0x1DF330, '\tbl\t', '\t0x12de3c')

    evidence = {
        'analysis': 'STATIC display/screen output chain dossier; no firmware executed',
        'firmware_reference': 'Nikon S33 V1.1; camera observed V1.0; offsets not portable without proof',
        'verified_blocks': 16,
        'script_sha256': sha(Path(__file__).read_bytes()),
        'block_sha256': {str(b['index']): b['sha256'] for b in blocks},
        'explicit_windows': [dict(block=wi, start=hex(s), end_exclusive=hex(e), name=n)
                             for wi, s, e, n in windows],
        'layers': {
            'object_ui': 'already documented: 0x1453e4 opens objects; resource framework; '
                         'render completion not executed (muludw 0x3342b4 stop in MENU_DIFFERENTIAL)',
            'font_context_library': {
                'cluster': '0x298000..0x29d000 (block 0)',
                'sequence': '0x1eb2c0..0x1eb410: create 0x2981a4, bind font 0x29af40/0x2986b0, '
                            'attach 0x2983dc, finalize 0x298740/0x298408/0x298dc8; '
                            'failures log via 0x156890(0x50,0x50,2,string)',
                'fail_strings': ['hfFontCreate Fail 0x3bb256', 'hfContextBindFont Fail 0x3bb280'],
                'second_entry': '0x1eb3b8 context rebind path calling 0xc588c, 0xc7e04, '
                                '0x32de80, 0x1ebde0, 0x1ebe20',
            },
            'lcd_driver_timing': {
                'tratto': '0x651ec0 (block 2) logger 0x1567f8(0x14, line, string)',
                'predicates': ['0x65208c', '0x6520a8'],
                'strings': ['Load LCD TG CLK OK 0x782172'],
            },
            'panel_vcom_test': {
                'tratto': '0x1df300 (block 0) iterates halfword parameter table, calls '
                          '0x32e180 and 0x12de3c; logs LCD V_COM = 1/0 %d',
            },
            'tv_lcd_mode_test': {
                'tratto': '0x16c3xx (block 0): TV OUT / LCD mode test with AV-cable strings, '
                          'key-state getter 0x16f920 via 0x210bc8 level, MMIO literal 0x0feb1000 '
                          'and 0x90a1100 in pool 0x16c3e4..0x16c410',
            },
            'panel_type_table': {
                'labels': 'LCD : GPT/WTK/TNA 640x480|960x240|960x480, LCD : Default (block 5)',
                'label_pointer': 'block 4 word 0x7cce1c -> 0x982e9f',
                'debug_commands': ['LCD_TypeSelect', 'LCD_TypeSetup', 'LCD_TypeGet'],
                'calibration_note': 'save LCD type in calibration fail (0x988799)',
            },
            'service_script_dictionary': {
                'region': '0x9a0c00..0x9a2000 (block 5), sorted keyword records '
                          'name + NULs + 0x07 + flag',
                'lcd_keywords': keyword_hits,
                'simulated_key_commands': [k.decode().rstrip('\0') for k in key_commands],
                'parser': 'not located in this pass; string references use '
                          'pc-relative forms without aligned pointers',
            },
            'bcip_command_layer': {
                'inventory': bcip,
                'display_commands': ['BCIP_LCD_PLAY_IMAGE', 'BCIP_SET_LCD_BACK_LIGHT'],
                'handlers': 'not attributed in this pass; description strings in block 1 '
                            'document parameters (image size/position/patterns; '
                            'backlight value 0-255)',
            },
        },
        'limits': [
            'Static V1.1 only; nothing executed, no hardware or USB access.',
            'The parser/dispatcher of the service-script dictionary and the BCIP handlers are not attributed yet.',
            'Font/context library internals (0x298000..0x29d000) not disassembled; glyph data and framebuffer target not identified.',
            'MMIO 0x0feb1000/0x90a1100 appear in the TV/LCD mode test pool; exact display controller registers and framebuffer address remain unknown.',
            'No proof that opening a UI object completes drawing: the object-to-pixels path is not executed.',
            'ARC objdump is linear; windows are rooted but branches were not executed.',
        ],
    }
    (out / 'verified_evidence.json').write_text(json.dumps(evidence, indent=2) + '\n')
    (out / 'gnu_verified.txt').write_text('\n\n'.join(listings) + '\n')
    print(f'16 blocks verified; {len(windows)} rooted windows; {len(bcip)} BCIP commands; '
          f'{len(keywords)} LCD script keywords; evidence in {out}')


if __name__ == '__main__':
    main()
