#!/usr/bin/env python3
"""Verify bounded HiddenMenu navigation and MSDC storage; no camera I/O."""
from datetime import datetime, timezone
from pathlib import Path
import json
import struct
import sys

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / 'S33-sections/analysis_codex'))
from static_common import BS, ORIGINAL, EXPECTED, raw, u32, cstring, sha, locate, disasm
from catalog_hiddenmenu import parse_lines

WINDOWS = [(0x7cff90, 0x7cffb0), (0x7cc88c, 0x7cc8ac),
           (0x806ca4, 0x806cd4), (0x806cd4, 0x806d48),
           (0x138f70, 0x138f78), (0x138f7c, 0x138f94),
           (0xc5f02, 0xc5f1e), (0x7d02ee, 0x7d0310),
           (0x631b14, 0x631bf0), (0x8098b8, 0x8098d4),
           (0x20e814, 0x20e844), (0x20ea5c, 0x20eac4),
           (0x7cd764, 0x7cd784), (0x7cd688, 0x7cd6a4), (0x7cd634, 0x7cd660)]


def main():
    out = ROOT / 'Risultati/HiddenMenu_Uscita' / datetime.now(timezone.utc).strftime('%Y%m%dT%H%M%SZ')
    out.mkdir(parents=True, exist_ok=False)
    firmware = ORIGINAL.read_bytes()
    dump_path = ROOT / 'DUMPS/MainCode.dmp'
    dump = dump_path.read_bytes()
    assert sha(firmware) == EXPECTED
    tools = {ROOT / 'work/build-arc/binutils' / n: None for n in ('objcopy', 'objdump')}
    tools = {p: sha(p.read_bytes()) for p in tools}
    spans = []

    def check_bytes(a, n):
        block, offset = locate(a, n)
        data = raw(a, n)
        assert dump[block['offset'] + offset:block['offset'] + offset + n] == data
        spans.append(dict(address=hex(a), bytes=n, sha256=sha(data)))

    rows = {}
    texts = []
    for start, end in WINDOWS:
        check_bytes(start, end - start)
        text = disasm(start, end)
        texts.append(text)
        rows.update({r['address']: r for r in parse_lines(text)})
    checks = [(0x7cffa4, 'mov_s', 'r0,0x20'), (0x7cffa8, 'bl', ';0x1453e4'),
              (0x7cc8a0, 'mov_s', 'r0,0x84'), (0x7cc8a4, 'bl', ';0x1453e4'),
              (0x806cbc, 'bl', ';0xc9d84'), (0x806cc0, 'bl', ';0xcbdf8'),
              (0x806cc4, 'bl', ';0x177030'), (0x806ccc, 'bl', ';0x1453e4'),
              (0x806cee, 'bl', ';0x12b0dc'), (0x806cf6, 'bne_s', ';0x806d34'),
              (0x806d12, 'bl', ';0x12bbb8'), (0x806d1c, 'cmp_s', 'r0,0x1'),
              (0x806d1e, 'bne_s', ';0x806d34'), (0x806d20, 'mov_s', 'r0,0x8'),
              (0x806d22, 'bl', ';0x16f920'), (0x806d28, 'beq_s', ';0x806d34'),
              (0x806d2a, 'mov_s', 'r0,0x20'), (0x806d2e, 'bl', ';0x1453e4'),
              (0x806d34, 'mov_s', 'r0,0x78'), (0x806d38, 'bl', ';0x1453e4'),
              (0x138f88, 'stb_s', 'r0,[r1,0]'), (0xc5f18, 'mov_s', 'r0,0x2'),
              (0xc5f1a, 'bl', ';0x138f7c'), (0x7d02fc, 'bl', ';0x138f7c'),
              (0x631b56, 'mov_s', 'r14,0x3'), (0x631b8a, 'bl', ';0x631e00'),
              (0x8098cc, 'bl', ';0x20e814'), (0x20e832, 'bl', ';0x169f60'),
              (0x20ea70, 'bl', ';0xcad5c'), (0x20ea7c, 'cmp_s', 'r0,0x1'),
              (0x20ea84, 'cmp_s', 'r0,0x3'), (0x20ea88, 'mov_s', 'r0,0x1'),
              (0x20ea8c, 'bl', ';0x1453e4'),
              (0x7cd778, 'mov_s', 'r0,0x20'), (0x7cd77c, 'bl', ';0x1453e4'),
              (0x7cd69c, 'bl', ';0x7cd784')]
    for address, op, fragment in checks:
        assert rows[address]['op'] == op and fragment in rows[address]['args'], rows[address]
    pools = {0x138f78: 0x366b9d, 0x806d48: 0x99f26c,
             0x3f5900 + 0x78 * 4: 0x99e1f0}
    for a, value in pools.items():
        check_bytes(a, 4)
        assert u32(a) == value
    check_bytes(0x366b9d, 1)
    assert raw(0x366b9d, 1) == b'\x02'
    assert cstring(0x99f26c) == '\\HiddenMenu'
    check_bytes(0x99f26c, len('\\HiddenMenu') + 1)
    catalog = json.loads((ROOT / 'S33-sections/analysis_codex/evidence/ui_catalog.json').read_text())
    menus = {r['id']: r for r in catalog['rows']}
    for menu, event, callback in [('0x36', '0x480', '0x7cff90'),
                                  ('0x20', '0x480', '0x7cc88c'),
                                  ('0x84', '0x2180', '0x806ca4'),
                                  ('0x84', '0x2700', '0x806cd4')]:
        assert any(e['event'] == event and e['callback'] == callback for e in menus[menu]['events'])
        record = next(e['record'] for e in menus[menu]['events'] if e['event'] == event)
        a = int(record, 16)
        check_bytes(a, 8)
        assert u32(a) == int(event, 16) and u32(a + 4) == int(callback, 16)
    assert menus['0x78']['internal_name'] == 'SetupMenu'
    check_bytes(0x77f69c, 32)
    assert struct.unpack('<8I', raw(0x77f69c, 32)) == (0x580, 0x631878, 0x700, 0x63195c,
                                                    0x2180, 0x631a38, 0x2700, 0x631b14)
    check_bytes(0x3e8bec, 8)
    assert (u32(0x3e8bec), u32(0x3e8bf0)) == (0x200, 0x20ea5c)
    check_bytes(0x3f5904, 4)
    assert u32(0x3f5904) == int(menus['0x1']['descriptor'],16)
    assert menus['0x1']['internal_name'] == 'CaptureLiveview'
    assert u32(0x7cd684) == 0x98425c
    footer = '<REV>:Dump2File & Exit. <S2>:Clear'
    assert cstring(0x98425c) == footer
    for a,n in [(0x7cd684,4),(0x98425c,len(footer)+1),(0x984174,8),(0x98415c,8)]: check_bytes(a,n)
    assert (u32(0x984174),u32(0x984178)) == (0x480,0x7cd764)
    assert (u32(0x98415c),u32(0x984160)) == (0x4406,0x7cd688)
    # Only the small setter body is exhaustive here, not its callers or lifecycle.
    setter = [r for a, r in rows.items() if 0x138f7c <= a < 0x138f94]
    assert not any(r['op'].startswith('bl') or r['op'].startswith('jl') for r in setter)
    assert sum(r['op'].startswith('stb') for r in setter) == 1
    (out / 'gnu_verified.txt').write_text('\n'.join(texts))
    previous = ROOT / json.loads((ROOT / 'Risultati/Dump_fotocamera/Clock_Perf/latest.json').read_text())['evidence']
    old = json.loads(previous.read_text())
    log_checks = []
    for name in ('ClockSettings.csv', 'PerfLog.txt'):
        source = ROOT / name
        expected = next(v for k, v in old['inputs'].items() if Path(k).name == name)
        assert sha(source.read_bytes()) == expected['sha256']
        assert sha((ROOT / expected['preserved_copy']).read_bytes()) == expected['sha256']
        log_checks.append(dict(file=name, sha256=expected['sha256'], saved_copy=expected['preserved_copy']))
    supplied = {name:(ROOT / name).read_bytes() for name in ('P1RES','NIKON001.DSC','ClockSettings.csv','PerfLog.txt')}
    marker = struct.unpack_from('<I', firmware, 0x480b4)[0]
    res_offset, res_size = struct.unpack_from('<II', firmware, marker+0x40)
    assert supplied['P1RES'] == firmware[res_offset:res_offset+res_size]
    reserved_path = ROOT / 'DUMPS/NANDReserved.dmp'; reserved = reserved_path.read_bytes()
    assert supplied['P1RES'] == reserved[512:512+res_size]
    assert supplied['NIKON001.DSC'] == b' '*512
    sources = out / 'fonti'; sources.mkdir()
    for name, data in supplied.items(): (sources / name).write_bytes(data)
    assert ORIGINAL.read_bytes() == firmware and dump_path.read_bytes() == dump
    assert all(sha(p.read_bytes()) == h for p, h in tools.items())
    assert all((ROOT / name).read_bytes() == data for name,data in supplied.items())
    assert reserved_path.read_bytes() == reserved
    result = dict(status='PASS_BOUNDED_EXIT_AND_MSDC_STORAGE_CHECKS', firmware_sha256=EXPECTED,
        main_dump_sha256=sha(dump), payloads_verified=len(BS), windows=len(WINDOWS),
        instruction_checks=len(checks), checked_spans=spans,
        tools_unchanged={str(p.relative_to(ROOT)): h for p, h in tools.items()},
        navigation={'debug_back': '36/0480 -> 20', 'root_back': '20/0480 -> 84',
                    'confirmation_2180': 'C9D84(1,1), CBDF8, 177030 then SetupMenu78',
                    'alternative_2700': 'prefix error ->78; otherwise attribute byte1 and logical key8 nonzero ->20, else78',
                    'generic_list_slot': '2700 selects fourth logical slot when applicable; physical button not established',
                    'setup_liveview_candidate': 'Setup default ->20E814; event0200 ->20EA5C; mode1 and secondary state!=3 ->CaptureLiveview1'},
        msdc={'address': '0x366b9d', 'initial_image_value': 2,
              'setter': '138F7C: byte store only, no function call or persistent commit',
              'known_override': 'C5F1A passes2 if logical keys9/11 both nonzero',
              'persistence_after_restart': 'not proven'},
        logs_rechecked=log_checks, prior_log_analysis=str(previous.relative_to(ROOT)),
        new_supplied_files={name:dict(bytes=len(data), sha256=sha(data), saved_copy=str((sources/name).relative_to(ROOT))) for name,data in supplied.items()},
        p1res_matches_original_and_reserved=True, nikon001_only_spaces=True,
        error_code_exit={'footer':footer,'event':'0x480','callback':'0x7cd764','requested_menu':'0x20',
                         'close_callback':'0x7cd688','export_call':'0x7cd69c -> 0x7cd784',
                         'scope':'Error Code submenu only; no hardware key action or export executed'},
        limits=['Static byte/instruction checks, not UI emulation or hardware navigation',
                'No global absence of indirect/persistent writers proven; no complete lifecycle effects closed',
                'No physical button or visible Yes/No mapped to2700/2180',
                'SetupMenu is not proof of photographing readiness or preserved settings',
                'No global save-all procedure; other options need individual tracing',
                'No new firmware, hardware command or GNU-tree write'])
    (out / 'verified_evidence.json').write_text(json.dumps(result, indent=2) + '\n')
    (out / 'script.py.snapshot').write_bytes(Path(__file__).read_bytes())
    (out.parent / 'latest.json').write_text(json.dumps({'evidence': str((out / 'verified_evidence.json').relative_to(ROOT))}, indent=2) + '\n')
    print(result['status'], len(WINDOWS), 'windows;', len(checks), 'instruction checks;', out)


if __name__ == '__main__':
    main()
