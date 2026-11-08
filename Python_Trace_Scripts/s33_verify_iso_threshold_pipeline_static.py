#!/usr/bin/env python3
"""Verify original V1.1 bytes for the ISO threshold-to-buffer path."""
from datetime import datetime, timezone
from pathlib import Path
import sys

sys.path.insert(0, str(Path(__file__).resolve().parents[1] / 'S33-sections/analysis_codex'))
from static_common import ROOT, raw, locate, u32, disasm


def main():
    windows = {
        'entry': (0xd8ca4, 0xd8d0a),
        'threshold_and_arithmetic': (0xd8d0a, 0xd8d7e),
        'first_buffer_update': (0xd8dd0, 0xd8e28),
        'alternative_buffer_update': (0xd8f36, 0xd8f68),
        'last_buffer_update_and_copy': (0xd9022, 0xd9076),
        'callee_entry': (0xfda28, 0xfda40),
        'callee_store': (0xfdbf0, 0xfdc0e),
        'downstream_classifier': (0xe27e8, 0xe28c8),
        'caller_initialization': (0xd5a64, 0xd5a80),
        'caller_a': (0xdb31c, 0xdb340),
        'caller_b': (0xdb640, 0xdb66a),
        'buffer_getter': (0xf6f14, 0xf6f1c),
    }
    checks = {
        'entry': ['mov_s\tr23,r1', 'mov_s\tr22,r2', 'ldh.x\tr17,[fp,-248]'],
        'threshold_and_arithmetic': [';0xe309c', ';0x103f70', 'ldw_s\tr1,[r0,0x22]',
            'ldh.x\tr25,[r20,4]', 'add\tr0,r1,r25', 'sub\tr14,r17,r4', 'sexw_s\tr14,r14'],
        'first_buffer_update': ['mov_s\tr1,r14', 'sub3\tr0,fp,0x19', ';0xfda28'],
        'alternative_buffer_update': [';0x1aa40c', 'sexw_s\tr1,r0', ';0xfda28'],
        'last_buffer_update_and_copy': ['ldh.x\tr1,[fp,-8]', ';0xfda28', ';0xf6f14',
            'add\tr0,r0,720', 'sub3\tr1,fp,0x19', 'mov_s\tr2,0x7c', ';0xad920'],
        'callee_entry': ['mov_s\tr14,r0', 'mov_s\tr18,r1'],
        'callee_store': ['sth\tr18,[r14,76]'],
        'downstream_classifier': ['ldh.x\tr15,[r14,76]', 'add\tr1,r1,300',
            'sub\tr1,r1,300', 'add\tr1,r1,1000', 'sub\tr1,r1,1000', 'mov_s\tr0,r13'],
        'caller_initialization': [';0xd8ca4'], 'caller_a': [';0xd8ca4'],
        'caller_b': [';0xd8ca4'], 'buffer_getter': [';0xf6f18'],
    }
    dump = (ROOT / 'DUMPS/MainCode.dmp').read_bytes()
    out = ROOT / 'Risultati/GUI_S33' / datetime.now(timezone.utc).strftime('iso_threshold_pipeline_static_%Y%m%dT%H%M%SZ')
    out.mkdir(parents=True)
    for name, (start, end) in windows.items():
        block, offset = locate(start, end - start)
        data = raw(start, end - start)
        assert data == dump[block['offset'] + offset:block['offset'] + offset + len(data)], name
        listing = disasm(start, end)
        for anchor in checks[name]:
            assert anchor in listing, (name, anchor)
        (out / (name + '.txt')).write_text(listing)
    for address, expected in [(0xf6f10, 0x37fbd0), (0xf6f18, 0x380574)]:
        block, offset = locate(address, 4)
        assert raw(address, 4) == dump[block['offset'] + offset:block['offset'] + offset + 4]
        assert u32(address) == expected, hex(address)
    assert 0x380574 + 720 + 76 == 0x380890
    (out / 'verifier_snapshot.py').write_bytes(Path(__file__).read_bytes())
    print('PASS: bytes originali e ancore GNU:', out)


if __name__ == '__main__':
    main()
