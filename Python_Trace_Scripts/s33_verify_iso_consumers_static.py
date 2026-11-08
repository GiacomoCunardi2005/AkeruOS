#!/usr/bin/env python3
"""Check original V1.1 bytes and disassembly anchors for ISO value consumers."""
from pathlib import Path
from datetime import datetime, timezone
import sys
sys.path.insert(0, str(Path(__file__).resolve().parents[1] / 'S33-sections/analysis_codex'))
from static_common import ROOT, raw, locate, u32, disasm

def main():
    windows = {
        'enum_restore': (0xca654, 0xca6a4),
        'enum_and_value': (0xd03b8, 0xd03e0),
        'iso_converter': (0x17c320, 0x17c3f8),
        'iso_value_access': (0xde736, 0xde7b4),
        'threshold_adjustment': (0xd8ca4, 0xd8d7e),
        'guard_helpers': (0x18d7c0, 0x18d81a),
        'threshold_branch': (0xfe2b2, 0xfe480),
        'caller': (0x65bde8, 0x65be04),
    }
    dump = (ROOT / 'DUMPS/MainCode.dmp').read_bytes()
    out = ROOT / 'Risultati/GUI_S33' / datetime.now(timezone.utc).strftime('iso_consumers_static_%Y%m%dT%H%M%SZ')
    out.mkdir(parents=True)
    evidence = {}
    for name, (start, end) in windows.items():
        block, offset = locate(start, end - start)
        data = raw(start, end - start)
        assert data == dump[block['offset'] + offset : block['offset'] + offset + len(data)], name
        evidence[name] = disasm(start, end)
    for address, expected in [(0xd03d4, 0x365787), (0x17c3e8, 0x367bc8),
                              (0xf6f10, 0x37fbd0), (0xfe504, 0x366374),
                              (0xfe510, 0x3663b0)]:
        block, offset = locate(address, 4)
        assert raw(address, 4) == dump[block['offset'] + offset : block['offset'] + offset + 4]
        assert u32(address) == expected, hex(address)
    checks = {
        'enum_restore': [';0xd03d8', 'stw_s\tr0,[r13,0x8]', 'ldb_s\tr0,[r13,0x8]', ';0x17c320'],
        'iso_converter': [';0x17c3e8', ';0xde78c'],
        'iso_value_access': ['stw_s\tr13,[r0,0x22]', 'ldw_s\tr0,[r0,0x22]'],
        'threshold_adjustment': [';0xf6f0c', 'ldw_s\tr1,[r0,0x22]', 'ldh.x\tr25,[r20,4]', 'add\tr0,r1,r25'],
        'guard_helpers': ['18d7c0:', 'mov_s\tr0,0', '18d7d8:', ';0x18d7c0', 'mov_s\tr0,0x1'],
        'threshold_branch': [';0x18d7d8', ';0x18d7c0', 'ldh\tr24,[r0,34]', 'mov.f\tr1,r24', 'stw_s\tr1,[r0,0x2c]'],
        'caller': [';0xca654'],
    }
    for name, anchors in checks.items():
        for anchor in anchors:
            assert anchor in evidence[name], (name, anchor)
    for name, listing in evidence.items():
        (out / (name + '.txt')).write_text(listing)
    (out / 'verifier_snapshot.py').write_bytes(Path(__file__).read_bytes())
    print('PASS: bytes payload == dump e ancore GNU; prove:', out)

if __name__ == '__main__':
    main()
