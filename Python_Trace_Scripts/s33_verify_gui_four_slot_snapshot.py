#!/usr/bin/env python3
"""Check the four GUI slot records against the V1.1 input snapshot."""
from datetime import datetime, timezone
from pathlib import Path
import hashlib
import json
import sys

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / 'S33-sections/analysis_codex'))
from static_common import disasm, locate, raw, u32


def main():
    dump = (ROOT / 'DUMPS/MainCode.dmp').read_bytes()

    def checked(start, end, code=True):
        block, offset = locate(start, end - start)
        assert raw(start, end - start) == dump[block['offset'] + offset:block['offset'] + offset + end - start]
        return disasm(start, end) if code else None

    ranges = [(0x2d62d8, 0x2d6300), (0x1406d0, 0x140700),
              (0x16ec38, 0x16ec86), (0x16e6e0, 0x16e830),
              (0x16f86c, 0x16f8ec), (0x16f6b0, 0x16f72c),
              (0x17bc7c, 0x17bccc), (0x15af0c, 0x15af4c)]
    windows = [checked(*pair) for pair in ranges]
    assert [u32(a) for a in (0x2d62e0, 0x2d62f0)] == [0x0fe70224, 0x0fe70228]
    assert windows[0].count('ldh.di') == 2 and 'asl_s\tr13,r13,0xa' in windows[0] and 'or_s\tr0,r0,r13' in windows[0]
    assert 'not_s\tr13,r14' in windows[1]
    assert all(x in windows[2] for x in (';0x16e6e0', ';0x16f86c', 'cmp_s\tr0,0x1'))
    assert all(x in windows[3] for x in ('0xfe31b188', '0xfe003000', 'cmp_s\tr14,0x1'))
    assert all(x in windows[4] for x in ('xor\tr19', 'xor\tr18', ';0x16f72c'))
    assert ';0x17bc7c' in windows[5] and 'bmsk_s\tr0,r0,0x6' in windows[6]
    assert ';0x17bd4c' in windows[7] and ';0x169e1c' in windows[7]

    checked(0x392f04, 0x392f04 + 16 * 20, code=False)
    checked(0x77f664, 0x77f664 + 8 * 64, code=False)
    slots = [(6, 12, 11, 0x580, 0x631878), (7, 7, 14, 0x700, 0x63195c),
             (8, 8, 67, 0x2180, 0x631a38), (9, 13, 78, 0x2700, 0x631b14)]
    table = raw(0x77f664, 8 * 64)
    entries = []
    for i in range(0, len(table), 8):
        event_id = int.from_bytes(table[i:i + 4], 'little')
        if not event_id:
            break
        entries.append((event_id, int.from_bytes(table[i + 4:i + 8], 'little')))
    else:
        raise AssertionError('class table has no terminator')
    rows = []
    for slot, (record, bit, key, event, callback) in enumerate(slots):
        rec = raw(0x392f04 + 20 * record, 20)
        assert int.from_bytes(rec[:8], 'little') == 1 << bit and rec[8:10] == bytes([bit, key])
        assert key << 7 == event and (event, callback) in entries
        assert 0xfe31b188 & (1 << bit)
        sources = []
        for reg, shift in ((0x0fe70224, 10), (0x0fe70228, 0)):
            for source_bit in range(16):
                if (1 << source_bit) << shift == 1 << bit:
                    sources.append({'register': hex(reg), 'bit': source_bit})
        rows.append({'slot': slot, 'snapshot_bit': bit, 'sources': sources,
                     'logical_key': key, 'event_nonzero': hex(event), 'callback': hex(callback)})
    assert [len(row['sources']) for row in rows] == [2, 1, 1, 2]

    output = ROOT / 'Risultati/GUI_S33' / datetime.now(timezone.utc).strftime('four_slot_snapshot_%Y%m%dT%H%M%SZ')
    output.mkdir(parents=True, exist_ok=False)
    (output / 'evidence.json').write_text(json.dumps({
        'status': 'PASS_STATIC_BOUNDED', 'dump_sha256': hashlib.sha256(dump).hexdigest(), 'rows': rows,
        'snapshot_formula': '(read16(0x0fe70224) << 10) | read16(0x0fe70228)',
        'limitations': ['Register values and physical buttons are not observed.',
                        'Monitoring, normalization, event filters, queue and GUI dispatch depend on runtime conditions.',
                        'Bit sources are algebraic dependencies, not verified independent physical signals.']}, indent=2) + '\n')
    (output / 'gnu_windows.txt').write_text('\n'.join(windows))
    (output / 'script.py.snapshot').write_bytes(Path(__file__).read_bytes())
    print('PASS: four snapshot bit dependencies and bounded event path;', output)


if __name__ == '__main__':
    main()
