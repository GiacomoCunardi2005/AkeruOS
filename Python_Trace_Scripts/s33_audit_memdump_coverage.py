#!/usr/bin/env python3
"""Compare Nikon's diagnostic range with verified V1.1 container descriptors."""
from datetime import datetime, timezone
from pathlib import Path
import json
import sys
from s33_trace_state_dispatch import verified_payloads

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / 'S33-sections/analysis_codex'))
from static_common import BS


def main():
    _, payloads, _ = verified_payloads(ROOT)
    dump_end = 0x0104074C
    rows = []
    for block in BS:
        payload = payloads[block['index']]
        start = block['load_address_candidate']
        end = start + block['size']
        covered = max(0, min(end, dump_end) - start)
        assert len(payload) == block['size'] and covered <= block['size']
        rows.append({'block': block['index'], 'type': block['type'], 'base_candidate': hex(start), 'end_exclusive': hex(end), 'size': block['size'], 'covered_bytes': covered, 'outside_bytes': block['size'] - covered})
    assert len(rows) == 16 and all(row['outside_bytes'] == 0 for row in rows[:10])
    assert rows[10]['end_exclusive'] == '0x1040800' and rows[10]['outside_bytes'] == 0xb4
    assert all(row['base_candidate'] == '0x1044800' and row['covered_bytes'] == 0 for row in rows[11:16])
    assert dump_end < 0x01040800 < 0x01044800
    out = ROOT / 'Risultati/Runtime_Kernel/MEMDUMP_Coverage' / datetime.now(timezone.utc).strftime('%Y%m%dT%H%M%S%fZ')
    out.mkdir(parents=True)
    evidence = {'dump_interval': ['0x0', hex(dump_end)], 'blocks': rows, 'known_software_table_addresses_outside': ['0x01040800', '0x0104088c'], 'limits': ['Descriptor addresses are candidates; no simultaneous overlay residency or physical RAM asserted.', 'This is static arithmetic, not a physical memory map or a capture.', 'NON_INSTALLARE.']}
    (out / 'evidence.json').write_text(json.dumps(evidence, indent=2) + '\n')
    print('PASS static coverage:', out)
    for row in rows[10:]:
        print('block', row['block'], 'covered', row['covered_bytes'], 'outside', row['outside_bytes'])


if __name__ == '__main__':
    main()
