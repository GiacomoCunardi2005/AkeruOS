#!/usr/bin/env python3
"""Verify S33 V1.1 static anchors connecting the exposure field to a calculation."""
from datetime import datetime, timezone
from pathlib import Path
import sys
sys.path.insert(0, str(Path(__file__).resolve().parents[1] / 'S33-sections/analysis_codex'))
from static_common import ROOT, raw, locate, u32, disasm


def main():
    windows = {
        'copy_context': (0xf6f54, 0xf6f88),
        'input_prepare': (0xd8cda, 0xd8d0e),
        'calculate_call': (0xd8e04, 0xd8e22),
        'branches': (0xfda88, 0xfdb12),
        'transform': (0xfdb50, 0xfdbd2),
        'fallback_call': (0xfdbd2, 0xfdbfe),
        'downstream_guard': (0xfde40, 0xfde5a),
        'downstream_use': (0xfdf7c, 0xfdf86),
        'buffer_copy': (0xd9064, 0xd9076),
    }
    anchors = {
        'copy_context': [';0xf6f10', 'mov_s\tr2,0x40', ';0xad920'],
        'input_prepare': ['sub2\tr0,fp,0x13', ';0xf6f54'],
        'calculate_call': ['sub2\tr2,fp,0x13', ';0xfda28'],
        'branches': ['ld_s\tr3,[r13,0x24]', 'ldw_s\tr2,[r13,0x22]', ';0xfdbd2'],
        'transform': ['ld_s\tr2,[r13,0x24]', ';0x336364', 'st\tr0,[fp,-92]'],
        'fallback_call': ['st\tr3,[fp,-92]', 'sub2\tr0,fp,0x1d', ';0xfde08'],
        'downstream_guard': ['ld_s\tr1,[r15,0x18]', ';0xfdfa6'],
        'downstream_use': ['ld_s\tr0,[r15,0x18]', ';0x18c99c'],
        'buffer_copy': ['add\tr0,r0,720', 'sub3\tr1,fp,0x19', ';0xad920'],
    }
    dump = (ROOT / 'DUMPS/MainCode.dmp').read_bytes()
    out = ROOT / 'Risultati/GUI_S33' / datetime.now(timezone.utc).strftime('time_calculation_static_%Y%m%dT%H%M%SZ')
    out.mkdir(parents=True)
    for name, (start, end) in windows.items():
        block, offset = locate(start, end - start)
        content = raw(start, end - start)
        assert content == dump[block['offset'] + offset:block['offset'] + offset + len(content)], name
        listing = disasm(start, end)
        for anchor in anchors.get(name, []):
            assert anchor in listing, (name, anchor)
        (out / (name + '.txt')).write_text(listing)
    literal_block, literal_offset = locate(0xf6f10, 4)
    assert raw(0xf6f10, 4) == dump[literal_block['offset'] + literal_offset:literal_block['offset'] + literal_offset + 4]
    assert u32(0xf6f10) == 0x37fbd0
    assert -76 + 0x24 == -40 and -116 + 0x18 == -92
    (out / 'verifier_snapshot.py').write_bytes(Path(__file__).read_bytes())
    print('PASS: byte dump e ancore di calcolo; prove:', out)


if __name__ == '__main__':
    main()
