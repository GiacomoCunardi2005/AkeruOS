#!/usr/bin/env python3
"""Compare real DSCo samples with the candidate V1.1 marker, read-only."""
from datetime import datetime, timezone
from pathlib import Path
import hashlib
import json
import sys

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / 'S33-sections/analysis_codex'))
from static_common import locate, raw


def sha(data):
    return hashlib.sha256(data).hexdigest()


def main():
    marker = raw(0x35231c, 32)
    block, offset = locate(0x35231c, 32)
    dump_path = ROOT / 'DUMPS/MainCode.dmp'
    dump = dump_path.read_bytes()
    assert marker == dump[block['offset'] + offset:block['offset'] + offset + 32]
    assert set(marker) == {0, 1} and len(marker) == 32
    paths = sorted((ROOT / 'RawsAnalysis').glob('DSCo*.raw'))
    assert [p.stem for p in paths] == [f'DSCo{i}' for i in range(1003, 1013)]
    start, step, half = 4208 * 3152, 2 * 4208, 4208 * 3152
    rows = []
    for path in paths:
        data = path.read_bytes()
        assert len(data) == 2 * half
        bits = [data[start + i * step] & 1 for i in range(32)]
        controls = [[data[start + i * step + 2 * k] & 1 for i in range(32)] for k in range(1, 65)]
        matches = [sum(x == y for x, y in zip(control, marker)) for control in controls]
        pair = path.with_name(path.name.replace('DSCo', 'CFAi'))
        cfa = pair.read_bytes()
        assert len(cfa) == 20808 + half and cfa[20808:] == data[:half]
        rows.append(dict(file=path.name, sha256=sha(data), cfa_file=pair.name, cfa_sha256=sha(cfa),
                         marker_bits=bits, marker_matches=sum(x == y for x, y in zip(bits, marker)),
                         neighbor_matches=matches, neighbor_all_zero=all(not any(c) for c in controls)))
    out = ROOT / 'outputs' / ('raw_marker_comparison_' + datetime.now(timezone.utc).strftime('%Y%m%dT%H%M%SZ'))
    out.mkdir(parents=True)
    result = dict(status='PASS_OBSERVED_COMPARISON', dump_sha256=sha(dump),
                  script_sha256=sha(Path(__file__).read_bytes()), marker_address='0x35231c',
                  marker_bits=list(marker), byte_offset_start=start, byte_stride=step,
                  neighbor_offsets_bytes=[2 * k for k in range(1, 65)], cases=rows,
                  limitations=['Candidate formula assumes r16=0 and identical base pointer; match does not establish producer or prior bits.',
                               'Nearby samples are controls, not independent random trials; no proof of sensor purity or full frame integrity.'])
    (out / 'comparison.json').write_text(json.dumps(result, indent=2) + '\n')
    print(out)
    print('32-bit marker matches:', [r['marker_matches'] for r in rows])
    print('Nearby matches range:', min(min(r['neighbor_matches']) for r in rows), max(max(r['neighbor_matches']) for r in rows))


if __name__ == '__main__':
    main()
