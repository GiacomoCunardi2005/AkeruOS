#!/usr/bin/env python3
"""Compare Nikon saves around the capacity of the synthetic FAT volume."""
from datetime import datetime, timezone
from pathlib import Path
import hashlib
import json
import struct
import subprocess
import tempfile
from s33_trace_state_dispatch import verified_payloads

ROOT = Path(__file__).resolve().parents[1]


def main():
    _, payloads, _ = verified_payloads(ROOT)
    out = ROOT / 'Risultati/Runtime_Kernel/MEMDUMP_Capacity_Boundary' / datetime.now(timezone.utc).strftime('%Y%m%dT%H%M%S%fZ')
    out.mkdir(parents=True)
    scripts = ROOT / 'S33-sections/analysis_ghidra/scripts'
    (out / 'probe_snapshot.java').write_bytes((scripts / 'ProbeMemdumpCapacityBoundary.java').read_bytes())
    with tempfile.TemporaryDirectory(prefix='s33-capacity-') as td:
        tmp = Path(td)
        for i in (0, 1):
            (tmp / f'p{i}.bin').write_bytes(payloads[i])
        cmd = [str(ROOT / 'tools/ghidra-arcompact/ghidra_12.2_DEV/support/analyzeHeadless'), str(tmp), 'model', '-import', str(tmp / 'p0.bin'), '-loader', 'BinaryLoader', '-loader-baseAddr', '0xad800', '-processor', 'ARCompact:LE:32:loopfix', '-noanalysis', '-scriptPath', str(scripts), '-postScript', 'ProbeMemdumpCapacityBoundary.java', str(out / 'trace.txt'), str(tmp / 'p1.bin'), '-deleteProject']
        (out / 'command.json').write_text(json.dumps(cmd, indent=2) + '\n')
        print('Prove:', out, flush=True)
        run = subprocess.run(cmd, stdout=subprocess.PIPE, stderr=subprocess.STDOUT, text=True, timeout=300)
        (out / 'headless.log').write_text(run.stdout)
        assert run.returncode == 0 and 'SCRIPT ERROR' not in run.stdout, run.stdout[-6000:]
    trace = (out / 'trace.txt').read_text()
    assert trace.endswith('COMPLETE cases=3\n'), trace
    for line in ('length=3839 source=high low_changed_after_first=765 status=0 size=4095', 'length=3841 source=high low_changed_after_first=765 status=1a00014 size=4096', 'length=3841 source=low low_changed_after_first=765 status=1a00014 size=4096'):
        assert line in trace, trace
    assert 'copy=100/100/300@21a79e' in trace, trace
    expected = bytes((i * 37 + (i >> 8) * 97 + 11) & 255 for i in range(4097))
    evidence = {}
    for length, source in ((3839, 'high'), (3841, 'high'), (3841, 'low')):
        image = (out / f'card_{length}_{source}.img').read_bytes()
        size = struct.unpack_from('<I', image, 100 * 512 + 28)[0]
        cluster = struct.unpack_from('<H', image, 100 * 512 + 26)[0]
        data, chain = bytearray(), []
        while len(data) < size:
            assert 2 <= cluster <= 5 and cluster not in chain
            chain.append(cluster)
            offset = (102 + (cluster - 2) * 2) * 512
            data.extend(image[offset:offset + 1024])
            pair = struct.unpack_from('<H', image, 20 * 512 + cluster + cluster // 2)[0]
            cluster = pair >> 4 if cluster & 1 else pair & 0xfff
        assert cluster >= 0xff8
        mismatches = [i for i in range(size) if data[i] != expected[i]]
        evidence[f'{length}_{source}'] = {'size': size, 'chain': chain, 'mismatch_count': len(mismatches), 'first_mismatch': mismatches[0] if mismatches else None, 'last_mismatch': mismatches[-1] if mismatches else None, 'image_sha256': hashlib.sha256(image).hexdigest()}
        assert len(mismatches) == (765 if source == 'low' else 0), evidence
    (out / 'evidence.json').write_text(json.dumps({'trace': trace, 'cases': evidence, 'limits': 'Synthetic FAT, controller and memory; no physical camera or SD.'}, indent=2) + '\n')
    print(trace, json.dumps(evidence), flush=True)


if __name__ == '__main__':
    main()
