#!/usr/bin/env python3
"""Compare Nikon lookup and predicate on a prepared synthetic FAT volume."""
from datetime import datetime, timezone
from pathlib import Path
import json
import subprocess
import tempfile
from s33_trace_state_dispatch import verified_payloads

ROOT = Path(__file__).resolve().parents[1]


def main():
    blocks, payloads, _ = verified_payloads(ROOT)
    out = ROOT / 'Risultati/Runtime_Kernel/MEMDUMP_Lookup' / datetime.now(timezone.utc).strftime('%Y%m%dT%H%M%S%fZ')
    out.mkdir(parents=True)
    scripts = ROOT / 'S33-sections/analysis_ghidra/scripts'
    (out / 'probe_snapshot.java').write_bytes((scripts / 'ProbeMemdumpLookup.java').read_bytes())
    with tempfile.TemporaryDirectory(prefix='s33-memdump-fat-') as td:
        temp = Path(td)
        for i in (0, 1):
            (temp / f'p{i}.bin').write_bytes(payloads[i])
        cmd = [str(ROOT / 'tools/ghidra-arcompact/ghidra_12.2_DEV/support/analyzeHeadless'), str(temp), 'model', '-import', str(temp / 'p0.bin'), '-loader', 'BinaryLoader', '-loader-baseAddr', '0xad800', '-processor', 'ARCompact:LE:32:loopfix', '-noanalysis', '-scriptPath', str(scripts), '-postScript', 'ProbeMemdumpLookup.java', str(out / 'trace.txt'), str(temp / 'p1.bin'), '-deleteProject']
        (out / 'command.json').write_text(json.dumps(cmd, indent=2) + '\n')
        p = subprocess.run(cmd, stdout=subprocess.PIPE, stderr=subprocess.STDOUT, text=True, timeout=300)
        (out / 'headless.log').write_text(p.stdout)
        assert p.returncode == 0 and 'SCRIPT ERROR' not in p.stdout, p.stdout[-5000:]
        trace = (out / 'trace.txt').read_text()
        assert trace == ('LOOKUP file raw=0 attr=32 predicate=0 present=1 injected=0\n'
                         'LOOKUP missing raw=1a00002 attr=165 predicate=0 present=0 injected=0\n'
                         'LOOKUP volume_error raw=1a00034 attr=165 predicate=0 present=0 injected=0\n'
                         'LOOKUP sector_read_error raw=1a00021 attr=165 predicate=0 present=0 injected=2\n'
                         'COMPLETE cases=4\n'), trace
    (out / 'evidence.json').write_text(json.dumps({
        'status': 'PASS_LOOKUP_PREDICATE_ERROR_COLLAPSE_SYNTHETIC_FAT',
        'payload_sha256': [b['sha256'] for b in blocks],
        'trace': trace, 'synthetic_sectors_preserved': 110,
        'limits': ['One prepared synthetic FAT/volume profile with injected final sector-read error; error values not generalized to all backends.',
                   'No physical SD, concurrency, exclusive reservation or subsequent dump.']
    }, indent=2) + '\n')
    print(trace, flush=True)


if __name__ == '__main__':
    main()
