#!/usr/bin/env python3
"""Exercise original MEMDUMP and wrappers over a fully synthetic source range."""
from datetime import datetime, timezone
from pathlib import Path
import hashlib
import json
import subprocess
import tempfile
from s33_trace_state_dispatch import verified_payloads

ROOT = Path(__file__).resolve().parents[1]
END = 0x104074c


def pattern(start, size):
    return bytes((x * 37 + (x >> 8) * 97 + 11) & 255 for x in range(start, start + size))


def main():
    blocks, payloads, _ = verified_payloads(ROOT)
    out = ROOT / 'Risultati/Runtime_Kernel/MEMDUMP_Full_Range' / datetime.now(timezone.utc).strftime('%Y%m%dT%H%M%S%fZ')
    out.mkdir(parents=True)
    scripts = ROOT / 'S33-sections/analysis_ghidra/scripts'
    (out / 'probe_snapshot.java').write_bytes((scripts / 'ProbeMemdumpFullRange.java').read_bytes())
    with tempfile.TemporaryDirectory(prefix='s33-memdump-full-') as td:
        temp = Path(td)
        for i in (0, 1):
            (temp / f'p{i}.bin').write_bytes(payloads[i])
        cmd = [str(ROOT / 'tools/ghidra-arcompact/ghidra_12.2_DEV/support/analyzeHeadless'), str(temp), 'model', '-import', str(temp / 'p0.bin'), '-loader', 'BinaryLoader', '-loader-baseAddr', '0xad800', '-processor', 'ARCompact:LE:32:loopfix', '-noanalysis', '-scriptPath', str(scripts), '-postScript', 'ProbeMemdumpFullRange.java', str(out / 'trace.txt'), str(temp / 'p1.bin'), '-deleteProject']
        (out / 'command.json').write_text(json.dumps(cmd, indent=2) + '\n')
        print('Prova:', out, flush=True)
        p = subprocess.run(cmd, stdout=subprocess.PIPE, stderr=subprocess.STDOUT, text=True, timeout=300)
        (out / 'headless.log').write_text(p.stdout)
        assert p.returncode == 0 and 'SCRIPT ERROR' not in p.stdout, p.stdout[-6000:]
        trace = (out / 'trace.txt').read_text()
        assert trace == f'PASS full-range bytes={END} writes=2 closes=2 message=393044\n', trace
    capture = (out / 'synthetic_MEMDUMP.bin').read_bytes()
    source = (pattern(0, 0xad800) + payloads[0] + pattern(0x35bc00, 0x4c00) + payloads[1]
              + pattern(0x360800 + len(payloads[1]), END - 0x360800 - len(payloads[1])))
    assert len(source) == len(capture) == END and source == capture
    result = {'status': 'PASS_FULL_RANGE_ORIGINAL_MEMDUMP_MODELED_STORAGE', 'bytes': END,
              'synthetic_sha256': hashlib.sha256(capture).hexdigest(), 'payload_sha256': [b['sha256'] for b in blocks[:2]],
              'limits': ['Synthetic memory and host storage, not FAT or physical RAM.', 'No boot, SD, camera, timing or concurrent changes.']}
    (out / 'evidence.json').write_text(json.dumps(result, indent=2) + '\n')
    print('PASS full original range with modeled storage:', out, flush=True)


if __name__ == '__main__':
    main()
