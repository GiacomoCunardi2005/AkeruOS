#!/usr/bin/env python3
"""Run the original MEMDUMP save wrapper against a synthetic FAT/controller."""
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
    blocks, payloads, _ = verified_payloads(ROOT)
    out = ROOT / 'Risultati/Runtime_Kernel/MEMDUMP_FAT' / datetime.now(timezone.utc).strftime('%Y%m%dT%H%M%S%fZ')
    out.mkdir(parents=True)
    scripts = ROOT / 'S33-sections/analysis_ghidra/scripts'
    (out / 'probe_snapshot.java').write_bytes((scripts / 'ProbeMemdumpFileWrite.java').read_bytes())
    with tempfile.TemporaryDirectory(prefix='s33-memdump-fat-') as td:
        temp = Path(td)
        for i in (0, 1):
            (temp / f'p{i}.bin').write_bytes(payloads[i])
        cmd = [str(ROOT / 'tools/ghidra-arcompact/ghidra_12.2_DEV/support/analyzeHeadless'), str(temp), 'model', '-import', str(temp / 'p0.bin'), '-loader', 'BinaryLoader', '-loader-baseAddr', '0xad800', '-processor', 'ARCompact:LE:32:loopfix', '-noanalysis', '-scriptPath', str(scripts), '-postScript', 'ProbeMemdumpFileWrite.java', str(out / 'trace.txt'), str(temp / 'p1.bin'), '-deleteProject']
        (out / 'command.json').write_text(json.dumps(cmd, indent=2) + '\n')
        p = subprocess.run(cmd, stdout=subprocess.PIPE, stderr=subprocess.STDOUT, text=True, timeout=300)
        (out / 'headless.log').write_text(p.stdout)
        assert p.returncode == 0 and 'SCRIPT ERROR' not in p.stdout, p.stdout[-5000:]
        trace = (out / 'trace.txt').read_text()
        assert 'PASS memdump-two-writes new first=0 second=0 size=769 reread=769' in trace
        assert 'PASS memdump-two-writes existing first=0 second=0 size=2817 reread=2817' in trace and trace.endswith('COMPLETE cases=2\n'), trace[-2000:]
    images = {}
    pattern = bytes(((i * 37 + 11) ^ ((i >> 8) * 97)) & 255 for i in range(769))
    for name, expected in [('new', pattern), ('existing', bytes([0xcc]) * 2048 + pattern)]:
        path = out / (name + '_partition.img')
        image = path.read_bytes()
        assert len(image) == 110 * 512
        root = 100 * 512
        assert image[root:root + 11] == b'TARGET  BIN' and struct.unpack_from('<I', image, root + 28)[0] == len(expected)
        cluster = struct.unpack_from('<H', image, root + 26)[0]
        chain, data = [], bytearray()
        while len(data) < len(expected):
            assert 2 <= cluster <= 5 and cluster not in chain
            chain.append(cluster)
            offset = (102 + (cluster - 2) * 2) * 512
            data.extend(image[offset:offset + 1024])
            pair = struct.unpack_from('<H', image, 20 * 512 + cluster + cluster // 2)[0]
            cluster = pair >> 4 if cluster & 1 else pair & 0xfff
        assert cluster >= 0xff8 and data[:len(expected)] == expected
        check = subprocess.run(['/usr/bin/fsck.fat', '-n', str(path)], stdout=subprocess.PIPE, stderr=subprocess.STDOUT, text=True, timeout=30)
        (out / (name + '_fsck.txt')).write_text(check.stdout)
        assert check.returncode == 0 and path.read_bytes() == image, check.stdout
        images[name] = {'bytes': len(expected), 'clusters': chain, 'sha256': hashlib.sha256(image).hexdigest()}
    (out / 'evidence.json').write_text(json.dumps({'status': 'PASS_MEMDUMP_SAVE_WRAPPERS_FAT_MODEL', 'payload_sha256': [b['sha256'] for b in blocks], 'images': images, 'limits': 'Shortened two writes; synthetic RAM, FS state, MMIO and DMA; no physical SD or camera.'}, indent=2) + '\n')
    print('PASS MEMDUMP wrappers with FAT/controller model:', out, flush=True)


if __name__ == '__main__':
    main()
