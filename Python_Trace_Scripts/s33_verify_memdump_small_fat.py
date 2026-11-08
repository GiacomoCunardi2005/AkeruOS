#!/usr/bin/env python3
"""Exercise the original MEMDUMP writer on a tiny synthetic FAT partition."""
from datetime import datetime, timezone
from pathlib import Path
import json
import hashlib
import struct
import subprocess
import tempfile
from s33_trace_state_dispatch import verified_payloads

ROOT = Path(__file__).resolve().parents[1]


def main():
    _, payloads, _ = verified_payloads(ROOT)
    out = ROOT / 'Risultati/Runtime_Kernel/MEMDUMP_Small_FAT' / datetime.now(timezone.utc).strftime('%Y%m%dT%H%M%S%fZ')
    out.mkdir(parents=True)
    scripts = ROOT / 'S33-sections/analysis_ghidra/scripts'
    (out / 'probe_snapshot.java').write_bytes((scripts / 'ProbeMemdumpFullFat.java').read_bytes())
    with tempfile.TemporaryDirectory(prefix='s33-memdump-small-fat-') as td:
        temp = Path(td)
        for i in (0, 1):
            (temp / f'p{i}.bin').write_bytes(payloads[i])
        cmd = [str(ROOT / 'tools/ghidra-arcompact/ghidra_12.2_DEV/support/analyzeHeadless'), str(temp), 'model', '-import', str(temp / 'p0.bin'), '-loader', 'BinaryLoader', '-loader-baseAddr', '0xad800', '-processor', 'ARCompact:LE:32:loopfix', '-noanalysis', '-scriptPath', str(scripts), '-postScript', 'ProbeMemdumpFullFat.java', str(out / 'trace.txt'), str(temp / 'p1.bin'), '-deleteProject']
        (out / 'command.json').write_text(json.dumps(cmd, indent=2) + '\n')
        print('Prova:', out, flush=True)
        p = subprocess.run(cmd, stdout=subprocess.PIPE, stderr=subprocess.STDOUT, text=True, timeout=300)
        (out / 'headless.log').write_text(p.stdout)
        assert p.returncode == 0 and 'SCRIPT ERROR' not in p.stdout, p.stdout[-6000:]
        trace = (out / 'trace.txt').read_text()
        assert trace == 'MODEL_LIMIT writes=2 closes=1 size=256 source=400 lba=2152 sectors=6 mode=1 status=0 count=256\nCOMPLETE cases=1\n', trace
    image = (out / 'small_card.img').read_bytes()
    assert len(image) == 110 * 512
    root = 100 * 512
    assert image[root:root+11] == b'TARGET  BIN'
    assert struct.unpack_from('<I', image, root + 28)[0] == 256
    cluster = struct.unpack_from('<H', image, root + 26)[0]
    assert cluster == 2
    saved = image[102 * 512:102 * 512 + 256]
    expected = bytes((x * 37 + (x >> 8) * 97 + 11) & 255 for x in range(256))
    assert saved == expected
    (out / 'evidence.json').write_text(json.dumps({
        'status': 'EXPECTED_MODEL_BOUNDARY_NOT_A_COMPLETED_DUMP',
        'first_write_bytes_verified': len(saved), 'second_write_stopped_before_sectors': 6,
        'fixture_supported_max_sectors': 4, 'source_at_boundary': '0x400',
        'image_sha256': hashlib.sha256(image).hexdigest(),
        'limits': ['No second write completion or close.', 'Synthetic FAT, prepared context, modeled peripherals and DMA; no physical card.']
    }, indent=2) + '\n')
    print(trace, flush=True)


if __name__ == '__main__':
    main()
