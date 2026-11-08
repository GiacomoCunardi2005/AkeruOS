#!/usr/bin/env python3
"""Exercise original MEMDUMP on a full synthetic FAT partition with a six-sector DMA model."""
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
    out = ROOT / 'Risultati/Runtime_Kernel/MEMDUMP_Small_FAT_Six' / datetime.now(timezone.utc).strftime('%Y%m%dT%H%M%S%fZ')
    out.mkdir(parents=True)
    scripts = ROOT / 'S33-sections/analysis_ghidra/scripts'
    (out / 'probe_snapshot.java').write_bytes((scripts / 'ProbeMemdumpFullFatSix.java').read_bytes())
    with tempfile.TemporaryDirectory(prefix='s33-memdump-small-fat-') as td:
        temp = Path(td)
        for i in (0, 1):
            (temp / f'p{i}.bin').write_bytes(payloads[i])
        cmd = [str(ROOT / 'tools/ghidra-arcompact/ghidra_12.2_DEV/support/analyzeHeadless'), str(temp), 'model', '-import', str(temp / 'p0.bin'), '-loader', 'BinaryLoader', '-loader-baseAddr', '0xad800', '-processor', 'ARCompact:LE:32:loopfix', '-noanalysis', '-scriptPath', str(scripts), '-postScript', 'ProbeMemdumpFullFatSix.java', str(out / 'trace.txt'), str(temp / 'p1.bin'), '-deleteProject']
        (out / 'command.json').write_text(json.dumps(cmd, indent=2) + '\n')
        print('Prova:', out, flush=True)
        p = subprocess.run(cmd, stdout=subprocess.PIPE, stderr=subprocess.STDOUT, text=True, timeout=300)
        (out / 'headless.log').write_text(p.stdout)
        assert p.returncode == 0 and 'SCRIPT ERROR' not in p.stdout, p.stdout[-6000:]
        trace = (out / 'trace.txt').read_text()
        assert trace == ('FULL_CARD writes=2 closes=2 message=39304e size=4096 dma6=1 '
                         'status=0 count=256 status=1a00014 count=3840\nCOMPLETE cases=1\n'), trace
    path = out / 'small_card.img'
    image = path.read_bytes()
    assert len(image) == 110 * 512 and image[100 * 512:100 * 512 + 11] == b'TARGET  BIN'
    assert struct.unpack_from('<I', image, 100 * 512 + 28)[0] == 4096
    cluster = struct.unpack_from('<H', image, 100 * 512 + 26)[0]
    chain, data = [], bytearray()
    while len(data) < 4096:
        assert 2 <= cluster <= 5 and cluster not in chain
        chain.append(cluster)
        offset = (102 + (cluster - 2) * 2) * 512
        data.extend(image[offset:offset + 1024])
        pair = struct.unpack_from('<H', image, 20 * 512 + cluster + cluster // 2)[0]
        cluster = pair >> 4 if cluster & 1 else pair & 0xfff
    assert cluster >= 0xff8
    expected = bytes((x * 37 + (x >> 8) * 97 + 11) & 255 for x in range(4096))
    assert data[:256] == expected[:256] and data[256:1024] == bytes([0xcc]) * 768
    assert data[1024:] == expected[1024:]
    check = subprocess.run(['/usr/bin/fsck.fat', '-n', str(path)], stdout=subprocess.PIPE, stderr=subprocess.STDOUT, text=True, timeout=30)
    (out / 'fsck.txt').write_text(check.stdout)
    assert check.returncode == 0 and path.read_bytes() == image, check.stdout
    (out / 'evidence.json').write_text(json.dumps({
        'status': 'EXPECTED_FULL_DISK_ERROR_WITH_DATA_GAP_IN_MODEL',
        'first_write_count': 256, 'second_write_status': '0x1a00014',
        'second_write_reported_count': 3840, 'file_size': 4096,
        'gap_offsets': [256, 1024], 'gap_fill': '0xcc', 'chain': chain,
        'image_sha256': hashlib.sha256(image).hexdigest(), 'fsck_exit': check.returncode,
        'limits': ['Synthetic FAT, prepared context, modeled six-sector DMA and peripheral state.',
                   'No physical SD, concurrent access, boot, power loss or full memory dump.']
    }, indent=2) + '\n')
    print(trace, flush=True)


if __name__ == '__main__':
    main()
