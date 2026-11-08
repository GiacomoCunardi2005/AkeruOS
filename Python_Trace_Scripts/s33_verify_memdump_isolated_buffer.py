#!/usr/bin/env python3
"""Run the original diagnostic with a separated synthetic FAT buffer."""
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
    out = ROOT / 'Risultati/Runtime_Kernel/MEMDUMP_Isolated_Buffer' / datetime.now(timezone.utc).strftime('%Y%m%dT%H%M%S%fZ')
    out.mkdir(parents=True)
    scripts = ROOT / 'S33-sections/analysis_ghidra/scripts'
    (out / 'probe_snapshot.java').write_bytes((scripts / 'ProbeMemdumpIsolatedBuffer.java').read_bytes())
    with tempfile.TemporaryDirectory(prefix='s33-isolated-') as td:
        tmp = Path(td)
        for i in (0, 1):
            (tmp / f'p{i}.bin').write_bytes(payloads[i])
        cmd = [str(ROOT / 'tools/ghidra-arcompact/ghidra_12.2_DEV/support/analyzeHeadless'), str(tmp), 'model', '-import', str(tmp / 'p0.bin'), '-loader', 'BinaryLoader', '-loader-baseAddr', '0xad800', '-processor', 'ARCompact:LE:32:loopfix', '-noanalysis', '-scriptPath', str(scripts), '-postScript', 'ProbeMemdumpIsolatedBuffer.java', str(out / 'trace.txt'), str(tmp / 'p1.bin'), '-deleteProject']
        (out / 'command.json').write_text(json.dumps(cmd, indent=2) + '\n')
        print('Prova:', out, flush=True)
        run = subprocess.run(cmd, stdout=subprocess.PIPE, stderr=subprocess.STDOUT, text=True, timeout=300)
        (out / 'headless.log').write_text(run.stdout)
        assert run.returncode == 0 and 'SCRIPT ERROR' not in run.stdout, run.stdout[-6000:]
    trace = (out / 'trace.txt').read_text()
    assert trace == ('ISOLATED buffer=201a010 source_preserved=1 saves=2 copy=1 writes=2 closes=2 message=39304e size=4096 dma6=1 '
                     'status=0 count=256 status=1a00014 count=3840\nCOMPLETE cases=1\n'), trace
    image = (out / 'card.img').read_bytes()
    assert len(image) == 110 * 512 and image[100 * 512:100 * 512 + 11] == b'TARGET  BIN'
    assert struct.unpack_from('<I', image, 100 * 512 + 28)[0] == 4096
    cluster = struct.unpack_from('<H', image, 100 * 512 + 26)[0]
    data, chain = bytearray(), []
    while len(data) < 4096:
        assert 2 <= cluster <= 5 and cluster not in chain
        chain.append(cluster)
        offset = (102 + (cluster - 2) * 2) * 512
        data.extend(image[offset:offset + 1024])
        pair = struct.unpack_from('<H', image, 20 * 512 + cluster + cluster // 2)[0]
        cluster = pair >> 4 if cluster & 1 else pair & 0xfff
    assert cluster >= 0xff8
    expected = bytes((i * 37 + (i >> 8) * 97 + 11) & 255 for i in range(4096))
    assert data == expected
    check = subprocess.run(['/usr/bin/fsck.fat', '-n', str(out / 'card.img')], stdout=subprocess.PIPE, stderr=subprocess.STDOUT, text=True, timeout=30)
    (out / 'fsck.txt').write_text(check.stdout)
    assert check.returncode == 0 and (out / 'card.img').read_bytes() == image
    (out / 'evidence.json').write_text(json.dumps({'trace': trace, 'chain': chain, 'bytes_matched': len(data), 'image_sha256': hashlib.sha256(image).hexdigest(), 'fsck_exit': check.returncode, 'limits': 'The filesystem context and buffer placement are synthetic; DMA/peripherals modeled; no physical camera or SD; file incomplete due to modeled capacity.'}, indent=2) + '\n')
    print(trace, flush=True)


if __name__ == '__main__':
    main()
