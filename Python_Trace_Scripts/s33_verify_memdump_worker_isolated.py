#!/usr/bin/env python3
"""Run the actual candidate worker on synthetic FAT with an isolated buffer."""
from datetime import datetime, timezone
from pathlib import Path
import hashlib
import json
import re
import struct
import subprocess
import sys
import tempfile
from s33_trace_state_dispatch import verified_payloads

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / 'S33-sections/analysis_codex'))
from static_common import BS


def main():
    _, payloads, _ = verified_payloads(ROOT)
    assert sys.argv[1:] in ([], ['--race'])
    race = bool(sys.argv[1:])
    bundle = ROOT / 'Risultati/Firmware_sperimentali/MEMDUMP' / ('OFFLINE_NON_INSTALLARE_20261106T145245285906Z' if race else 'OFFLINE_NON_INSTALLARE_20261106T142642215902Z')
    package = (bundle / 'firmware.bin').read_bytes()
    manifest = json.loads((bundle / 'delta.json').read_text())
    assert hashlib.sha256(package).hexdigest() == manifest['candidate_sha256']
    tbm = struct.unpack_from('<I', package, 0x480ac)[0]
    block = BS[9]
    resource = package[tbm + block['offset']:tbm + block['offset'] + block['size']]
    match = re.search(r'^([0-9a-f]+)\s+t\s+memdump_task$', (bundle / 'payload_symbols.log').read_text(), re.M)
    assert match
    out = ROOT / 'Risultati/Runtime_Kernel' / ('MEMDUMP_Reservation_Race' if race else 'MEMDUMP_Worker_Isolated') / datetime.now(timezone.utc).strftime('%Y%m%dT%H%M%S%fZ')
    out.mkdir(parents=True)
    scripts = ROOT / 'S33-sections/analysis_ghidra/scripts'
    for name in ('ProbeMemdumpWorkerFat.java', 'ProbeMemdumpWorkerIsolated.java'):
        (out / name).write_bytes((scripts / name).read_bytes())
    script = 'ProbeMemdumpReservationRace.java' if race else 'ProbeMemdumpWorkerIsolated.java'
    if race:
        (out / script).write_bytes((scripts / script).read_bytes())
    with tempfile.TemporaryDirectory(prefix='s33-worker-isolated-') as td:
        tmp = Path(td)
        for i in (0, 1):
            (tmp / f'p{i}.bin').write_bytes(payloads[i])
        (tmp / 'resource.bin').write_bytes(resource)
        cmd = [str(ROOT / 'tools/ghidra-arcompact/ghidra_12.2_DEV/support/analyzeHeadless'), str(tmp), 'model', '-import', str(tmp / 'p0.bin'), '-loader', 'BinaryLoader', '-loader-baseAddr', '0xad800', '-processor', 'ARCompact:LE:32:loopfix', '-noanalysis', '-scriptPath', str(scripts), '-postScript', script, str(out / 'trace.txt'), str(tmp / 'p1.bin'), str(tmp / 'resource.bin'), hex(int(match[1], 16)), '-deleteProject']
        (out / 'command.json').write_text(json.dumps(cmd, indent=2) + '\n')
        print('Prove:', out, flush=True)
        run = subprocess.run(cmd, stdout=subprocess.PIPE, stderr=subprocess.STDOUT, text=True, timeout=300)
        (out / 'headless.log').write_text(run.stdout)
        assert run.returncode == 0 and 'SCRIPT ERROR' not in run.stdout, run.stdout[-6000:]
    trace = (out / 'trace.txt').read_text()
    if race:
        assert 'RACE injected=1 competing_status=0 writes=3 closes=4 size=4096 message=39304e' in trace and trace.endswith('COMPLETE cases=1\n'), trace
        image = (out / 'race_card.img').read_bytes()
        assert image[100 * 512:100 * 512 + 11] == b'MEMDUMP BIN'
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
        assert data[:512] == bytes((i * 19 + 7) & 255 for i in range(512))
        assert data[512:768] == bytes((i * 37 + (i >> 8) * 97 + 11) & 255 for i in range(256))
        check = subprocess.run(['/usr/bin/fsck.fat', '-n', str(out / 'race_card.img')], stdout=subprocess.PIPE, stderr=subprocess.STDOUT, text=True, timeout=30)
        (out / 'fsck.txt').write_text(check.stdout)
        assert check.returncode == 0 and (out / 'race_card.img').read_bytes() == image
        (out / 'evidence.json').write_text(json.dumps({'candidate_sha256': manifest['candidate_sha256'], 'trace': trace, 'competing_prefix_bytes': 512, 'dump_prefix_offset': 512, 'file_size': len(data), 'chain': chain, 'image_sha256': hashlib.sha256(image).hexdigest(), 'fsck_exit': check.returncode, 'limits': 'Single-thread modeled interleaving; FAT/context/DMA synthetic; volume fills, physical scheduling and filesystem unverified.'}, indent=2) + '\n')
        print(trace, flush=True)
        return
    assert trace == ('WORKER_FAT new writes=2 closes=3 message=39304e size=4096 dma6=1 status=0 count=256 status=1a00014 count=3840\n'
                     'BUFFER new saves=2 source_preserved=1\nWORKER_FAT existing writes=0 closes=0 message=0 size=2048 dma6=0\n'
                     'BUFFER existing saves=0 source_preserved=0\nCOMPLETE cases=2\n'), trace
    image = (out / 'new_card.img').read_bytes()
    assert len(image) == 110 * 512 and image[100 * 512:100 * 512 + 11] == b'MEMDUMP BIN'
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
    assert data == bytes((i * 37 + (i >> 8) * 97 + 11) & 255 for i in range(4096))
    check = subprocess.run(['/usr/bin/fsck.fat', '-n', str(out / 'new_card.img')], stdout=subprocess.PIPE, stderr=subprocess.STDOUT, text=True, timeout=30)
    (out / 'fsck.txt').write_text(check.stdout)
    assert check.returncode == 0 and (out / 'new_card.img').read_bytes() == image
    (out / 'evidence.json').write_text(json.dumps({'candidate_sha256': manifest['candidate_sha256'], 'trace': trace, 'chain': chain, 'bytes_matched': len(data), 'image_sha256': hashlib.sha256(image).hexdigest(), 'fsck_exit': check.returncode, 'limits': 'Task invoked directly; scheduler, filesystem context, buffer placement, DMA and peripherals are modeled. Synthetic volume full; no physical camera or SD.'}, indent=2) + '\n')
    print(trace, flush=True)


if __name__ == '__main__':
    main()
