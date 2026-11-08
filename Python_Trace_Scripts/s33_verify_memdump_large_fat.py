#!/usr/bin/env python3
"""Exercise the full original MEMDUMP on a large synthetic FAT12 volume."""
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
END = 0x104074c


def main():
    _, payloads, _ = verified_payloads(ROOT)
    assert sys.argv[1:] in ([], ['--candidate'], ['--hook'], ['--hook-delayed'], ['--hook-real-delay'], ['--hook-timeout'])
    candidate = bool(sys.argv[1:])
    hook = sys.argv[1:] in (['--hook'], ['--hook-delayed'], ['--hook-real-delay'], ['--hook-timeout'])
    delayed = sys.argv[1:] == ['--hook-delayed']
    real_delay = sys.argv[1:] == ['--hook-real-delay']
    timeout = sys.argv[1:] == ['--hook-timeout']
    candidate_hash = None
    script = 'ProbeMemdumpHookDelayTimeout.java' if timeout else 'ProbeMemdumpHookRealDelay.java' if real_delay else 'ProbeMemdumpHookDelayedLargeFat.java' if delayed else 'ProbeMemdumpHookLargeFat.java' if hook else 'ProbeMemdumpWorkerLargeFat.java' if candidate else 'ProbeMemdumpLargeFat.java'
    result_dir = 'MEMDUMP_Hook_Delay_Timeout' if timeout else 'MEMDUMP_Hook_Real_Delay' if real_delay else 'MEMDUMP_Hook_Delayed_Large_FAT' if delayed else 'MEMDUMP_Hook_Large_FAT' if hook else 'MEMDUMP_Worker_Large_FAT' if candidate else 'MEMDUMP_Large_FAT'
    out = ROOT / 'Risultati/Runtime_Kernel' / result_dir / datetime.now(timezone.utc).strftime('%Y%m%dT%H%M%S%fZ')
    out.mkdir(parents=True)
    scripts = ROOT / 'S33-sections/analysis_ghidra/scripts'
    (out / 'probe_snapshot.java').write_bytes((scripts / script).read_bytes())
    if candidate:
        (out / 'base_probe_snapshot.java').write_bytes((scripts / 'ProbeMemdumpLargeFat.java').read_bytes())
    if hook:
        (out / 'worker_probe_snapshot.java').write_bytes((scripts / 'ProbeMemdumpWorkerLargeFat.java').read_bytes())
    if delayed or real_delay or timeout:
        (out / 'hook_probe_snapshot.java').write_bytes((scripts / 'ProbeMemdumpHookLargeFat.java').read_bytes())
    if timeout:
        (out / 'real_delay_probe_snapshot.java').write_bytes((scripts / 'ProbeMemdumpHookRealDelay.java').read_bytes())
    with tempfile.TemporaryDirectory(prefix='s33-large-fat-') as td:
        tmp = Path(td)
        for i in (0, 1):
            (tmp / f'p{i}.bin').write_bytes(payloads[i])
        extra = []
        if candidate:
            sys.path.insert(0, str(ROOT / 'S33-sections/analysis_codex'))
            from static_common import BS
            bundle = ROOT / 'Risultati/Firmware_sperimentali/MEMDUMP/OFFLINE_NON_INSTALLARE_20261106T145245285906Z'
            package = (bundle / 'firmware.bin').read_bytes()
            candidate_hash = hashlib.sha256(package).hexdigest()
            assert candidate_hash == json.loads((bundle / 'delta.json').read_text())['candidate_sha256']
            base = struct.unpack_from('<I', package, 0x480ac)[0] + BS[9]['offset']
            if hook:
                main_base = struct.unpack_from('<I', package, 0x480ac)[0] + BS[0]['offset']
                (tmp / 'p0.bin').write_bytes(package[main_base:main_base + BS[0]['size']])
            (tmp / 'resource.bin').write_bytes(package[base:base + BS[9]['size']])
            match = re.search(r'^([0-9a-f]+)\s+t\s+memdump_task$', (bundle / 'payload_symbols.log').read_text(), re.M)
            assert match
            extra = [str(tmp / 'resource.bin'), hex(int(match[1], 16))]
        cmd = [str(ROOT / 'tools/ghidra-arcompact/ghidra_12.2_DEV/support/analyzeHeadless'), str(tmp), 'model', '-import', str(tmp / 'p0.bin'), '-loader', 'BinaryLoader', '-loader-baseAddr', '0xad800', '-processor', 'ARCompact:LE:32:loopfix', '-noanalysis', '-scriptPath', str(scripts), '-postScript', script, str(out / 'trace.txt'), str(tmp / 'p1.bin'), *extra, '-deleteProject']
        (out / 'command.json').write_text(json.dumps(cmd, indent=2) + '\n')
        print('Prova:', out, flush=True)
        run = subprocess.run(cmd, stdout=subprocess.PIPE, stderr=subprocess.STDOUT, text=True, timeout=900)
        (out / 'headless.log').write_text(run.stdout)
        assert run.returncode == 0 and 'SCRIPT ERROR' not in run.stdout, run.stdout[-6000:]
    trace = (out / 'trace.txt').read_text()
    if timeout:
        assert trace == 'TIMEOUT waits=29 ticks=290 reservations=0 writes=0 card_sectors=110 tasks=1 signals=3 frame=fixture\nCOMPLETE cases=1\n', trace
        (out / 'evidence.json').write_text(json.dumps({'candidate_sha256': candidate_hash, 'trace': trace, 'limits': 'Synthetic volume, 10 Hz software clock, timer invocation and CPU switch; no physical timing or hardware.'}, indent=2) + '\n')
        print(trace, flush=True)
        return
    assert f'LARGE size={END} writes=2 closes={3 if candidate else 2} message=393044' in trace and trace.endswith('COMPLETE cases=1\n'), trace
    if hook:
        assert 'HOOK signals=2 tasks=1 entry=' in trace and 'scheduler=fixture' in trace, trace
    if delayed:
        assert 'WAITS count=2 readiness=fixture' in trace, trace
    if real_delay:
        assert 'REAL_DELAY waits=2 ticks=20 clock_hz=10 frame=fixture' in trace, trace
    assert 'raw_count=256 requested=256 file_error=0 status=0 count=256' in trace, trace
    assert 'raw_count=17040972 requested=17040972 file_error=0 status=0 count=17040972' in trace, trace
    image = (out / 'large_card.img').read_bytes()
    assert len(image) == (102 + 1100 * 32) * 512 and image[100 * 512:100 * 512 + 11] == (b'MEMDUMP BIN' if candidate else b'TARGET  BIN')
    assert struct.unpack_from('<I', image, 100 * 512 + 28)[0] == END
    cluster = struct.unpack_from('<H', image, 100 * 512 + 26)[0]
    data, chain = bytearray(), []
    while len(data) < END:
        assert 2 <= cluster <= 1101 and cluster not in chain
        chain.append(cluster)
        offset = (102 + (cluster - 2) * 32) * 512
        data.extend(image[offset:offset + 32 * 512])
        pair = struct.unpack_from('<H', image, 20 * 512 + cluster + cluster // 2)[0]
        cluster = pair >> 4 if cluster & 1 else pair & 0xfff
    assert cluster >= 0xff8
    data = data[:END]
    expected_low = bytes((i * 37 + (i >> 8) * 97 + 11) & 255 for i in range(0xad800))
    assert data[:0xad800] == expected_low
    snapshot = expected_low[:256] + (out / 'source_at_second_save.bin').read_bytes()
    assert len(snapshot) == END
    differing = [i for i, (a, b) in enumerate(zip(data, snapshot)) if a != b]
    dma_bytes = 0
    if candidate:
        dma = (out / 'source_at_bulk_dma.bin').read_bytes()
        assert len(dma) == 21728 * 512 and data[0x4000:0x4000 + len(dma)] == dma
        assert all(0x4000 <= i < 0x4000 + len(dma) for i in differing)
        dma_bytes = len(dma)
    check = subprocess.run(['/usr/bin/fsck.fat', '-n', str(out / 'large_card.img')], stdout=subprocess.PIPE, stderr=subprocess.STDOUT, text=True, timeout=30)
    (out / 'fsck.txt').write_text(check.stdout)
    assert check.returncode == 0 and (out / 'large_card.img').read_bytes() == image
    (out / 'evidence.json').write_text(json.dumps({'candidate_sha256': candidate_hash, 'trace': trace, 'bytes': END, 'clusters': len(chain), 'low_bytes_matched': len(expected_low), 'snapshot_differing_bytes': len(differing), 'differing_offsets': differing, 'bulk_dma_bytes_matched_at_transfer': dma_bytes, 'source_snapshot_sha256': hashlib.sha256(snapshot).hexdigest(), 'file_sha256': hashlib.sha256(data).hexdigest(), 'image_sha256': hashlib.sha256(image).hexdigest(), 'fsck_exit': check.returncode, 'limits': 'Hook entered directly and scheduler simulated; synthetic FAT/context/buffer/DMA; snapshot captured before the second save while firmware continued executing; no atomicity, physical RAM, SD, boot or camera demonstrated.' if hook else 'Task/diagnostic invoked directly; synthetic FAT/context/buffer/DMA; snapshot captured before the second save while firmware continued executing; no atomicity, physical RAM, SD, boot or camera demonstrated.'}, indent=2) + '\n')
    print(trace, 'Snapshot differences:', len(differing), flush=True)


if __name__ == '__main__':
    main()
