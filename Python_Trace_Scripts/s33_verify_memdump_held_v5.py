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
    assert sys.argv[1:] in ([], ['--candidate'], ['--hook'], ['--rival'], ['--file-error'], ['--checked'], ['--checked-file-error'], ['--map-empty'], ['--map-fixture'], ['--map-errors'], ['--range'], ['--range-full'], ['--hook-delayed'], ['--hook-real-delay'], ['--hook-timeout'], ['--dsptest'])
    dsptest = sys.argv[1:] == ['--dsptest']  # v5 held path + payload DSP probes (declared model)
    map_errors = sys.argv[1:] == ['--map-errors']
    map_fixture = sys.argv[1:] in (['--map-fixture'], ['--map-errors'])
    empty = sys.argv[1:] in (['--map-empty'], ['--map-fixture'], ['--map-errors'])
    checked = sys.argv[1:] in (['--checked'], ['--checked-file-error'])
    file_error = sys.argv[1:] in (['--file-error'], ['--checked-file-error'])
    rival = sys.argv[1:] == ['--rival']
    full = sys.argv[1:] == ['--range-full']
    rng = sys.argv[1:] in (['--range'], ['--range-full'])
    end = 0x100100 if rng else END
    candidate = bool(sys.argv[1:])
    hook = sys.argv[1:] in (['--hook'], ['--rival'], ['--file-error'], ['--checked'], ['--checked-file-error'], ['--map-empty'], ['--map-fixture'], ['--map-errors'], ['--range'], ['--range-full'], ['--hook-delayed'], ['--hook-real-delay'], ['--hook-timeout'], ['--dsptest'])
    delayed = sys.argv[1:] == ['--hook-delayed']
    real_delay = sys.argv[1:] == ['--hook-real-delay']
    timeout = sys.argv[1:] == ['--hook-timeout']
    candidate_hash = None
    script = 'ProbeMemdumpDspTest.java' if dsptest else 'ProbeMemdumpV8Errors.java' if map_errors else 'ProbeMemdumpV8Map.java' if map_fixture else 'ProbeMemdumpV8Empty.java' if empty else 'ProbeMemdumpV7FileError.java' if checked and file_error else 'ProbeMemdumpV5FileError.java' if file_error else 'ProbeMemdumpV5Rival.java' if rival else 'ProbeMemdumpV6FullFat.java' if full else 'ProbeMemdumpV6LargeFat.java' if rng else 'ProbeMemdumpHeldV5LargeFat.java' if hook else 'ProbeMemdumpHookDelayTimeout.java' if timeout else 'ProbeMemdumpHookRealDelay.java' if real_delay else 'ProbeMemdumpHookDelayedLargeFat.java' if delayed else 'ProbeMemdumpHookLargeFat.java' if hook else 'ProbeMemdumpWorkerLargeFat.java' if candidate else 'ProbeMemdumpLargeFat.java'
    result_dir = 'MEMDUMP_DSPTEST_Hook_FAT' if dsptest else 'MEMDUMP_V8_Map_Errors' if map_errors else 'MEMDUMP_V8_Fixture_Map' if map_fixture else 'MEMDUMP_V8_Empty_Map' if empty else 'MEMDUMP_V7_File_Error_FAT' if checked and file_error else 'MEMDUMP_V7_Hook_FAT' if checked else 'MEMDUMP_V5_File_Error_FAT' if file_error else 'MEMDUMP_V5_Rival_FAT' if rival else 'MEMDUMP_V6_Hook_Full_FAT' if full else 'MEMDUMP_V6_Hook_Large_FAT' if rng else 'MEMDUMP_Hook_Delay_Timeout' if timeout else 'MEMDUMP_Hook_Real_Delay' if real_delay else 'MEMDUMP_Hook_Delayed_Large_FAT' if delayed else 'MEMDUMP_Held_V5_Hook_Large_FAT' if hook else 'MEMDUMP_Worker_Large_FAT' if candidate else 'MEMDUMP_Large_FAT'
    out = ROOT / 'Risultati/Runtime_Kernel' / result_dir / datetime.now(timezone.utc).strftime('%Y%m%dT%H%M%S%fZ')
    out.mkdir(parents=True)
    scripts = ROOT / 'S33-sections/analysis_ghidra/scripts'
    (out / 'probe_snapshot.java').write_bytes((scripts / script).read_bytes())
    if candidate:
        (out / 'base_probe_snapshot.java').write_bytes((scripts / 'ProbeMemdumpLargeFat.java').read_bytes())
    if hook:
        (out / 'v5_probe_snapshot.java').write_bytes((scripts / 'ProbeMemdumpHookLargeFat.java').read_bytes())
        (out / 'worker_probe_snapshot.java').write_bytes((scripts / 'ProbeMemdumpWorkerLargeFat.java').read_bytes())
    if rng or rival or file_error or dsptest:
        (out / 'held_probe_snapshot.java').write_bytes((scripts / 'ProbeMemdumpHeldV5LargeFat.java').read_bytes())
    if full:
        (out / 'range_probe_snapshot.java').write_bytes((scripts / 'ProbeMemdumpV6LargeFat.java').read_bytes())
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
            bundle = ROOT / 'Risultati/Firmware_sperimentali/MEMDUMP' / ('DSPTEST_OFFLINE_NON_INSTALLARE_20261108T103625759247Z' if dsptest else 'OFFLINE_NON_INSTALLARE_20261107T130016443730Z' if empty else 'OFFLINE_NON_INSTALLARE_20261107T125157753626Z' if checked else 'OFFLINE_NON_INSTALLARE_20261106T183614975474Z' if rng else 'OFFLINE_NON_INSTALLARE_20261106T164839522756Z')
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
            if map_fixture:
                symbols = (bundle / 'payload_symbols.log').read_text()
                for name in ('akeru_map_count', 'akeru_map_regions', 'akeru_map_session'):
                    symbol = re.search(r'^([0-9a-f]+)\s+T\s+' + name + r'$', symbols, re.M)
                    assert symbol
                    extra.append(hex(int(symbol[1], 16)))
        cmd = [str(ROOT / 'tools/ghidra-arcompact/ghidra_12.2_DEV/support/analyzeHeadless'), str(tmp), 'model', '-import', str(tmp / 'p0.bin'), '-loader', 'BinaryLoader', '-loader-baseAddr', '0xad800', '-processor', 'ARCompact:LE:32:loopfix', '-noanalysis', '-scriptPath', str(scripts), '-postScript', script, str(out / 'trace.txt'), str(tmp / 'p1.bin'), *extra, '-deleteProject']
        (out / 'command.json').write_text(json.dumps(cmd, indent=2) + '\n')
        print('Prova:', out, flush=True)
        run = subprocess.run(cmd, stdout=subprocess.PIPE, stderr=subprocess.STDOUT, text=True, timeout=900)
        (out / 'headless.log').write_text(run.stdout)
        assert run.returncode == 0 and 'SCRIPT ERROR' not in run.stdout, run.stdout[-6000:]
    trace = (out / 'trace.txt').read_text()
    if map_errors:
        assert trace == 'COLLISION completed=1 closes=1 protected=1024 third=absent\nFULL completed=1 closes=2 message=39304e third=absent\nCOMPLETE cases=2\n', trace
        details = {}
        for filename in ('existing.img', 'full.img'):
            image_path = out / filename; image = image_path.read_bytes()
            assert len(image) == 110*512
            entries = [image[100*512+32*i:100*512+32*(i+1)] for i in range(3)]
            by_name = {e[:11]: e for e in entries if e[0] not in (0, 0xe5)}
            assert b'00010000BIN' not in by_name and set(by_name) == {b'00004000BIN', b'00008000BIN'}
            def content(entry):
                size = struct.unpack_from('<I', entry, 28)[0]; cluster = struct.unpack_from('<H', entry, 26)[0]
                data = bytearray(); chain = []
                while len(data) < size:
                    assert 2 <= cluster <= 5 and cluster not in chain
                    chain.append(cluster); start=(102+(cluster-2)*2)*512
                    data.extend(image[start:start+1024]); pair=struct.unpack_from('<H',image,20*512+cluster+cluster//2)[0]
                    cluster=pair>>4 if cluster&1 else pair&0xfff
                assert cluster >= 0xff8
                return bytes(data[:size])
            low = bytes((j*37+(j>>8)*97+11)&255 for j in range(256))
            def pattern(base,n): return bytes(((j+base)*37+((j+base)>>8)*97+11)&255 for j in range(n))
            assert content(by_name[b'00004000BIN']) == low+pattern(0x4000,512)
            second=content(by_name[b'00008000BIN'])
            assert second == (b'\xcc'*2048 if filename=='existing.img' else low+pattern(0x8000,2816))
            check=subprocess.run(['/usr/bin/fsck.fat','-n',str(image_path)],stdout=subprocess.PIPE,stderr=subprocess.STDOUT,text=True,timeout=30)
            (out/(filename+'.fsck.txt')).write_text(check.stdout)
            assert check.returncode==0 and image_path.read_bytes()==image
            details[filename]={'second_bytes':len(second),'sha256':hashlib.sha256(image).hexdigest(),'fsck_exit':check.returncode}
        (out/'evidence.json').write_text(json.dumps({'candidate_sha256':candidate_hash,'trace':trace,'images':details,'limits':'Synthetic map injected into emulated RAM; direct hook entry, scheduler, FAT, DMA and memory modeled; no physical SD, boot, or RAM tested.'},indent=2)+'\n')
        print(trace,flush=True)
        return
    if map_fixture:
        assert trace == 'V8_MAP signals=2 tasks=1 files=2 closes=2 complete=2 map=fixture\nCOMPLETE cases=1\n', trace
        image_path = out / 'map_card.img'; image = image_path.read_bytes()
        assert len(image) == 110*512
        for i, (name, base, length) in enumerate(((b'00004000BIN', 0x4000, 512), (b'00008000BIN', 0x8000, 768))):
            entry_data = image[100*512+32*i:100*512+32*(i+1)]
            assert entry_data[:11] == name and struct.unpack_from('<I', entry_data, 28)[0] == length+256
            cluster = struct.unpack_from('<H', entry_data, 26)[0]; assert 2 <= cluster <= 5
            data = image[(102+(cluster-2)*2)*512:][:length+256]
            expected = bytes((j*37+(j>>8)*97+11)&255 for j in range(256))
            expected += bytes(((j+base)*37+((j+base)>>8)*97+11)&255 for j in range(length))
            assert data == expected
            pair = struct.unpack_from('<H', image, 20*512+cluster+cluster//2)[0]
            assert (pair >> 4 if cluster & 1 else pair & 0xfff) >= 0xff8
        check = subprocess.run(['/usr/bin/fsck.fat', '-n', str(image_path)], stdout=subprocess.PIPE, stderr=subprocess.STDOUT, text=True, timeout=30)
        (out / 'fsck.txt').write_text(check.stdout)
        assert check.returncode == 0 and image_path.read_bytes() == image
        (out / 'evidence.json').write_text(json.dumps({'candidate_sha256': candidate_hash, 'trace': trace, 'fsck_exit': check.returncode, 'limits': 'Synthetic map injected into emulated RAM; direct hook entry, scheduler, FAT, DMA and memory modeled; no physical SD, boot, or RAM tested.'}, indent=2) + '\n')
        print(trace, flush=True)
        return
    if empty:
        assert trace == 'EMPTY_MAP signals=2 tasks=1 writes=0 closes=0 unchanged=110\nCOMPLETE cases=1\n', trace
        (out / 'evidence.json').write_text(json.dumps({'candidate_sha256': candidate_hash, 'trace': trace, 'limits': 'Direct hook entry, task creation and scheduler modeled; no physical SD, boot, or RAM tested.'}, indent=2) + '\n')
        print(trace, flush=True)
        return
    if full:
        assert trace.endswith('COMPLETE cases=2\n') and 'FULL_V6 size=4096 writes=0 closes=1 message=39304e' in trace, trace
        assert 'EXISTING_V6 sectors_unchanged=110 writes=0 closes=0 size=2048' in trace, trace
        assert 'raw_count=256 requested=256 file_error=0' in trace and 'raw_count=3840 requested=1048576 file_error=1a00014' in trace, trace
        image_path = out / 'full_card.img'
        image = image_path.read_bytes()
        assert len(image) == 110 * 512 and image[100*512:100*512+11] == b'MEMHI   BIN'
        assert struct.unpack_from('<I', image, 100*512+28)[0] == 4096
        data = image[102*512:110*512]
        expected = bytes((i * 37 + (i >> 8) * 97 + 11) & 255 for i in range(256))
        expected += bytes(((i + 0x0f600000) * 37 + ((i + 0x0f600000) >> 8) * 97 + 11) & 255 for i in range(3840))
        assert data == expected
        check = subprocess.run(['/usr/bin/fsck.fat', '-n', str(image_path)], stdout=subprocess.PIPE, stderr=subprocess.STDOUT, text=True, timeout=30)
        (out / 'fsck.txt').write_text(check.stdout)
        assert check.returncode == 0 and image_path.read_bytes() == image
        (out / 'evidence.json').write_text(json.dumps({'candidate_sha256': candidate_hash, 'trace': trace, 'file_bytes': len(data), 'high_bytes_matched': 3840, 'fsck_exit': check.returncode, 'limits': 'Synthetic four-cluster FAT, scheduler, high RAM and DMA; no physical SD, memory, boot, or recovery demonstrated.'}, indent=2) + '\n')
        print(trace, flush=True)
        return
    if timeout:
        assert trace == 'TIMEOUT waits=29 ticks=290 reservations=0 writes=0 card_sectors=110 tasks=1 signals=3 frame=fixture\nCOMPLETE cases=1\n', trace
        (out / 'evidence.json').write_text(json.dumps({'candidate_sha256': candidate_hash, 'trace': trace, 'limits': 'Synthetic volume, 10 Hz software clock, timer invocation and CPU switch; no physical timing or hardware.'}, indent=2) + '\n')
        print(trace, flush=True)
        return
    message = '39304e' if checked and file_error else '393044'
    assert f'LARGE size={end} writes={0 if hook else 2} closes={1 if hook else 3 if candidate else 2} message={message}' in trace and trace.endswith('COMPLETE cases=1\n'), trace
    if rival:
        assert 'RIVAL status=1a00012 unchanged=35302 task_switch=none\n' in trace, trace
    if file_error:
        assert f"FILE_ERROR injected=1a00006 status=0 count=17040972 diagnostic={'failure' if checked else 'success'}\n" in trace, trace
    if hook:
        assert 'HOOK signals=2 tasks=1 entry=' in trace and 'scheduler=fixture' in trace, trace
    if dsptest:
        assert 'DSP modeled_ops=608 semantics=declared_model\n' in trace, trace
    if delayed:
        assert 'WAITS count=2 readiness=fixture' in trace, trace
    if real_delay:
        assert 'REAL_DELAY waits=2 ticks=20 clock_hz=10 frame=fixture' in trace, trace
    assert 'raw_count=256 requested=256 file_error=0' in trace, trace
    assert f'raw_count={0x100000 if rng else 17040972} requested={0x100000 if rng else 17040972} file_error=0' in trace, trace
    image = (out / 'large_card.img').read_bytes()
    assert len(image) == (102 + 1100 * 32) * 512 and image[100 * 512:100 * 512 + 11] == (b'MEMHI   BIN' if rng else b'DSPTEST BIN' if dsptest else b'MEMDUMP BIN' if candidate else b'TARGET  BIN')
    assert struct.unpack_from('<I', image, 100 * 512 + 28)[0] == end
    cluster = struct.unpack_from('<H', image, 100 * 512 + 26)[0]
    data, chain = bytearray(), []
    while len(data) < end:
        assert 2 <= cluster <= 1101 and cluster not in chain
        chain.append(cluster)
        offset = (102 + (cluster - 2) * 32) * 512
        data.extend(image[offset:offset + 32 * 512])
        pair = struct.unpack_from('<H', image, 20 * 512 + cluster + cluster // 2)[0]
        cluster = pair >> 4 if cluster & 1 else pair & 0xfff
    assert cluster >= 0xff8
    data = data[:end]
    expected_low = bytes((i * 37 + (i >> 8) * 97 + 11) & 255 for i in range(256 if rng else 0xad800))
    assert data[:len(expected_low)] == expected_low
    if rng:
        assert data[256:] == bytes(((i + 0x0f600000) * 37 + ((i + 0x0f600000) >> 8) * 97 + 11) & 255 for i in range(0x100000))
    # The old 0x12BD5C snapshot point is not reached by the v5 adapter.
    dma_bytes = 0
    if candidate and not rng:
        dma = (out / 'source_at_bulk_dma.bin').read_bytes()
        assert len(dma) == 21728 * 512 and data[0x4000:0x4000 + len(dma)] == dma
        dma_bytes = len(dma)
    if dsptest:
        from s33_dsptest_analyze import analyze
        # shortcut: model task stack (0x10D715C) is outside the dump; hardware v5 task stack was 0x52A28 (inside).
        assert analyze(bytes(data))['status'] == 'TABLE_NOT_FOUND'
        report = analyze((out / 'dspt_stack_window.bin').read_bytes())
        (out / 'dsptest_analysis.json').write_text(json.dumps(report, indent=1) + '\n')
        # Model results equal H1 by construction: this checks table placement/integrity, not CPU semantics.
        assert report['status'] == 'OK' and all(d['match'] == d['total'] for d in report['categories'].values()), report
        print('DSPT table', report['table_offset'], 'records 608 inputs OK', flush=True)
    check = subprocess.run(['/usr/bin/fsck.fat', '-n', str(out / 'large_card.img')], stdout=subprocess.PIPE, stderr=subprocess.STDOUT, text=True, timeout=30)
    (out / 'fsck.txt').write_text(check.stdout)
    assert check.returncode == 0 and (out / 'large_card.img').read_bytes() == image
    (out / 'evidence.json').write_text(json.dumps({'candidate_sha256': candidate_hash, 'trace': trace, 'bytes': end, 'clusters': len(chain), 'low_bytes_matched': len(expected_low), 'high_bytes_matched': 0x100000 if rng else 0, 'snapshot_differing_bytes': None, 'differing_offsets': None, 'bulk_dma_bytes_matched_at_transfer': None if rng else dma_bytes,  'file_sha256': hashlib.sha256(data).hexdigest(), 'image_sha256': hashlib.sha256(image).hexdigest(), 'fsck_exit': check.returncode, 'limits': 'Synthetic FAT/context/buffer/DMA; ' + ('hook entered directly and scheduler simulated' if hook else 'task or diagnostic entered directly') + ('; rival invocation injected without a task switch' if rival else '') + ('; file-error injected after successful write, not generated by modeled FAT' if file_error else '') + '; no physical RAM, SD, boot, atomicity or camera demonstrated.'}, indent=2) + '\n')
    print(trace, 'Snapshot differences: not measured', flush=True)


if __name__ == '__main__':
    main()
