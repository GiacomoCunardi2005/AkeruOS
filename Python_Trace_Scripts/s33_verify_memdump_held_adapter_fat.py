#!/usr/bin/env python3
"""Execute the compiled ARC adapter with Nikon diagnostic and synthetic FAT."""
from datetime import datetime, timezone
from types import SimpleNamespace
from pathlib import Path
import hashlib
import struct
import subprocess
import tempfile
import sys
import re
from s33_run_gnu_arc700 import ROOT, LEGACY, TOOLCHAIN, Runner, sha
from s33_trace_state_dispatch import verified_payloads


def main():
    assert sys.argv[1:] in ([], ['--map'])
    mapped = sys.argv[1:] == ['--map']
    _, payloads, _ = verified_payloads(ROOT)
    out = ROOT / 'Risultati/Runtime_Kernel' / ('MEMDUMP_Map_Adapter_FAT' if mapped else 'MEMDUMP_Held_Adapter_FAT') / datetime.now(timezone.utc).strftime('%Y%m%dT%H%M%S%fZ')
    runner = Runner(SimpleNamespace(legacy_root=LEGACY, toolchain=TOOLCHAIN, output=out, action='memdump-held-adapter-fat'))
    print('Prova:', out, flush=True)
    try:
        runner.prepare()
        source = ROOT / ('AkeruOS/nikon_v11_memdump_map.c' if mapped else 'AkeruOS/nikon_v11_memdump_held.c')
        obj, elf, binary = out / 'adapter.o', out / 'adapter.elf', out / 'adapter.bin'
        result = runner.command('compile', [TOOLCHAIN / 'arc-elf32-gcc', '-mcpu=arc700', '-Os', '-mno-sdata', '-mlong-calls', '-ffreestanding', '-fno-builtin', '-ffunction-sections', '-fdata-sections', '-Wall', '-Wextra', '-Werror', '-I', ROOT / 'AkeruOS', '-c', source, '-o', obj])
        assert result.returncode == 0, result.stdout
        objects = [obj]
        if mapped:
            for stem in ('nikon_v11_memdump_held_scope', 'nikon_v11_memdump_task_current'):
                extra = ROOT / 'AkeruOS' / (stem + '.c'); extra_obj = out / (stem + '.o')
                result = runner.command(stem + '_compile', [TOOLCHAIN / 'arc-elf32-gcc', '-mcpu=arc700', '-Os', '-mno-sdata', '-mlong-calls', '-ffreestanding', '-fno-builtin', '-ffunction-sections', '-fdata-sections', '-Wall', '-Wextra', '-Werror', '-I', ROOT / 'AkeruOS', '-c', extra, '-o', extra_obj])
                assert result.returncode == 0, result.stdout
                objects.append(extra_obj)
        script = out / 'adapter.ld'
        script.write_text('ENTRY(' + ('akeru_memdump_map_run' if mapped else 'akeru_memdump_held_route') + ')\nSECTIONS { . = 0x3000000; .text : { *(.text .text.*) *(.rodata .rodata.*) } /DISCARD/ : { *(.comment) *(.ARC.attributes) } }\n')
        defs = ['--defsym=nikon_v11_save_original=0x12bd5c', '--defsym=nikon_v11_write_original=0x12de3c']
        if mapped:
            defs += ['--defsym=nikon_v11_open_new_original=0x12dbfc', '--defsym=nikon_v11_close_original=0x12d604', '--defsym=nikon_v11_memdump_original=0x16ed40', '--defsym=nikon_v11_enter_critical_original=0x1786e8', '--defsym=nikon_v11_leave_critical_original=0x179354', '-uakeru_memdump_held_route']
        result = runner.command('link', [TOOLCHAIN / 'arc-elf32-ld', '-EL', '--gc-sections', '-T', script, *defs, '-o', elf, *objects])
        assert result.returncode == 0, result.stdout
        result = runner.command('extract', [TOOLCHAIN / 'arc-elf32-objcopy', '-O', 'binary', '--only-section=.text', elf, binary])
        assert result.returncode == 0, result.stdout
        result = runner.command('symbols', [TOOLCHAIN / 'arc-elf32-nm', '-n', elf])
        assert result.returncode == 0
        def symbol(name):
            match = re.search(r'^([0-9a-f]+)\s+T\s+' + name + r'$', result.stdout, re.M)
            assert match, result.stdout
            return '0x' + match.group(1)
        route = symbol('akeru_memdump_held_route')
        entry = symbol('akeru_memdump_map_run') if mapped else route
        scripts = ROOT / 'S33-sections/analysis_ghidra/scripts'
        for name in (('ProbeMemdumpMapFat.java', 'ProbeMemdumpFullFatSix.java', 'ProbeMemdumpFullFat.java') if mapped else ('ProbeMemdumpHeldAdapterFat.java', 'ProbeMemdumpHeldDiagnostic.java', 'ProbeMemdumpReservation.java')):
            (out / name).write_bytes((scripts / name).read_bytes())
        with tempfile.TemporaryDirectory(prefix='s33-held-adapter-fat-') as td:
            tmp = Path(td)
            for i in (0, 1):
                (tmp / f'p{i}.bin').write_bytes(payloads[i])
            cmd = [str(ROOT / 'tools/ghidra-arcompact/ghidra_12.2_DEV/support/analyzeHeadless'), str(tmp), 'model', '-import', str(tmp / 'p0.bin'), '-loader', 'BinaryLoader', '-loader-baseAddr', '0xad800', '-processor', 'ARCompact:LE:32:loopfix', '-noanalysis', '-scriptPath', str(scripts), '-postScript', 'ProbeMemdumpMapFat.java' if mapped else 'ProbeMemdumpHeldAdapterFat.java', str(out / 'trace.txt'), str(tmp / 'p1.bin'), str(binary), entry, *([route] if mapped else []), '-deleteProject']
            result = runner.command('ghidra', cmd, timeout=300)
            assert result.returncode == 0 and 'SCRIPT ERROR' not in result.stdout, result.stdout[-5000:]
        trace = (out / 'trace.txt').read_text()
        if mapped:
            assert trace == 'MAP files=2 redirects=4 closes=2 completed=2\nCOMPLETE cases=1\n', trace
            image_path = out / 'map_card.img'; image = image_path.read_bytes()
            assert len(image) == 110 * 512
            for i, (name, base, length) in enumerate(((b'00004000BIN', 0x4000, 512), (b'00008000BIN', 0x8000, 768))):
                entry_data = image[100*512 + 32*i:100*512 + 32*(i+1)]
                assert entry_data[:11] == name and struct.unpack_from('<I', entry_data, 28)[0] == length + 256
                cluster = struct.unpack_from('<H', entry_data, 26)[0]
                assert 2 <= cluster <= 5
                data = image[(102 + (cluster-2)*2)*512:][:length+256]
                expected = bytes((j*37+(j>>8)*97+11)&255 for j in range(256))
                expected += bytes(((j+base)*37+((j+base)>>8)*97+11)&255 for j in range(length))
                assert data == expected
                pair = struct.unpack_from('<H', image, 20*512 + cluster + cluster//2)[0]
                assert (pair >> 4 if cluster & 1 else pair & 0xfff) >= 0xff8
            check = subprocess.run(['/usr/bin/fsck.fat', '-n', str(image_path)], stdout=subprocess.PIPE, stderr=subprocess.STDOUT, text=True, timeout=30)
            (out / 'fsck.txt').write_text(check.stdout)
            assert check.returncode == 0 and image_path.read_bytes() == image
            runner.results.update(status='PASS_MULTIREGION_ORIGINAL_DIAGNOSTIC_SYNTHETIC_FAT', source_sha256=sha(source), adapter_sha256=sha(binary), trace=trace, image_sha256=hashlib.sha256(image).hexdigest(), fsck_exit=check.returncode, limits=['Call-site dispatch, RAM, FAT context, heap, DMA and controller modeled.', 'No candidate firmware, physical map, SD, scheduler or hardware tested.'])
            runner.finish()
            print(trace, flush=True)
            return
        assert trace == 'HELD_DIAG redirects=2 rival=1a00012 first=0/256 second=1a00014/3840 message=39304e closes=1 size=4096\nCOMPLETE cases=1\n', trace
        image_path = out / 'diagnostic_held.img'
        image = image_path.read_bytes()
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
        assert cluster >= 0xff8 and data == bytes((i * 37 + (i >> 8) * 97 + 11) & 255 for i in range(4096))
        check = subprocess.run(['/usr/bin/fsck.fat', '-n', str(image_path)], stdout=subprocess.PIPE, stderr=subprocess.STDOUT, text=True, timeout=30)
        (out / 'fsck.txt').write_text(check.stdout)
        assert check.returncode == 0 and image_path.read_bytes() == image
        runner.results.update(status='PASS_COMPILED_ADAPTER_ORIGINAL_DIAGNOSTIC_SYNTHETIC_FAT', source_sha256=sha(source), adapter_sha256=sha(binary), trace=trace, image_sha256=hashlib.sha256(image).hexdigest(), fsck_exit=check.returncode,
            limits=['Task identity, call-site dispatch, FAT context, heap, DMA and controller are modeled.', 'Volume fills at 4096 bytes; no installed adapter, complete physical dump, SD or hardware tested.'])
        runner.finish()
    except Exception as exc:
        runner.results.update(status='FAIL', error=repr(exc))
        raise
    finally:
        runner.save()
    print(trace, flush=True)


if __name__ == '__main__':
    main()
