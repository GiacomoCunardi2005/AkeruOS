#!/usr/bin/env python3
"""Compile/test the cooperative RAM dumper on host and compile its ARC700 object."""
from datetime import datetime, timezone
from pathlib import Path
import json
import re
import subprocess
import struct
import uuid

from s33_run_gnu_arc700 import ROOT, sha
from s33_read_ram_dump import parse_dump


def main():
    out = ROOT/'Risultati/Runtime_Kernel/RAM_Dumper'/(
        datetime.now(timezone.utc).strftime('%Y%m%dT%H%M%SZ')+'_'+uuid.uuid4().hex[:8])
    out.mkdir(parents=True)
    print('Evidence:', out, flush=True)
    sources = [ROOT/'AkeruOS/ram_dump.c', ROOT/'AkeruOS/ram_dump.h',
               ROOT/'AkeruOS/tests/ram_dump_test.c', Path(__file__),
               ROOT/'Python_Trace_Scripts/s33_read_ram_dump.py',
               ROOT/'AkeruOS/nikon_v11_sd_io.c', ROOT/'AkeruOS/nikon_v11_sd_io.h',
               ROOT/'AkeruOS/tests/nikon_v11_sd_io_test.c']
    before = {str(p.relative_to(ROOT)): sha(p) for p in sources}
    report = dict(status='RUNNING', source_hashes=before, hardware_tested=False,
                  nikon_api_bindings_verified=False, installable=False)

    def command(name, cmd):
        (out/f'{name}.command.json').write_text(json.dumps([str(x) for x in cmd], indent=2)+'\n')
        p = subprocess.run([str(x) for x in cmd], text=True, stdout=subprocess.PIPE,
                           stderr=subprocess.STDOUT, timeout=60)
        (out/f'{name}.log').write_text(p.stdout)
        if p.returncode:
            raise RuntimeError(f'{name}: exit={p.returncode}\n{p.stdout[-4000:]}')
        return p.stdout

    try:
        host = out/'ram_dump_test'
        command('host_build', ['cc','-std=c11','-Wall','-Wextra','-Werror','-g',
            '-fsanitize=address,undefined','-fno-omit-frame-pointer',
            '-I'+str(ROOT/'AkeruOS'), *[sources[i] for i in (0,2)], '-o',host])
        fixture = out/'fixture.dmp'
        log = command('host_test', [host, fixture])
        assert log.strip() == 'PASS host_cases=28'
        blob = fixture.read_bytes()
        decoded = parse_dump(blob)
        assert decoded['atomic'] is False and len(decoded['regions']) == 11
        for r in decoded['regions']:
            expected = bytes(((a^(a>>8))&255) for a in range(r['address'], r['address']+r['length']))
            assert r['data'] == expected
        rejected = 0

        def reject(data):
            nonlocal rejected
            try:
                parse_dump(data)
            except ValueError:
                rejected += 1
            else:
                raise AssertionError('Invalid dump accepted')

        for size in (0,7,8,31,32,43,len(blob)-17,len(blob)-16,len(blob)-1):
            reject(blob[:size])
        reject(blob+b'X')
        for offset in (0,8,16,20,28,32,36,44,len(blob)-16,len(blob)-8):
            bad = bytearray(blob);bad[offset] ^= 0xff;reject(bad)
        # Clock timestamps may wrap; content CRC is independent of clock units.
        wrapped = bytearray(blob)
        struct.pack_into('<I',wrapped,24,0xfffffff0)
        struct.pack_into('<I',wrapped,len(wrapped)-4,16)
        assert parse_dump(wrapped)['end_ms'] == 16
        sd_host = out/'sd_io_test'
        command('sd_io_host_build', ['cc','-std=c11','-Wall','-Wextra','-Werror','-g',
            '-fsanitize=address,undefined','-fno-omit-frame-pointer',
            '-I'+str(ROOT/'AkeruOS'), sources[0], sources[5], sources[7], '-o',sd_host])
        sd_fixture = out/'sd_io_fixture.dmp'
        sd_log = command('sd_io_host_test', [sd_host, sd_fixture])
        assert sd_log.strip() == 'PASS sd_io_cases=20', sd_log
        sd_decoded = parse_dump(sd_fixture.read_bytes())
        assert sd_decoded['total_bytes'] == 64 and len(sd_decoded['regions']) == 1
        assert sd_decoded['regions'][0]['data'] == bytes(range(64))
        sd_obj = out/'nikon_v11_sd_io_arc700.o'
        command('sd_io_arc_build', ['arc-snps-elf-gcc','-mcpu=arc700','-mno-sdata',
            '-mlong-calls','-O2','-ffreestanding','-fno-builtin','-Wall','-Wextra',
            '-Werror','-c',sources[5],'-o',sd_obj])
        sd_disasm = command('sd_io_arc_disassembly', ['arc-snps-elf-objdump','-dr',sd_obj])
        assert 'R_ARC_SDA_' not in sd_disasm
        sd_unresolved = command('sd_io_arc_undefined', ['arc-snps-elf-nm','-u',sd_obj])
        assert set(re.findall(r'\bU (\w+)',sd_unresolved)) == {
            'nikon_v11_file_write_original','nikon_v11_file_close_original'}
        sd_size = command('sd_io_arc_size', ['arc-snps-elf-size',sd_obj]).splitlines()[1].split()
        assert int(sd_size[1]) == int(sd_size[2]) == 0
        obj = out/'ram_dump_arc700.o'
        command('arc_build', ['arc-snps-elf-gcc','-mcpu=arc700','-mno-sdata','-O2',
            '-ffreestanding','-fno-builtin','-Wall','-Wextra','-Werror','-c',sources[0],'-o',obj])
        disasm = command('arc_disassembly', ['arc-snps-elf-objdump','-dr',obj])
        assert 'R_ARC_SDA_' not in disasm
        unresolved = command('arc_undefined', ['arc-snps-elf-nm','-u',obj])
        assert not unresolved.strip(), unresolved
        report.update(status='PASS_OFFLINE_RAM_DUMPER', host_cases=28,
                      malformed_dumps_rejected=rejected, crc_and_data_verified=True,
                      arc700_compiled=True, unresolved_symbols=[],
                      sd_io_host_cases=20, sd_io_engine_fixture_bytes=64,
                      sd_io_arc700_text_bytes=int(sd_size[0]),
                      sd_io_scope='Write/close only; original Nikon APIs mocked on host',
                      selected_fixture_regions=11, selected_fixture_ram_bytes=decoded['total_bytes'],
                      selected_fixture_file_bytes=len(blob), default_interval_ms=5000,
                      full_map_stream_test_bytes=128*1024*1024, scratch_bytes=4096,
                      default_snapshot_limit=1, physical_ram_map_supplied=False,
                      filename_pattern='B:AKR00000.DMP',
                      limits=['Host adapter tests and ARC compilation, not Nikon execution',
                              'Full SD session adapter, exclusive creation and marker identity remain incomplete',
                              'This host suite mocks native APIs; original CPU-path checks are in s33_verify_ram_dump_sd_io_port.py',
                              'RTOS/task runtime components exist but are not integrated into an update',
                              'Sequential captures are not atomic; live RAM can change',
                              'CRC/footer do not certify physical SD persistence'])
        for p in sources:
            assert sha(p) == before[str(p.relative_to(ROOT))]
            (out/p.name).write_bytes(p.read_bytes())
    except Exception as exc:
        report.update(status='FAIL', error=repr(exc))
        raise
    finally:
        report['files'] = {p.name: sha(p) for p in out.iterdir() if p.is_file()}
        (out/'verified_evidence.json').write_text(json.dumps(report, indent=2)+'\n')
    (out.parent/'latest.json').write_text(json.dumps(dict(
        evidence=str((out/'verified_evidence.json').relative_to(ROOT)),status=report['status']), indent=2)+'\n')
    print(report['status'], 'host_cases=28', f'malformed_rejected={rejected}',out/'verified_evidence.json',flush=True)


if __name__ == '__main__':
    main()
