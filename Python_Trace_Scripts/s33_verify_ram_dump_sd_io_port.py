#!/usr/bin/env python3
"""Compiled C port plus original Nikon write/close, with existing synthetic FAT/SD lab."""
from datetime import datetime, timezone
from pathlib import Path
import json, re, subprocess, tempfile
from s33_trace_state_dispatch import verified_payloads, sha
ROOT = Path(__file__).resolve().parents[1]


def main(marker=False):
    blocks, payloads, _ = verified_payloads(ROOT)
    suite = 'RAM_Dumper_SD_Marker' if marker else 'RAM_Dumper_SD_IO_Port'
    probe = 'ProbeDumpSDMarker.java' if marker else 'ProbeDumpSDIOPort.java'
    out = ROOT/'Risultati/Runtime_Kernel'/suite/datetime.now(timezone.utc).strftime('%Y%m%dT%H%M%SZ')
    out.mkdir(parents=True, exist_ok=False)
    print('Evidence:', out, flush=True)
    scripts = ROOT/'S33-sections/analysis_ghidra/scripts'
    sources = [Path(__file__), ROOT/'AkeruOS/nikon_v11_sd_io.c', ROOT/'AkeruOS/nikon_v11_sd_io.h']
    sources += [scripts/n for n in ['ProbeDumpSDIOPort.java','ProbeDumpSDFileLifecycle.java',
        'ProbeDumpSDFileWrite.java','ProbeDumpSDWritePartition.java','ProbeDumpSDWriteAsync.java',
        'ProbeDumpSDReadArbitration.java','ProbeDumpSDReadStatus.java','ProbeDumpSDMutex.java','ProbeStatusRead.java']]
    if marker:
        sources += [ROOT/'AkeruOS/nikon_v11_sd_marker.c', ROOT/'AkeruOS/nikon_v11_sd_marker.h',
            scripts/probe, ROOT/'Python_Trace_Scripts/s33_verify_ram_dump_sd_marker.py']
    inputs = {str(p.relative_to(ROOT)):sha(p.read_bytes()) for p in sources}
    for p in sources:
        (out/(p.name+'.snapshot')).write_bytes(p.read_bytes())

    def command(name, cmd, timeout=60):
        (out/(name+'.command.json')).write_text(json.dumps([str(x) for x in cmd],indent=2)+'\n')
        r = subprocess.run([str(x) for x in cmd],stdout=subprocess.PIPE,stderr=subprocess.STDOUT,text=True,timeout=timeout)
        (out/(name+'.log')).write_text(r.stdout)
        assert r.returncode == 0 and 'SCRIPT ERROR' not in r.stdout,r.stdout[-7000:]
        return r.stdout

    obj, elf, binary = [out/('port'+s) for s in ['.o','.elf','.bin']]
    command('compile',['arc-snps-elf-gcc','-mcpu=arc700','-mno-sdata','-mlong-calls','-O2',
        '-ffreestanding','-fno-builtin','-Wall','-Wextra','-Werror','-c',sources[1],'-o',obj])
    objects = [obj]
    if marker:
        marker_obj = out/'marker.o'
        command('marker_compile',['arc-snps-elf-gcc','-mcpu=arc700','-mno-sdata','-mlong-calls','-O2',
            '-ffreestanding','-fno-builtin','-Wall','-Wextra','-Werror','-c',ROOT/'AkeruOS/nikon_v11_sd_marker.c','-o',marker_obj])
        objects.append(marker_obj)
    object_sizes = {}
    for built in objects:
        row = command(built.stem+'_size',['arc-snps-elf-size',built]).splitlines()[1].split()
        assert int(row[1]) == int(row[2]) == 0
        object_sizes[built.name] = dict(text=int(row[0]),data=int(row[1]),bss=int(row[2]))
        assert 'R_ARC_SDA_' not in command(built.stem+'_relocations',['arc-snps-elf-objdump','-r',built])
    linker = out/'port.ld'
    linker.write_text('SECTIONS { . = 0x02021000; .text : { *(.text*) *(.rodata*) } }\n'
        'nikon_v11_file_write_original = 0x12de3c;\nnikon_v11_file_close_original = 0x12d604;\n'
        'nikon_v11_fs_wait_original = 0x23eca4;\nnikon_v11_fs_post_original = 0x23ee48;\n')
    command('link',['arc-snps-elf-ld','-EL','-T',linker,'-o',elf,*objects])
    command('binary',['arc-snps-elf-objcopy','-O','binary',elf,binary])
    symbols = command('symbols',['arc-snps-elf-nm','-n',elf])
    entries = {name:'0x'+address for address,name in re.findall(r'^(\w+) T (akeru_nikon_v11_sd_\w+)$',symbols,re.M)}
    names = [f'akeru_nikon_v11_sd_io_{s}' for s in ['take','write','close']]
    if marker:
        names.append('akeru_nikon_v11_sd_marker_check')
    assert set(entries) == set(names)
    assert not command('undefined',['arc-snps-elf-nm','-u',elf]).strip()
    command('disassembly',['arc-snps-elf-objdump','-d',elf])
    with tempfile.TemporaryDirectory(prefix='s33-sd-io-port-') as td:
        temp = Path(td)
        for i in (0,1):
            (temp/f'p{i}.bin').write_bytes(payloads[i])
        command('headless',[ROOT/'tools/ghidra-arcompact/ghidra_12.2_DEV/support/analyzeHeadless',temp,
            'port','-import',temp/'p0.bin','-loader','BinaryLoader','-loader-baseAddr','0xad800',
            '-processor','ARCompact:LE:32:loopfix','-noanalysis','-scriptPath',scripts,'-postScript',
            probe,out/'trace.txt',temp/'p1.bin',binary,
            *[entries[name] for name in names],'-deleteProject'],300)
    trace = (out/'trace.txt').read_text()
    expected_cases = 14 if marker else 7
    assert trace.endswith(f'COMPLETE cases={expected_cases}\n') and trace.count('PASS sd-marker ' if marker else 'PASS sd-io-port ') == expected_cases
    assert all(sha((ROOT/p).read_bytes()) == value for p,value in inputs.items())
    result = dict(status='PASS_COMPILED_C_PORT_WITH_ORIGINAL_NIKON_WRITE_CLOSE',cpu_cases=7,
        sources=inputs,entry_points=entries,object_sizes=object_sizes,port_binary_sha256=sha(binary.read_bytes()),
        hardware_tested=False,installable=False,full_sd_adapter=False,physical_ram_map_complete=False,
        payload_hashes={str(b['index']):b['sha256'] for b in blocks},trace=trace,
        limits=['Prepared backend1 FAT12/registry/kernel, synthetic SD sectors and MMIO, modeled DMA/DSP as existing lifecycle lab',
            '16 bytes of declared decoder read-ahead padding after compiled C code, outside extracted binary',
            'Application write/close execute as compiled ARC code; no native write/close mock in these seven cases',
            'Only write/close ownership port; marker identity, exclusive creation session and backend guards not implemented here',
            'No hardware persistence, full physical RAM map, module residency or installable update; NON_INSTALLARE'])
    if marker:
        result.update(status='PASS_COMPILED_C_MARKER_IDENTITY_WITH_ORIGINAL_READ_OPEN_CLOSE',cpu_cases=14,
            limits=[
                'Original upper read-open/parser/lookup and close; allocator257 null with explicit error reproduces original false-success record',
                'Compiled C checker uses original FS wait/post, rejects backend7 before dereferencing its deliberately invalid private pointer',
                'Normal/readonly marker pins block tested original reconfiguration/volume-close routes until released',
                'Other negative predicates change declared live lab fields then restore them for close, not observed device states',
                'Wait/post error cases corrupt semaphore magic in the laboratory, retain file on C error, then explicitly repair lab state before cleanup',
                'Prepared backend1 FAT12/kernel/registry and synthetic SD/MMIO/DMA/DSP; 16-byte decoder read-ahead padding',
                'No complete armed/open_new session, exhaustive concurrency/pin proof, FAT16/32 execution, physical persistence or RAM map; NON_INSTALLARE'])
    (out/'verified_evidence.json').write_text(json.dumps(result,indent=2)+'\n')
    (out.parent/'latest.json').write_text(json.dumps(dict(evidence=str((out/'verified_evidence.json').relative_to(ROOT))),indent=2)+'\n')
    print(trace,end='');print(out)


if __name__ == '__main__':
    main()
