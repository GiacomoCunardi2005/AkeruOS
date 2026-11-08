#!/usr/bin/env python3
"""Original PMSD/DEVSD write engines, command/PIO stores and original readback on a RAM card."""
from datetime import datetime, timezone
from pathlib import Path
import json, re, subprocess, sys, tempfile
from s33_trace_state_dispatch import verified_payloads, sha
ROOT = Path(__file__).resolve().parents[1]


def main():
    blocks, payloads, _ = verified_payloads(ROOT)
    out = ROOT/'Risultati/Runtime_Kernel/RAM_Dumper_SD_Write_Partition'/datetime.now(timezone.utc).strftime('%Y%m%dT%H%M%SZ')
    out.mkdir(parents=True, exist_ok=False)
    scripts = ROOT/'S33-sections/analysis_ghidra/scripts'
    sources = [Path(__file__)]+[scripts/n for n in ['ProbeDumpSDWritePartition.java', 'ProbeDumpSDWriteAsync.java', 'ProbeDumpSDReadArbitration.java', 'ProbeDumpSDReadStatus.java', 'ProbeDumpSDMutex.java', 'ProbeStatusRead.java']]
    inputs = {str(p.relative_to(ROOT)): sha(p.read_bytes()) for p in sources}
    for p in sources:
        (out/(p.name+'.snapshot')).write_bytes(p.read_bytes())
    with tempfile.TemporaryDirectory(prefix='s33-sd-write-pm-') as td:
        temp = Path(td)
        for i in (0, 1):
            (temp/f'p{i}.bin').write_bytes(payloads[i])
        cmd = [str(ROOT/'tools/ghidra-arcompact/ghidra_12.2_DEV/support/analyzeHeadless'), str(temp), 'write', '-import', str(temp/'p0.bin'), '-loader', 'BinaryLoader', '-loader-baseAddr', '0xad800', '-processor', 'ARCompact:LE:32:loopfix', '-noanalysis', '-scriptPath', str(scripts), '-postScript', 'ProbeDumpSDWritePartition.java', str(out/'trace.txt'), str(temp/'p1.bin'), '-deleteProject']
        (out/'command.json').write_text(json.dumps(cmd, indent=2)+'\n')
        r = subprocess.run(cmd, stdout=subprocess.PIPE, stderr=subprocess.STDOUT, text=True, timeout=300)
        (out/'headless.log').write_text(r.stdout)
        assert r.returncode == 0 and 'SCRIPT ERROR' not in r.stdout, r.stdout[-6000:]
        trace = (out/'trace.txt').read_text()
        assert trace.endswith('COMPLETE cases=24\n') and trace.count('PASS write-partition ') == 24
    rows = []
    for line in trace.splitlines():
        if not line.startswith('PASS write-partition '):
            continue
        row = dict(re.findall(r'(\w+)=(\S+)', line))
        row['name'] = line.split()[2]
        rows.append(row)
    by_name = {r['name']: r for r in rows}
    assert by_name['partition_1']['rawCount'] == '1' and by_name['partition_2']['readbackBytes'] == '1024'
    for name in ['partition_pio-error4', 'partition_pio-error8']:
        assert by_name[name]['rawCount'] == '0' and by_name[name]['attempts'] == '3' and by_name[name]['portBytes'] == '768'
    assert by_name['partition_command-error']['portBytes'] == '0' and by_name['partition_bypass']['attempts'] == '0'
    assert by_name['async_timeout']['timeouts'] == '9' and by_name['async_timeout']['ticks'] == '900'
    captures = {}
    pattern = bytes(((k*37+11)^((k>>8)*97))&255 for k in range(2048))
    assert pattern[:512] != pattern[512:1024]
    for row in rows:
        size = int(row['portBytes'])
        if not size:
            continue
        p = out/(row['name']+'.dat')
        data = p.read_bytes()
        unit = 256 if row['name'].startswith('partition_pio-error') else int(row['count'])*512
        assert len(data) == size and data == pattern[:unit]*int(row['attempts']), row
        captures[p.name] = dict(bytes=len(data), sha256=sha(data))
    sys.path.insert(0, str(ROOT/'S33-sections/analysis_codex'))
    from static_common import disasm, u32
    spans = [(0x25B9C0,0x25BB5C),(0x25BB5C,0x25BC3C),(0x3042A8,0x3042E4),
             (0x168410,0x1684D4),(0x2A0C14,0x2A0C60),(0x2A0C60,0x2A0D50),
             (0x2A0D56,0x2A0D70),(0x2A0870,0x2A08B0),(0x2A0504,0x2A05F4),
             (0x1FA090,0x1FA0C0),(0x25A430,0x25A444),(0x25A41C,0x25A430),
             (0x25A278,0x25A39C),(0x25A5F8,0x25A658),(0x25A658,0x25A690),
             (0x1F4958,0x1F49A4),(0x21A4B8,0x21A778),(0x21A798,0x21AA3C),
             (0x2A1344,0x2A1398),(0x12DE3C,0x12DF00),(0x2A0D70,0x2A0E48)]
    listing = ''.join(disasm(a,b) for a,b in spans)
    (out/'gnu_verified.txt').write_text(listing)
    checks = {0x25BA6A:';0x2e5648',0x25BBEA:';0x2e5648',0x25BAD2:';0x2e5634',
              0x25BBF8:';0x2e5634',0x25BACC:';0x25bad2',0x25BB1A:'mov_s\tr14,0',
              0x3042C0:';0x304004',0x3042DE:';0x3040dc',0x16845A:';0x25b9c0',
              0x168464:';0x25bb5c',0x2A089A:';0x1fa090',0x25A43A:'sth.di\tr1,[r2]',
              0x1F4994:';0x21a4b8',0x21A4F0:';0x2a1344',0x21A894:';0x2a0d70',
              0x12DEC6:';0x1fa090',0x2A0E44:';0x2a0c14'}
    for a,token in checks.items():
        lines = [line for line in listing.splitlines() if re.match(rf'\s*{a:x}:',line)]
        assert len(lines)==1 and token in lines[0], (hex(a),token,lines)
    assert [u32(0x25BD54),u32(0x25BD58),u32(0x376050)] == [0xE00302,0xE00303,0x1684B4]
    assert all(sha((ROOT/p).read_bytes())==h for p,h in inputs.items())
    result = dict(status='PASS_ORIGINAL_PMSD_DEVSD_WRITE_COMMAND_PIO_AND_READBACK_PROFILE',
        cpu_cases=len(rows), returned_cases=len(rows), cases=rows, port_captures=captures,
        readback_cases=sum(int(r['readbackBytes'])>0 for r in rows), readback_bytes=sum(int(r['readbackBytes']) for r in rows),
        gnu_windows=len(spans), instruction_checks=len(checks), sources=inputs,
        payload_hashes={str(b['index']):b['sha256'] for b in blocks},
        original_bodies=['2A0C60 transfer/seek,1FA090 dispatch,2A0890 PMSD,2A0534 DEVSD,1684B4/168410 retries',
            '25B9C0/25BB5C original multi/single write engines and task priority getter/setter',
            '2E514C/2E509C/2E52F4/25A278 command,actual response loads and25AA8C control',
            '3042A8 selects304004 PIO for mode0 and3040DC for mode1;PIO store25A43A executes before capture',
            'Aligned mode1 original resource/start/status/callback/event/deadline/progress/release',
            'B15B4/B16D0 command/PIO original readback writes target buffer from actual25A426 port loads'],
        static_only_bodies=['12DE3C upper write wrapper and1F4958 filesystem callback',
            '21A4B8 file writer via2A1344 and cluster write2A0D70/2A0C14;not executed by the24CPUcases'],
        fixtures=['Prepared one-task kernel,priority0 ready record,handles,partition1 offset2048,capacity and512byte units;no mount/create',
            'MMIO ready/response/status samples;each original PIO store forwards its pair to an explicit byte-array card model;read port serves that model',
            'Asynchronous DMA is intentionally absent:successful completion does not change the byte-array card;not treated as verified data transfer',
            '25B63C recovery,25BF3C query,17FAA4 cache and2E500C delay are return fixtures',
            '3342A8/336364 products modeled;B2D50 CPU frame switching remains abstract;callbacks/tick invoked by C ABI'],
        conclusions=['Original write mode0 from partition adapter reachesPIO;aligned mode1 is a separate path,unaligned mode1 falls back toPIO',
            'PIO write then original read engine reproduces known content on in-memory card;does not prove a FAT file or persistence',
            'Two injectedPIO errors each execute3attempts with256bytes perattempt yet DEVSD/PMSD count0;no claim of physical bytecount',
            'Write stopE00200 accepted at exact capacity edge,propagated away from it;end cleanupD special0 also covered',
            'Single completion failure occurs after full port emission;full buffer emission alone does not imply successful engine result',
            'Volume flag49 exact1 reports full count with no engine/store;flag2 executes normally;producer remains unknown'],
        limits=['First missing upper component is original filesystem file write/create/cluster allocation andclose;not an end-to-end file test',
            'No physical SD,DMA,electricalIRQ/cache/persistence proof;not compatible-image validation;NON_INSTALLARE'])
    (out/'verified_evidence.json').write_text(json.dumps(result,indent=2)+'\n')
    (out.parent/'latest.json').write_text(json.dumps({'evidence':str((out/'verified_evidence.json').relative_to(ROOT))},indent=2)+'\n')
    print(trace,end='');print(out)


if __name__=='__main__':
    main()
