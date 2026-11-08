#!/usr/bin/env python3
"""Execute original SD asynchronous write service/resource/status/event/cleanup without physical DMA."""
from datetime import datetime, timezone
from pathlib import Path
import json, re, subprocess, sys, tempfile
from s33_trace_state_dispatch import verified_payloads, sha
from s33_trace_transfer_callbacks import WINDOWS as CALLBACK_WINDOWS
from s33_trace_transfer_release import WINDOWS as RELEASE_WINDOWS
ROOT = Path(__file__).resolve().parents[1]


def main():
    blocks, payloads, _ = verified_payloads(ROOT)
    out = ROOT/'Risultati/Runtime_Kernel/RAM_Dumper_SD_Write_Async'/datetime.now(timezone.utc).strftime('%Y%m%dT%H%M%SZ')
    out.mkdir(parents=True, exist_ok=False)
    scripts = ROOT/'S33-sections/analysis_ghidra/scripts'
    sources = [Path(__file__), ROOT/'Python_Trace_Scripts/s33_trace_transfer_callbacks.py', ROOT/'Python_Trace_Scripts/s33_trace_transfer_release.py']+[scripts/n for n in ['ProbeDumpSDWriteAsync.java', 'ProbeDumpSDReadArbitration.java', 'ProbeDumpSDReadStatus.java', 'ProbeDumpSDMutex.java', 'ProbeStatusRead.java']]
    inputs = {str(p.relative_to(ROOT)): sha(p.read_bytes()) for p in sources}
    for p in sources:
        (out/(p.name+'.snapshot')).write_bytes(p.read_bytes())
    with tempfile.TemporaryDirectory(prefix='s33-sd-write-') as td:
        temp = Path(td)
        for i in (0, 1):
            (temp/f'p{i}.bin').write_bytes(payloads[i])
        cmd = [str(ROOT/'tools/ghidra-arcompact/ghidra_12.2_DEV/support/analyzeHeadless'), str(temp), 'write', '-import', str(temp/'p0.bin'), '-loader', 'BinaryLoader', '-loader-baseAddr', '0xad800', '-processor', 'ARCompact:LE:32:loopfix', '-noanalysis', '-scriptPath', str(scripts), '-postScript', 'ProbeDumpSDWriteAsync.java', str(out/'trace.txt'), str(temp/'p1.bin'), '-deleteProject']
        (out/'command.json').write_text(json.dumps(cmd, indent=2)+'\n')
        r = subprocess.run(cmd, stdout=subprocess.PIPE, stderr=subprocess.STDOUT, text=True, timeout=300)
        (out/'headless.log').write_text(r.stdout)
        assert r.returncode == 0 and 'SCRIPT ERROR' not in r.stdout, r.stdout[-6000:]
        trace = (out/'trace.txt').read_text()
        assert trace.endswith('COMPLETE cases=36\n') and trace.count('PASS ') == 36
        totals = {k:sum(map(int,re.findall(r'\b'+k+r'=(\d+)',trace))) for k in ['timeouts','progress','ticks']}
        assert totals == dict(timeouts=48,progress=48,ticks=4800),totals
    sys.path.insert(0, str(ROOT/'S33-sections/analysis_codex'))
    from static_common import disasm, u32, raw
    captures = {}
    source = bytes((k*37+11)&255 for k in range(16,1040))
    for name in re.findall(r'capture=(\S+)',trace):
        data = (out/name).read_bytes()
        assert data == source[:len(data)] and len(data) in (256,1024),(name,len(data))
        captures[name] = dict(bytes=len(data),sha256=sha(data))
    assert len(captures)==12 and sum(v['bytes'] for v in captures.values())==9216
    spans = [(a,b) for a,b,_ in CALLBACK_WINDOWS+RELEASE_WINDOWS]+[(0x3040DC,0x3042A8), (0x3042E4,0x304368), (0x304374,0x304380), (0x2BFE88,0x2BFF26), (0x303F24,0x3040DC), (0x25A430,0x25A444), (0x25A084,0x25A098)]
    listing = ''.join(disasm(a,b) for a,b in spans)
    (out/'gnu_verified.txt').write_text(listing)
    checks = {0x304124:';0x2bfe88', 0x304150:';0x266768', 0x30416A:';0x26671c',
              0x3041A0:';0x2c00e4', 0x3041C8:';0x158d04', 0x3041D4:';0x266e9c',
              0x3041E8:'cmp_s\tr14,0x9', 0x30427A:';0x2c0e70', 0x304298:';0x2667b0',
              0x3042EC:'btst_s\tr0,0x2', 0x304300:'btst_s\tr0,0x3',
              0x2BFF30:'st\tr2,[r16]', 0x2C01D2:';0x266fc8',
              0x268BC8:'st_s\tr0,[r1,0]', 0x268A50:'jl_s\t[r0]',
              0x2C0E6E:'st_s\tr1,[r15,0]', 0x2C0C82:'st_s\tr1,[r14,0x4]',
              0x25A43A:'sth.di\tr1,[r2]', 0x304042:'ldh.ab\tr1,[r15,2]',
              0x303F60:'ldb_s\tr1,[r14,0]', 0x3040B2:'btst_s\tr0,0x7'}
    for a,token in checks.items():
        lines = [line for line in listing.splitlines() if re.match(rf'\s*{a:x}:',line)]
        assert len(lines)==1 and token in lines[0],(hex(a),token,lines)
    assert [u32(a) for a in range(0x304390,0x3043AC,4)] == [0x3042E4,0x304324,0xE00005,0x304368,0x304374,0xE01211,0xE01321]
    assert [u32(0x2C00A4),u32(0x2C00AC),u32(0x2C00B4),u32(0x268E14)] == [0x512C5C,0x512C80,0x512CA4,0x36B3D8]
    assert [u32(0x374300),u32(0x374304),u32(0x374308)] == [0x53454D4C,0x1E00000,1]
    assert raw(0x374310,40)==bytes(40)
    assert all(sha((ROOT/p).read_bytes())==h for p,h in inputs.items())
    result = dict(status='PASS_ORIGINAL_SD_ASYNC_WRITE_SERVICE_RESOURCE_EVENT_AND_CLEANUP_PROFILE',
        cpu_cases=36,async_cases=24,pio_cases=12,returned_cases=36,timeout_progress_totals=totals,pio_port_captures=captures,gnu_windows=len(spans),instruction_checks=len(checks),sources=inputs,
        payload_hashes={str(b['index']):b['sha256'] for b in blocks},
        original_bodies=['3040DC aligned write caller,2BFE88/2BFAF8 acquire,2C00E4 start/programmers',
            '15933C semaphore initialization,1594E4 actual token reservation and1594A4 post',
            '266768/26671C status registration,router040E/2640E0/2667FC and3042E4/304324 status callbacks',
            '268BC4 callback setter,2689FC stored-callback dispatch through268A50 and304368/304374 completion SET',
            '158C30 event initialization,actual timedWAIT registration,event wake/query/CLEAR and2C0C84/2C0B84 release',
            '2F70C4 tick timeout and266E9C actual write progress getter fromFEE0538',
            '3040DC unaligned fallback to304004/303F24 original source loads and25A430 MMIO port stores'],
        fixtures=['Prepared one-task kernel and initialized framework;synthetic ready/status/pending MMIO samples',
            'B2D50 intercepted before CPU frame save;original walkers dispatched by C ABI and return permitted only after original event wake',
            '3342A8/336364 products modeled;resource/status/event/stop routines are not return fixtures',
            'No physical DMA,cache effects,media or filesystem;write source/guards remain unchanged;PIO port stores captured after original CPU instruction'],
        conclusions=['Original write object512C5C is distinct from receive512CC8 and uses resource1E00000',
            'Write completion publishes200/200000;status bit2 publishes400/400000 and returnsE01211;bit3 publishes800/800000 and returnsE01321',
            'Both status bits prioritize bit2;error before completion wins and retains completion pending',
            'Original release restores resource token1,clears software flags/object selector/caller handle and restores controller mask',
            'Forced auto-clear1 consumes error before query and returns0;original static eventflags2 selects0',
            'After one real timeout,completion succeeds;9 stagnant actual progress reads failE01211;change at5 resets count and permits14 timeout returns',
            'PIO unaligned paths store1024original source bytes on8success cases;4injected errors after256bytes returnE01200/E01310 with exact partial captures',
            'Real framework enable failure200604 occurs before start and leaves token0,object andmaskEFDF retained'],
        limits=['Only first write object and one-step1024byte operation tested here;other object start paths remain open;clock1000/1000 synthetic',
            'PIO copies execute into synthetic MMIO,asynchronous profiles have no data copy;neither proves data reached physical SD',
            'Write filesystem/creation/close binding,full physical RAM map and compatible resident task remain needed;NON_INSTALLARE'])
    (out/'verified_evidence.json').write_text(json.dumps(result,indent=2)+'\n')
    (out.parent/'latest.json').write_text(json.dumps({'evidence':str((out/'verified_evidence.json').relative_to(ROOT))},indent=2)+'\n')
    print(trace,end='')
    print(out)


if __name__=='__main__':
    main()
