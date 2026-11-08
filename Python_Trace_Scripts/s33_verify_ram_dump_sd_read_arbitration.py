#!/usr/bin/env python3
"""Original receive-resource tokens, timed semaphore wake, selection and software stop hooks."""
from datetime import datetime, timezone
from pathlib import Path
import json, re, subprocess, sys, tempfile
from s33_trace_state_dispatch import verified_payloads, sha
ROOT = Path(__file__).resolve().parents[1]


def main():
    blocks, payloads, _ = verified_payloads(ROOT)
    out = ROOT/'Risultati/Runtime_Kernel/RAM_Dumper_SD_Read_Arbitration'/datetime.now(timezone.utc).strftime('%Y%m%dT%H%M%SZ')
    out.mkdir(parents=True, exist_ok=False)
    scripts = ROOT/'S33-sections/analysis_ghidra/scripts'
    sources = [Path(__file__)]+[scripts/n for n in ['ProbeDumpSDReadArbitration.java', 'ProbeDumpSDReadStatus.java', 'ProbeDumpSDMutex.java', 'ProbeStatusRead.java']]
    inputs = {str(p.relative_to(ROOT)): sha(p.read_bytes()) for p in sources}
    for p in sources:
        (out/(p.name+'.snapshot')).write_bytes(p.read_bytes())
    with tempfile.TemporaryDirectory(prefix='s33-sd-arbitration-') as td:
        temp = Path(td)
        for i in (0, 1):
            (temp/f'p{i}.bin').write_bytes(payloads[i])
        cmd = [str(ROOT/'tools/ghidra-arcompact/ghidra_12.2_DEV/support/analyzeHeadless'), str(temp), 'arbitration', '-import', str(temp/'p0.bin'), '-loader', 'BinaryLoader', '-loader-baseAddr', '0xad800', '-processor', 'ARCompact:LE:32:loopfix', '-noanalysis', '-scriptPath', str(scripts), '-postScript', 'ProbeDumpSDReadArbitration.java', str(out/'trace.txt'), str(temp/'p1.bin'), '-deleteProject']
        (out/'command.json').write_text(json.dumps(cmd, indent=2)+'\n')
        r = subprocess.run(cmd, stdout=subprocess.PIPE, stderr=subprocess.STDOUT, text=True, timeout=300)
        (out/'headless.log').write_text(r.stdout)
        assert r.returncode == 0 and 'SCRIPT ERROR' not in r.stdout, r.stdout[-6000:]
        trace = (out/'trace.txt').read_text()
        assert trace.endswith('COMPLETE cases=34\n') and trace.count('PASS ') == 34
        assert trace.count('RESOURCE reader tries=1 posts=1 stops=1 firstToken=1\n') == 16
        assert trace.count('RESOURCE reader tries=1 posts=0 stops=0 firstToken=0\n') == 2
    sys.path.insert(0, str(ROOT/'S33-sections/analysis_codex'))
    from static_common import disasm, raw, u32
    spans = [(0x15933C, 0x1593AC), (0x1593AC, 0x1593E8), (0x1593F6, 0x159528),
             (0x23EA7C, 0x23EAE8), (0x23EE48, 0x23EFBC), (0x267BAC, 0x267BDC),
             (0x27FFB2, 0x27FFD0), (0x27FFD8, 0x280016), (0x280024, 0x280072),
             (0x280084, 0x2800A4), (0x2800B0, 0x2800D0), (0x2800DC, 0x2800EE),
             (0x2810A8, 0x2810CE), (0x28112C, 0x281158)]
    listing = ''.join(disasm(a, b) for a, b in spans)
    (out/'gnu_verified.txt').write_text(listing)
    checks = {0x15935A:';0x23ea7c', 0x159396:'ld_s\tr0,[r2,0x24]',
              0x159446:';0x23eca4', 0x159466:';0x23ed7c', 0x1594CC:';0x23ee48',
              0x1594F6:';0x23ef54', 0x1594FC:'stb_s\tr0,[r13,0]',
              0x23EA8E:'st_s\tr1,[r0,0x18]', 0x23EED2:'ld_s\tr1,[r1,0x4]',
              0x23EF1C:'st_s\tr2,[r0,0x18]', 0x23EF86:'sub_s\tr2,r2,0x1',
              0x23EF88:'st_s\tr2,[r0,0x18]', 0x267BB0:'stb_s\tr1,[r0,0]',
              0x267BB8:'stb_s\tr1,[r0,0]', 0x267BC0:'stb_s\tr1,[r0,0]',
              0x27FFE0:';0x1594a4', 0x28002C:';0x1594a4', 0x280048:';0x1593ac',
              0x28005C:';0x27ffb2', 0x2810C6:';0x1594a4'}
    for a, token in checks.items():
        lines = [line for line in listing.splitlines() if re.match(rf'\s*{a:x}:', line)]
        assert len(lines) == 1 and token in lines[0], (hex(a), token, lines)
    assert u32(0x159528) == 0x373D18
    rows = [0x3743A8, 0x3743E0, 0x374418]
    for i, row in enumerate(rows):
        assert [u32(row), u32(row+4), u32(row+8), u32(row+12)] == [0x53454D4C, 0x1E00003+i, 1, 0x800]
        assert raw(row+16, 40) == bytes(40)
    assert [u32(a) for a in range(0x267C28, 0x267C40, 4)] == [0x36B3E7, 0x36B3E8, 0x36B3E9, 0x36B3E4, 0x36B3E5, 0x36B3E6]
    assert all(sha((ROOT/p).read_bytes()) == h for p, h in inputs.items())
    result = dict(status='PASS_ORIGINAL_SD_RESOURCE_RESERVATION_POST_AND_SOFTWARE_STOP_PROFILE',
        cpu_cases=34, arbitration_cases=16, reader_cases=18, returned_cases=34,
        gnu_windows=len(spans), instruction_checks=len(checks), sources=inputs,
        payload_hashes={str(b['index']): b['sha256'] for b in blocks},
        original_bodies=['15933C/23EA7C semaphore initialization from original IDs1E00003/4/5 and count1 records',
            '1594E4/23EF54 try-acquire decrements token and stores only one success byte',
            '1593AC/23ED7C real timed semaphore wait,2313AC/28179C deadline and2F70C4 timeout or1594A4/23EE48 wake',
            '27FCD4 selector reserves first/third/second objects;not-ready speculative reservations posted back',
            '281158/281064 release and267BAC/BB4/BBC plus software flag helper siblings execute unchanged',
            'Inherited18 reader scenarios with status router/event initialization/wait/error/cleanup and actual resource operations'],
        fixtures=['Prepared one-task kernel/ready/deadline/global semaphore ring;original resource and event constructors',
            'Synthetic MMIO readiness/status/pending,framework initialized flag,CPU identity and clock1000/1000',
            'B2D50 intercepted before frame save;C-ABI post/ticks/walkers invoked and switch returned only after original wake',
            '3342A8/336364 products modeled;no resource API or stop-hook return replacement',
            'No DMA data transfer;inherited1024-byte buffer31 andA5guards checked unchanged'],
        conclusions=['Corrects historical query terminology:1594E4 is a nonblocking token reservation,not a readonly availability query',
            'Try-acquire1then0 and post restores1;unknown/uninitialized resource errors leave output and count untouched',
            'Timed wait returns200507 after5 software ticks or0 after post;post to waiter transfers token with count remaining0',
            'Held acquisition orderCC8,D10,CEC reserves three distinct objects;reverse release restores all three tokens',
            'Not-ready first/third hardware samples cause speculative tokens to be posted before second-object acquisition',
            'Fixed configuration modes3/4/6 bypass resource try/post;ordinary token ownership cannot be assumed for that path',
            '267BAC andfive siblings only clear software bytes;standalone return retains flag address,not an error-status contract',
            'Normal reader completion/error returns token1;early framework enable failure retains token0 and acquired association'],
        limits=['Sequential held-object and one-waiter tests,not arbitrary concurrent task scheduling or fairness',
            'Software flag clearing does not prove electrical engine stop or last physical buffer use',
            'Write path,filesystem binding,full physical RAM map,hardware-compatible task/hook and actual dump remain open;NON_INSTALLARE'])
    (out/'verified_evidence.json').write_text(json.dumps(result, indent=2)+'\n')
    (out.parent/'latest.json').write_text(json.dumps({'evidence': str((out/'verified_evidence.json').relative_to(ROOT))}, indent=2)+'\n')
    print(trace, end='')
    print(out)


if __name__ == '__main__':
    main()
