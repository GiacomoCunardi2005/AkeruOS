#!/usr/bin/env python3
"""Original SD n/d context locking, temporary field and bounded direct-store census."""
from datetime import datetime, timezone
from pathlib import Path
import hashlib, json, re, subprocess, sys, tempfile
from s33_trace_state_dispatch import verified_payloads, sha
ROOT=Path(__file__).resolve().parents[1]


def main():
    blocks,payloads,_=verified_payloads(ROOT)
    out=ROOT/'Risultati/Runtime_Kernel/RAM_Dumper_SD_Mutex'/datetime.now(timezone.utc).strftime('%Y%m%dT%H%M%SZ');out.mkdir(parents=True,exist_ok=False)
    scripts=ROOT/'S33-sections/analysis_ghidra/scripts';probe=scripts/'ProbeDumpSDMutex.java';helper=scripts/'ProbeStatusRead.java'
    inputs={str(p.relative_to(ROOT)):sha(p.read_bytes()) for p in [Path(__file__),probe,helper]}
    for p in [Path(__file__),probe,helper]:(out/(p.name+'.snapshot')).write_bytes(p.read_bytes())
    with tempfile.TemporaryDirectory(prefix='s33-sd-mutex-') as td:
        temp=Path(td)
        for i in (0,1):(temp/f'p{i}.bin').write_bytes(payloads[i])
        cmd=[str(ROOT/'tools/ghidra-arcompact/ghidra_12.2_DEV/support/analyzeHeadless'),str(temp),'mutex','-import',str(temp/'p0.bin'),'-loader','BinaryLoader','-loader-baseAddr','0xad800','-processor','ARCompact:LE:32:loopfix','-noanalysis','-scriptPath',str(scripts),'-postScript',probe.name,str(out/'trace.txt'),str(temp/'p1.bin'),'-deleteProject']
        (out/'command.json').write_text(json.dumps(cmd,indent=2)+'\n')
        r=subprocess.run(cmd,stdout=subprocess.PIPE,stderr=subprocess.STDOUT,text=True,timeout=180);(out/'headless.log').write_text(r.stdout)
        assert r.returncode==0 and 'SCRIPT ERROR' not in r.stdout,r.stdout[-4000:]
        trace=(out/'trace.txt').read_text();assert trace.endswith('COMPLETE cases=22\n') and trace.count('PASS ')==22
    sys.path.insert(0,str(ROOT/'S33-sections/analysis_codex'))
    from static_common import disasm, raw
    assert 0x1f455c+2*int.from_bytes(raw(0x1f455c+3,1),'little',signed=True)==0x1f4624
    spans=[(0x2a1300,0x2a1344),(0x2a1398,0x2a13a4),(0x2a1648,0x2a16f0),(0x2a1858,0x2a1914),(0x2a191a,0x2a1934),(0x1f4624,0x1f4642),(0x2abd0e,0x2abd36),(0x1f35d4,0x1f3608),(0x1f3956,0x1f39b6),(0x23eca4,0x23ed7c),(0x23ee48,0x23ef54)]
    spans += [(0x1f3554,0x1f35d0),(0x268ee4,0x268f88),(0x269f1c,0x269f20),(0xad90c,0xad914),(0x23ea7c,0x23eae8)]
    spans += [(0x1786e8,0x178718),(0x179354,0x179388)]
    (out/'gnu_verified.txt').write_text(''.join(disasm(a,b) for a,b in spans))
    candidate=ROOT/'Ghidra_Results/ghidra_reports/ptp_usb_audit/block00_linear_candidates.txt'
    matches=[]
    for line in candidate.read_text().splitlines():
        m=re.match(r'\s*([0-9a-f]+):',line)
        if m and (0x1f3000<=int(m[1],16)<0x1f9000 or 0x2a0000<=int(m[1],16)<0x2b0000) and re.search(r'\bst(?:_s|\.as)?\s+.*\[r\d+,(?:112|0x70|760|0x2f8|190)\]',line):matches.append(line.strip())
    assert len(matches)==7
    (out/'bounded_store_candidates.json').write_text(json.dumps(dict(source=str(candidate.relative_to(ROOT)),sha256=sha(candidate.read_bytes()),ranges=['1F3000..1F9000','2A0000..2B0000'],matches=matches,limit='Linear candidates, explicit printed offsets only; not dataflow, aliases, memset or exhaustive writer proof'),indent=2)+'\n')
    assert all(sha((ROOT/p).read_bytes())==digest for p,digest in inputs.items())
    result=dict(status='PASS_ORIGINAL_N_D_CONTEXT_SEMAPHORE_AND_INITIALIZATION',cpu_cases=22,payload_hashes={str(b['index']):b['sha256']for b in blocks},sources=inputs,gnu_windows=len(spans),
        assumptions=['Fourteen n/d cases: kernel acquire/release are recorders; same context+388 asserted, no scheduler or contention', 'Four separate semaphore cases execute original23ECA4/23EE48 with explicit kernel/task/ready queue; stop before scheduler B2D50', 'Original context resolver2A1300 and n/d helpers execute', 'D-mode path parser29FFB0 supplies explicit parsed strings; not end-to-end path parsing', 'Create2AC2B4 and file allocation2AC528 are fixtures, no directory mutation'],
        conclusions=['Both helpers enter create under the same resolved-context synchronization object', 'D-mode sets field190 only for parsed backslash plus nonempty next byte and clears it before release', 'N-mode does not normalize field190; initial1 remains1 under lock', '23ECA4/23EE48 implement wait/post on counting semaphore, magic6C77736D; count1 then second wait in same task queues, not recursive ownership'],
        constructor_cases=4,constructor_assumptions=['Original1F3554,268EE4,269F1C,AD90C,13A954,23EA7C,1786E8 and179354 execute; lower allocator2E4EC4 supplies explicit storage or null, metadata2599AC, registration2A3C5C, free25980C and secondary allocation2A3E78 are fixtures'],
        constructor_conclusions=['Successful construction zeroes852 bytes before registration; context+760 and+70 remain0; context+388 semaphore is initialized count1, magic6C77736D and empty waiter list', 'Allocation failure returns01A00006 without registration; registration failure requests free and returns01A00002', 'With registration/free fixtures, original critical services leave task+0x68 nesting1 on registration failure; no global firmware defect inferred', 'Secondary allocation null is stored at context+416, yet constructor returns0 with semaphore initialized and nesting balanced'],
        limits=['No proof of all later writers, alias contexts, physical SD or complete filesystem', 'Backend selection+70 preflight stability across mount/unmount remains open', 'Actual registration/free side effects and physical interrupt delivery not modeled', 'No installable dumper or complete physical RAM map'])
    (out/'verified_evidence.json').write_text(json.dumps(result,indent=2)+'\n');(out.parent/'latest.json').write_text(json.dumps(dict(evidence=str((out/'verified_evidence.json').relative_to(ROOT))),indent=2)+'\n');print(trace,end='');print(out)


if __name__=='__main__':main()
