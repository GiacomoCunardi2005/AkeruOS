#!/usr/bin/env python3
"""Original SD mount, backend selection and semaphore cleanup; offline only."""
from datetime import datetime, timezone
from pathlib import Path
import json, re, subprocess, sys, tempfile
from s33_trace_state_dispatch import verified_payloads, sha
ROOT=Path(__file__).resolve().parents[1]


def main():
    blocks,payloads,_=verified_payloads(ROOT)
    out=ROOT/'Risultati/Runtime_Kernel/RAM_Dumper_SD_Mount'/datetime.now(timezone.utc).strftime('%Y%m%dT%H%M%SZ');out.mkdir(parents=True,exist_ok=False)
    scripts=ROOT/'S33-sections/analysis_ghidra/scripts'
    sources=[Path(__file__)]+[scripts/n for n in ['ProbeDumpSDMount.java','ProbeDumpSDMutex.java','ProbeStatusRead.java']]
    inputs={str(p.relative_to(ROOT)):sha(p.read_bytes())for p in sources}
    for p in sources:(out/(p.name+'.snapshot')).write_bytes(p.read_bytes())
    with tempfile.TemporaryDirectory(prefix='s33-sd-mount-')as td:
        temp=Path(td)
        for i in (0,1):(temp/f'p{i}.bin').write_bytes(payloads[i])
        cmd=[str(ROOT/'tools/ghidra-arcompact/ghidra_12.2_DEV/support/analyzeHeadless'),str(temp),'mount','-import',str(temp/'p0.bin'),'-loader','BinaryLoader','-loader-baseAddr','0xad800','-processor','ARCompact:LE:32:loopfix','-noanalysis','-scriptPath',str(scripts),'-postScript','ProbeDumpSDMount.java',str(out/'trace.txt'),str(temp/'p1.bin'),'-deleteProject']
        (out/'command.json').write_text(json.dumps(cmd,indent=2)+'\n')
        r=subprocess.run(cmd,stdout=subprocess.PIPE,stderr=subprocess.STDOUT,text=True,timeout=180);(out/'headless.log').write_text(r.stdout)
        assert r.returncode==0 and 'SCRIPT ERROR'not in r.stdout,r.stdout[-4000:]
        trace=(out/'trace.txt').read_text();assert trace.endswith('COMPLETE cases=16\n')and trace.count('PASS ')==16
    sys.path.insert(0,str(ROOT/'S33-sections/analysis_codex'))
    from static_common import disasm, u32
    spans=[(0x1f3ef0,0x1f4118),(0x1f35d4,0x1f3608),(0x1f3608,0x1f36c0),(0x1f43ac,0x1f43f0),(0x1f43f0,0x1f4420),(0x23eca4,0x23ed7c),(0x23ee48,0x23ef54)]
    spans += [(0x1f46c4,0x1f46fc),(0x1f4710,0x1f4736),(0x1f4834,0x1f48a4),(0x2a12d8,0x2a1300),(0x2a1398,0x2a13a4),(0x1f661c,0x1f6628),(0x1f48a4,0x1f48e8),(0x2a45e4,0x2a45f0),(0x1f21f8,0x1f22c0)]
    listing=''.join(disasm(a,b)for a,b in spans);(out/'gnu_verified.txt').write_text(listing)
    checks={0x1f3f62:';0x23eca4',0x1f3f8e:';0x1f4110',0x1f410a:';0x23ee48',0x1f3f2c:'st.as\tr15,[r14,106]',0x1f35f4:'st_s\tr0,[r14,0x70]',0x1f364e:'st_s\tr0,[r15,0x70]'}
    for a,s in checks.items():
        lines=[line for line in listing.splitlines()if re.match(rf'\s*{a:x}:',line)];assert len(lines)==1 and s in lines[0],(hex(a),s,lines)
    assert u32(0x1f3900)==0x1f43ac and u32(0x1f3904)==0x1f48a4 and u32(0x1f4c48)==0x1a00010
    assert u32(0x1f392c)==0x1a0000c and u32(0x1f4374)==0xa0a1 and u32(0x1f4378)==0x25980c
    assert all(sha((ROOT/p).read_bytes())==h for p,h in inputs.items())
    result=dict(status='PASS_ORIGINAL_MOUNT_SEMAPHORE_AND_BACKEND_SELECTION',cpu_cases=16,gnu_windows=len(spans),instruction_checks=len(checks),sources=inputs,payload_hashes={str(b['index']):b['sha256']for b in blocks},
        original_bodies=['1F3EF0 mount','1F35D4 backend selector','1F3608 special backend init','1F48A4 callback close ->1F46C4 volume close','2A12D8 context resolver','2A45E4 zero-halfword gate','23ECA4 wait','23EE48 post','13A954 memset and millicode'],
        fixtures=['Resolver1F19E0','Device ioctl1F2348 and geometry2A4544','Sector read2A0C60','Heap268EE4/259A58/25980C','Registration2A4528 and setup2A45D4','Special predicate1F64E8 and metadata1F8E94/1F9970','Regular parser1F37AC and notifications225674/2261CC', 'Close ioctl3 is a fixture; gate2A45E4 executes against explicit halfword context+108'],
        conclusions=['Mount takes context+388 before selecting backend and releases it on success and tested allocation/parser failures','Query A0A1 error after wait reaches return1F4110 without post in this body; count stays0','Context+424 lower-handle publication occurs before wait and remains on tested errors except resolver refusal','Selected backend7 remains7 even when special init predicate refuses with01A0000C','Mount waiting on semaphore0 queues before query/backend modification', 'Volume close1F46C4 releases first acquisition before backend7 clears context+424; backend1 reacquires for cleanup; backend and ready fields retained in both tested branches', 'Original close gate2A45E4 accepts halfword context+108 zero, refuses1 with01A00010', 'Static generic open1F21F8 releases kernel+334 registry semaphore before calling device open; not an outer callback lock'],
        limits=['No physical mount, SD I/O, real heap, concurrent task or complete filesystem','No global leak claim: ioctl/notification fixtures and caller cleanup remain outside scope','Regular parser readiness/state is supplied by fixture','Close callback1F48A4 uses file+4 zero volume branch, buffers null; backend12 and upper caller cleanup outside scope', 'Other backend writers/aliases remain open','No exclusive-create binding or installable RAM dumper'])
    (out/'verified_evidence.json').write_text(json.dumps(result,indent=2)+'\n');(out.parent/'latest.json').write_text(json.dumps({'evidence':str((out/'verified_evidence.json').relative_to(ROOT))},indent=2)+'\n');print(trace,end='');print(out)


if __name__=='__main__':main()
