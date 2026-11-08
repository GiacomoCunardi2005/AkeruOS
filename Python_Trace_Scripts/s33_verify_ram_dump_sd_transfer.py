#!/usr/bin/env python3
"""Original lower transfer wrapper and generic dispatch; synthetic device callbacks."""
from datetime import datetime, timezone
from pathlib import Path
import json, re, subprocess, sys, tempfile
from s33_trace_state_dispatch import verified_payloads, sha
ROOT=Path(__file__).resolve().parents[1]


def main():
    blocks,payloads,_=verified_payloads(ROOT)
    out=ROOT/'Risultati/Runtime_Kernel/RAM_Dumper_SD_Transfer'/datetime.now(timezone.utc).strftime('%Y%m%dT%H%M%SZ');out.mkdir(parents=True,exist_ok=False)
    scripts=ROOT/'S33-sections/analysis_ghidra/scripts'
    sources=[Path(__file__)]+[scripts/n for n in ['ProbeDumpSDTransfer.java','ProbeDumpSDMutex.java','ProbeStatusRead.java']]
    inputs={str(p.relative_to(ROOT)):sha(p.read_bytes())for p in sources}
    for p in sources:(out/(p.name+'.snapshot')).write_bytes(p.read_bytes())
    with tempfile.TemporaryDirectory(prefix='s33-sd-tree-')as td:
        temp=Path(td)
        for i in (0,1):(temp/f'p{i}.bin').write_bytes(payloads[i])
        cmd=[str(ROOT/'tools/ghidra-arcompact/ghidra_12.2_DEV/support/analyzeHeadless'),str(temp),'tree','-import',str(temp/'p0.bin'),'-loader','BinaryLoader','-loader-baseAddr','0xad800','-processor','ARCompact:LE:32:loopfix','-noanalysis','-scriptPath',str(scripts),'-postScript','ProbeDumpSDTransfer.java',str(out/'trace.txt'),str(temp/'p1.bin'),'-deleteProject']
        (out/'command.json').write_text(json.dumps(cmd,indent=2)+'\n')
        r=subprocess.run(cmd,stdout=subprocess.PIPE,stderr=subprocess.STDOUT,text=True,timeout=180);(out/'headless.log').write_text(r.stdout)
        assert r.returncode==0 and 'SCRIPT ERROR'not in r.stdout,r.stdout[-4000:]
        trace=(out/'trace.txt').read_text();assert trace.endswith('COMPLETE cases=25\n')and trace.count('PASS ')==25
    sys.path.insert(0,str(ROOT/'S33-sections/analysis_codex'))
    from static_common import disasm, u32
    spans=[(0x2a0c14,0x2a0c60),(0x2a0c60,0x2a0d50),(0x2a0d56,0x2a0d70),(0x1f3524,0x1f3554),(0x1fa090,0x1fa0c0),(0x226204,0x22624c),(0x1f2348,0x1f237e),(0x3342a8,0x3342cc)]
    listing=''.join(disasm(a,b)for a,b in spans);(out/'gnu_verified.txt').write_text(listing)
    checks={0x2a0c4e:';0x1fa090',0x2a0c9c:';0x226204',0x2a0cee:';0x1f3524',0x2a0d12:';0x2a0c14',0x2a0d1c:'ld_s\tr13,[r0,0xc]',0x226244:'mov_s\tr0,0',0x1f3536:'ld_s\tr3,[r3,0x14]',0x1fa0a2:'ld_s\tr3,[r3,0x18]'}
    for a,token in checks.items():
        lines=[line for line in listing.splitlines()if re.match(rf'\s*{a:x}:',line)];assert len(lines)==1 and token in lines[0],(hex(a),token,lines)
    assert [u32(a)for a in [0x2a1124,0x2a1128,0x2a112c,0x2a1130]]==[0x1a0000f,0x1a0000e,0x1a0000d,0x1a00009]
    assert all(sha((ROOT/p).read_bytes())==h for p,h in inputs.items())
    result=dict(status='PASS_ORIGINAL_LOWER_TRANSFER_AND_GENERIC_DEVICE_DISPATCH',cpu_cases=25,gnu_windows=len(spans),instruction_checks=len(checks),sources=inputs,payload_hashes={str(b['index']):b['sha256']for b in blocks},
        original_bodies=['2A0C60 lower transfer wrapper','2A0C14 write residual helper','1F3524/1FA090 generic read/write dispatch','226204 seek and1F2348 ioctl dispatch'],
        fixtures=['Prepared handle and synthetic device callbacks at0F000200/300; callback returns chosen count/error and does not access hardware','3342A8 modulo32 product boundary for byte position conversion; unsupported MULUDW not executed'],
        conclusions=['Read and write attempt callback at most once; residual asserted at original common exit','Partial/zero/minus1 result with handle error0 can return status0 with residual remaining','Full or overreported count returns0 regardless of retained handle error','Missing callback sets handle error102C and returns it through wrapper','Original seek discards control7 result; wrapper ignores2015/2016 control results','Block-unit and512-byte-unit paths, controls ordering and selected error mapping verified'],
        limits=['Injected callback combinations are contract tests, not observed driver behavior','No physical SD completion or persistence, no full mounted volume','Not yet integrated with scanner/reader suite; byte multiplication conditional on model'])
    (out/'verified_evidence.json').write_text(json.dumps(result,indent=2)+'\n');(out.parent/'latest.json').write_text(json.dumps({'evidence':str((out/'verified_evidence.json').relative_to(ROOT))},indent=2)+'\n');print(trace,end='');print(out)


if __name__=='__main__':main()
