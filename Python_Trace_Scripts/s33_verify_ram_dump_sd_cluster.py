#!/usr/bin/env python3
"""Original record advancement and FAT reader/cache with declared fixtures."""
from datetime import datetime, timezone
from pathlib import Path
import json, re, subprocess, sys, tempfile
from s33_trace_state_dispatch import verified_payloads, sha
ROOT=Path(__file__).resolve().parents[1]


def main():
    blocks,payloads,_=verified_payloads(ROOT)
    out=ROOT/'Risultati/Runtime_Kernel/RAM_Dumper_SD_Cluster'/datetime.now(timezone.utc).strftime('%Y%m%dT%H%M%SZ');out.mkdir(parents=True,exist_ok=False)
    scripts=ROOT/'S33-sections/analysis_ghidra/scripts'
    sources=[Path(__file__)]+[scripts/n for n in ['ProbeDumpSDCluster.java','ProbeDumpSDMutex.java','ProbeStatusRead.java']]
    inputs={str(p.relative_to(ROOT)):sha(p.read_bytes())for p in sources}
    for p in sources:(out/(p.name+'.snapshot')).write_bytes(p.read_bytes())
    with tempfile.TemporaryDirectory(prefix='s33-sd-tree-')as td:
        temp=Path(td)
        for i in (0,1):(temp/f'p{i}.bin').write_bytes(payloads[i])
        cmd=[str(ROOT/'tools/ghidra-arcompact/ghidra_12.2_DEV/support/analyzeHeadless'),str(temp),'tree','-import',str(temp/'p0.bin'),'-loader','BinaryLoader','-loader-baseAddr','0xad800','-processor','ARCompact:LE:32:loopfix','-noanalysis','-scriptPath',str(scripts),'-postScript','ProbeDumpSDCluster.java',str(out/'trace.txt'),str(temp/'p1.bin'),'-deleteProject']
        (out/'command.json').write_text(json.dumps(cmd,indent=2)+'\n')
        r=subprocess.run(cmd,stdout=subprocess.PIPE,stderr=subprocess.STDOUT,text=True,timeout=180);(out/'headless.log').write_text(r.stdout)
        assert r.returncode==0 and 'SCRIPT ERROR'not in r.stdout,r.stdout[-4000:]
        trace=(out/'trace.txt').read_text();assert trace.endswith('COMPLETE cases=34\n')and trace.count('PASS ')==34
    sys.path.insert(0,str(ROOT/'S33-sections/analysis_codex'))
    from static_common import disasm, u32
    spans=[(0x2abc68,0x2abcd4),(0x1f2484,0x1f250c),(0x1f250c,0x1f25d8),(0x1f25d8,0x1f271c),(0x1f2734,0x1f277c),(0x335b34,0x335c4c)]
    listing=''.join(disasm(a,b)for a,b in spans);(out/'gnu_verified.txt').write_text(listing)
    checks={0x2abca6:';0x1f25d8',0x2abcb4:'mov_s\tr13,0',0x2abcc6:'st\tr14,[r17]',0x1f2656:';0x1f250c',0x1f259a:';0x2a0c60',0x1f26b2:'bls',0x1f26ca:'bls',0x1f2774:'bmsk\tr0,r14,0x1b'}
    for a,token in checks.items():
        lines=[line for line in listing.splitlines()if re.match(rf'\s*{a:x}:',line)];assert len(lines)==1 and token in lines[0],(hex(a),token,lines)
    assert [u32(a)for a in [0x1f271c,0x1f2724,0x1f2728,0x1f272c,0x1f2730]]==[0x369368,0x36938c,0xfffffff,0x1a0001e,0xffffff8]
    assert all(sha((ROOT/p).read_bytes())==h for p,h in inputs.items())
    result=dict(status='PASS_ORIGINAL_RECORD_ADVANCE_AND_FAT_READER_CACHE',cpu_cases=34,advance_cases=12,fat_cases=22,gnu_windows=len(spans),instruction_checks=len(checks),sources=inputs,payload_hashes={str(b['index']):b['sha256']for b in blocks},
        original_bodies=['2ABC68 record advance and335B34 unsigned division','1F25D8 FAT entry decoder and1F250C window loader','1F2484 pending consumer on clean state'],
        fixtures=['Advance matrix replaces1F25D8 with next/error recorder; separate FAT matrix executes it','FAT matrix replaces2A0C60 with synthetic read of two512-byte sectors, injected error or success','3342A8 modulo32 product boundary; DSP semantics not proven','Prepared context/window/global cache pointer0; no mounted physical volume'],
        conclusions=['Root exhaustion publishes cluster1,index0; cluster boundary invokes FAT and resets index only when status0','FAT failure still publishes returned cluster but retains incremented index','FAT12 even/odd, cross-sector entry and FAT16/32 decodes executed','Threshold valuesFF8/FFF8/0FFFFFF8 retained; strictly greater normalized to0FFFFFFF','Raw32 entry high nibble is compared before final28-bit mask;F0000003 becomes sentinel','Cold aligned two-sector window and forced reload exercised; read errors propagated'],
        limits=['No scanner or multi-cluster lookup integration in this group','No FAT update/write/mirror/cache-list path or FAT32 multi-entry scan','Injected geometry and lower transfer; product model conditional; no hardware or installable dumper'])
    (out/'verified_evidence.json').write_text(json.dumps(result,indent=2)+'\n');(out.parent/'latest.json').write_text(json.dumps({'evidence':str((out/'verified_evidence.json').relative_to(ROOT))},indent=2)+'\n');print(trace,end='');print(out)


if __name__=='__main__':main()
