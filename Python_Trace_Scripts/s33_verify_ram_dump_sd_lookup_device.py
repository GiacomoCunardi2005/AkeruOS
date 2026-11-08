#!/usr/bin/env python3
"""Original lookup through generic device read callback on a synthetic sector tree."""
from datetime import datetime, timezone
from pathlib import Path
import json, re, subprocess, sys, tempfile
from s33_trace_state_dispatch import verified_payloads, sha
ROOT=Path(__file__).resolve().parents[1]


def main():
    blocks,payloads,_=verified_payloads(ROOT)
    out=ROOT/'Risultati/Runtime_Kernel/RAM_Dumper_SD_Lookup_Device'/datetime.now(timezone.utc).strftime('%Y%m%dT%H%M%SZ');out.mkdir(parents=True,exist_ok=False)
    scripts=ROOT/'S33-sections/analysis_ghidra/scripts'
    sources=[Path(__file__)]+[scripts/n for n in ['ProbeDumpSDLookupDevice.java','ProbeDumpSDLookupTree.java','ProbeDumpSDLookup.java','ProbeDumpSDMutex.java','ProbeStatusRead.java']]
    inputs={str(p.relative_to(ROOT)):sha(p.read_bytes())for p in sources}
    for p in sources:(out/(p.name+'.snapshot')).write_bytes(p.read_bytes())
    with tempfile.TemporaryDirectory(prefix='s33-sd-tree-')as td:
        temp=Path(td)
        for i in (0,1):(temp/f'p{i}.bin').write_bytes(payloads[i])
        cmd=[str(ROOT/'tools/ghidra-arcompact/ghidra_12.2_DEV/support/analyzeHeadless'),str(temp),'tree','-import',str(temp/'p0.bin'),'-loader','BinaryLoader','-loader-baseAddr','0xad800','-processor','ARCompact:LE:32:loopfix','-noanalysis','-scriptPath',str(scripts),'-postScript','ProbeDumpSDLookupDevice.java',str(out/'trace.txt'),str(temp/'p1.bin'),'-deleteProject']
        (out/'command.json').write_text(json.dumps(cmd,indent=2)+'\n')
        r=subprocess.run(cmd,stdout=subprocess.PIPE,stderr=subprocess.STDOUT,text=True,timeout=180);(out/'headless.log').write_text(r.stdout)
        assert r.returncode==0 and 'SCRIPT ERROR'not in r.stdout,r.stdout[-4000:]
        trace=(out/'trace.txt').read_text();assert trace.endswith('COMPLETE cases=20\n')and trace.count('PASS ')==20
    sys.path.insert(0,str(ROOT/'S33-sections/analysis_codex'))
    from static_common import disasm, u32
    spans=[(0x2a3360,0x2a358c),(0x29ff74,0x2a005c),(0x2a0484,0x2a04b0),(0x2a47c4,0x2a47e8),(0x2a461c,0x2a4694),(0x259a58,0x259afc),(0x2a318c,0x2a3244),(0x2a3250,0x2a3360),(0x2a0444,0x2a0468),(0x2a2d88,0x2a318c),(0x2a017c,0x2a01ac),(0x2a01ac,0x2a0268),(0x2a0144,0x2a017c),(0x2a1178,0x2a1270),(0x2a10f4,0x2a1124),(0x2a113c,0x2a1178),(0x3342a8,0x3342cc),(0x2a0c14,0x2a0c60),(0x2a0c60,0x2a0d50),(0x2a0d56,0x2a0d70),(0x1f3524,0x1f3554),(0x226204,0x22624c)]
    listing=''.join(disasm(a,b)for a,b in spans);(out/'gnu_verified.txt').write_text(listing)
    checks={0x2a33aa:';0x29ffb0',0x2a344e:';0x2a318c',0x2a353a:';0x2a2d88',0x2a354c:'st\tr1,[r17]',0x259aa0:';0x2e4ec4',0x2a3268:';0x2a2d88',0x2a3272:';0x2a3316',0x2a3298:'and.f\tr0,r0,r4'}
    for a,s in checks.items():
        lines=[line for line in listing.splitlines()if re.match(rf'\s*{a:x}:',line)];assert len(lines)==1 and s in lines[0],(hex(a),s,lines)
    assert [u32(a)for a in [0x2a3710,0x2a3718,0x2a371c,0x2a3720]]==[0x1a00006,0x1a00003,0x1a00002,0x1a00013]
    assert all(sha((ROOT/p).read_bytes())==h for p,h in inputs.items())
    result=dict(status='PASS_ORIGINAL_LOOKUP_THROUGH_GENERIC_DEVICE_CALLBACK',cpu_cases=20,gnu_windows=len(spans),instruction_checks=len(checks),sources=inputs,payload_hashes={str(b['index']):b['sha256']for b in blocks},
        original_bodies=['2A3360 coordinator','29FFB0/29FF74 parser','2A318C directory walker','2A2D88 record scanner, short-name parser/comparator and attribute filter','2A1178 sector reader and2A10F4 pending-write consumer','2A0C60 lower transfer,226204 seek,1F3524 generic read dispatch','259A58 allocation wrapper with original critical counter'],
        fixtures=['2E4EC4 supplies guarded scratch0/A5 or null; metadata/free are recorders','Synthetic device callback at0F000200 supplies sectors at LBA100/101/102 using handle position set by original seek; current directory0x123 translates to390 and aliases root','Prepared block-unit device and successful control7 callback;2015/2016 disabled by explicit context+848=1','3342A8 replaced by modulo32 product, unsupported MULUDW semantics not established','Prepared sector buffers and geometry; no mounted physical volume','21B2CC/21A454 disable external cached objects;2A29B4 returns cache miss','2ABC68 terminates advancement on injected read errors; no FAT chain followed','Prepared backend1 context, no full open callback or scheduler'],
        conclusions=['Coordinator/walker/finder/sector reader/lower transfer/seek/generic read execute in same case against one tree; device callback sees translated handle position, selected buffer and count1','Absolute/relative and nested path results checked through pointer, cluster/index and read routes','Leaf miss01A00002, directory failure01A00003 and leaf read error01A00021 asserted; directory I/O also becomes01A00003','Parser allocation257 failure under scratch0 returns zero directory entry with status0; independent exact-name final fixture previously hid this outcome','All acquired scratch released once; sectors and input path preserved'],
        limits=['Synthetic lower transfers and cache misses only; non-root translation conditional on multiply model; no real SD/FAT, multi-sector chain or DCIM/long-name coverage','No integrated r/open callback or physical exclusive creation','No installable dumper or full physical RAM map'])
    (out/'verified_evidence.json').write_text(json.dumps(result,indent=2)+'\n');(out.parent/'latest.json').write_text(json.dumps({'evidence':str((out/'verified_evidence.json').relative_to(ROOT))},indent=2)+'\n');print(trace,end='');print(out)


if __name__=='__main__':main()
