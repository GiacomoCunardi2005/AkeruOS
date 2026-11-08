#!/usr/bin/env python3
"""Original multi-sector/multi-cluster lookup with synthetic FAT and device callbacks."""
from datetime import datetime, timezone
from pathlib import Path
import json, re, subprocess, sys, tempfile
from s33_trace_state_dispatch import verified_payloads, sha
ROOT=Path(__file__).resolve().parents[1]


def main():
    blocks,payloads,_=verified_payloads(ROOT)
    out=ROOT/'Risultati/Runtime_Kernel/RAM_Dumper_SD_Chain'/datetime.now(timezone.utc).strftime('%Y%m%dT%H%M%SZ');out.mkdir(parents=True,exist_ok=False)
    scripts=ROOT/'S33-sections/analysis_ghidra/scripts'
    sources=[Path(__file__)]+[scripts/n for n in ['ProbeDumpSDChain.java','ProbeDumpSDLookupTree.java','ProbeDumpSDLookup.java','ProbeDumpSDMutex.java','ProbeStatusRead.java']]
    inputs={str(p.relative_to(ROOT)):sha(p.read_bytes())for p in sources}
    for p in sources:(out/(p.name+'.snapshot')).write_bytes(p.read_bytes())
    with tempfile.TemporaryDirectory(prefix='s33-sd-tree-')as td:
        temp=Path(td)
        for i in (0,1):(temp/f'p{i}.bin').write_bytes(payloads[i])
        cmd=[str(ROOT/'tools/ghidra-arcompact/ghidra_12.2_DEV/support/analyzeHeadless'),str(temp),'tree','-import',str(temp/'p0.bin'),'-loader','BinaryLoader','-loader-baseAddr','0xad800','-processor','ARCompact:LE:32:loopfix','-noanalysis','-scriptPath',str(scripts),'-postScript','ProbeDumpSDChain.java',str(out/'trace.txt'),str(temp/'p1.bin'),'-deleteProject']
        (out/'command.json').write_text(json.dumps(cmd,indent=2)+'\n')
        r=subprocess.run(cmd,stdout=subprocess.PIPE,stderr=subprocess.STDOUT,text=True,timeout=180);(out/'headless.log').write_text(r.stdout)
        assert r.returncode==0 and 'SCRIPT ERROR'not in r.stdout,r.stdout[-4000:]
        trace=(out/'trace.txt').read_text();assert trace.endswith('COMPLETE cases=13\n')and trace.count('PASS ')==13
    sys.path.insert(0,str(ROOT/'S33-sections/analysis_codex'))
    from static_common import disasm, u32
    spans=[(0x2a3360,0x2a358c),(0x29ff74,0x2a005c),(0x2a0484,0x2a04b0),(0x2a47c4,0x2a47e8),(0x2a461c,0x2a4694),(0x259a58,0x259afc),(0x2a318c,0x2a3244),(0x2a3250,0x2a3360),(0x2a0444,0x2a0468),(0x2a2d88,0x2a318c),(0x2a017c,0x2a01ac),(0x2a01ac,0x2a0268),(0x2a0144,0x2a017c),(0x2a1178,0x2a1270),(0x2a10f4,0x2a1124),(0x2a113c,0x2a1178),(0x3342a8,0x3342cc),(0x2a0c14,0x2a0c60),(0x2a0c60,0x2a0d50),(0x2a0d56,0x2a0d70),(0x1f3524,0x1f3554),(0x226204,0x22624c),(0x2abc68,0x2abcd4),(0x1f2484,0x1f250c),(0x1f250c,0x1f25d8),(0x1f25d8,0x1f271c),(0x1f2734,0x1f277c),(0x335b34,0x335c4c)]
    listing=''.join(disasm(a,b)for a,b in spans);(out/'gnu_verified.txt').write_text(listing)
    checks={0x2a33aa:';0x29ffb0',0x2a344e:';0x2a318c',0x2a353a:';0x2a2d88',0x2a354c:'st\tr1,[r17]',0x259aa0:';0x2e4ec4',0x2a3268:';0x2a2d88',0x2a3272:';0x2a3316',0x2a3298:'and.f\tr0,r0,r4',0x2a30e6:';0x2abc68',0x2a30ec:'cmp_s\tr0,0',0x2a30ee:'bne_s',0x2a317e:'ld_s\tr1,[sp,0x2c]',0x2a3180:'st_s\tr1,[r0,0]',0x1f26b2:'bls'}
    for a,s in checks.items():
        lines=[line for line in listing.splitlines()if re.match(rf'\s*{a:x}:',line)];assert len(lines)==1 and s in lines[0],(hex(a),s,lines)
    assert [u32(a)for a in [0x2a3710,0x2a3718,0x2a371c,0x2a3720]]==[0x1a00006,0x1a00003,0x1a00002,0x1a00013]
    assert all(sha((ROOT/p).read_bytes())==h for p,h in inputs.items())
    result=dict(status='PASS_ORIGINAL_LOOKUP_MULTI_SECTOR_AND_FAT_CHAIN',cpu_cases=13,returned_cases=12,bounded_cycle_observations=1,gnu_windows=len(spans),instruction_checks=len(checks),sources=inputs,payload_hashes={str(b['index']):b['sha256']for b in blocks},
        original_bodies=['2A3360 coordinator and parser','2A318C directory walker','2A2D88 scanner including original2ABC68 advancement','1F25D8 FAT reader,1F250C window load and clean1F2484','2A1178 sector reader,2A0C60 lower transfer,226204 seek and1F3524 dispatch','Original unsigned division335B34 and allocation critical counters'],
        fixtures=['Prepared FAT12 volume:512-byte sectors,16records/sector,2sectors/cluster,root100/101,data102,FAT20/21','Device callbacks supply synthetic sectors or injected FAT/data read error; controls7 return0','3342A8 modulo32 product; DSP semantics not established','2E4EC4 supplies guarded zero scratch; metadata/free recorders; external caches and fastpath disabled'],
        conclusions=['Root exhaustion without end marker attempts position102 and returns01A0000D before lower device access','Root second sector, second sector within cluster, one/two FAT hops and nested lookup verified through final record bytes and metadata','FAT I/O failure reaches scanner as01A00021 but lookup returns01A00002; last successful data-read status reused','Synthetic corrupt FAT entry0 redirects subdirectory lookup to root and returns root TARGET.BIN with status0','ThresholdFF8 retained by FAT decoder; following it hits sector-reader bounds and returns01A0000D','Cycle2to3to2 repeats data sectors; bounded observation stops at twelfth callback without normal return'],
        limits=['Cycle observation deliberately stopped while call active; fixture allocations disposed with emulator, not normal cleanup proof','No long names/DCIM, cache-list path, concurrent task, physical driver or persistence','No single r/open-driver-close execution, exclusive creation, full RAM map or installable dumper'])
    (out/'verified_evidence.json').write_text(json.dumps(result,indent=2)+'\n');(out.parent/'latest.json').write_text(json.dumps({'evidence':str((out/'verified_evidence.json').relative_to(ROOT))},indent=2)+'\n');print(trace,end='');print(out)


if __name__=='__main__':main()
