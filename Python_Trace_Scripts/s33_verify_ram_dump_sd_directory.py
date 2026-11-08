#!/usr/bin/env python3
"""Original lookup coordinator and directory walker; guarded record fixtures, offline only."""
from datetime import datetime, timezone
from pathlib import Path
import json, re, subprocess, sys, tempfile
from s33_trace_state_dispatch import verified_payloads, sha
ROOT=Path(__file__).resolve().parents[1]


def main():
    blocks,payloads,_=verified_payloads(ROOT)
    out=ROOT/'Risultati/Runtime_Kernel/RAM_Dumper_SD_Directory'/datetime.now(timezone.utc).strftime('%Y%m%dT%H%M%SZ');out.mkdir(parents=True,exist_ok=False)
    scripts=ROOT/'S33-sections/analysis_ghidra/scripts'
    sources=[Path(__file__)]+[scripts/n for n in ['ProbeDumpSDDirectory.java','ProbeDumpSDLookup.java','ProbeDumpSDMutex.java','ProbeStatusRead.java']]
    inputs={str(p.relative_to(ROOT)):sha(p.read_bytes())for p in sources}
    for p in sources:(out/(p.name+'.snapshot')).write_bytes(p.read_bytes())
    with tempfile.TemporaryDirectory(prefix='s33-sd-directory-')as td:
        temp=Path(td)
        for i in (0,1):(temp/f'p{i}.bin').write_bytes(payloads[i])
        cmd=[str(ROOT/'tools/ghidra-arcompact/ghidra_12.2_DEV/support/analyzeHeadless'),str(temp),'directory','-import',str(temp/'p0.bin'),'-loader','BinaryLoader','-loader-baseAddr','0xad800','-processor','ARCompact:LE:32:loopfix','-noanalysis','-scriptPath',str(scripts),'-postScript','ProbeDumpSDDirectory.java',str(out/'trace.txt'),str(temp/'p1.bin'),'-deleteProject']
        (out/'command.json').write_text(json.dumps(cmd,indent=2)+'\n')
        r=subprocess.run(cmd,stdout=subprocess.PIPE,stderr=subprocess.STDOUT,text=True,timeout=180);(out/'headless.log').write_text(r.stdout)
        assert r.returncode==0 and 'SCRIPT ERROR'not in r.stdout,r.stdout[-4000:]
        trace=(out/'trace.txt').read_text();assert trace.endswith('COMPLETE cases=20\n')and trace.count('PASS ')==20
    sys.path.insert(0,str(ROOT/'S33-sections/analysis_codex'))
    from static_common import disasm, u32
    spans=[(0x2a3360,0x2a358c),(0x29ff74,0x2a005c),(0x2a0484,0x2a04b0),(0x2a47c4,0x2a47e8),(0x2a461c,0x2a4694),(0x259a58,0x259afc),(0x2a318c,0x2a3244),(0x2a3250,0x2a3360),(0x2a0444,0x2a0468)]
    listing=''.join(disasm(a,b)for a,b in spans);(out/'gnu_verified.txt').write_text(listing)
    checks={0x2a33aa:';0x29ffb0',0x2a344e:';0x2a318c',0x2a353a:';0x2a2d88',0x2a354c:'st\tr1,[r17]',0x259aa0:';0x2e4ec4',0x2a3268:';0x2a2d88',0x2a3272:';0x2a3316',0x2a3298:'and.f\tr0,r0,r4'}
    for a,s in checks.items():
        lines=[line for line in listing.splitlines()if re.match(rf'\s*{a:x}:',line)];assert len(lines)==1 and s in lines[0],(hex(a),s,lines)
    assert [u32(a)for a in [0x2a3710,0x2a3718,0x2a371c,0x2a3720]]==[0x1a00006,0x1a00003,0x1a00002,0x1a00013]
    assert all(sha((ROOT/p).read_bytes())==h for p,h in inputs.items())
    result=dict(status='PASS_ORIGINAL_LOOKUP_AND_DIRECTORY_WALKER',cpu_cases=20,gnu_windows=len(spans),instruction_checks=len(checks),sources=inputs,payload_hashes={str(b['index']):b['sha256']for b in blocks},
        original_bodies=['2A3360 lookup coordinator with original2A318C directory walker','29FFB0/29FF74 path split','2A47C4/2A461C validation and string primitives','259A58 allocation wrapper with original critical counter','2A0484 comparison and numeric cache branch'],
        fixtures=['Heap2E4EC4 supplies exact guarded allocations filled0/A5 or null; allocator metadata2599AC recorder','Free25980C records owned buffers and checks guards','Directory record lookup2A2D88 supplies DIR/sub entries with explicit32-bit cluster fields or null/error','Final record lookup2A2D88 dataset matches only AKERUDMP.ON/FILE.BIN/DIR; supplies explicit status/metadata','Context prepared backend1 and search flag1/0; no full open callback/scheduler'],
        conclusions=['Original coordinator, parser and directory walker execute; lower record finding isolated', 'Directory null record and explicit01A00021 both collapse to sentinel1 then coordinator01A00003', 'Walker256-byte allocation failure also becomes01A00003, while earlier outer allocation failures remain01A00006', 'Backend1 directory cluster fields0x12345/0x23456 become0x2345/0x3456 after original16-bit mask; root0 and relative base0x123 preserved','Scratch buffers released exactly once with guards intact in completed cases','Missing final entry with lower status0 produces01A00002; directory sentinel1 produces01A00003','Outer scratch failures produce01A00006; null path produces01A00013','Search component state context+764 cleared on tested completed exits', 'Parser internal257-byte allocation failure is not propagated by2A3360; under zero-filled scratch it proceeds to empty leaf and becomes01A00002', 'Trailing separator DIR is normalized to final DIR; root and relative bases differ0/context+74', 'Root path final-call branch depends on explicit0/A5 scratch fill; no global heap initialization inferred'],
        limits=['Record finder2A2D88 remains fixture for both directory and final record; no sector/FAT reads, backend12 or DCIM optimization coverage','Explicit0/A5 heap profiles, not measured Nikon heap contents','No integration of this coordinator yet with prior r callback proof','No installable RAM dumper or full physical RAM map'])
    (out/'verified_evidence.json').write_text(json.dumps(result,indent=2)+'\n');(out.parent/'latest.json').write_text(json.dumps({'evidence':str((out/'verified_evidence.json').relative_to(ROOT))},indent=2)+'\n');print(trace,end='');print(out)


if __name__=='__main__':main()
