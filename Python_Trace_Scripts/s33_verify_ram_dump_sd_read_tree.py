#!/usr/bin/env python3
"""Original r/open, lookup stack and close on shared synthetic sectors; offline only."""
from datetime import datetime, timezone
from pathlib import Path
import json, re, subprocess, sys, tempfile
from s33_trace_state_dispatch import verified_payloads, sha
ROOT=Path(__file__).resolve().parents[1]


def main():
    blocks,payloads,_=verified_payloads(ROOT)
    out=ROOT/'Risultati/Runtime_Kernel/RAM_Dumper_SD_Read_Tree'/datetime.now(timezone.utc).strftime('%Y%m%dT%H%M%SZ');out.mkdir(parents=True,exist_ok=False)
    scripts=ROOT/'S33-sections/analysis_ghidra/scripts'
    sources=[Path(__file__)]+[scripts/n for n in ['ProbeDumpSDReadTree.java','ProbeDumpSDLookupTree.java','ProbeDumpSDLookup.java','ProbeDumpSDMutex.java','ProbeStatusRead.java']]
    inputs={str(p.relative_to(ROOT)):sha(p.read_bytes())for p in sources}
    for p in sources:(out/(p.name+'.snapshot')).write_bytes(p.read_bytes())
    with tempfile.TemporaryDirectory(prefix='s33-sd-read-tree-')as td:
        temp=Path(td)
        for i in (0,1):(temp/f'p{i}.bin').write_bytes(payloads[i])
        cmd=[str(ROOT/'tools/ghidra-arcompact/ghidra_12.2_DEV/support/analyzeHeadless'),str(temp),'read-tree','-import',str(temp/'p0.bin'),'-loader','BinaryLoader','-loader-baseAddr','0xad800','-processor','ARCompact:LE:32:loopfix','-noanalysis','-scriptPath',str(scripts),'-postScript','ProbeDumpSDReadTree.java',str(out/'trace.txt'),str(temp/'p1.bin'),'-deleteProject']
        (out/'command.json').write_text(json.dumps(cmd,indent=2)+'\n')
        r=subprocess.run(cmd,stdout=subprocess.PIPE,stderr=subprocess.STDOUT,text=True,timeout=180);(out/'headless.log').write_text(r.stdout)
        assert r.returncode==0 and 'SCRIPT ERROR'not in r.stdout,r.stdout[-4000:]
        trace=(out/'trace.txt').read_text();assert trace.endswith('COMPLETE cases=7\n')and trace.count('PASS ')==7
    sys.path.insert(0,str(ROOT/'S33-sections/analysis_codex'))
    from static_common import disasm, u32
    spans=[(0x2a3360,0x2a358c),(0x29ff74,0x2a005c),(0x2a0484,0x2a04b0),(0x2a47c4,0x2a47e8),(0x2a461c,0x2a4694),(0x259a58,0x259afc),(0x2a318c,0x2a3244),(0x2a3250,0x2a3360),(0x2a0444,0x2a0468),(0x2a2d88,0x2a318c),(0x2a017c,0x2a01ac),(0x2a01ac,0x2a0268),(0x2a0144,0x2a017c),(0x21a0d0,0x21a190),(0x1f43ac,0x1f43f0),(0x1f4586,0x1f45a4),(0x1f48a4,0x1f48e8),(0x231158,0x231198)]
    listing=''.join(disasm(a,b)for a,b in spans);(out/'gnu_verified.txt').write_text(listing)
    checks={0x2a33aa:';0x29ffb0',0x2a344e:';0x2a318c',0x2a353a:';0x2a2d88',0x2a354c:'st\tr1,[r17]',0x259aa0:';0x2e4ec4',0x2a3268:';0x2a2d88',0x2a3272:';0x2a3316',0x2a3298:'and.f\tr0,r0,r4'}
    for a,s in checks.items():
        lines=[line for line in listing.splitlines()if re.match(rf'\s*{a:x}:',line)];assert len(lines)==1 and s in lines[0],(hex(a),s,lines)
    assert [u32(a)for a in [0x2a3710,0x2a3718,0x2a371c,0x2a3720]]==[0x1a00006,0x1a00003,0x1a00002,0x1a00013]
    assert all(sha((ROOT/p).read_bytes())==h for p,h in inputs.items())
    result=dict(status='PASS_ORIGINAL_READ_OPEN_LOOKUP_AND_CLOSE_SHARED_TREE',cpu_cases=7,gnu_windows=len(spans),instruction_checks=len(checks),sources=inputs,payload_hashes={str(b['index']):b['sha256']for b in blocks},
        original_bodies=['2A3360 coordinator','29FFB0/29FF74 parser','2A318C directory walker','2A2D88 record scanner, short-name parser/comparator and attribute filter','259A58 allocation wrapper with original critical counter','1F43AC r callback ->21A0D0 and file-object list','1F48A4 file/volume close','2AC528/2AC564 file-object add/remove','231158 original task error storage'],
        fixtures=['2E4EC4 supplies guarded scratch0 or null; one paired null case supplies error-out01A00006, others0; metadata/free are recorders','2A1178 supplies shared root/DIR/sub synthetic sectors, current directory0x123 aliases root','21B2CC/21A454 disable external cached objects;2A29B4 returns cache miss','2ABC68 terminates advancement on injected read errors; no FAT chain followed','Prepared mounted backend1 context, generic wrapper and list/semaphore;2F7ABC supplies zeroed80-byte object,2F7AF0 records release', 'Close clock/cache dirty path disabled and volume ioctl3 succeeds; no generic upper wrapper or scheduler'],
        conclusions=['Read callback/coordinator/walker/finder and file/volume closes execute against same sector tree', 'Read success registers object, blocks volume close, then file close removes object and permits volume close', 'Parser257-byte allocation failure under zero scratch returns a free zero entry as success and r callback registers it; no create call executes', 'Same false-success occurs when null allocation also supplies error01A00006: original231158 stores task+38 error, while r returns0','Root and nested read results checked through object metadata, copied record and sector routes','Leaf miss01A00002, directory failure01A00003 and leaf read error01A00021 asserted; directory I/O also becomes01A00003','Parser allocation257 failure under scratch0 returns zero directory entry with status0; independent exact-name final fixture previously hid this outcome','All acquired scratch released once; sectors and input path preserved'],
        limits=['Synthetic sectors and cache misses only; no real SD/FAT/cache, multi-sector chain or DCIM/long-name coverage','No physical exclusive creation or full cache/dirty/close I/O coverage','No installable dumper or full physical RAM map'])
    (out/'verified_evidence.json').write_text(json.dumps(result,indent=2)+'\n');(out.parent/'latest.json').write_text(json.dumps({'evidence':str((out/'verified_evidence.json').relative_to(ROOT))},indent=2)+'\n');print(trace,end='');print(out)


if __name__=='__main__':main()
