#!/usr/bin/env python3
"""Original directory record finder over one synthetic sector; offline only."""
from datetime import datetime, timezone
from pathlib import Path
import json, re, subprocess, sys, tempfile
from s33_trace_state_dispatch import verified_payloads, sha
ROOT=Path(__file__).resolve().parents[1]


def main():
    blocks,payloads,_=verified_payloads(ROOT)
    out=ROOT/'Risultati/Runtime_Kernel/RAM_Dumper_SD_Record_Finder'/datetime.now(timezone.utc).strftime('%Y%m%dT%H%M%SZ');out.mkdir(parents=True,exist_ok=False)
    scripts=ROOT/'S33-sections/analysis_ghidra/scripts'
    sources=[Path(__file__)]+[scripts/n for n in ['ProbeDumpSDRecordFinder.java','ProbeDumpSDMutex.java','ProbeStatusRead.java']]
    inputs={str(p.relative_to(ROOT)):sha(p.read_bytes())for p in sources}
    for p in sources:(out/(p.name+'.snapshot')).write_bytes(p.read_bytes())
    with tempfile.TemporaryDirectory(prefix='s33-sd-finder-')as td:
        temp=Path(td)
        for i in (0,1):(temp/f'p{i}.bin').write_bytes(payloads[i])
        cmd=[str(ROOT/'tools/ghidra-arcompact/ghidra_12.2_DEV/support/analyzeHeadless'),str(temp),'finder','-import',str(temp/'p0.bin'),'-loader','BinaryLoader','-loader-baseAddr','0xad800','-processor','ARCompact:LE:32:loopfix','-noanalysis','-scriptPath',str(scripts),'-postScript','ProbeDumpSDRecordFinder.java',str(out/'trace.txt'),str(temp/'p1.bin'),'-deleteProject']
        (out/'command.json').write_text(json.dumps(cmd,indent=2)+'\n')
        r=subprocess.run(cmd,stdout=subprocess.PIPE,stderr=subprocess.STDOUT,text=True,timeout=180);(out/'headless.log').write_text(r.stdout)
        assert r.returncode==0 and 'SCRIPT ERROR'not in r.stdout,r.stdout[-4000:]
        trace=(out/'trace.txt').read_text();assert trace.endswith('COMPLETE cases=8\n')and trace.count('PASS ')==8
    sys.path.insert(0,str(ROOT/'S33-sections/analysis_codex'))
    from static_common import disasm, u32
    spans=[(0x2a2d88,0x2a318c),(0x2a017c,0x2a01ac),(0x2a01ac,0x2a0268),(0x2a0144,0x2a017c)]
    listing=''.join(disasm(a,b)for a,b in spans);(out/'gnu_verified.txt').write_text(listing)
    checks={0x2a2f3e:';0x2a1178',0x2a2fec:';0x2a017c',0x2a3088:';0x2a0144',0x2a311e:'st_s\tr1,[r0,0]'}
    for a,s in checks.items():
        lines=[line for line in listing.splitlines()if re.match(rf'\s*{a:x}:',line)];assert len(lines)==1 and s in lines[0],(hex(a),s,lines)
    assert all(sha((ROOT/p).read_bytes())==h for p,h in inputs.items())
    result=dict(status='PASS_ORIGINAL_RECORD_FINDER_SINGLE_SECTOR',cpu_cases=8,gnu_windows=len(spans),instruction_checks=len(checks),sources=inputs,payload_hashes={str(b['index']):b['sha256']for b in blocks},
        original_bodies=['2A2D88 record scanner','2A01AC short-name parser','2A0144 name comparison','2A017C attribute filter','String/numeric/millicode helpers'],
        fixtures=['2A1178 returns explicit512-byte sector or01A00021','21B2CC/21A454 return0 to disable external cached objects','Root cluster0, entries-per-sector16, one-sector context; no complete lookup/open wrapper'],
        conclusions=['Original scanner finds matching first/later entries, skips deleted and nonmatching records','Lowercase query matches uppercase short entry','Selector16 skips regular DIR entry and selects attribute10 DIR record','Zero end marker stops before later matching data','End-marker missing record returns null without writing caller status: CAFEBABE preserved, or0 when initialized0; sector error preserves01A00021','Synthetic sector unchanged and query restored on tested returns'],
        limits=['Single root sector and short names only; no long-name chain, cluster advancement, real cache or FAT/SD I/O','No combined coordinator/walker/open execution yet','No installable RAM dumper or physical memory map'])
    (out/'verified_evidence.json').write_text(json.dumps(result,indent=2)+'\n');(out.parent/'latest.json').write_text(json.dumps({'evidence':str((out/'verified_evidence.json').relative_to(ROOT))},indent=2)+'\n');print(trace,end='');print(out)


if __name__=='__main__':main()
