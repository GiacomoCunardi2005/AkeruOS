#!/usr/bin/env python3
"""Original sector reader and pending-write consumer; synthetic lower transfer only."""
from datetime import datetime, timezone
from pathlib import Path
import json, re, subprocess, sys, tempfile
from s33_trace_state_dispatch import verified_payloads, sha
ROOT=Path(__file__).resolve().parents[1]


def main():
    blocks,payloads,_=verified_payloads(ROOT)
    out=ROOT/'Risultati/Runtime_Kernel/RAM_Dumper_SD_Sector_Reader'/datetime.now(timezone.utc).strftime('%Y%m%dT%H%M%SZ');out.mkdir(parents=True,exist_ok=False)
    scripts=ROOT/'S33-sections/analysis_ghidra/scripts'
    sources=[Path(__file__)]+[scripts/n for n in ['ProbeDumpSDSectorReader.java','ProbeDumpSDMutex.java','ProbeStatusRead.java']]
    inputs={str(p.relative_to(ROOT)):sha(p.read_bytes())for p in sources}
    for p in sources:(out/(p.name+'.snapshot')).write_bytes(p.read_bytes())
    with tempfile.TemporaryDirectory(prefix='s33-sd-tree-')as td:
        temp=Path(td)
        for i in (0,1):(temp/f'p{i}.bin').write_bytes(payloads[i])
        cmd=[str(ROOT/'tools/ghidra-arcompact/ghidra_12.2_DEV/support/analyzeHeadless'),str(temp),'tree','-import',str(temp/'p0.bin'),'-loader','BinaryLoader','-loader-baseAddr','0xad800','-processor','ARCompact:LE:32:loopfix','-noanalysis','-scriptPath',str(scripts),'-postScript','ProbeDumpSDSectorReader.java',str(out/'trace.txt'),str(temp/'p1.bin'),'-deleteProject']
        (out/'command.json').write_text(json.dumps(cmd,indent=2)+'\n')
        r=subprocess.run(cmd,stdout=subprocess.PIPE,stderr=subprocess.STDOUT,text=True,timeout=180);(out/'headless.log').write_text(r.stdout)
        assert r.returncode==0 and 'SCRIPT ERROR'not in r.stdout,r.stdout[-4000:]
        trace=(out/'trace.txt').read_text();assert trace.endswith('COMPLETE cases=28\n')and trace.count('PASS ')==28
    sys.path.insert(0,str(ROOT/'S33-sections/analysis_codex'))
    from static_common import disasm, u32
    spans=[(0x2a10f4,0x2a1124),(0x2a113c,0x2a1178),(0x2a1178,0x2a1270),(0x225618,0x225622),(0x3342a8,0x3342cc)]
    listing=''.join(disasm(a,b)for a,b in spans);(out/'gnu_verified.txt').write_text(listing)
    checks={0x2a1114:';0x2a0c60',0x2a111e:'st.as',0x2a1152:';0x225618',0x2a116c:';0x225618',0x2a119c:';0x3342a8',0x2a11ae:';0x2a10f4',0x2a11b6:'st_s',0x2a11ec:'mov_s\tr0,r7',0x2a121e:';0x2a10f4',0x2a1264:'st.as'}
    for a,token in checks.items():
        lines=[line for line in listing.splitlines()if re.match(rf'\s*{a:x}:',line)];assert len(lines)==1 and token in lines[0],(hex(a),token,lines)
    assert u32(0x2a112c)==0x1a0000d
    assert all(sha((ROOT/p).read_bytes())==h for p,h in inputs.items())
    result=dict(status='PASS_ORIGINAL_SECTOR_READER_AND_PENDING_WRITE_CONSUMER',cpu_cases=28,gnu_windows=len(spans),instruction_checks=len(checks),sources=inputs,payload_hashes={str(b['index']):b['sha256']for b in blocks},
        original_bodies=['2A1178 sector reader address arithmetic around declared multiply boundary','2A10F4 pending-write consumer','225618 and original memory copy'],
        fixtures=['3342A8 multiply helper replaced by modulo32 product because MULUDW is unsupported in P-code; DSP hardware semantics not established','Prepared context: root start100, data start104, sectors per cluster4, sector size512; explicit upper bound per case','2A0C60 lower transfer recorder: verifies selector/LBA/count/buffer, fills read buffers or returns injected error; no hardware'],
        conclusions=['Root must remain below data start; non-root uses (cluster-2)*sectorsPerCluster+dataStart+index; upper start bound inclusive','Cache hit may return pending data without flushing; control1 forces reload','Write failure retains pending flag but matching mirror buffers are still copied','Invalid address invokes flush then overwrites its error with01A0000D','Bulk path checks starting address locally, passes count through, bypasses cache and pending flush','Invalid mode3 preserves status and returns supplied r7; no claim about valid runtime callers'],
        limits=['Lower transfer and driver not executed; no physical read/write or persistence claim','Non-root address formula conditional on multiply model; synthetic geometry and isolated caller; lookup integration still separate','No RAM map, exclusive file creation or installable dumper'])
    (out/'verified_evidence.json').write_text(json.dumps(result,indent=2)+'\n');(out.parent/'latest.json').write_text(json.dumps({'evidence':str((out/'verified_evidence.json').relative_to(ROOT))},indent=2)+'\n');print(trace,end='');print(out)


if __name__=='__main__':main()
