#!/usr/bin/env python3
"""Original filesystem transfer through PMSD/DEVSD and SD retry adapters, engine status fixtures."""
from datetime import datetime, timezone
from pathlib import Path
import json, re, subprocess, sys, tempfile
from s33_trace_state_dispatch import verified_payloads, sha
ROOT=Path(__file__).resolve().parents[1]


def main():
    blocks,payloads,_=verified_payloads(ROOT)
    out=ROOT/'Risultati/Runtime_Kernel/RAM_Dumper_SD_Partition'/datetime.now(timezone.utc).strftime('%Y%m%dT%H%M%SZ');out.mkdir(parents=True,exist_ok=False)
    scripts=ROOT/'S33-sections/analysis_ghidra/scripts'
    sources=[Path(__file__)]+[scripts/n for n in ['ProbeDumpSDPartition.java','ProbeDumpSDMutex.java','ProbeStatusRead.java']]
    inputs={str(p.relative_to(ROOT)):sha(p.read_bytes())for p in sources}
    for p in sources:(out/(p.name+'.snapshot')).write_bytes(p.read_bytes())
    with tempfile.TemporaryDirectory(prefix='s33-sd-tree-')as td:
        temp=Path(td)
        for i in (0,1):(temp/f'p{i}.bin').write_bytes(payloads[i])
        cmd=[str(ROOT/'tools/ghidra-arcompact/ghidra_12.2_DEV/support/analyzeHeadless'),str(temp),'tree','-import',str(temp/'p0.bin'),'-loader','BinaryLoader','-loader-baseAddr','0xad800','-processor','ARCompact:LE:32:loopfix','-noanalysis','-scriptPath',str(scripts),'-postScript','ProbeDumpSDPartition.java',str(out/'trace.txt'),str(temp/'p1.bin'),'-deleteProject']
        (out/'command.json').write_text(json.dumps(cmd,indent=2)+'\n')
        r=subprocess.run(cmd,stdout=subprocess.PIPE,stderr=subprocess.STDOUT,text=True,timeout=180);(out/'headless.log').write_text(r.stdout)
        assert r.returncode==0 and 'SCRIPT ERROR'not in r.stdout,r.stdout[-4000:]
        trace=(out/'trace.txt').read_text();assert trace.endswith('COMPLETE cases=22\n')and trace.count('PASS ')==22
    sys.path.insert(0,str(ROOT/'S33-sections/analysis_codex'))
    from static_common import disasm, u32
    spans=[(0x2a0c60,0x2a0d50),(0x2a0d56,0x2a0d70),(0x2a0c14,0x2a0c60),(0x1f3524,0x1f3554),(0x1fa090,0x1fa0c0),(0x226204,0x22624c),(0x2a0870,0x2a08b0),(0x2a0504,0x2a05f4),(0x1681d0,0x16827c),(0x168410,0x1684d4),(0x2a0a14,0x2a0a46),(0x2a0a52,0x2a0a86),(0x2a0b16,0x2a0b24),(0x2a0ab0,0x2a0ab6),(0x2a0af2,0x2a0afa)]
    listing=''.join(disasm(a,b)for a,b in spans);(out/'gnu_verified.txt').write_text(listing)
    checks={0x2a087a:';0x1f3524',0x2a089a:';0x1fa090',0x2a05e2:'jl_s.d',0x2a05b8:';0x2a05e6',0x2a05e8:'st_s\tr0,[r14,0xc]',0x168218:';0xb15b4',0x168222:';0xb16d0',0x16845a:';0x25b9c0',0x168464:';0x25bb5c',0x2a0a6a:'st_s\tr1,[r14,0x10]'}
    for a,token in checks.items():
        lines=[line for line in listing.splitlines()if re.match(rf'\s*{a:x}:',line)];assert len(lines)==1 and token in lines[0],(hex(a),token,lines)
    assert [u32(a)for a in [0x37604c,0x376050,0x2a0680,0x1680d0,0x1687b4]]==[0x16825c,0x1684b4,0x376018,0x4463e0,0x4463e0]
    assert all(sha((ROOT/p).read_bytes())==h for p,h in inputs.items())
    result=dict(status='PASS_ORIGINAL_PMSD_DEVSD_TRANSFER_AND_RETRY_ADAPTERS',cpu_cases=22,gnu_windows=len(spans),instruction_checks=len(checks),sources=inputs,payload_hashes={str(b['index']):b['sha256']for b in blocks},
        original_bodies=['2A0C60 transfer,226204 seek and generic1F3524/1FA090 dispatch','2A0870/2A0890 PMSD forwarding/error copy,2A0A14 control7 partition offset','2A0504 volume resolver and2A0594/2A0534 DEVSD all-or-zero result adaptation','16825C/1681D0 SD read and1684B4/168410 SD write retry adapters'],
        fixtures=['Prepared handles/device slots,partition index1/offset2048 and block units;volume row0 raw handle identity supplied','Low engine B15B4/B16D0/25B9C0/25BB5C return chosen status; successful reads fill fixture buffer only','25B63C recovery and25BF3C query are result recorders; no MMIO or physical transfer','Volume flag49 injected0/1/2;runtime producer not established;19cases2015/2016 disabled,3cases prepare original PM semaphore and execute the bracket'],
        conclusions=['Normal raw callback returns whole requested count or0 and writes backend status to file error;PMSD copies error;FS returns status','Position7 translated through original partition control7 to2055','Exact flag49==1 skips read and write engines, reports success and leaves read buffer unchanged;flag2 does not bypass','Read and write retry at most3 times with observed recovery0/1 routing;write recovery fallback and ignored query error executed','Three synchronized cases execute original2015/2016, wait/post, selector update and seek under PM semaphore; restored on data error','FS count0 still positions the raw handle but skips data callbacks'],
        limits=['Engine status0 is assumed completion at declared boundary, not buffer/MMIO/persistence proof','No observed partial-count physical driver response;all-or-zero ABI does not prove lower engine full transfer','Prepared partition state;no mount or runtime producer of bypass flag covered','No hardware or installable dumper'])
    (out/'verified_evidence.json').write_text(json.dumps(result,indent=2)+'\n');(out.parent/'latest.json').write_text(json.dumps({'evidence':str((out/'verified_evidence.json').relative_to(ROOT))},indent=2)+'\n');print(trace,end='');print(out)


if __name__=='__main__':main()
