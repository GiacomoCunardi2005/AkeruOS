#!/usr/bin/env python3
"""Original CPU SD data reader with MMIO status/data samples; no physical device."""
from datetime import datetime, timezone
from pathlib import Path
import json, re, subprocess, sys, tempfile
from s33_trace_state_dispatch import verified_payloads, sha
ROOT=Path(__file__).resolve().parents[1]


def main():
    blocks,payloads,_=verified_payloads(ROOT)
    out=ROOT/'Risultati/Runtime_Kernel/RAM_Dumper_SD_Read_PIO'/datetime.now(timezone.utc).strftime('%Y%m%dT%H%M%SZ');out.mkdir(parents=True,exist_ok=False)
    scripts=ROOT/'S33-sections/analysis_ghidra/scripts'
    sources=[Path(__file__)]+[scripts/n for n in ['ProbeDumpSDReadPIO.java','ProbeDumpSDMutex.java','ProbeStatusRead.java']]
    inputs={str(p.relative_to(ROOT)):sha(p.read_bytes())for p in sources}
    for p in sources:(out/(p.name+'.snapshot')).write_bytes(p.read_bytes())
    with tempfile.TemporaryDirectory(prefix='s33-sd-tree-')as td:
        temp=Path(td)
        for i in (0,1):(temp/f'p{i}.bin').write_bytes(payloads[i])
        cmd=[str(ROOT/'tools/ghidra-arcompact/ghidra_12.2_DEV/support/analyzeHeadless'),str(temp),'tree','-import',str(temp/'p0.bin'),'-loader','BinaryLoader','-loader-baseAddr','0xad800','-processor','ARCompact:LE:32:loopfix','-noanalysis','-scriptPath',str(scripts),'-postScript','ProbeDumpSDReadPIO.java',str(out/'trace.txt'),str(temp/'p1.bin'),'-deleteProject']
        (out/'command.json').write_text(json.dumps(cmd,indent=2)+'\n')
        r=subprocess.run(cmd,stdout=subprocess.PIPE,stderr=subprocess.STDOUT,text=True,timeout=180);(out/'headless.log').write_text(r.stdout)
        assert r.returncode==0 and 'SCRIPT ERROR'not in r.stdout,r.stdout[-4000:]
        trace=(out/'trace.txt').read_text();assert trace.endswith('COMPLETE cases=20\n')and trace.count('PASS ')==20
    sys.path.insert(0,str(ROOT/'S33-sections/analysis_codex'))
    from static_common import disasm, u32
    spans=[(0x25a690,0x25a74c),(0x25a74c,0x25a83c),(0x25a084,0x25a098),(0x25a0bc,0x25a0d0),(0x25a41c,0x25a430)]
    listing=''.join(disasm(a,b)for a,b in spans);(out/'gnu_verified.txt').write_text(listing)
    checks={0x25a426:'ldh.di',0x25a7ba:'sth.ab',0x25a6ee:'stb_s',0x25a6f2:'stb_s',0x25a7b4:';0x25a41c',0x25a820:'btst_s\tr0,0x7',0x25a76c:';0x2e500c'}
    for a,token in checks.items():
        lines=[line for line in listing.splitlines()if re.match(rf'\s*{a:x}:',line)];assert len(lines)==1 and token in lines[0],(hex(a),token,lines)
    assert [u32(a)for a in [0x25a9a8,0x25a9ac,0x25a9b0,0x25a9b4,0x25a9b8]]==[0xe01510,0xe01610,0xe01611,0x1b2920,0xe01410]
    assert all(sha((ROOT/p).read_bytes())==h for p,h in inputs.items())
    result=dict(status='PASS_ORIGINAL_SD_CPU_READER_MMIO_SAMPLE_PROFILE',cpu_cases=20,returned_cases=18,bounded_wait_observations=2,gnu_windows=len(spans),instruction_checks=len(checks),sources=inputs,payload_hashes={str(b['index']):b['sha256']for b in blocks},
        original_bodies=['25A74C halfword CPU read and25A690 odd-destination byte copy','25A084/25A0BC/25A41C actual halfword MMIO loads','Original buffer stores and status/poll/error branches'],
        fixtures=['Uninitialized MMIO page0FF01000;host supplies halfword samples immediately before original loads','Status profile ready/batch/wait/error;data stream deterministic0x4100+n*73;selector0/800','Delay2E500C records argument10 and returns0;no time simulation','Bounded waits deliberately stopped at32status0 or64status1 read entries'],
        conclusions=['Exact destination bytes verified for half/odd alignment,one/two blocks,512x2 and selectors0/800','Initial errorsE01510/E01610 and bit0 priority;mid-data errorE01611 after exactly2halfwords','Data copied before final bit7 polling;bounded final wait has full fixture buffer but no normal return','Zero/odd block-size contract exercised explicitly;not normal physical geometry'],
        limits=['Synthetic MMIO states/data,not measured FIFO/interrupt/cache behavior','Final timeout1B2920 verified statically,not exhausted dynamically','Two bounded cases do not prove normal return or cleanup;no complete SD command transaction yet','No physical hardware,full RAM map or installable dumper'])
    (out/'verified_evidence.json').write_text(json.dumps(result,indent=2)+'\n');(out.parent/'latest.json').write_text(json.dumps({'evidence':str((out/'verified_evidence.json').relative_to(ROOT))},indent=2)+'\n');print(trace,end='');print(out)


if __name__=='__main__':main()
