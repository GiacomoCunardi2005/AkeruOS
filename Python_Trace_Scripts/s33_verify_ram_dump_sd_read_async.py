#!/usr/bin/env python3
"""Original aligned SD asynchronous-reader control flow with lower service/event fixtures."""
from datetime import datetime, timezone
from pathlib import Path
import json, re, subprocess, sys, tempfile
from s33_trace_state_dispatch import verified_payloads, sha
ROOT=Path(__file__).resolve().parents[1]


def main():
    blocks,payloads,_=verified_payloads(ROOT)
    out=ROOT/'Risultati/Runtime_Kernel/RAM_Dumper_SD_Read_Async'/datetime.now(timezone.utc).strftime('%Y%m%dT%H%M%SZ');out.mkdir(parents=True,exist_ok=False)
    scripts=ROOT/'S33-sections/analysis_ghidra/scripts'
    sources=[Path(__file__)]+[scripts/n for n in ['ProbeDumpSDReadAsync.java','ProbeDumpSDMutex.java','ProbeStatusRead.java']]
    inputs={str(p.relative_to(ROOT)):sha(p.read_bytes())for p in sources}
    for p in sources:(out/(p.name+'.snapshot')).write_bytes(p.read_bytes())
    with tempfile.TemporaryDirectory(prefix='s33-sd-tree-')as td:
        temp=Path(td)
        for i in (0,1):(temp/f'p{i}.bin').write_bytes(payloads[i])
        cmd=[str(ROOT/'tools/ghidra-arcompact/ghidra_12.2_DEV/support/analyzeHeadless'),str(temp),'tree','-import',str(temp/'p0.bin'),'-loader','BinaryLoader','-loader-baseAddr','0xad800','-processor','ARCompact:LE:32:loopfix','-noanalysis','-scriptPath',str(scripts),'-postScript','ProbeDumpSDReadAsync.java',str(out/'trace.txt'),str(temp/'p1.bin'),'-deleteProject']
        (out/'command.json').write_text(json.dumps(cmd,indent=2)+'\n')
        r=subprocess.run(cmd,stdout=subprocess.PIPE,stderr=subprocess.STDOUT,text=True,timeout=180);(out/'headless.log').write_text(r.stdout)
        assert r.returncode==0 and 'SCRIPT ERROR'not in r.stdout,r.stdout[-4000:]
        trace=(out/'trace.txt').read_text();assert trace.endswith('COMPLETE cases=21\n')and trace.count('PASS ')==21
    sys.path.insert(0,str(ROOT/'S33-sections/analysis_codex'))
    from static_common import disasm, u32
    spans=[(0x25a83c,0x25a994),(0x25a9d4,0x25aa54),(0x25a444,0x25a494),(0x2812b8,0x2812bc),(0x3342a8,0x3342cc)]
    listing=''.join(disasm(a,b)for a,b in spans);(out/'gnu_verified.txt').write_text(listing)
    checks={0x25a888:';0x2801f0',0x25a8b4:';0x266768',0x25a8cc:';0x26671c',0x25a8e6:';0x158ce0',0x25a8fe:';0x28080c',0x25a924:';0x158d04',0x25a930:';0x266e9c',0x25a944:'cmp_s\tr14,0x1e',0x25a948:';0x281158',0x25aa10:';0x2812b8',0x25aa44:';0x2667b0',0x25a45c:'sth.di',0x25a47e:'sth.di',0x2812b8:';0x281158'}
    for a,token in checks.items():
        lines=[line for line in listing.splitlines()if re.match(rf'\s*{a:x}:',line)];assert len(lines)==1 and token in lines[0],(hex(a),token,lines)
    assert [u32(a)for a in [0x25a9bc,0x25a9c0,0x25a9c4,0x25a9c8,0x25a9cc,0x25a9d0,0x25ab44,0x25ab48]]==[0x25ad3c,0x25ad78,0xe00005,0x25adbc,0x25adc4,0xe01520,0xe00005,0xe01620]
    assert all(sha((ROOT/p).read_bytes())==h for p,h in inputs.items())
    result=dict(status='PASS_ORIGINAL_SD_READ_ASYNC_CALLER_SERVICE_EVENT_FIXTURES',cpu_cases=21,returned_cases=20,bounded_progress_observations=1,gnu_windows=len(spans),instruction_checks=len(checks),sources=inputs,payload_hashes={str(b['index']):b['sha256']for b in blocks},
        original_bodies=['25A83C aligned asynchronous-read caller and original branches/error cleanup','25A444/25A464 MMIO mask RMW and25A488 port-address getter','2812B8 branch alias reaches281158 boundary; release body replaced'],
        fixtures=['2801F0 acquire publishes synthetic transfer handle;28080C start and266E9C progress supplied;281158 release result/cell consumption supplied','266768/26671C registration/enable and2667B0 unregister recorders;158CE0/158D04/158E28 event clear/wait/query outcomes supplied','3342A8 modulo32 product replaces unsupported MULUDW; no transfer occurs and exact1024-byte buffer remains31 in every scenario','Prepared selectors0/800,MMIO maskFFFF,stack and handle cells; no RTOS scheduling,actual object acquisition or physical MMIO'],
        conclusions=['Early registration/enable/event-clear errors return after acquisition without release or common mask restore in this caller; lower service ownership is not established','Original caller counts30 consecutive unchanged progress observations; a change after10 stagnant checks permits41total waits before its later30-stagnant exit','Continuing progress observed through63queries; deliberate stop at64th wait entry,without normal return or cleanup','Selector-specific service IDs1002/1004,callbacks,event masks1C0/1C0000 and original MMIO mask clear/restore asserted','Event bits7/19 chooseE01520,bits8/20 chooseE01620; first error priority and zero-mask query after injected successful wait verified conditionally','Start error survives failed release; normal finish release error propagates and unregister is called twice; unregister error after successful finish is not propagated','All successful fixture-completion results leave destination untouched: caller control flow only,not a real data transfer proof'],
        limits=['API fixtures may supply combinations not reachable under real event/service contracts; empty successful event query is not evidence of a real race','Acquired handle retention after early errors is only caller-boundary evidence,not a diagnosed hardware leak','Actual2801F0/28080C/281158,callback invocation,RTOS/DMA/cache and buffer ownership remain unverified','No integration into filesystem chain or RAM dumper and no new BIN'])
    (out/'verified_evidence.json').write_text(json.dumps(result,indent=2)+'\n');(out.parent/'latest.json').write_text(json.dumps({'evidence':str((out/'verified_evidence.json').relative_to(ROOT))},indent=2)+'\n');print(trace,end='');print(out)


if __name__=='__main__':main()
