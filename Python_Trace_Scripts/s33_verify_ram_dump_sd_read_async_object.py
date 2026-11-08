#!/usr/bin/env python3
"""Original SD asynchronous reader plus receive-object acquisition and release."""
from datetime import datetime, timezone
from pathlib import Path
import json, re, subprocess, sys, tempfile
from s33_trace_state_dispatch import verified_payloads, sha
ROOT=Path(__file__).resolve().parents[1]


def main():
    blocks,payloads,_=verified_payloads(ROOT)
    out=ROOT/'Risultati/Runtime_Kernel/RAM_Dumper_SD_Read_Async_Object'/datetime.now(timezone.utc).strftime('%Y%m%dT%H%M%SZ');out.mkdir(parents=True,exist_ok=False)
    scripts=ROOT/'S33-sections/analysis_ghidra/scripts'
    sources=[Path(__file__)]+[scripts/n for n in ['ProbeDumpSDReadAsyncObject.java','ProbeDumpSDReadAsync.java','ProbeDumpSDMutex.java','ProbeStatusRead.java']]
    inputs={str(p.relative_to(ROOT)):sha(p.read_bytes())for p in sources}
    for p in sources:(out/(p.name+'.snapshot')).write_bytes(p.read_bytes())
    with tempfile.TemporaryDirectory(prefix='s33-sd-tree-')as td:
        temp=Path(td)
        for i in (0,1):(temp/f'p{i}.bin').write_bytes(payloads[i])
        cmd=[str(ROOT/'tools/ghidra-arcompact/ghidra_12.2_DEV/support/analyzeHeadless'),str(temp),'tree','-import',str(temp/'p0.bin'),'-loader','BinaryLoader','-loader-baseAddr','0xad800','-processor','ARCompact:LE:32:loopfix','-noanalysis','-scriptPath',str(scripts),'-postScript','ProbeDumpSDReadAsyncObject.java',str(out/'trace.txt'),str(temp/'p1.bin'),'-deleteProject']
        (out/'command.json').write_text(json.dumps(cmd,indent=2)+'\n')
        r=subprocess.run(cmd,stdout=subprocess.PIPE,stderr=subprocess.STDOUT,text=True,timeout=180);(out/'headless.log').write_text(r.stdout)
        assert r.returncode==0 and 'SCRIPT ERROR'not in r.stdout,r.stdout[-4000:]
        trace=(out/'trace.txt').read_text();assert trace.endswith('COMPLETE cases=21\n')and trace.count('PASS ')==21
    sys.path.insert(0,str(ROOT/'S33-sections/analysis_codex'))
    from static_common import disasm, u32
    spans=[(2467900, 2468244), (2468308, 2468436), (2466884, 2466964), (2626232, 2626236), (3359400, 3359436), (2621936, 2622092), (2620628, 2620682), (2620724, 2620740), (2620744, 2620776), (2620776, 2620796), (2620804, 2620820), (2620824, 2620868), (2620876, 2620900), (2620900, 2620940), (2621362, 2621392), (2621400, 2621462), (2621476, 2621554), (2621572, 2621604), (2621616, 2621648), (2621660, 2621678), (2621192, 2621208), (2621212, 2621248), (2621256, 2621272), (2621276, 2621312), (2621320, 2621336), (2621340, 2621362), (2621784, 2621796), (2621926, 2621936), (2625880, 2625916), (2625924, 2625944), (2625948, 2625972), (2625976, 2625996), (2626000, 2626036), (2626048, 2626068), (2626072, 2626088), (2626092, 2626124), (2626136, 2626156), (2626160, 2626184), (2626188, 2626232), (2625508, 2625544), (2625566, 2625608), (2625612, 2625636), (2625636, 2625692), (2625704, 2625742), (2625742, 2625760), (2625772, 2625824), (2625836, 2625880)]
    listing=''.join(disasm(a,b)for a,b in spans);(out/'gnu_verified.txt').write_text(listing)
    checks={0x25a888:';0x2801f0',0x25a8b4:';0x266768',0x25a8cc:';0x26671c',0x25a8e6:';0x158ce0',0x25a8fe:';0x28080c',0x25a924:';0x158d04',0x25a930:';0x266e9c',0x25a944:'cmp_s\tr14,0x1e',0x25a948:';0x281158',0x25aa10:';0x2812b8',0x25aa44:';0x2667b0',0x25a45c:'sth.di',0x25a47e:'sth.di',0x2812b8:';0x281158'}
    checks.update({0x280264:';0x27fcd4',0x280280:'st\tr2,[r16]',0x2812a8:';0x281064',0x2812b4:'st_s\tr1,[r15,0]',0x281092:'st_s\tr13,[r0,0x4]'})
    for a,token in checks.items():
        lines=[line for line in listing.splitlines()if re.match(rf'\s*{a:x}:',line)];assert len(lines)==1 and token in lines[0],(hex(a),token,lines)
    assert [u32(a)for a in [0x25a9bc,0x25a9c0,0x25a9c4,0x25a9c8,0x25a9cc,0x25a9d0,0x25ab44,0x25ab48]]==[0x25ad3c,0x25ad78,0xe00005,0x25adbc,0x25adc4,0xe01520,0xe00005,0xe01620]
    assert [u32(a)for a in [0x27fd2c,0x28039c]]==[0x512cc8,0xf4240]
    assert all(sha((ROOT/p).read_bytes())==h for p,h in inputs.items())
    result=dict(status='PASS_ORIGINAL_SD_ASYNC_CALLER_AND_RECEIVE_OBJECT_LIFETIME',cpu_cases=21,returned_cases=20,bounded_progress_observations=1,gnu_windows=len(spans),instruction_checks=len(checks),sources=inputs,payload_hashes={str(b['index']):b['sha256']for b in blocks},
        original_bodies=['25A83C aligned asynchronous reader and25A444/25A464 controller mask helpers','2801F0/27FCD4 actual object acquire/select and281158/281064 release via2812B8 alias','1786E8/179354 nested critical counters and original receive-object controller MMIO stores'],
        fixtures=['Prepared first fixed object512CC8 selected by1594E4 query returning available1 and ready MMIO bit0=1;post1594A4/stop267BAC outcomes supplied','28080C start and266E9C progress remain fixtures; no actual asynchronous data transfer','266768/26671C registration/enable and2667B0 unregister recorders;158CE0/158D04/158E28 event clear/wait/query outcomes supplied','3342A8 modulo32 product replaces unsupported MULUDW; destination1024bytes remain31 withA5guards'],
        conclusions=['Real acquire publishes object512CC8 withF4240,id202/203,total1024,step1024 before upper callback-registration stages','Early register/enable/clear errors leave that real object+4 active and caller stack handle published,with controller mask2010still cleared; actual concurrent ownership not proved','Real release clears object+4 and stack handle even on injected semaphore-post error; finish error still causes two unregister calls','Start error remains primary over release-post error even though release consumes real object; unregister error after successful finish remains ignored','Thirty stagnant checks,progress reset at11 allowing41waits and63progress observations before bounded stop reproduced with actual object lifetime','No normal-cleanup claim for bounded progress; object selector remains nonzero and no release was invoked'],
        limits=['Underlying semaphore/stop outcomes are supplied,not a real resource arbitration or physical stop proof','Start/progress/callback registration and all event API outcomes remain fixtures; no buffer contents transferred','No asynchronous path integrated into filesystem chain,actual DMA/cache/interrupt scheduling or physical persistence','No RAM dumper binding or new BIN'])
    (out/'verified_evidence.json').write_text(json.dumps(result,indent=2)+'\n');(out.parent/'latest.json').write_text(json.dumps({'evidence':str((out/'verified_evidence.json').relative_to(ROOT))},indent=2)+'\n');print(trace,end='');print(out)


if __name__=='__main__':main()
