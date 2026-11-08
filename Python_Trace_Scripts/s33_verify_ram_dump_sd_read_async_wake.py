#!/usr/bin/env python3
"""Original SD timed-event registration, event/tick wake and resumed read lifecycle at a declared CPU-switch boundary."""
from datetime import datetime, timezone
from pathlib import Path
import json, re, subprocess, sys, tempfile
from s33_trace_state_dispatch import verified_payloads, sha
ROOT=Path(__file__).resolve().parents[1]


def main():
    blocks,payloads,_=verified_payloads(ROOT)
    out=ROOT/'Risultati/Runtime_Kernel/RAM_Dumper_SD_Read_Async_Wake'/datetime.now(timezone.utc).strftime('%Y%m%dT%H%M%SZ');out.mkdir(parents=True,exist_ok=False)
    scripts=ROOT/'S33-sections/analysis_ghidra/scripts'
    sources=[Path(__file__)]+[scripts/n for n in ['ProbeDumpSDReadAsyncWake.java','ProbeDumpSDMutex.java','ProbeStatusRead.java']]
    inputs={str(p.relative_to(ROOT)):sha(p.read_bytes())for p in sources}
    for p in sources:(out/(p.name+'.snapshot')).write_bytes(p.read_bytes())
    with tempfile.TemporaryDirectory(prefix='s33-sd-tree-')as td:
        temp=Path(td)
        for i in (0,1):(temp/f'p{i}.bin').write_bytes(payloads[i])
        cmd=[str(ROOT/'tools/ghidra-arcompact/ghidra_12.2_DEV/support/analyzeHeadless'),str(temp),'tree','-import',str(temp/'p0.bin'),'-loader','BinaryLoader','-loader-baseAddr','0xad800','-processor','ARCompact:LE:32:loopfix','-noanalysis','-scriptPath',str(scripts),'-postScript','ProbeDumpSDReadAsyncWake.java',str(out/'trace.txt'),str(temp/'p1.bin'),'-deleteProject']
        (out/'command.json').write_text(json.dumps(cmd,indent=2)+'\n')
        r=subprocess.run(cmd,stdout=subprocess.PIPE,stderr=subprocess.STDOUT,text=True,timeout=300);(out/'headless.log').write_text(r.stdout)
        assert r.returncode==0 and 'SCRIPT ERROR'not in r.stdout,r.stdout[-4000:]
        trace=(out/'trace.txt').read_text();assert trace.endswith('COMPLETE cases=8\n')and trace.count('PASS ')==8
    sys.path.insert(0,str(ROOT/'S33-sections/analysis_codex'))
    from static_common import disasm, u32
    spans=[(732468, 732496), (1412236, 1412640), (1412648, 1412680), (1554288, 1554720), (1854508, 1854524), (2298672, 2298744), (2298796, 2298912), (2344564, 2344736), (2344792, 2345280), (2466884, 2466964), (2467900, 2468244), (2468308, 2468436), (2469308, 2469328), (2518684, 2518736), (2518752, 2518812), (2518960, 2518984), (2522912, 2522924), (2523188, 2523204), (2523208, 2523248), (2523256, 2523288), (2523292, 2523328), (2523336, 2523368), (2523372, 2523412), (2523420, 2523436), (2525444, 2525448), (2525452, 2525468), (2525532, 2525548), (2525612, 2525628), (2525686, 2525692), (2529340, 2529416), (2620628, 2620682), (2620724, 2620740), (2620744, 2620796), (2620804, 2620820), (2620824, 2620868), (2620876, 2620940), (2621192, 2621208), (2621212, 2621248), (2621256, 2621272), (2621276, 2621312), (2621320, 2621336), (2621340, 2621392), (2621400, 2621462), (2621476, 2621554), (2621572, 2621604), (2621616, 2621648), (2621660, 2621678), (2621784, 2621796), (2621926, 2622092), (2622264, 2622340), (2622384, 2622396), (2622400, 2622416), (2622472, 2622492), (2622496, 2622504), (2622512, 2622520), (2622524, 2622532), (2622536, 2622596), (2622600, 2622612), (2622616, 2622624), (2622628, 2622636), (2622640, 2622648), (2622652, 2622660), (2622784, 2622860), (2622864, 2622876), (2622880, 2622896), (2623140, 2623220), (2623224, 2623236), (2623240, 2623256), (2623500, 2623544), (2623556, 2623576), (2623580, 2623628), (2623636, 2623652), (2623656, 2623672), (2623676, 2623700), (2623704, 2623724), (2623728, 2623748), (2623756, 2623788), (2623792, 2623828), (2623832, 2623880), (2623888, 2623928), (2623940, 2623960), (2623964, 2624012), (2624286, 2624312), (2624328, 2624348), (2624352, 2624400), (2624476, 2624488), (2624492, 2624512), (2624516, 2624536), (2624544, 2624576), (2624580, 2624616), (2624620, 2624700), (2625508, 2625544), (2625566, 2625608), (2625612, 2625692), (2625704, 2625760), (2625772, 2625824), (2625836, 2625916), (2625924, 2625944), (2625948, 2625972), (2625976, 2625996), (2626000, 2626036), (2626048, 2626068), (2626072, 2626088), (2626092, 2626124), (2626136, 2626156), (2626160, 2626184), (2626188, 2626236), (2627484, 2627592), (2630340, 2630388), (2922812, 2923232), (3109060, 3109532), (3359400, 3359436)]
    listing=''.join(disasm(a,b)for a,b in spans);(out/'gnu_verified.txt').write_text(listing)
    checks={0x23c6de:'st_s\tr3,[r14,0x14]',0x2313da:';0x28179c',0x2817e6:'st_s\tr0,[r1,0]',0x2817f6:'sth',0x281800:';0xb2d50',0x2f70d6:'add.f',0x2f7130:'sth',0x2f7168:'st_s\tr0,[r1,0]',0x2f7174:'stw_s',0x2f7182:'st\tr8,[r5,8]',0x23c812:'st\tr7,[r4,48]',0x2c9a88:'mov_s\tr0,0x1310',0x266ee0:'ldh.di',0x266ee4:'asl_s\tr0,r0,0x7',0x25a944:'cmp_s\tr14,0x1e',0x2812b4:'st_s\tr1,[r15,0]'}
    for a,token in checks.items():
        lines=[line for line in listing.splitlines()if re.match(rf'\s*{a:x}:',line)];assert len(lines)==1 and token in lines[0],(hex(a),token,lines)
    assert [u32(a)for a in [0x158e48,0x373228,0x37322c,0x373230]]==[0x372a48,0x45564e4c,0xe00005,2]
    assert all(u32(0x372a48+i*0x38)==0x45564e4c and u32(0x372a4c+i*0x38)!=0 for i in range(85))
    assert u32(0x373ce0)==0 and (0x373228-0x372a48)//0x38==36
    assert all(sha((ROOT/p).read_bytes())==h for p,h in inputs.items())
    result=dict(status='PASS_ORIGINAL_SD_TIMED_EVENT_WAKE_AND_PROGRESS_SWITCH_BOUNDARY_PROFILE',cpu_cases=8,returned_cases=7,bounded_progress_observations=1,gnu_windows=len(spans),instruction_checks=len(checks),sources=inputs,payload_hashes={str(b['index']):b['sha256']for b in blocks},
        original_bodies=['23C674 lower event constructor,25A83C/acquire/start/programmers and281158 release','158CBC/23C758 SET,158CE0/23C8AC CLEAR,158D04/2C9994 WAIT and158E28 query','2313AC absolute deadline plus28179C ordered queue insertion/removal of ready node','2F70C4 software tick increments time,expires deadline,unlinks event wait and reinserts ready task','267F20 stored-callback dispatcher and25ADBC/25ADC4 event publication;266E9C actual progress load/scaling','Original timeout mapping and30-stagnant retry loop in caller'],
        fixtures=['Prepared kernel,current/ready ring,empty deadline ring,active upper event record and zero trace hooks;lower event object initialized by original constructor','CPU switchB2D50 intercepted before CPU frame save;C-ABI event dispatcher or software ticks run at that boundary;arguments restored and switch returned only after actual list/task state becomes ready','Software ticks invoked directly,not TIMER0/CPU interrupt delivery;clock profile1000/1000 and zero timebase are synthetic','Resource semaphore query/post,stop hook,status registration/enable/unregister outcomes supplied;3342A8/336364 products modeled','Only progress halfword samples supplied;no data transfer and1024-byte destination remains31'],
        conclusions=['Original event wake removes both event waiter and deadline node,clears task wait cause and permits actual WAIT to return0','Original tick expiry removes both nodes and makes task ready while retaining nonzero wait cause;actual WAIT returns timeout200305 and reaches actual266E9C','A later completion after one timeout reaches success;progress sample1exports128and resets caller stagnation count','No-progress30real timeout returns leadE01520;progress change at11permits41real timeout returns before failure','Continuing progress stops at64th WAIT entry after63real timeout/progress cycles;no final release claimed','Lower event constructor writes marker6C65766E at record+20;needed to distinguish valid timed resume from invalid-object1039 path','CPU context save/restore,scheduler fairness and electrical stop remain outside evidence'],
        limits=['B2D50 is a declared switch-return boundary,not an executed CPU context switch or genuine interrupt context','Ticks are software invocations with prepared clock parameters;no measured time/frequency or physical timer behavior','Only one current task and one deadline at a time;ordering across multiple queued tasks not tested here','No async filesystem binding,physical DMA/cache,buffers,persistence,RAM dump or new BIN'])
    (out/'verified_evidence.json').write_text(json.dumps(result,indent=2)+'\n');(out.parent/'latest.json').write_text(json.dumps({'evidence':str((out/'verified_evidence.json').relative_to(ROOT))},indent=2)+'\n');print(trace,end='');print(out)


if __name__=='__main__':main()
