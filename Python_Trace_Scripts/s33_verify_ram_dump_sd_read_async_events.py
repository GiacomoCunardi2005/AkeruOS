#!/usr/bin/env python3
"""Integrated original SD receive lifecycle and event SET/WAIT/query/CLEAR with prepared RTOS state."""
from datetime import datetime, timezone
from pathlib import Path
import json, re, subprocess, sys, tempfile
from s33_trace_state_dispatch import verified_payloads, sha
ROOT=Path(__file__).resolve().parents[1]


def main():
    blocks,payloads,_=verified_payloads(ROOT)
    out=ROOT/'Risultati/Runtime_Kernel/RAM_Dumper_SD_Read_Async_Events'/datetime.now(timezone.utc).strftime('%Y%m%dT%H%M%SZ');out.mkdir(parents=True,exist_ok=False)
    scripts=ROOT/'S33-sections/analysis_ghidra/scripts'
    sources=[Path(__file__)]+[scripts/n for n in ['ProbeDumpSDReadAsyncEvents.java','ProbeDumpSDMutex.java','ProbeStatusRead.java']]
    inputs={str(p.relative_to(ROOT)):sha(p.read_bytes())for p in sources}
    for p in sources:(out/(p.name+'.snapshot')).write_bytes(p.read_bytes())
    with tempfile.TemporaryDirectory(prefix='s33-sd-tree-')as td:
        temp=Path(td)
        for i in (0,1):(temp/f'p{i}.bin').write_bytes(payloads[i])
        cmd=[str(ROOT/'tools/ghidra-arcompact/ghidra_12.2_DEV/support/analyzeHeadless'),str(temp),'tree','-import',str(temp/'p0.bin'),'-loader','BinaryLoader','-loader-baseAddr','0xad800','-processor','ARCompact:LE:32:loopfix','-noanalysis','-scriptPath',str(scripts),'-postScript','ProbeDumpSDReadAsyncEvents.java',str(out/'trace.txt'),str(temp/'p1.bin'),'-deleteProject']
        (out/'command.json').write_text(json.dumps(cmd,indent=2)+'\n')
        r=subprocess.run(cmd,stdout=subprocess.PIPE,stderr=subprocess.STDOUT,text=True,timeout=180);(out/'headless.log').write_text(r.stdout)
        assert r.returncode==0 and 'SCRIPT ERROR'not in r.stdout,r.stdout[-4000:]
        trace=(out/'trace.txt').read_text();assert trace.endswith('COMPLETE cases=13\n')and trace.count('PASS ')==13
    sys.path.insert(0,str(ROOT/'S33-sections/analysis_codex'))
    from static_common import disasm, u32
    spans=[(732468, 732496), (1412236, 1412640), (1412648, 1412680), (1554288, 1554336), (1854508, 1854524), (2298672, 2298744), (2344792, 2345280), (2466884, 2466964), (2467900, 2468244), (2468308, 2468436), (2469308, 2469328), (2518684, 2518736), (2518752, 2518812), (2518960, 2518984), (2522912, 2522924), (2523188, 2523204), (2523208, 2523248), (2523256, 2523288), (2523292, 2523328), (2523336, 2523368), (2523372, 2523412), (2523420, 2523436), (2525444, 2525448), (2525452, 2525468), (2525532, 2525548), (2525612, 2525628), (2525686, 2525692), (2529340, 2529416), (2620628, 2620682), (2620724, 2620740), (2620744, 2620796), (2620804, 2620820), (2620824, 2620868), (2620876, 2620940), (2621192, 2621208), (2621212, 2621248), (2621256, 2621272), (2621276, 2621312), (2621320, 2621336), (2621340, 2621392), (2621400, 2621462), (2621476, 2621554), (2621572, 2621604), (2621616, 2621648), (2621660, 2621678), (2621784, 2621796), (2621926, 2622092), (2622264, 2622340), (2622384, 2622396), (2622400, 2622416), (2622472, 2622492), (2622496, 2622504), (2622512, 2622520), (2622524, 2622532), (2622536, 2622596), (2622600, 2622612), (2622616, 2622624), (2622628, 2622636), (2622640, 2622648), (2622652, 2622660), (2622784, 2622860), (2622864, 2622876), (2622880, 2622896), (2623140, 2623220), (2623224, 2623236), (2623240, 2623256), (2623500, 2623544), (2623556, 2623576), (2623580, 2623628), (2623636, 2623652), (2623656, 2623672), (2623676, 2623700), (2623704, 2623724), (2623728, 2623748), (2623756, 2623788), (2623792, 2623828), (2623832, 2623880), (2623888, 2623928), (2623940, 2623960), (2623964, 2624012), (2624286, 2624312), (2624328, 2624348), (2624352, 2624400), (2624476, 2624488), (2624492, 2624512), (2624516, 2624536), (2624544, 2624576), (2624580, 2624616), (2624620, 2624700), (2625508, 2625544), (2625566, 2625608), (2625612, 2625692), (2625704, 2625760), (2625772, 2625824), (2625836, 2625916), (2625924, 2625944), (2625948, 2625972), (2625976, 2625996), (2626000, 2626036), (2626048, 2626068), (2626072, 2626088), (2626092, 2626124), (2626136, 2626156), (2626160, 2626184), (2626188, 2626236), (2630340, 2630388), (2922812, 2923232), (3359400, 3359436)]
    listing=''.join(disasm(a,b)for a,b in spans);(out/'gnu_verified.txt').write_text(listing)
    checks={0x25a888:';0x2801f0',0x25a8fe:';0x28080c',0x25a924:';0x158d04',0x25aa10:';0x2812b8',0x2812b4:'st_s\tr1,[r15,0]',0x280c9e:'st_s\tr0,[r14,0x8]',0x2689f6:'jl_s\t[r0]',0x25adbe:';0x158cbc',0x158cd0:';0x23c758',0x158cf4:';0x23c8ac',0x158dbe:'mov_s',0x158e3c:'st_s\tr0,[r13,0]',0x23c868:'st_s\tr3,[r0,0x18]',0x23c8d0:'st_s\tr2,[r0,0x18]',0x23c938:';0x2c9994',0x2c9a04:'st\tr5,[r13,24]',0x2c9a68:'stw_s',0x2c9a6a:'st_s\tr2,[r15,0x8]',0x2c9a6c:'st_s\tr0,[r15,0x30]'}
    for a,token in checks.items():
        lines=[line for line in listing.splitlines()if re.match(rf'\s*{a:x}:',line)];assert len(lines)==1 and token in lines[0],(hex(a),token,lines)
    assert [u32(a)for a in [0x158e48,0x373228,0x37322c,0x373230]]==[0x372a48,0x45564e4c,0xe00005,2]
    assert all(u32(0x372a48+i*0x38)==0x45564e4c and u32(0x372a4c+i*0x38)!=0 for i in range(85))
    assert u32(0x373ce0)==0 and (0x373228-0x372a48)//0x38==36
    assert all(sha((ROOT/p).read_bytes())==h for p,h in inputs.items())
    result=dict(status='PASS_ORIGINAL_SD_RECEIVE_LIFECYCLE_AND_RTOS_EVENT_PROFILE',cpu_cases=13,returned_cases=10,blocked_wait_observations=3,gnu_windows=len(spans),instruction_checks=len(checks),sources=inputs,payload_hashes={str(b['index']):b['sha256']for b in blocks},
        original_bodies=['25A83C reader plus2801F0/27FCD4 acquire,28080C/programmers and281158/281064 release','267F20 MMIO dispatcher,stored callback25ADBC/25ADC4 and158CBC/23C758 actual event SET','158CE0/23C8AC actual CLEAR,158D04/23C938/2C9994 actual WAIT and158E28 actual query','231330/23C904/2C993C/26983C deadline preparation with declared multiply models;original335D34 division','Original nested critical sections andB2D34 same-ready-task fast return'],
        fixtures=['Static event record373228 forE00005 prepared with active gate,empty waiter ring and mode0or1;other85-entry event table identity retained','Prepared kernel/current/ready task,zero34FAD4timebase,clock-conversion parameters1000/1000 and disabled trace hooks;not a Nikon boot state','Dispatcher explicitly invoked as nested C-ABI call before WAIT,with volatile argument restoration and callee/stack checks;no CPU interrupt context delivery','Object semaphore query/post,stop hook and status callback register/enable/unregister outcomes supplied','3342A8 modulo32 product and336364 product for32bit operands supplied;DSP timing/clock not established','No data transfer:1024-byte buffer remains31;other IRQ maskFE1000C=7 and pendingFE10008unknown'],
        conclusions=['Real callback SET supplies the bits that actual WAIT consumes/tests and actual query/CLEAR observe;stale matching bits removed initially,unrelatedbit1retained','Immediate ready WAIT returns without scheduler and lower mode1auto-clear removes completion before query;reader still returns0from successful wait path','No IRQ,masked IRQ and missing status enqueue one original event waiter with taskstate1069 before explicit deadline-scheduler boundary2313AC;deadline triplet100/0/0asserted under synthetic clock profile;endByte1does not imply completion','Real release clears objectid/handle even on post error;upper finish error keeps two unregister calls','Inactive/malformed event record causes real resolver errors200304/200307 after object acquisition and skips common caller cleanup','Getter266E9C is not reached in these ready/blocked profiles;progress-only matrices remain separate evidence'],
        limits=['Three waiting observations stop before2313AC;no timeout expiration,wakeup,context switch or normal cleanup proved for those paths','Prepared event/kernel state,resource arbitration,stop hook and upper status callback registration are not full boot/scheduler proofs','Original progress getter not integrated on a timed-out WAIT yet;no filesystem async path or physical buffer ownership/persistence','No RAM dumper binding or new BIN'])
    (out/'verified_evidence.json').write_text(json.dumps(result,indent=2)+'\n');(out.parent/'latest.json').write_text(json.dumps({'evidence':str((out/'verified_evidence.json').relative_to(ROOT))},indent=2)+'\n');print(trace,end='');print(out)


if __name__=='__main__':main()
