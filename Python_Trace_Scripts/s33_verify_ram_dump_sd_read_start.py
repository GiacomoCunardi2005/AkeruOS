#!/usr/bin/env python3
"""Original receive start, buffer programming, progress and callback dispatch with explicit MMIO profiles."""
from datetime import datetime, timezone
from pathlib import Path
import json, re, subprocess, sys, tempfile
from s33_trace_state_dispatch import verified_payloads, sha
ROOT=Path(__file__).resolve().parents[1]


def main():
    blocks,payloads,_=verified_payloads(ROOT)
    out=ROOT/'Risultati/Runtime_Kernel/RAM_Dumper_SD_Read_Start'/datetime.now(timezone.utc).strftime('%Y%m%dT%H%M%SZ');out.mkdir(parents=True,exist_ok=False)
    scripts=ROOT/'S33-sections/analysis_ghidra/scripts'
    sources=[Path(__file__)]+[scripts/n for n in ['ProbeDumpSDReadStart.java','ProbeDumpSDMutex.java','ProbeStatusRead.java']]
    inputs={str(p.relative_to(ROOT)):sha(p.read_bytes())for p in sources}
    for p in sources:(out/(p.name+'.snapshot')).write_bytes(p.read_bytes())
    with tempfile.TemporaryDirectory(prefix='s33-sd-tree-')as td:
        temp=Path(td)
        for i in (0,1):(temp/f'p{i}.bin').write_bytes(payloads[i])
        cmd=[str(ROOT/'tools/ghidra-arcompact/ghidra_12.2_DEV/support/analyzeHeadless'),str(temp),'tree','-import',str(temp/'p0.bin'),'-loader','BinaryLoader','-loader-baseAddr','0xad800','-processor','ARCompact:LE:32:loopfix','-noanalysis','-scriptPath',str(scripts),'-postScript','ProbeDumpSDReadStart.java',str(out/'trace.txt'),str(temp/'p1.bin'),'-deleteProject']
        (out/'command.json').write_text(json.dumps(cmd,indent=2)+'\n')
        r=subprocess.run(cmd,stdout=subprocess.PIPE,stderr=subprocess.STDOUT,text=True,timeout=180);(out/'headless.log').write_text(r.stdout)
        assert r.returncode==0 and 'SCRIPT ERROR'not in r.stdout,r.stdout[-4000:]
        trace=(out/'trace.txt').read_text();assert trace.endswith('COMPLETE cases=33\n')and trace.count('PASS ')==33
    sys.path.insert(0,str(ROOT/'S33-sections/analysis_codex'))
    from static_common import disasm, u32
    spans=[(0x28080c,0x280838),(0x280844,0x280858),(0x28085c,0x28088c),(0x280894,0x2808a4),(0x2808a8,0x2808b8),(0x2808bc,0x2808d4),(0x2808d8,0x2808ec),(0x2808f0,0x280904),(0x28090c,0x28092c),(0x280930,0x280954),(0x280958,0x280988),(0x280990,0x2809b8),(0x2809c4,0x2809d8),(0x2809dc,0x280a0c),(0x280b1e,0x280b38),(0x280b48,0x280b5c),(0x280b60,0x280b90),(0x280bdc,0x280be8),(0x280bec,0x280c00),(0x280c04,0x280c18),(0x280c20,0x280c40),(0x280c44,0x280c68),(0x280c6c,0x280cbc),(0x280338,0x280384),(0x2803b0,0x2803bc),(0x2803c0,0x2803d0),(0x280408,0x28041c),(0x280420,0x280428),(0x280430,0x280438),(0x28043c,0x280444),(0x280448,0x280484),(0x280488,0x280494),(0x280498,0x2804a0),(0x2804a4,0x2804ac),(0x2804b0,0x2804b8),(0x2804bc,0x2804c4),(0x280540,0x28058c),(0x280590,0x28059c),(0x2805a0,0x2805b0),(0x2806a4,0x2806f4),(0x2806f8,0x280704),(0x280708,0x280718),(0x2822c4,0x2822f4),(0x266fb0,0x266fc8),(0x266e9c,0x266ed0),(0x266ee0,0x266f1c),(0x267f20,0x267f2c),(0x268034,0x268044),(0x268048,0x268070),(0x268078,0x268098),(0x26809c,0x2680c0),(0x2680c8,0x2680e8),(0x2680ec,0x268114),(0x26811c,0x26812c),(0x268904,0x268908),(0x26890c,0x26891c),(0x26895c,0x26896c),(0x2689ac,0x2689bc),(0x2689f6,0x2689fc),(0x25adbc,0x25add0)]
    listing=''.join(disasm(a,b)for a,b in spans);(out/'gnu_verified.txt').write_text(listing)
    checks={0x28086e:';0x280338',0x2808c8:';0x266fb0',0x2809ee:';0x280540',0x280b72:';0x2806a4',0x280c9e:'st_s\tr0,[r14,0x8]',0x280ca4:'stb\tr1,[r16]',0x280cb2:';0x179354',0x2803b0:'sth.di',0x2822d0:';0x335b34',0x266fb4:'st_s\tr0,[r1,0]',0x266ee0:'ldh.di',0x266ee4:'asl_s\tr0,r0,0x7',0x26807c:'ld_s\tr0,[r14,0]',0x2689f6:'jl_s\t[r0]',0x25adbe:';0x158cbc',0x25adcc:'bset_s\tr1,r1,0x12'}
    for a,token in checks.items():
        lines=[line for line in listing.splitlines()if re.match(rf'\s*{a:x}:',line)];assert len(lines)==1 and token in lines[0],(hex(a),token,lines)
    assert [u32(a)for a in [0x26704c,0x267050,0x267054,0x268074,0x2680c4,0x268118]]==[0x36b358,0x36b35c,0x36b360,0x36b358,0x36b35c,0x36b360]
    assert [u32(a)for a in [0x266ed4,0x266ed8,0x266edc,0x267014,0x267018,0x26701c,0x267020,0x280ce0,0x25add4]]==[0xfee0538,0xfee032c,0xfee03ac,0xfee04f4,0xfee00ec,0xfee016c,0x1e03600,0x1e03d71,0xe00005]
    assert u32(0x268908)==0xfe1000c and u32(0x26891c)==0xfe10008
    assert all(sha((ROOT/p).read_bytes())==h for p,h in inputs.items())
    result=dict(status='PASS_ORIGINAL_SD_RECEIVE_START_PROGRESS_AND_CALLBACK_DISPATCH_MMIO_PROFILE',cpu_cases=33,start_cases=13,progress_cases=20,returned_cases=33,gnu_windows=len(spans),instruction_checks=len(checks),sources=inputs,payload_hashes={str(b['index']):b['sha256']for b in blocks},
        original_bodies=['28080C receive start and280338/280540/2806A4 buffer programmers','2822C4 count decomposition with original335B34 unsigned divisions','266FB0/266FB8/266FC0 callback setters and267F20 MMIO dispatcher through2689F6 indirect call','25ADBC/25ADC4 original callback tails to158CBC boundary','266E9C progress MMIO load and128scaling;1786E8/179354 critical counters'],
        fixtures=['Prepared objects512CC8/512CEC/512D10 withF4240,id202/203,total/step; no acquisition or release in this group','MMIO pages initialized0; dispatcher entered explicitly after start with status bit7/0/1 and target mask supplied;other causes masked byFE1000C=7,FE10008 remains uninitialized;no physical interrupt delivery','158CBC event publication recorder returns0; event object,waiters and scheduling not executed','No data-port emulation or transfer:1024-byte destination remains31withA5guards; high step cases only program registers'],
        conclusions=['Original start programs buffer low/high address register pairs,stores callback in36B358/35C/360 and subtractsstep fromobject+8','End byte reflects remaining==0 after subtraction; return0 is not callback execution or data delivery','Original setter-to-MMIO-dispatch-to-indirect-callback chain reaches original SD callback and eventE00005mask40/40000; masked/no-status suppress callback,nonnullstatus withnullcallback acknowledges without event','Prepared zero-total start wraps unsigned remaining toFFFFFC00; no complete acquire/caller reachability claim for this profile','Progress maps six fixed write/read object pointers to halfword registers and returns sample<<7;unknown pointer/null output1E03600 without output change','Progress succeeds for matching pointers whose object fields are zero; no active-id/ownership validation in this getter'],
        limits=['Manually entered MMIO dispatcher is not interrupt routing,vector delivery or electrical writeback proof','Prepared descriptors include contract-edge values;normal runtime reachability not established for every profile','Event API result remains supplied; no RTOS waiting or original async reader/start/progress integration yet','No physical DMA/cache/buffer lifetime,persistence,RAM dumper binding or new BIN'])
    (out/'verified_evidence.json').write_text(json.dumps(result,indent=2)+'\n');(out.parent/'latest.json').write_text(json.dumps({'evidence':str((out/'verified_evidence.json').relative_to(ROOT))},indent=2)+'\n');print(trace,end='');print(out)


if __name__=='__main__':main()
