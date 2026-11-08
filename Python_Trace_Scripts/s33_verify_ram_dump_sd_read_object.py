#!/usr/bin/env python3
"""Original SD receive-object acquisition, selector and release with semaphore result fixtures."""
from datetime import datetime, timezone
from pathlib import Path
import json, re, subprocess, sys, tempfile
from s33_trace_state_dispatch import verified_payloads, sha
ROOT=Path(__file__).resolve().parents[1]


def main():
    blocks,payloads,_=verified_payloads(ROOT)
    out=ROOT/'Risultati/Runtime_Kernel/RAM_Dumper_SD_Read_Object'/datetime.now(timezone.utc).strftime('%Y%m%dT%H%M%SZ');out.mkdir(parents=True,exist_ok=False)
    scripts=ROOT/'S33-sections/analysis_ghidra/scripts'
    sources=[Path(__file__)]+[scripts/n for n in ['ProbeDumpSDReadObject.java','ProbeDumpSDMutex.java','ProbeStatusRead.java']]
    inputs={str(p.relative_to(ROOT)):sha(p.read_bytes())for p in sources}
    for p in sources:(out/(p.name+'.snapshot')).write_bytes(p.read_bytes())
    with tempfile.TemporaryDirectory(prefix='s33-sd-tree-')as td:
        temp=Path(td)
        for i in (0,1):(temp/f'p{i}.bin').write_bytes(payloads[i])
        cmd=[str(ROOT/'tools/ghidra-arcompact/ghidra_12.2_DEV/support/analyzeHeadless'),str(temp),'tree','-import',str(temp/'p0.bin'),'-loader','BinaryLoader','-loader-baseAddr','0xad800','-processor','ARCompact:LE:32:loopfix','-noanalysis','-scriptPath',str(scripts),'-postScript','ProbeDumpSDReadObject.java',str(out/'trace.txt'),str(temp/'p1.bin'),'-deleteProject']
        (out/'command.json').write_text(json.dumps(cmd,indent=2)+'\n')
        r=subprocess.run(cmd,stdout=subprocess.PIPE,stderr=subprocess.STDOUT,text=True,timeout=180);(out/'headless.log').write_text(r.stdout)
        assert r.returncode==0 and 'SCRIPT ERROR'not in r.stdout,r.stdout[-4000:]
        trace=(out/'trace.txt').read_text();assert trace.endswith('COMPLETE cases=18\n')and trace.count('PASS ')==18
    sys.path.insert(0,str(ROOT/'S33-sections/analysis_codex'))
    from static_common import disasm, u32
    spans=[(0x2801f0,0x28028c),(0x27fcd4,0x27fd0a),(0x27fd34,0x27fd44),(0x27fd48,0x27fd68),(0x27fd68,0x27fd7c),(0x27fd84,0x27fd94),(0x27fd98,0x27fdc4),(0x27fdcc,0x27fde4),(0x27fde4,0x27fe0c),(0x27ffb2,0x27ffd0),(0x27ffd8,0x280016),(0x280024,0x280072),(0x280084,0x2800a4),(0x2800b0,0x2800d0),(0x2800dc,0x2800ee),(0x27ff08,0x27ff18),(0x27ff1c,0x27ff40),(0x27ff48,0x27ff58),(0x27ff5c,0x27ff80),(0x27ff88,0x27ff98),(0x27ff9c,0x27ffb2),(0x280158,0x280164),(0x2801e6,0x2801f0),(0x281158,0x28117c),(0x281184,0x281198),(0x28119c,0x2811b4),(0x2811b8,0x2811cc),(0x2811d0,0x2811f4),(0x281200,0x281214),(0x281218,0x281228),(0x28122c,0x28124c),(0x281258,0x28126c),(0x281270,0x281288),(0x28128c,0x2812b8),(0x2812b8,0x2812bc),(0x280fe4,0x281008),(0x28101e,0x281048),(0x28104c,0x281064),(0x281064,0x28109c),(0x2810a8,0x2810ce),(0x2810ce,0x2810e0),(0x2810ec,0x281120),(0x28112c,0x281158)]
    listing=''.join(disasm(a,b)for a,b in spans);(out/'gnu_verified.txt').write_text(listing)
    checks={0x280264:';0x27fcd4',0x280280:'st\tr2,[r16]',0x2812a8:';0x281064',0x2812b4:'st_s\tr1,[r15,0]',0x281092:'st_s\tr13,[r0,0x4]',0x2812b8:';0x281158'}
    for a,token in checks.items():
        lines=[line for line in listing.splitlines()if re.match(rf'\s*{a:x}:',line)];assert len(lines)==1 and token in lines[0],(hex(a),token,lines)
    assert [u32(a)for a in [0x27fd2c,0x27fd7c,0x27fdc4,0x280388,0x28038c,0x280390,0x280394,0x28039c]]==[0x512cc8,0x512cec,0x512d10,0x1e02400,0x1e02410,0x1e02411,0x1e02413,0xf4240]
    assert all(sha((ROOT/p).read_bytes())==h for p,h in inputs.items())
    result=dict(status='PASS_ORIGINAL_SD_RECEIVE_OBJECT_SELECT_ACQUIRE_RELEASE',cpu_cases=18,returned_cases=18,gnu_windows=len(spans),instruction_checks=len(checks),sources=inputs,payload_hashes={str(b['index']):b['sha256']for b in blocks},
        original_bodies=['2801F0 acquisition and original unsigned remainder335B34 validation','27FCD4 selector branches for IDs202/203 and fixed modes3/4/6','281158 release and2812B8 alias,280FE4/281064 common cleanup','Original1786E8/179354 nested critical counters and controller MMIO stores'],
        fixtures=['Prepared MMIO halfwordsFFFF and three36-byte objects512CC8/512CEC/512D10;global3F76D4 configuration and36C19B software flags supplied','1594E4 semaphore queries,1593AC waits,1594A4 posts supplied; no scheduler or actual semaphore ownership established','267BAC/267BB4/267BBC stop hooks replaced withE09999; no physical stop guarantee','No28080C start or data transfer; high sizes are descriptor-contract tests without huge buffers'],
        conclusions=['Original selector chooses three fixed objects with36byte stride using configured mode or supplied semaphore availability','Acquire publishesF4240,id,total,step and pointer;fields16through35 remainA5','Null output,port/step alignment,remainder and inclusive80000000 step bound tested;FFFFFFFF total skips remainder and upper bound','Query/wait failure leaves caller public output unchanged even though selector has initialized its private output slot','Original release clears object+4 and caller handle even when semaphore post returns injected error; error propagated by lower release helper','Matched fixed configuration skips semaphore post; original critical sections balanced in every completed path','Normal stop-hook injected error is not propagated by this caller; no proof of real stopping or buffer reuse'],
        limits=['Prepared semaphore outcomes may not match live availability; no concurrent/repeated acquire race proof','Original objects acquired/released without start,callbacks or event delivery; no full async-reader integration yet','No datasheet/electrical MMIO,RTOS/DMA/cache or physical persistence','No RAM dumper binding or new BIN'])
    (out/'verified_evidence.json').write_text(json.dumps(result,indent=2)+'\n');(out.parent/'latest.json').write_text(json.dumps({'evidence':str((out/'verified_evidence.json').relative_to(ROOT))},indent=2)+'\n');print(trace,end='');print(out)


if __name__=='__main__':main()
