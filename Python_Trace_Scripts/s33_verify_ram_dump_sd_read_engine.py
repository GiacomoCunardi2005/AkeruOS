#!/usr/bin/env python3
"""Original SD read engines, descriptors, PIO and completion with declared command/MMIO fixtures."""
from datetime import datetime, timezone
from pathlib import Path
import json, re, subprocess, sys, tempfile
from s33_trace_state_dispatch import verified_payloads, sha
ROOT=Path(__file__).resolve().parents[1]


def main():
    blocks,payloads,_=verified_payloads(ROOT)
    out=ROOT/'Risultati/Runtime_Kernel/RAM_Dumper_SD_Read_Engine'/datetime.now(timezone.utc).strftime('%Y%m%dT%H%M%SZ');out.mkdir(parents=True,exist_ok=False)
    scripts=ROOT/'S33-sections/analysis_ghidra/scripts'
    sources=[Path(__file__)]+[scripts/n for n in ['ProbeDumpSDReadEngine.java','ProbeDumpSDReadPIO.java','ProbeDumpSDMutex.java','ProbeStatusRead.java']]
    inputs={str(p.relative_to(ROOT)):sha(p.read_bytes())for p in sources}
    for p in sources:(out/(p.name+'.snapshot')).write_bytes(p.read_bytes())
    with tempfile.TemporaryDirectory(prefix='s33-sd-tree-')as td:
        temp=Path(td)
        for i in (0,1):(temp/f'p{i}.bin').write_bytes(payloads[i])
        cmd=[str(ROOT/'tools/ghidra-arcompact/ghidra_12.2_DEV/support/analyzeHeadless'),str(temp),'tree','-import',str(temp/'p0.bin'),'-loader','BinaryLoader','-loader-baseAddr','0xad800','-processor','ARCompact:LE:32:loopfix','-noanalysis','-scriptPath',str(scripts),'-postScript','ProbeDumpSDReadEngine.java',str(out/'trace.txt'),str(temp/'p1.bin'),'-deleteProject']
        (out/'command.json').write_text(json.dumps(cmd,indent=2)+'\n')
        r=subprocess.run(cmd,stdout=subprocess.PIPE,stderr=subprocess.STDOUT,text=True,timeout=180);(out/'headless.log').write_text(r.stdout)
        assert r.returncode==0 and 'SCRIPT ERROR'not in r.stdout,r.stdout[-4000:]
        trace=(out/'trace.txt').read_text();assert trace.endswith('COMPLETE cases=28\n')and trace.count('PASS ')==28
    sys.path.insert(0,str(ROOT/'S33-sections/analysis_codex'))
    from static_common import disasm, u32
    spans=[(0xb15b4,0xb16d0),(0xb16d0,0xb1704),(0xb1710,0xb17b0),(0x2e509c,0x2e50cc),(0x2e514c,0x2e51e4),(0x2e52e8,0x2e52f4),(0x25aa54,0x25aa8c),(0x25a690,0x25a74c),(0x25a74c,0x25a83c),(0x25a83c,0x25a994),(0x25a9d4,0x25aa54),(0x25a658,0x25a690),(0x25a084,0x25a098),(0x25a0bc,0x25a0d0),(0x25a41c,0x25a430),(0x25a488,0x25a49c)]
    listing=''.join(disasm(a,b)for a,b in spans);(out/'gnu_verified.txt').write_text(listing)
    checks={0xb164a:';0x2e52e8',0xb1768:';0x2e52e8',0xb1680:'cmp_s\tr0,0xe00200',0xb1688:';0x2e5634',0xb1678:'cmp_s\tr13,0',0x25aa68:';0x25a74c',0x25aa84:';0x25a83c',0x2e51d4:';0x2e5634',0x25a866:'mov.ne'}
    for a,token in checks.items():
        lines=[line for line in listing.splitlines()if re.match(rf'\s*{a:x}:',line)];assert len(lines)==1 and token in lines[0],(hex(a),token,lines)
    assert [u32(a)for a in [0xb1708,0xb170c,0x2e51e8]]==[0xe00300,0xe00301,0xe00011]
    assert all(sha((ROOT/p).read_bytes())==h for p,h in inputs.items())
    result=dict(status='PASS_ORIGINAL_SD_READ_ENGINES_DESCRIPTORS_PIO_AND_COMPLETION',cpu_cases=28,returned_cases=27,bounded_wait_observations=1,gnu_windows=len(spans),instruction_checks=len(checks),sources=inputs,payload_hashes={str(b['index']):b['sha256']for b in blocks},
        original_bodies=['B15B4/B16D0 read engines','2E514C preparation with100poll bound and2E509C descriptor constructor','2E52E8/25AA54 read path selection','25A74C/25A690 PIO and25A658 completion,actual MMIO halfword loads/buffer stores','25A83C service path up to injected acquisition failure or unaligned PIO fallback'],
        fixtures=['2E52F4 command dispatcher returns chosen status and setup response state3/4/2;no command MMIO emission','25AA8C control calls recorded;17FAA4 cache preparation recorded;2801F0 service acquisition returns injected failure','MMIO status and data samples supplied just before original loads;delay2E500C returns0','3342A8 modulo32 product model,not DSP hardware proof;synthetic capacity100/blocksize16'],
        conclusions=['Single/multi descriptors,block/byte addressing,capacity checks andPIO copies asserted; rejected range still issues recovery command0D','Data error prevails over stop error;cleanup command error ignored','Multi stopE00200 accepted away from end boundary then completion checked','Single success has no separate completion poll after PIO;multi waits for bit8 after full buffer copy','28cases include state4 setup without07/completion,real100setup polls andone deliberately bounded final completion wait','Mode1 unaligned falls back toPIO;aligned acquisition failure returns injected error'],
        limits=['Command dispatcher,control/cache/service boundaries modeled;not full hardware read transaction','One bounded case stopped active with full buffer andno normal cleanup','No async service completion,concurrency,persistence or physical driver validation','No hardware action or installable dumper'])
    (out/'verified_evidence.json').write_text(json.dumps(result,indent=2)+'\n');(out.parent/'latest.json').write_text(json.dumps({'evidence':str((out/'verified_evidence.json').relative_to(ROOT))},indent=2)+'\n');print(trace,end='');print(out)


if __name__=='__main__':main()
