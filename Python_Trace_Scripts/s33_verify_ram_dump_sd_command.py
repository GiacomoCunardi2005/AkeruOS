#!/usr/bin/env python3
"""Original SD command dispatcher, response decoding and control polling with MMIO samples."""
from datetime import datetime, timezone
from pathlib import Path
import json, re, subprocess, sys, tempfile
from s33_trace_state_dispatch import verified_payloads, sha
ROOT=Path(__file__).resolve().parents[1]


def main():
    blocks,payloads,_=verified_payloads(ROOT)
    out=ROOT/'Risultati/Runtime_Kernel/RAM_Dumper_SD_Command'/datetime.now(timezone.utc).strftime('%Y%m%dT%H%M%SZ');out.mkdir(parents=True,exist_ok=False)
    scripts=ROOT/'S33-sections/analysis_ghidra/scripts'
    sources=[Path(__file__)]+[scripts/n for n in ['ProbeDumpSDCommand.java','ProbeDumpSDMutex.java','ProbeStatusRead.java']]
    inputs={str(p.relative_to(ROOT)):sha(p.read_bytes())for p in sources}
    for p in sources:(out/(p.name+'.snapshot')).write_bytes(p.read_bytes())
    with tempfile.TemporaryDirectory(prefix='s33-sd-tree-')as td:
        temp=Path(td)
        for i in (0,1):(temp/f'p{i}.bin').write_bytes(payloads[i])
        cmd=[str(ROOT/'tools/ghidra-arcompact/ghidra_12.2_DEV/support/analyzeHeadless'),str(temp),'tree','-import',str(temp/'p0.bin'),'-loader','BinaryLoader','-loader-baseAddr','0xad800','-processor','ARCompact:LE:32:loopfix','-noanalysis','-scriptPath',str(scripts),'-postScript','ProbeDumpSDCommand.java',str(out/'trace.txt'),str(temp/'p1.bin'),'-deleteProject']
        (out/'command.json').write_text(json.dumps(cmd,indent=2)+'\n')
        r=subprocess.run(cmd,stdout=subprocess.PIPE,stderr=subprocess.STDOUT,text=True,timeout=180);(out/'headless.log').write_text(r.stdout)
        assert r.returncode==0 and 'SCRIPT ERROR'not in r.stdout,r.stdout[-4000:]
        trace=(out/'trace.txt').read_text();assert trace.endswith('COMPLETE cases=40\n')and trace.count('PASS ')==40
    sys.path.insert(0,str(ROOT/'S33-sections/analysis_codex'))
    from static_common import disasm, u32
    spans=[(0x2e509c,0x2e50cc),(0x2e52f4,0x2e5320),(0x2e5332,0x2e53ce),(0x2e53d8,0x2e5414),(0x2e5464,0x2e5578),(0x2e5234,0x2e52e8),(0x2e51ec,0x2e5234),(0x25a278,0x25a2bc),(0x25a39c,0x25a41c),(0x25a5f8,0x25a658),(0x25a084,0x25a098),(0x25a098,0x25a0bc),(0x25a0bc,0x25a0d0),(0x25aa8c,0x25aaf2),(0x25a158,0x25a18c)]
    listing=''.join(disasm(a,b)for a,b in spans);(out/'gnu_verified.txt').write_text(listing)
    checks={0x2e547e:';0x25a278',0x2e5484:';0x25a5f8',0x2e548e:';0x2e556c',0x2e549c:';0x25a3e0',0x25a3fe:'ldh.di',0x25a414:'sth.ab',0x25a0b2:'sth.di',0x25aaa2:'cmp\tr14,2000',0x25aade:'cmp\tr14,2000'}
    for a,token in checks.items():
        lines=[line for line in listing.splitlines()if re.match(rf'\s*{a:x}:',line)];assert len(lines)==1 and token in lines[0],(hex(a),token,lines)
    assert [u32(a)for a in [0x2e5460,0x25ab4c,0x25ab50]]==[0xff01854,0x36b242,0x36b243]
    assert [u32(a)for a in range(0x2e5414,0x2e5460,4)]==list(range(0xe00200,0xe00213))
    assert all(sha((ROOT/p).read_bytes())==h for p,h in inputs.items())
    result=dict(status='PASS_ORIGINAL_SD_COMMAND_DISPATCH_RESPONSE_AND_CONTROL_MMIO_PROFILE',cpu_cases=40,command_cases=28,control_cases=12,gnu_windows=len(spans),instruction_checks=len(checks),sources=inputs,payload_hashes={str(b['index']):b['sha256']for b in blocks},
        original_bodies=['2E509C constructor and2E52F4 command dispatcher','25A39C data length/count registers and25A278 command/argument/config stores','25A5F8 command polling and25A098 status writeback','25A3E0 response port loads/byte swap,2E5234/2E51EC status decoding','25AA8C gate control and25A158 bit3 RMW'],
        fixtures=['Status0/status1 and response-port halfwords supplied immediately before original MMIO loads','Prepared descriptors and reset MMIO page;selectors0/800 and disable-other400;global gate flags injected0/1','No dispatcher/result/response helper replacement;no timing/electrical semantics modeled'],
        conclusions=['Exact MMIO store order/values and response byte order/status decoded in original bodies','Actual8000poll timeout executed for response type1 and type0;type0 discards command poll error/timeout and returns0','Response error priority and states3/4 verified; skipped response leaves old descriptor state/buffer untouched','High count word,zero count,full32bit argument and selector subtraction asserted;initial high-count clear at2E5464 is fixed0FF01854 even for selector800 while25A39C uses selected base','Gate enable/disable2000poll bounds executed;protected disable flags suppress write/poll while enable still operates'],
        limits=['Profiles are injected states/responses,not electrical device behavior or W1C proof','Only descriptor types0/1/2 and selected opcodes covered;special data-bearing command families not covered','No full read-engine/FS integration with these original command bodies yet','No physical hardware,full RAM map or installable dumper'])
    (out/'verified_evidence.json').write_text(json.dumps(result,indent=2)+'\n');(out.parent/'latest.json').write_text(json.dumps({'evidence':str((out/'verified_evidence.json').relative_to(ROOT))},indent=2)+'\n');print(trace,end='');print(out)


if __name__=='__main__':main()
