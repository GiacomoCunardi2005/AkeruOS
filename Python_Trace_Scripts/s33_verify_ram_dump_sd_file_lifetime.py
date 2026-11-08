#!/usr/bin/env python3
"""Original ordinary-backend file objects, list count and volume lifetime; offline only."""
from datetime import datetime, timezone
from pathlib import Path
import json, re, subprocess, sys, tempfile
from s33_trace_state_dispatch import verified_payloads, sha
ROOT=Path(__file__).resolve().parents[1]


def main():
    blocks,payloads,_=verified_payloads(ROOT)
    out=ROOT/'Risultati/Runtime_Kernel/RAM_Dumper_SD_File_Lifetime'/datetime.now(timezone.utc).strftime('%Y%m%dT%H%M%SZ');out.mkdir(parents=True,exist_ok=False)
    scripts=ROOT/'S33-sections/analysis_ghidra/scripts'
    sources=[Path(__file__)]+[scripts/n for n in ['ProbeDumpSDFileLifetime.java','ProbeDumpSDMutex.java','ProbeStatusRead.java']]
    inputs={str(p.relative_to(ROOT)):sha(p.read_bytes())for p in sources}
    for p in sources:(out/(p.name+'.snapshot')).write_bytes(p.read_bytes())
    with tempfile.TemporaryDirectory(prefix='s33-sd-file-lifetime-')as td:
        temp=Path(td)
        for i in (0,1):(temp/f'p{i}.bin').write_bytes(payloads[i])
        cmd=[str(ROOT/'tools/ghidra-arcompact/ghidra_12.2_DEV/support/analyzeHeadless'),str(temp),'lifetime','-import',str(temp/'p0.bin'),'-loader','BinaryLoader','-loader-baseAddr','0xad800','-processor','ARCompact:LE:32:loopfix','-noanalysis','-scriptPath',str(scripts),'-postScript','ProbeDumpSDFileLifetime.java',str(out/'trace.txt'),str(temp/'p1.bin'),'-deleteProject']
        (out/'command.json').write_text(json.dumps(cmd,indent=2)+'\n')
        r=subprocess.run(cmd,stdout=subprocess.PIPE,stderr=subprocess.STDOUT,text=True,timeout=180);(out/'headless.log').write_text(r.stdout)
        assert r.returncode==0 and 'SCRIPT ERROR'not in r.stdout,r.stdout[-4000:]
        trace=(out/'trace.txt').read_text();assert trace.endswith('COMPLETE cases=6\n')and trace.count('PASS ')==6
    sys.path.insert(0,str(ROOT/'S33-sections/analysis_codex'))
    from static_common import disasm, u32
    spans=[(0x2a45d4,0x2a45f0),(0x2ac528,0x2ac564),(0x2ac564,0x2ac584),(0x2e8a54,0x2e8aa8),(0x2e8bb0,0x2e8bd8),(0x225618,0x225622),(0x1f45fc,0x1f4624),(0x2a1344,0x2a1398),(0x21ad30,0x21ae94),(0x1f48a4,0x1f48e8),(0x1f46c4,0x1f46fc),(0x1f4710,0x1f4736),(0x1f4834,0x1f48a4),(0x225a60,0x225aa8),(0x225c14,0x225c22)]
    listing=''.join(disasm(a,b)for a,b in spans);(out/'gnu_verified.txt').write_text(listing)
    checks={0x2ac544:';0x2e8a54',0x2ac56e:';0x2e8bb0',0x21ae80:';0x2ac564',0x1f4618:'st_s\tr0,[r14,0x4]',0x2e8a98:'stw_s\tr1,[r13,0x8]',0x2e8bce:'stw_s\tr0,[r14,0x8]'}
    for a,s in checks.items():
        lines=[line for line in listing.splitlines()if re.match(rf'\s*{a:x}:',line)];assert len(lines)==1 and s in lines[0],(hex(a),s,lines)
    assert u32(0x225e10)==0x1a00010
    assert u32(0x2ac740)==0x4d465356 and u32(0x1f4c48)==0x1a00010
    candidate=ROOT/'Ghidra_Results/ghidra_reports/ptp_usb_audit/block00_linear_candidates.txt'
    calls=[line.strip()for line in candidate.read_text().splitlines()if re.search(r';0x(?:2e8a54|2e8bb0|2ac564|2ac528|2a45d4|2a45e4)\b',line)]
    assert len(calls)==14
    (out/'linear_call_candidates.json').write_text(json.dumps({'source':str(candidate.relative_to(ROOT)),'sha256':sha(candidate.read_bytes()),'calls':calls,'limit':'Main linear candidates only, not all payloads, indirect calls, aliases or a writer census'},indent=2)+'\n')
    assert all(sha((ROOT/p).read_bytes())==h for p,h in inputs.items())
    result=dict(status='PASS_ORIGINAL_FILE_LIST_AND_VOLUME_LIFETIME',cpu_cases=6,gnu_windows=len(spans),instruction_checks=len(checks),sources=inputs,payload_hashes={str(b['index']):b['sha256']for b in blocks},
        original_bodies=['1F43AC open callback through n/2A1648','2AC528 file allocator adapter','2A45D4 list initialization','2E8A54 append /2E8BB0 unlink with original critical primitives','1F48A4 file close through21AD30 and2AC564','1F48A4 volume close through1F46C4 and2A45E4','225A60 reconfiguration refusal gate','Original semaphore wait/post, memcpy and millicode'],
        fixtures=['2AC2B4 directory create returns explicit entry or collision, not physical exclusive creation','File pool2F7ABC supplies zeroed80-byte objects or null; release2F7AF0 records magic state','21B300 clock supplies zeros','21A424 cache predicate forced0, dirty field0 so storage-update branches bypassed','Volume ioctl3 returns0','Generic32-byte wrappers preallocated by harness; no registry/genericopen/genericclose execution'],
        conclusions=['Context+108 is the count of intrusive file-object list rooted at context+100 for tested backend1','Original n open callback adds objects; original file close removes them and complements magic before pool release','Volume close refuses01A00010 until last object removed; two release orders preserve ring/count', '225A60 refuses01A00010 with live objects before ready/backend/volume mutation in three sequences','Allocation failure/collision do not add an object; null release is a no-op','Device close callback leaves generic wrapper+4 unchanged after object release; upper layer owns wrapper destruction'],
        limits=['Backend1 only: no claim of pinning backend7 or12','Sequential prepared mounted context, no physical SD, real pool/cache, concurrent scheduler or crash persistence','Directory create is a fixture, so no new standalone proof of physical exclusive creation','No complete writer census or proof that every unmount/format/backend-change path checks this list','No installable RAM dumper or complete physical RAM map'])
    (out/'verified_evidence.json').write_text(json.dumps(result,indent=2)+'\n');(out.parent/'latest.json').write_text(json.dumps({'evidence':str((out/'verified_evidence.json').relative_to(ROOT))},indent=2)+'\n');print(trace,end='');print(out)


if __name__=='__main__':main()
