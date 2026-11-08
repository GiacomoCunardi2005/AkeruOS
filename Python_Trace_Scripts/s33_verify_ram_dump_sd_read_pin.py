#!/usr/bin/env python3
"""Original existing-file r/r+ open and read-handle lifetime; offline only."""
from datetime import datetime, timezone
from pathlib import Path
import json, re, subprocess, sys, tempfile
from s33_trace_state_dispatch import verified_payloads, sha
ROOT=Path(__file__).resolve().parents[1]


def main():
    blocks,payloads,_=verified_payloads(ROOT)
    out=ROOT/'Risultati/Runtime_Kernel/RAM_Dumper_SD_Read_Pin'/datetime.now(timezone.utc).strftime('%Y%m%dT%H%M%SZ');out.mkdir(parents=True,exist_ok=False)
    scripts=ROOT/'S33-sections/analysis_ghidra/scripts'
    sources=[Path(__file__)]+[scripts/n for n in ['ProbeDumpSDReadPin.java','ProbeDumpSDFileLifetime.java','ProbeDumpSDMutex.java','ProbeStatusRead.java']]
    inputs={str(p.relative_to(ROOT)):sha(p.read_bytes())for p in sources}
    for p in sources:(out/(p.name+'.snapshot')).write_bytes(p.read_bytes())
    with tempfile.TemporaryDirectory(prefix='s33-sd-read-pin-')as td:
        temp=Path(td)
        for i in (0,1):(temp/f'p{i}.bin').write_bytes(payloads[i])
        cmd=[str(ROOT/'tools/ghidra-arcompact/ghidra_12.2_DEV/support/analyzeHeadless'),str(temp),'read-pin','-import',str(temp/'p0.bin'),'-loader','BinaryLoader','-loader-baseAddr','0xad800','-processor','ARCompact:LE:32:loopfix','-noanalysis','-scriptPath',str(scripts),'-postScript','ProbeDumpSDReadPin.java',str(out/'trace.txt'),str(temp/'p1.bin'),'-deleteProject']
        (out/'command.json').write_text(json.dumps(cmd,indent=2)+'\n')
        r=subprocess.run(cmd,stdout=subprocess.PIPE,stderr=subprocess.STDOUT,text=True,timeout=180);(out/'headless.log').write_text(r.stdout)
        assert r.returncode==0 and 'SCRIPT ERROR'not in r.stdout,r.stdout[-4000:]
        trace=(out/'trace.txt').read_text();assert trace.endswith('COMPLETE cases=12\n')and trace.count('PASS ')==12
    sys.path.insert(0,str(ROOT/'S33-sections/analysis_codex'))
    from static_common import disasm, u32, BS, PS
    spans=[(0x1f4586,0x1f45a4),(0x21a0d0,0x21a190),(0x2ac528,0x2ac564),(0x2ac564,0x2ac584),(0x1f48a4,0x1f48e8),(0x2a1300,0x2a1344),(0x225a60,0x225a90),(0x225ab0,0x225ae0),(0x225f4c,0x225f8e),(0x1f3f90,0x1f3fc0),(0x1f46c4,0x1f46fc)]
    listing=''.join(disasm(a,b)for a,b in spans);(out/'gnu_verified.txt').write_text(listing)
    checks={0x1f459a:';0x21a0d0',0x21a114:';0x2a3360',0x21a14e:';0x2ac528',0x21a10a:'st.as\tr1,[r0,180]',0x21a17c:'st.as\tr14,[r0,180]',0x21a15c:'sth\tr16,[r13,44]',0x225ab2:';0x1f35d4',0x225f66:';0x1f3608',0x1f3faa:';0x1f35d4',0x1f3fbc:';0x1f3608',0x1f46f4:';0x1f35d4'}
    for a,s in checks.items():
        lines=[line for line in listing.splitlines()if re.match(rf'\s*{a:x}:',line)];assert len(lines)==1 and s in lines[0],(hex(a),s,lines)
    assert [u32(a)for a in [0x21a314,0x21a318,0x21a31c,0x2a13ec]]==[0x1a00004,0x1a0000e,0x1a00006,0x1a0000c]
    candidate=ROOT/'Ghidra_Results/ghidra_reports/ptp_usb_audit/block00_linear_candidates.txt'
    calls=[line.strip()for line in candidate.read_text().splitlines()if re.search(r';0x(?:1f35d4|1f3608)\b',line)]
    assert len(calls)==5
    pointers={}
    for target in [0x1f35d4,0x1f3608]:
        pointers[hex(target)]={}
        le=target.to_bytes(4,'little')
        for encoding,needle in [('LE32',le),('ARC_LIMM',le[2:]+le[:2])]:
            hits=[]
            for b in BS:
                data=PS[b['index']];start=0
                while (at:=data.find(needle,start))>=0:
                    hits.append({'payload':b['index'],'cpu':hex(b['load_address_candidate']+at)});start=at+1
            pointers[hex(target)][encoding]=hits
    (out/'backend_helper_candidates.json').write_text(json.dumps({'source':str(candidate.relative_to(ROOT)),'source_sha256':sha(candidate.read_bytes()),'main_linear_calls':calls,'all16_payload_byte_patterns':pointers,'limit':'Calls are Main linear candidates; no general negative for indirect/computed calls or other writers'},indent=2)+'\n')
    assert all(sha((ROOT/p).read_bytes())==h for p,h in inputs.items())
    result=dict(status='PASS_ORIGINAL_EXISTING_READ_OPEN_AND_VOLUME_PIN',cpu_cases=12,gnu_windows=len(spans),instruction_checks=len(checks),sources=inputs,payload_hashes={str(b['index']):b['sha256']for b in blocks},
        original_bodies=['1F43AC parser r/r+ ->21A0D0','2AC528 and list add/remove','1F48A4 file/volume close and21AD30','225A60 occupied-list refusal','Original semaphore/critical primitives, memcpy and millicode'],
        fixtures=['Lookup2A3360 supplies existing32-byte directory entry or explicit01A00002; not physical directory traversal','File pool2F7ABC supplies zeroed80-byte objects or null; pool release is recorder','Clock21B300 zeros, cache predicate21A424 zero and dirty field0','Volume ioctl3 succeeds','Generic wrappers prepared directly; no generic upper open/close','One combined case uses parent n-create fixture2AC2B4, not physical exclusive creation'],
        conclusions=['r reaches lookup2A3360 with r5=0; read execution rejects any visit to create2AC2B4','r object mode0 and r+ mode2; directory/volume attrs18 refused, read-only attr1 accepted by r but refused by r+','Read object increments context+108 and blocks tested volume close/225A60 until released','Lookup error, pool null and not-ready return respective errors without a file object','Context+720 search flag cleared before post on tested lookup/attribute/allocator returns','One retained r object survives n open/close using a distinct output filename; list2->1 keeps volume-close refusal, then read close permits it'],
        limits=['Prepared sequential mounted backend1 only; no proof of complete filesystem, physical read-only I/O or all backend mutation paths','Lookup and cache are fixtures; do not infer zero media writes or missing-file semantics from supplied error alone','No scheduler, real pool, generic wrappers lifetime or crash persistence','No installation-ready dumper or complete physical RAM map'])
    (out/'verified_evidence.json').write_text(json.dumps(result,indent=2)+'\n');(out.parent/'latest.json').write_text(json.dumps({'evidence':str((out/'verified_evidence.json').relative_to(ROOT))},indent=2)+'\n');print(trace,end='');print(out)


if __name__=='__main__':main()
