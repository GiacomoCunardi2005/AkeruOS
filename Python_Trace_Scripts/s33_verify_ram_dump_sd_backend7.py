#!/usr/bin/env python3
"""Original backend7 initialization on a local exFAT image, with explicit sector boundary."""
from datetime import datetime, timezone
from pathlib import Path
import hashlib,json,subprocess,tempfile
from s33_trace_state_dispatch import verified_payloads,sha
ROOT=Path(__file__).resolve().parents[1]

def main():
    blocks,payloads,_=verified_payloads(ROOT)
    out=ROOT/'Risultati/Runtime_Kernel/RAM_Dumper_SD_Backend7'/datetime.now(timezone.utc).strftime('%Y%m%dT%H%M%SZ')
    out.mkdir(parents=True,exist_ok=False)
    image=out/'exfat_input.img'
    with image.open('xb') as f:f.truncate(64*1024*1024)
    mkfs=subprocess.run(['/usr/bin/mkfs.exfat','-P','none','-s','512','-c','4096','-L','AKERULAB',str(image)],capture_output=True,text=True)
    (out/'mkfs.log').write_text(mkfs.stdout+mkfs.stderr);assert mkfs.returncode==0
    scripts=ROOT/'S33-sections/analysis_ghidra/scripts'
    sources=[Path(__file__)]+[scripts/n for n in ['ProbeDumpSDBackend7.java','ProbeDumpSDFileLifecycle.java','ProbeDumpSDFileWrite.java','ProbeDumpSDWritePartition.java','ProbeDumpSDWriteAsync.java','ProbeDumpSDReadArbitration.java','ProbeDumpSDReadStatus.java','ProbeDumpSDMutex.java','ProbeStatusRead.java']]
    inputs={str(p.relative_to(ROOT)):sha(p.read_bytes()) for p in sources}
    for p in sources:(out/(p.name+'.snapshot')).write_bytes(p.read_bytes())
    with tempfile.TemporaryDirectory(prefix='s33-backend7-') as td:
        temp=Path(td)
        for i in (0,1):(temp/f'p{i}.bin').write_bytes(payloads[i])
        cmd=[str(ROOT/'tools/ghidra-arcompact/ghidra_12.2_DEV/support/analyzeHeadless'),str(temp),'backend7','-import',str(temp/'p0.bin'),'-loader','BinaryLoader','-loader-baseAddr','0xad800','-processor','ARCompact:LE:32:loopfix','-noanalysis','-scriptPath',str(scripts),'-postScript','ProbeDumpSDBackend7.java',str(out/'trace.txt'),str(temp/'p1.bin'),str(image),'-deleteProject']
        (out/'command.json').write_text(json.dumps(cmd,indent=2)+'\n')
        r=subprocess.run(cmd,stdout=subprocess.PIPE,stderr=subprocess.STDOUT,text=True,timeout=300)
        (out/'headless.log').write_text(r.stdout)
        assert r.returncode==0 and 'SCRIPT ERROR' not in r.stdout,r.stdout[-7000:]
    trace=(out/'trace.txt').read_text();assert trace.endswith('COMPLETE cases=1\n')
    assert all(sha((ROOT/p).read_bytes())==v for p,v in inputs.items())
    result=dict(status='PASS_ORIGINAL_BACKEND7_INITIALIZER',cpu_cases=1,sources=inputs,input_image_sha256=sha(image.read_bytes()),trace=trace,payload_hashes={str(b['index']):b['sha256'] for b in blocks},limits=['Sector2A0C60 explicit host copy,notSDcontroller;nohardware','Workspaceglobal pointers explicitlyprovided,notoriginalallocation/mount','Nooriginalbackend7fileoperationtested yet;NON_INSTALLARE'])
    (out/'verified_evidence.json').write_text(json.dumps(result,indent=2)+'\n')
    (out.parent/'latest.json').write_text(json.dumps(dict(evidence=str((out/'verified_evidence.json').relative_to(ROOT))),indent=2)+'\n')
    print(trace,end='');print(out)
if __name__=='__main__':main()
