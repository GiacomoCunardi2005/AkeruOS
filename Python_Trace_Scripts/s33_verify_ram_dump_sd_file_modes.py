#!/usr/bin/env python3
"""Original open modes on a synthetic FAT card and the closed backend7 ready gate."""
from datetime import datetime, timezone
from pathlib import Path
import json, re, struct, subprocess, sys, tempfile
from s33_trace_state_dispatch import verified_payloads, sha
ROOT=Path(__file__).resolve().parents[1]


def main():
    blocks,payloads,_=verified_payloads(ROOT)
    out=ROOT/'Risultati/Runtime_Kernel/RAM_Dumper_SD_File_Modes'/datetime.now(timezone.utc).strftime('%Y%m%dT%H%M%SZ')
    out.mkdir(parents=True,exist_ok=False)
    scripts=ROOT/'S33-sections/analysis_ghidra/scripts'
    sources=[Path(__file__)]+[scripts/n for n in ['ProbeDumpSDFileModes.java','ProbeDumpSDFileLifecycle.java','ProbeDumpSDFileWrite.java','ProbeDumpSDWritePartition.java','ProbeDumpSDWriteAsync.java','ProbeDumpSDReadArbitration.java','ProbeDumpSDReadStatus.java','ProbeDumpSDMutex.java','ProbeStatusRead.java']]
    inputs={str(p.relative_to(ROOT)):sha(p.read_bytes()) for p in sources}
    for p in sources:(out/(p.name+'.snapshot')).write_bytes(p.read_bytes())
    with tempfile.TemporaryDirectory(prefix='s33-sd-modes-') as td:
        temp=Path(td)
        for i in (0,1):(temp/f'p{i}.bin').write_bytes(payloads[i])
        cmd=[str(ROOT/'tools/ghidra-arcompact/ghidra_12.2_DEV/support/analyzeHeadless'),str(temp),'modes','-import',str(temp/'p0.bin'),'-loader','BinaryLoader','-loader-baseAddr','0xad800','-processor','ARCompact:LE:32:loopfix','-noanalysis','-scriptPath',str(scripts),'-postScript','ProbeDumpSDFileModes.java',str(out/'trace.txt'),str(temp/'p1.bin'),'-deleteProject']
        (out/'command.json').write_text(json.dumps(cmd,indent=2)+'\n')
        r=subprocess.run(cmd,stdout=subprocess.PIPE,stderr=subprocess.STDOUT,text=True,timeout=300)
        (out/'headless.log').write_text(r.stdout)
        assert r.returncode==0 and 'SCRIPT ERROR' not in r.stdout,r.stdout[-6000:]
    trace=(out/'trace.txt').read_text()
    assert trace.endswith('COMPLETE cases=20\n') and trace.count('PASS mode ')==20
    cases={line.split()[2]:dict(re.findall(r'(\w+)=(\S+)',line)) for line in trace.splitlines() if line.startswith('PASS mode ')}
    images={}
    for name,row in cases.items():
        img=(out/(name+'_partition.img')).read_bytes()
        assert len(img)==110*512 and img[510:512]==b'\x55\xaa'
        entries=[]
        for at in range(100*512,102*512,32):
            if img[at]==0:break
            assert img[at]!=0xe5
            entries.append(dict(name=img[at:at+11].decode('ascii'),cluster=struct.unpack_from('<H',img,at+26)[0],size=struct.unpack_from('<I',img,at+28)[0]))
        if name in ['new-r','new-rplus']:assert entries==[]
        else:assert entries and entries[0]['name']=='TARGET  BIN'
        if name.startswith('new-') and not name.startswith(('new-x','new-r')):assert entries[0]['size']==0
        if name.startswith('existing-w'):assert entries[0]['size']==0
        if name.endswith(('-x','-xplus')):
            expected=['TARGET  BIN','TMP00000@@@']+(['TMP00001@@@'] if name.startswith('existing-') else [])
            assert [v['name'] for v in entries]==expected,(name,entries)
            assert entries[-1]['size']==0
        def fat(cluster):
            pair=struct.unpack_from('<H',img,20*512+cluster+cluster//2)[0]
            return pair>>4 if cluster&1 else pair&0xfff
        empty=name in ['new-w','new-wplus','new-n','new-nplus','new-r','new-rplus','existing-w','existing-wplus']
        assert [fat(c) for c in range(2,6)]==([0,0,0,0] if empty else [3,0xfff,0xfff if name in ['existing-x','existing-xplus'] else 0,0]),name
        assert img[102*512:]==b'\xcc'*(8*512),'mode open must not invent data writes'
        if row['status']=='0':
            wanted=2 if name.endswith(('plus','-x')) else 0 if name.endswith('-r') else 1
            assert int(row['privateMode'],16)==wanted,(name,row)
        before=sha(img)
        check=subprocess.run(['/usr/bin/fsck.fat','-n',str(out/(name+'_partition.img'))],stdout=subprocess.PIPE,stderr=subprocess.STDOUT,text=True,timeout=30)
        (out/(name+'_fsck.txt')).write_text(check.stdout)
        assert sha((out/(name+'_partition.img')).read_bytes())==before
        assert check.returncode==0,(name,check.stdout)
        images[name]=dict(sha256=before,entries=entries,fsck_exit=check.returncode,fsck_log_sha256=sha(check.stdout.encode()))
    sys.path.insert(0,str(ROOT/'S33-sections/analysis_codex'))
    from static_common import disasm,u32
    spans=[(0x1f43ac,0x1f4482),(0x1f449a,0x1f4542),(0x1f4574,0x1f46c2),
           (0x2a16f0,0x2a1744),(0x2a1748,0x2a17dc),(0x2a17f4,0x2a1858),
           (0x1f8b44,0x1f8b58),(0x1f9058,0x1f9072),(0x1f35fc,0x1f3608)]
    listing=''.join(disasm(a,b) for a,b in spans)
    (out/'gnu_verified.txt').write_text(listing)
    checks={0x1f44e6:';0x1f8b44',0x1f451a:';0x1f9058',0x1f45f6:';0x2a13f8',0x1f4612:';0x2a1648',
            0x1f457c:';0x2a16f0',0x2a17c2:';0x2ac2b4',0x2a1758:'mov\tr21,0x2',0x2a1822:'sth\tr21,[r13,44]',
            0x1f8b52:';0x1f8d6a',0x1f906c:';0x1f924e',0x1f35fe:'cmp_s\tr0,0x7'}
    for a,token in checks.items():
        hits=[line for line in listing.splitlines() if re.match(rf'\s*{a:x}:',line)]
        assert len(hits)==1 and token in hits[0],(hex(a),token,hits)
    assert u32(0x1f8c34)==u32(0x1f904c)+0x14==0x369400
    assert all(sha((ROOT/p).read_bytes())==h for p,h in inputs.items())
    result=dict(status='PASS_ORIGINAL_FAT_OPEN_MODES_AND_CLOSED_BACKEND7_GATE',cpu_cases=20,returned_cases=20,cases=cases,images=images,gnu_windows=len(spans),instruction_checks=len(checks),sources=inputs,payload_hashes={str(b['index']):b['sha256'] for b in blocks},trace=trace,
        verified=['Original generic registry open/free andclose callbacks;w/w+/n/n+/r/r+/x/x+ onexisting/absent targets withoriginal FAT operations',
                  'x/x+ generateTMP00000.@@@ andskipcollision toTMP00001.@@@ whilepreserving oldentry',
                  'Backend7 n/w andn+/w+ execute sameoriginal create/lookup path;closedreadygate returnsfailure andrestores descriptor slot'],
        fixtures=['Prepared FAT12 geometry/context anddevice registry;heap/pool/clock andmotor MMIO boundaries inheritedfromlifecycle suite',
                  'Backend7 gate369400 explicitlyzero;noopened backend7 volume orsuccessfulbackend7 filesystem operation'],
        limits=['Backend7 live create/truncate semantics andx collision behavior remainunverified;no universal n-as-exclusive contract',
                'No originalmount/fullkernel boot/concurrency/physicalSD/DMA/IRQ proof;NON_INSTALLARE'])
    (out/'verified_evidence.json').write_text(json.dumps(result,indent=2)+'\n')
    (out.parent/'latest.json').write_text(json.dumps(dict(evidence=str((out/'verified_evidence.json').relative_to(ROOT))),indent=2)+'\n')
    print(trace,end='');print(out)


if __name__=='__main__':main()
