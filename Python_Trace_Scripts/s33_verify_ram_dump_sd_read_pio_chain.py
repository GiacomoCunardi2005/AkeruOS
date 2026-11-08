#!/usr/bin/env python3
"""Original multi-sector/multi-cluster lookup with synthetic FAT and device callbacks."""
from datetime import datetime, timezone
from pathlib import Path
import json, re, subprocess, sys, tempfile
from s33_trace_state_dispatch import verified_payloads, sha
ROOT=Path(__file__).resolve().parents[1]


def main():
    blocks,payloads,_=verified_payloads(ROOT)
    out=ROOT/'Risultati/Runtime_Kernel/RAM_Dumper_SD_Read_PIO_Chain'/datetime.now(timezone.utc).strftime('%Y%m%dT%H%M%SZ');out.mkdir(parents=True,exist_ok=False)
    scripts=ROOT/'S33-sections/analysis_ghidra/scripts'
    sources=[Path(__file__)]+[scripts/n for n in ['ProbeDumpSDReadPIOChain.java','ProbeDumpSDReadSDChain.java','ProbeDumpSDReadChain.java','ProbeDumpSDChain.java','ProbeDumpSDLookupTree.java','ProbeDumpSDLookup.java','ProbeDumpSDMutex.java','ProbeStatusRead.java']]
    inputs={str(p.relative_to(ROOT)):sha(p.read_bytes())for p in sources}
    for p in sources:(out/(p.name+'.snapshot')).write_bytes(p.read_bytes())
    with tempfile.TemporaryDirectory(prefix='s33-sd-tree-')as td:
        temp=Path(td)
        for i in (0,1):(temp/f'p{i}.bin').write_bytes(payloads[i])
        cmd=[str(ROOT/'tools/ghidra-arcompact/ghidra_12.2_DEV/support/analyzeHeadless'),str(temp),'tree','-import',str(temp/'p0.bin'),'-loader','BinaryLoader','-loader-baseAddr','0xad800','-processor','ARCompact:LE:32:loopfix','-noanalysis','-scriptPath',str(scripts),'-postScript','ProbeDumpSDReadPIOChain.java',str(out/'trace.txt'),str(temp/'p1.bin'),'-deleteProject']
        (out/'command.json').write_text(json.dumps(cmd,indent=2)+'\n')
        r=subprocess.run(cmd,stdout=subprocess.PIPE,stderr=subprocess.STDOUT,text=True,timeout=180);(out/'headless.log').write_text(r.stdout)
        assert r.returncode==0 and 'SCRIPT ERROR'not in r.stdout,r.stdout[-4000:]
        trace=(out/'trace.txt').read_text();assert trace.endswith('COMPLETE cases=13\n')and trace.count('PASS ')==13
    sys.path.insert(0,str(ROOT/'S33-sections/analysis_codex'))
    from static_common import disasm, u32
    spans=[(0x2a3360,0x2a358c),(0x29ff74,0x2a005c),(0x2a0484,0x2a04b0),(0x2a47c4,0x2a47e8),(0x2a461c,0x2a4694),(0x259a58,0x259afc),(0x2a318c,0x2a3244),(0x2a3250,0x2a3360),(0x2a0444,0x2a0468),(0x2a2d88,0x2a318c),(0x2a017c,0x2a01ac),(0x2a01ac,0x2a0268),(0x2a0144,0x2a017c),(0x2a1178,0x2a1270),(0x2a10f4,0x2a1124),(0x2a113c,0x2a1178),(0x3342a8,0x3342cc),(0x2a0c14,0x2a0c60),(0x2a0c60,0x2a0d50),(0x2a0d56,0x2a0d70),(0x1f3524,0x1f3554),(0x226204,0x22624c),(0x2abc68,0x2abcd4),(0x1f2484,0x1f250c),(0x1f250c,0x1f25d8),(0x1f25d8,0x1f271c),(0x1f2734,0x1f277c),(0x335b34,0x335c4c)]
    spans += [(0x1f43ac,0x1f43f0),(0x1f4586,0x1f45a4),(0x21a0d0,0x21a190),(0x1f48a4,0x1f48e8),(0x1f4834,0x1f4894),(0x1f36c0,0x1f3708)]
    spans += [(0x2a0870,0x2a0890),(0x2a0504,0x2a0534),(0x2a0594,0x2a05f4),(0x1681d0,0x16827c),(0x2a0a14,0x2a0a46),(0x2a0a52,0x2a0a86),(0x2a0b16,0x2a0b24),(0x2a0ab0,0x2a0ab6),(0x2a0af2,0x2a0afa)]
    spans += [(0xb15b4,0xb16d0),(0xb16d0,0xb1704),(0xb1710,0xb17b0),(0x2e509c,0x2e50cc),(0x2e514c,0x2e51e4),(0x2e52e8,0x2e52f4),(0x25aa54,0x25aa8c),(0x25a690,0x25a74c),(0x25a74c,0x25a83c),(0x25a658,0x25a690),(0x25a084,0x25a098),(0x25a0bc,0x25a0d0),(0x25a41c,0x25a430)]
    listing=''.join(disasm(a,b)for a,b in spans);(out/'gnu_verified.txt').write_text(listing)
    checks={0x2a33aa:';0x29ffb0',0x2a344e:';0x2a318c',0x2a353a:';0x2a2d88',0x2a354c:'st\tr1,[r17]',0x259aa0:';0x2e4ec4',0x2a3268:';0x2a2d88',0x2a3272:';0x2a3316',0x2a3298:'and.f\tr0,r0,r4',0x2a30e6:';0x2abc68',0x2a30ec:'cmp_s\tr0,0',0x2a30ee:'bne_s',0x2a317e:'ld_s\tr1,[sp,0x2c]',0x2a3180:'st_s\tr1,[r0,0]',0x1f26b2:'bls'}
    for a,s in checks.items():
        lines=[line for line in listing.splitlines()if re.match(rf'\s*{a:x}:',line)];assert len(lines)==1 and s in lines[0],(hex(a),s,lines)
    assert [u32(a)for a in [0x2a3710,0x2a3718,0x2a371c,0x2a3720]]==[0x1a00006,0x1a00003,0x1a00002,0x1a00013]
    assert all(sha((ROOT/p).read_bytes())==h for p,h in inputs.items())
    result=dict(status='PASS_ORIGINAL_READ_FAT_SD_ENGINES_PIO_MMIO_AND_CLOSE',cpu_cases=13,returned_cases=12,bounded_cycle_observations=1,gnu_windows=len(spans),instruction_checks=len(checks),sources=inputs,payload_hashes={str(b['index']):b['sha256']for b in blocks},
        original_bodies=['2A3360 coordinator and parser','2A318C directory walker','2A2D88 scanner including original2ABC68 advancement','1F25D8 FAT reader,1F250C window load and clean1F2484','2A1178 sector reader,2A0C60 lower transfer,226204 seek and1F3524 dispatch','Original unsigned division335B34 and allocation critical counters','1F43AC/21A0D0 read-open,2AC528/2AC564 object list,1F48A4 file/volume close and1F36C0 FAT-buffer release','PMSD2A0870/2A0A14,DEVSD2A0504/2A0594,16825C/1681D0 SD read adapter','B15B4/B16D0 read engines,2E514C preparation,2E509C descriptors,2E52E8/25AA54,25A74C PIO and25A658 completion'],
        fixtures=['Prepared FAT12 volume:512-byte sectors,16records/sector,2sectors/cluster,root100/101,data102,FAT20/21','Original MMIO loads receive synthetic status and sector halfwords; no host buffer fill at engine boundary;25B63C recovery succeeds','2E52F4 command results supplied with setup response3;25AA8C control recorded; no command MMIO or real hardware','Prepared PMSD offset2048/block units;original2015 selects partition1 from FS context while PM semaphore held;DEVSD row0 raw-handle identity and bypass flag0 supplied','3342A8 modulo32 product; DSP semantics not established','2E4EC4 supplies guarded zero scratch; metadata/free recorders; external caches and fastpath disabled','Prepared r wrapper, mounted context/list and semaphore;2F7ABC zeroed80-byte object,2F7AF0 release recorder; clock/dirty and close ioctl3 fixtures','Context+788=1 declares prepared FAT buffer owned; all four buffer releases recorded once under semaphore on normal returns'],
        conclusions=['Original PM2015/2016 bracket and semaphore execute inside FS semaphore; balance asserted including aborted cycle with one outstanding bracket','Original PIO stores populate sector/FAT buffers from actual halfword MMIO load instructions; stream consumption and final32-byte file identity asserted','PMSD translates positions through original seek and DEVSD returns requested count or0; SD adapter retries each injected I/O failure three times','Successful r registers expected32-byte record, blocks volume close until file release, then frees four owned buffers; errors register no file','Synthetic FAT0 fallback is accepted by r as a real root file with list count1','Root exhaustion without end marker attempts position102 and returns01A0000D before lower device access','Root second sector, second sector within cluster, one/two FAT hops and nested lookup verified through final record bytes and metadata','FAT PIO errorE01510 reaches scanner but lookup returns01A00002; last successful data-read status reused','Synthetic corrupt FAT entry0 redirects subdirectory lookup to root and returns root TARGET.BIN with status0','ThresholdFF8 retained by FAT decoder; following it hits sector-reader bounds and returns01A0000D','Cycle2to3to2 repeats data sectors; bounded observation stops at twelfth callback without normal return'],
        limits=['Cycle observation deliberately stopped while call active; fixture allocations disposed with emulator, not normal cleanup proof','No long names/DCIM, cache-list path, concurrent task, physical MMIO or persistence','Full r/lookup/FAT/PMSD/DEVSD/read-engine/PIO/close integrated;command dispatcher results,control,recovery,upper generic wrapper,mount,dirty writeback and physical exclusive creation not covered','No full RAM map or installable dumper'])
    (out/'verified_evidence.json').write_text(json.dumps(result,indent=2)+'\n');(out.parent/'latest.json').write_text(json.dumps({'evidence':str((out/'verified_evidence.json').relative_to(ROOT))},indent=2)+'\n');print(trace,end='');print(out)


if __name__=='__main__':main()
