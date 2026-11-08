#!/usr/bin/env python3
"""Offline, bounded inventory of current-acquisition writers and call candidates."""
import concurrent.futures
import json
import re
import struct
import tempfile
from pathlib import Path
from s33_trace_state_dispatch import verified_payloads, run, sha

ROOT = Path(__file__).resolve().parents[1]
OUT = ROOT / 'Ghidra_Results/ghidra_reports/current_acquisition'
TARGETS = {0x18E1AC, 0x18E41C, 0x18E8FC, 0x18EA10, 0x18EE50, 0x18F66C, 0x1435FC}
WINDOWS = [
 (2,0x659712,0x659804,'AutoSceneReconfigurationCalls'),
 (0,0x1435FC,0x1436A2,'ReconfigureResourcesAndReset'),
 (0,0xC6440,0xC644C,'ConstantDescriptorCounts'),
 (0,0x13901C,0x139030,'ReconfigureZeroCaller'),
 (2,0x655320,0x65534E,'DescriptorCountTwentyOrTwelveOrEleven'),
 (2,0x65AD82,0x65AD9A,'DescriptorCountTwelveOrEleven'),
 (0,0x18E1AC,0x18E1C4,'SetDescriptorCount'),
 (0,0x18E41C,0x18E4A8,'ResetResourceContext'),
 (0,0x18E4B4,0x18E5D4,'PoolInitializationWriters'),
 (0,0x18E8FC,0x18E968,'AcquireOrReturnCurrentAcquisition'),
 (0,0x18EA10,0x18EA48,'PublishCurrentAcquisitionUnderLock'),
 (0,0x18EE50,0x18EE74,'PublishCurrentAcquisitionWrapper'),
 (0,0x18EE98,0x18EF44,'ProcessingContextAliasOne'),
 (0,0x18EF44,0x18EFC2,'ProcessingContextAliasTwo'),
 (0,0x18F260,0x18F30C,'ProcessingFinalizerAlias'),
 (0,0x18F66C,0x18F6BC,'RecyclePendingProcessingNode'),
 (2,0x65F608,0x65F9E0,'OutcomeEventErrorStateZero'),
]


def main():
    blocks,payloads,block_dir=verified_payloads(ROOT)
    info={b['index']:b for b in blocks}
    tools=ROOT/'work/build-arc/binutils'
    OUT.mkdir(parents=True,exist_ok=True)
    def word(i,a):return struct.unpack_from('<I',payloads[i],a-info[i]['load_address_candidate'])[0]
    assert [word(0,a) for a in [0x18E4AC,0x18E5D8,0x18EA4C,0x18EE48,0x18F220,0x18F30C,0x18F7A4]] == [0x368024]*7
    assert word(0,0x18E1C4)==0x368058
    assert word(0,(0x18E91A&~3)-208*4)==0x368024
    assert word(0,(0x18F67C&~3)-220*4)==0x368024
    hits=[];listings=[];roundtrips=[]
    with tempfile.TemporaryDirectory(prefix='s33-current-') as td:
        def scan(i):
            elf,back=Path(td)/f'{i}.elf',Path(td)/f'{i}.bin'
            run([tools/'objcopy','-I','binary','-O','elf32-littlearc','-B','arc',
                 '--rename-section','.data=.text,alloc,load,readonly,code,contents',
                 '--change-section-vma',f'.data={info[i]["load_address_candidate"]:#x}',
                 '--strip-all',block_dir/info[i]['file'],elf])
            run([tools/'objcopy','--dump-section',f'.text={back}',elf])
            assert back.read_bytes()==payloads[i]
            full=run([tools/'objdump','-d','-m','arc:ARC700','-EL',elf])
            candidates=[]
            for l in full.splitlines():
                m=re.match(r'^\s*([a-f0-9]+):.*\t(b(?:l)?(?:_s)?(?:\.[a-z]+)?)\t.*;0x([a-f0-9]+)\s*$',l)
                if m and int(m[3],16) in TARGETS:
                    candidates.append(dict(block=i,site=hex(int(m[1],16)),target=hex(int(m[3],16)),line=l.strip()))
            selected=[]
            for bi,start,end,label in WINDOWS:
                if bi!=i:continue
                t=run([tools/'objdump','-d','-m','arc:ARC700','-EL',f'--start-address={start:#x}',f'--stop-address={end:#x}',elf])
                assert 'out of bounds' not in t.lower(),label
                selected.append(f'WINDOW BLOCK {i} {label}\n'+t.replace(str(elf),f'verified-block{i}.elf'))
            return i,candidates,selected
        with concurrent.futures.ThreadPoolExecutor(max_workers=3) as executor:
            for i,candidates,selected in executor.map(scan,range(11)):
                hits.extend(candidates);listings.extend(selected);roundtrips.append(i)
                print(f'Block {i:02}: roundtrip OK, {len(candidates)} branch candidates',flush=True)
    listing='\n'.join(listings)
    def line(a):
        found=[l for l in listing.splitlines() if re.match(rf'^\s*{a:x}:',l)]
        assert len(found)==1,(hex(a),found)
        return found[0]
    stores={0x18E452:('st_s','r13,[r14,0x1c]'),0x18E592:('st','r19,[r1,28]'),
            0x18E5AA:('st','r19,[r1,28]'),0x18E94E:('st_s','r13,[r14,0x1c]'),
            0x18EA38:('st_s','r15,[r14,0x1c]'),0x18EE6A:('st_s','r1,[r13,0x1c]')}
    for a,(opcode,operands) in stores.items():
        assert f'\t{opcode}\t{operands}' in line(a),line(a)
    edges=[(0x18E946,0x277244),(0x18EA32,0x27722C),(0x18EE66,0x18E9D0),
           (0x18F68A,0x18E8B4),(0x18F698,0x18E9D0),(0x18F6B2,0x141D80),
           (0x143618,0x15A5C8),(0x143620,0x141DD0),(0x14366A,0x18E1AC),
           (0x143670,0x18E41C),(0x143680,0x18E1AC),(0x14368E,0x18E1AC),
           (0x13902C,0x1435FC),(0x655330,0x18E1AC),(0x65AD96,0x18E1AC),
           (0x659728,0x15A5C8),(0x659734,0x1435FC),(0x659800,0x1435FC)]
    for site,target in edges:assert f';0x{target:x}' in line(site),line(site)
    for a,v in [(0xC6440,12),(0xC6444,11),(0xC6448,9),(0x65532E,20),(0x659732,2)]:
        assert f'mov_s\tr0,0x{v:x}' in line(a),line(a)
    pointer_candidates=[]
    for b in blocks:
        for target in sorted(TARGETS):
            le=struct.pack('<I',target)
            for encoding,needle in [('LE32',le),('ARC_halfword_order',le[2:]+le[:2])]:
                start=0
                while (offset:=payloads[b['index']].find(needle,start)) >= 0:
                    pointer_candidates.append(dict(block=b['index'],address=hex(b['load_address_candidate']+offset),target=hex(target),encoding=encoding))
                    start=offset+1
    (OUT/'pointer_candidates.json').write_text(json.dumps(pointer_candidates,indent=2)+'\n')
    (OUT/'gnu_verified.txt').write_text(listing)
    (OUT/'branch_candidates.json').write_text(json.dumps(hits,indent=2)+'\n')
    result=dict(firmware='S33 V1.1 static only',verified_blocks=16,
        script_sha256=sha(Path(__file__).read_bytes()),block_sha256={str(b['index']):b['sha256'] for b in blocks},
        candidate_scan_blocks=roundtrips,elf_roundtrip_blocks=roundtrips,
        candidate_count=len(hits),pointer_candidate_count=len(pointer_candidates),windows=[dict(block=i,start=hex(a),end=hex(b),label=l) for i,a,b,l in WINDOWS],
        current_pointer='0x368040 = 0x368024+0x1c',
        verified_store_sites=[hex(a) for a in stores],
        processing_alias_stores=['0x18ef2e','0x18ef6a','0x18f29c'],
        observations={
         'descriptor_counts':'Reconfiguration selects 12/9/11; two block-02 callers also write count, including conditional 20 at 0x65532e',
         'autoscene':'0x659734 requests configuration 2 under mode/flag/discriminant guards; 0x659800 requests 0 or 1 from 0xcfe18; same-configuration guard can skip reset',
         'reconfiguration':'0x1435fc skips equal configuration; otherwise waits ImgMgr, attempts discard, stores configuration and resets context via 0x18e41c; wait/discard results not tested locally',
         'reset':'0x18e41c and newly prepared pool zero current pointer; already-active pool bypasses reset',
         'acquire_or_current':'0x18e8fc pops A only when current null; clear at 0x18e94e follows pop error, not an existing nonnull acquisition',
         'publish':'0x18ea10 and 0x18ee50 publish current node to B and clear current even when push fails',
         'recycle':'0x18f66c pops B into processing+0x20, pushes A, clears processing only on success; no current-acquisition clear',
         'aliases':'stores using r14+0x1c in processing callbacks refer to incoming processing context, not resource global',
        },
        limits=['Branch candidates from linear disassembly are not verified call sites until anchored review',
                'Candidate scan covers blocks 00-10 only, excludes overlays 11-15 and indirect calls',
                'Literal aliases and six selected stores are verified, not an exhaustive proof of all writers',
                'Global recovery, runtime reachability and absence of leaks remain unproven'])
    (OUT/'verified_evidence.json').write_text(json.dumps(result,indent=2)+'\n')
    print(f'PASS: 16 hashes, {len(roundtrips)} roundtrips, {len(WINDOWS)} windows, {len(stores)} stores, {len(hits)} branch candidates')

if __name__=='__main__':main()
