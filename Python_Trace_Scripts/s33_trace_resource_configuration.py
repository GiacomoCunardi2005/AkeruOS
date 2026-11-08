#!/usr/bin/env python3
"""S33 V1.1 offline resource-configuration storage and AutoScene branch evidence."""
import json
import re
import struct
import tempfile
from pathlib import Path
from s33_trace_state_dispatch import verified_payloads, run, sha

ROOT=Path(__file__).resolve().parents[1]
WINDOWS=[
 (0,0x1435FC,0x1436A2,'ConfigurationCompareStoreAndReset'),
 (0,0x1436A4,0x1436AA,'ConfigurationGetter'),
 (0,0x2019C0,0x2019DC,'SeparateByteSetter'),
 (0,0x2019DC,0x2019E4,'SeparateByteGetter'),
 (0,0xCFE18,0xCFE52,'ZeroOrOneConfigurationPredicate'),
 (0,0xCA384,0xCA388,'PredicateReturnTrampoline'),
 (0,0x15AD44,0x15AD4C,'PredicateFirstByteGetter'),
 (0,0x16F920,0x16F928,'LogicalControlReadWithDelaySlot'),
 (0,0x13901C,0x139030,'ConfigurationZeroCaller'),
 (2,0x6528D0,0x6528F0,'ConfigurationPredicateCaller'),
 (2,0x659712,0x659804,'AutoSceneAlternativeBranches'),
 (2,0x664C58,0x664C82,'ConfigurationTwoCaller'),
 (4,0x7C941C,0x7C945E,'ConfigurationZeroBlockFourCaller'),
]


def main():
    blocks,payloads,block_dir=verified_payloads(ROOT)
    info={b['index']:b for b in blocks}
    out=ROOT/'Ghidra_Results/ghidra_reports/resource_configuration'
    out.mkdir(parents=True,exist_ok=True)
    tools=ROOT/'work/build-arc/binutils'
    def word(i,a):
        ofs=a-info[i]['load_address_candidate']
        assert 0<=ofs<=len(payloads[i])-4
        return struct.unpack_from('<I',payloads[i],ofs)[0]
    assert word(0,(0x14360E&~3)-130*4)==0x366E24
    assert word(0,0x1436AC)==0x366E24+8==0x366E2C
    assert word(1,0x366E2C)==0
    assert word(0,(0x2019C8&~3)-79*4)==0x369624
    assert word(0,0x2019E4)==0x369624+16==0x369634
    assert payloads[1][0x369634-info[1]['load_address_candidate']:0x369636-info[1]['load_address_candidate']]==bytes([0,255])
    assert word(0,0x15AEE8)==0x367390
    assert word(0,0x16FA34)+4*0x66==0x4469A0
    listings=[];roundtrips=[]
    with tempfile.TemporaryDirectory(prefix='s33-config-') as td:
        for i in (0,2,4):
            elf,back=Path(td)/f'{i}.elf',Path(td)/f'{i}.bin'
            run([tools/'objcopy','-I','binary','-O','elf32-littlearc','-B','arc',
                 '--rename-section','.data=.text,alloc,load,readonly,code,contents',
                 '--change-section-vma',f'.data={info[i]["load_address_candidate"]:#x}',
                 '--strip-all',block_dir/info[i]['file'],elf])
            run([tools/'objcopy','--dump-section',f'.text={back}',elf])
            assert back.read_bytes()==payloads[i];roundtrips.append(i)
            for bi,start,end,label in WINDOWS:
                if i!=bi:continue
                t=run([tools/'objdump','-d','-m','arc:ARC700','-EL',f'--start-address={start:#x}',f'--stop-address={end:#x}',elf])
                assert 'out of bounds' not in t.lower(),label
                listings.append(f'WINDOW BLOCK {i} {label}\n'+t.replace(str(elf),f'verified-block{i}.elf'))
    listing='\n'.join(listings)
    def line(a):
        hits=[l for l in listing.splitlines() if re.match(rf'^\s*{a:x}:',l)]
        assert len(hits)==1,(hex(a),hits)
        return hits[0]
    checks={0x143616:('beq_s',';0x143696'),0x143624:('st_s','r13,[r14,0x8]'),
            0x2019CE:('stb_s','r0,[r2,0x10]'),0x2019D0:('stb_s','r1,[r2,0x11]'),
            0x659732:('mov_s','r0,0x2'),0x6597C2:('mov_s','r0,0'),
            0x659764:('b_s',';0x659804'),0x659770:('beq_s',';0x659804'),
            0x6597A2:('beq_s',';0x659804'),0x6597B4:('beq_s',';0x659804'),
            0x6597C0:('b_s',';0x659758'),0xCFE46:('bne_s',';0xcfe4c'),
            0x16F926:('ldb_s','r0,[r1,0]')}
    for a,(opcode,operand) in checks.items():assert f'\t{opcode}\t' in line(a) and operand in line(a),line(a)
    edges=[(0x143618,0x15A5C8),(0x143620,0x141DD0),(0x143670,0x18E41C),
           (0x13902C,0x1435FC),(0x6528E8,0x1435FC),(0x659734,0x1435FC),
           (0x659800,0x1435FC),(0x664C76,0x1435FC),(0x7C9448,0x1435FC),
           (0x6597C4,0x2019C0),(0x6597F2,0xCFE18),(0xCFE1A,0x15AD44),
           (0xCFE24,0x16F920)]
    for site,target in edges:assert f';0x{target:x}' in line(site),line(site)
    # Bind negative leaf conclusion to its entire instruction interval, not a sample.
    leaf=listing.split('WINDOW BLOCK 0 SeparateByteSetter\n')[1].split('WINDOW ')[0]
    assert not re.search(r'\t(?:bl(?:_s)?(?:\.[a-z]+)?|jl(?:_s)?(?:\.[a-z]+)?)\t',leaf)
    literal_hits=[]
    for b in blocks:
        d=payloads[b['index']]
        for value in (0x366E24,0x366E2C):
            start=0
            while (off:=d.find(struct.pack('<I',value),start))>=0:
                literal_hits.append(dict(block=b['index'],address=hex(b['load_address_candidate']+off),value=hex(value)));start=off+1
    result=dict(firmware='S33 V1.1 static only',verified_blocks=16,
        script_sha256=sha(Path(__file__).read_bytes()),block_sha256={str(b['index']):b['sha256'] for b in blocks},
        elf_roundtrip_blocks=roundtrips,windows=[dict(block=i,start=hex(a),end=hex(b),label=l) for i,a,b,l in WINDOWS],
        configuration=dict(context='0x366e24',field='0x366e2c',sample_initial_value=0,getter='0x1436a4',checked_writer='0x143624',literal_hits=literal_hits),
        separate_byte_setter=dict(entry='0x2019c0',stores={'0x369634':'low byte of r0','0x369635':'0xff'},contains_calls=False),
        configuration_predicate=dict(entry='0xcfe18',inhibit_byte='0x367390',logical_control_byte='0x4469a0',accepted_modes=['0x2c','0x6d','0x7d'],
                                     limitation='Multiple mode reads; single-mode expression requires stability'),
        checked_edges=[dict(site=hex(a),target=hex(b)) for a,b in edges],
        observations=['AutoScene 2 and 0/1 configuration requests are alternative local branches',
                      'Same configuration skips local wait/discard/reset in 0x1435fc',
                      '0x2019c0 has only two explicit byte stores and no buffer operations or nested calls'],
        limits=['Initial bytes are firmware payload values, not observed running RAM',
                'Literal inventory does not cover computed/aliased pointer writes',
                'No whole-program proof of recovery or descriptor-exhaustion reachability',
                'Static V1.1 addresses do not establish hardware V1.0 compatibility'])
    (out/'gnu_verified.txt').write_text(listing)
    (out/'verified_evidence.json').write_text(json.dumps(result,indent=2)+'\n')
    print(f'PASS: 16 hashes, {len(roundtrips)} roundtrips, {len(WINDOWS)} windows, {len(edges)} edges, {len(checks)} instruction checks')

if __name__=='__main__':main()
