#!/usr/bin/env python3
"""Decode supplied NAND metadata and reconstruct the seven logical exports.

Read-only camera/GNU inputs. Original CPU helpers test the observed metadata
decoder, encoder, partition-size extraction and unmapped-page FF behavior.
No ECC correction, NAND controller, physical bad-block diagnosis or boot.
"""
from pathlib import Path
from types import SimpleNamespace
from datetime import datetime, timezone
from collections import Counter
import hashlib
import json
import re
import struct
import sys

from s33_run_gnu_arc700 import ROOT, LEGACY, TOOLCHAIN, Runner, sha
from s33_verify_gnu_dsp_lab import compile_probe
sys.path.insert(0, str(ROOT/'S33-sections/analysis_codex'))
from static_common import BS, PS, disasm, raw, u32, locate

WINDOWS = [(0x16f3a4,0x16f41c), (0x30026c,0x3004f8),
    (0x25ce58,0x25cec4), (0x25cedc,0x25cf10), (0x25cf10,0x25cf6c),
    (0x29dea8,0x29ded0), (0x1ecb0c,0x1ecba4), (0x25c87c,0x25c968),
    (0x25c62e,0x25c63a), (0x25c6bc,0x25c6f0)]
PARTITIONS = [
    ('BootCode.dmp',0xc4,0xd2), ('Calibration.dmp',0xc6,0xd4),
    ('Calibration_2.dmp',0xc8,0xd6), ('CameraParam.dmp',0xca,0xd8),
    ('CameraParam_2.dmp',0xcc,0xda), ('NANDReserved.dmp',0xce,0xdc),
    ('MainCode.dmp',0xd0,0xde)]
FIELD_OFFSETS = [0xae,0xb0,0xb2,0xd2,0xd4,0xd8,0xdc,0xde,0xe8,0xea]


def encode_tag(logical):
    word = 0x1000 | (logical << 1)
    return word | (word.bit_count() & 1)


def tags(spare):
    return [int.from_bytes(spare[g*16+k:g*16+k+2], 'big') for g in range(4) for k in (6,11)]


def main():
    out = ROOT/'Risultati/Dump_fotocamera/Partizioni_Logiche'/datetime.now(timezone.utc).strftime('%Y%m%dT%H%M%SZ')
    r = Runner(SimpleNamespace(legacy_root=LEGACY,toolchain=TOOLCHAIN,output=out,
                              action='nand-logical-metadata-and-complete-partition-exports'))
    print('Evidence:',out,flush=True)
    try:
        r.prepare()
        r.results['assumptions'] = ['Reconstruction from supplied raw records and metadata, no camera connection',
            'Strict clean tags only; differing/redundant metadata is not silently corrected',
            'Missing logical entries filled FF under the separately tested original reader contract',
            'CPU setup uses laboratory pointers/stack and geometry4x512-byte units per page']
        r.results['limits'] = ['No full NAND controller/ECC/chip geometry or recovery certification',
            'No physical bad-block diagnosis from zero or FF export patterns',
            'Missing logical FF data is reader output, not evidence of physical bytes in an unallocated block',
            'No full lookup-table initialization, duplicate resolution, concurrency or complete boot execution',
            'NANDPartition P3 field is not written by the size getter; zero remains observed export state']
        previous=ROOT/json.loads((ROOT/'Risultati/Dump_fotocamera/NAND_Loader/latest.json').read_text())['evidence']
        old=json.loads(previous.read_text());assert old['status']=='PASS_NAND_BOOT_TABLE_AND_CONDITIONAL_HANDOFF'
        for p,h in old['input_hashes'].items():
            assert sha(Path(p))==h,p;r.input_hashes[p]=h
        r.input_hashes[str(previous)]=sha(previous)
        nand=(ROOT/'DUMPS/NANDP1.dmp').read_bytes()
        assert len(nand)==324*64*2112
        table=nand[0x231a:0x240e]
        supplied=(ROOT/'DUMPS/MainCode.dmp').read_bytes()
        spans=[]

        def check_span(a,n):
            b,o=locate(a,n);data=raw(a,n)
            assert supplied[b['offset']+o:b['offset']+o+n]==data,(hex(a),n)
            spans.append(dict(address=hex(a),bytes=n,sha256=hashlib.sha256(data).hexdigest()))

        listings=[];instructions={}
        for a,b in WINDOWS:
            check_span(a,b-a);text=disasm(a,b);listings.append(text)
            for line in text.splitlines():
                m=re.match(r'\s*([0-9a-f]+):\t([^\t]+)\t(\S+)(?:\t(.*))?$',line)
                if m:instructions[int(m[1],16)]=(m[3],(m[4] or '').strip())
        (out/'gnu_verified.txt').write_text('\n'.join(listings))

        def ins(pc,mn,op):
            actual=instructions[pc]
            assert actual[0]==mn and actual[1].split('\t;')[0]==op,(hex(pc),actual)

        for a,v in {0x25c868:0x50e9c0,0x25c86c:0xffff,0x1ecee8:0x36b254,
                    0x25cec4:0x50f52c,0x16f62c:0x4467f0}.items():
            check_span(a,4);assert u32(a)==v
        ins(0x25ce60,'ldb_s','r1,[r0,0x6]');ins(0x25ce62,'ldb_s','r15,[r0,0x7]')
        ins(0x25ce68,'ldb_s','r1,[r0,0xb]');ins(0x25ce6a,'ldb_s','r0,[r0,0xc]')
        ins(0x25ceba,'sth','r15,[r16,4]')
        ins(0x25cf38,'bset_s','r13,r13,0xc');ins(0x25cf3a,'add1_s','r13,r13,r0')
        ins(0x25cf52,'stb_s','r0,[r14,0x6]');ins(0x25cf56,'stb_s','r13,[r14,0x7]')
        ins(0x25c8de,'ldw_s','r0,[r0,0]');ins(0x25c8e0,'stw_s','r0,[r13,0x12]')
        ins(0x25c636,'mov','r2,2000');ins(0x25c6ea,'sth','r19,[r0]')
        ins(0x1ecb32,'ldw_s','r0,[r2,0x2]')
        ins(0x1ecb34,'cmp_s','r0,0xffff');ins(0x1ecb48,'mov_s','r1,0xff')
        logical_map={};block_rows=[];page_stats=Counter();samples=[]
        for physical in range(324):
            block=nand[physical*64*2112:(physical+1)*64*2112]
            spare=block[2048:2112];words=tags(spare)
            clean=len(set(words))==1 and words[0]&0xf000==0x1000 and words[0].bit_count()%2==0
            row=dict(physical_export_block=physical,first_record=physical*64,raw_offset=hex(physical*64*2112))
            if clean:
                logical=(words[0]&0xfff)>>1
                assert logical not in logical_map,('Duplicate logical ID requires real conflict policy',logical)
                assert encode_tag(logical)==words[0]
                logical_map[logical]=physical;samples.append((logical,spare[:16]))
                row.update(status='clean_logical_tag',logical=logical,tag=hex(words[0]))
                for j in range(64):
                    page=block[j*2112:(j+1)*2112]
                    if tags(page[2048:])==words:page_stats['consistent_tags']+=1
                    else:
                        assert page==b'\xff'*2112,(physical,j)
                        page_stats['fully_erased_records_within_mapped_blocks']+=1
            elif block==b'\xff'*len(block):row.update(status='all_FF_record_block')
            elif all(block[j*2112:j*2112+2048]==b'\0'*2048 and
                     block[j*2112+2048:(j+1)*2112]==bytes([0 if j<4 else 255])*64 for j in range(64)):
                row.update(status='zero_data_all_pages_zero_spare_first4_FF_spare_remaining60')
            else:
                assert physical==0;row.update(status='special_BootNAND_BFN_record_layout')
            block_rows.append(row)
        assert len(logical_map)==295 and page_stats==Counter(consistent_tags=18832,fully_erased_records_within_mapped_blocks=48)
        missing=[i for i in range(312) if i not in logical_map]
        assert missing==[0,*range(161,165),*range(300,312)]
        (out/'logical_to_physical.json').write_text(json.dumps(dict(
            candidate_runtime_lut='0x50E9C0',entry_bytes=2,unmapped=65535,
            entries=[dict(logical=i,physical=logical_map.get(i),runtime_value=logical_map.get(i,65535)) for i in range(312)],
            physical_blocks=block_rows,page_checks=dict(page_stats)),indent=2)+'\n')
        reconstructed=out/'ricostruiti';reconstructed.mkdir();parts=[]
        for name,start_off,size_off in PARTITIONS:
            start,count=struct.unpack_from('<H',table,start_off)[0],struct.unpack_from('<H',table,size_off)[0]
            chunks=[];mapping=[]
            for logical in range(start,start+count):
                physical=logical_map.get(logical)
                if physical is None:data=b'\xff'*0x20000
                else:data=b''.join(nand[(physical*64+j)*2112:(physical*64+j)*2112+2048] for j in range(64))
                chunks.append(data);mapping.append(dict(logical=logical,physical=physical,generated_FF=physical is None))
            data=b''.join(chunks);source=ROOT/'DUMPS'/name
            assert data==source.read_bytes(),name
            (reconstructed/name).write_bytes(data)
            parts.append(dict(file=name,start_field=hex(start_off),count_field=hex(size_off),
                start_logical=start,blocks=count,bytes=len(data),sha256=sha(source),mapping=mapping,
                complete_export_match=True,unmapped_FF_blocks=sum(m['generated_FF'] for m in mapping)))
        assert sum(p['unmapped_FF_blocks'] for p in parts)==16
        (out/'partition_mapping.json').write_text(json.dumps(parts,indent=2)+'\n')
        fields=re.findall(r'^(\w+)\s*=\s*(0x[0-9a-fA-F]+)',(ROOT/'DUMPS/NANDPartition.txt').read_text(),re.M)
        assert len(fields)==11
        label_pools=[0x3004fc,0x300508,0x300510,0x300518,0x300520,0x300528,
                     0x300530,0x300538,0x300540,0x300548,0x300550]
        value_loads=[0x300302,0x300332,0x30035e,0x30038a,0x3003b6,0x3003e2,
                     0x30040e,0x30043a,0x300466,0x300492,0x3004be]
        for (key,_),pool,pc,off in zip(fields,label_pools,value_loads,[0,2,4,6,8,10,12,14,20,16,18]):
            check_span(pool,4);label=u32(pool)
            data=raw(label,128).split(b'\0')[0]
            check_span(label,len(data)+1);assert data.decode('ascii')==key
            ins(pc,'ldw_s',f'r3,[r3,{hex(off) if off else "0"}]')
        expected=[];mapped_fields=[]
        for i,off in enumerate(FIELD_OFFSETS):
            key,value=fields[i if i<8 else i+1]
            decoded=struct.unpack_from('<H',table,off)[0]*(8 if 3<=i<8 else 1)
            assert decoded==int(value,16)
            expected.append(decoded);mapped_fields.append(dict(name=key,value=decoded,p1idstr_offset=hex(off),getter_output_offset=2*i))
        assert fields[8]==('uwSize_P3Partition','0x0000')
        (out/'partition_text_fields.json').write_text(json.dumps(dict(mapped_fields=mapped_fields,
            p3=dict(observed=0,output_offset=20,written_by_getter=False,source_unknown=True)),indent=2)+'\n')
        # Execute original decoder on every clean first-record tag, plus two
        # invalid forms and two single-bit disagreement paths. No ECC body correction.
        test_samples=[dict(data=d,logical=l,good=True,kind='observed') for l,d in samples]
        test_samples += [dict(data=b'\xff'*16,logical=None,good=False,kind='erased'),
                         dict(data=b'\0'*16,logical=None,good=False,kind='zero')]
        for position in (7,12):
            sample=bytearray(samples[0][1]);sample[position]^=1
            test_samples.append(dict(data=bytes(sample),logical=samples[0][0],good=True,kind=f'one_bit_copy_disagreement_{position}'))
        (out/'metadata_samples.bin').write_bytes(b''.join(x['data'] for x in test_samples))
        (out/'p1idstr.bin').write_bytes(table)
        (out/'main0_original.bin').write_bytes(PS[0])
        geometry=bytearray(20);geometry[5]=64;geometry[16]=4
        # Existing GNU mmap support indexes from the address aligned down to8.
        # Both selected globals have low address bits4: preserve a4-byte prefix.
        (out/'geometry_lab.bin').write_bytes(b'\xa5'*4+geometry)
        (out/'unmapped_state_lab.bin').write_bytes(b'\xa5'*4+b'\0\0\xff\xff\0\0\0\0')
        (out/'ff_buffer_lab.bin').write_bytes(b'\xa5'*2056)
        asm=' mov r20,0\n'
        for i,test in enumerate(test_samples):
            asm+=(f' mov r0,{0x18000+16*i:#x}\n mov r1,0x1c000\n mov r12,0x25ce58\n jl [r12]\n cmp r0,0\n'
                +(' bne fail\n mov r1,0x1c000\n ldh r0,[r1,4]\n'+f' cmp r0,{test["logical"]}\n bne fail\n' if test['good'] else ' beq fail\n')
                +' add r20,r20,1\n')
        for logical in (0,14,165):
            word=encode_tag(logical)
            asm+=(f' mov r1,0x1e000\n mov r2,{logical}\n sth r2,[r1,4]\n mov r0,0x1d000\n'
                  ' mov r12,0x25cf10\n jl [r12]\n mov r1,0x1d000\n')
            for group in range(4):
                for off,val in [(4,255),(5,255),(6,word>>8),(7,word&255),(11,word>>8),(12,word&255)]:
                    asm+=f' ldb r0,[r1,{16*group+off}]\n cmp r0,{val}\n bne fail\n'
            asm+=' add r20,r20,1\n'
        # Original size-extraction body, excluding calls/pool-dependent setup.
        ins(0x16f3c8,'ldh','r0,[r1,174]')
        ins(0x16f40c,'stw_s','r0,[r2,0x12]')
        asm+=' mov r1,0x1c000\n mov r0,0xa5a5\n sth r0,[r1,20]\n mov r1,0x1b000\n mov r2,0x1c000\n'
        asm+=' .byte '+','.join(f'0x{x:02x}' for x in raw(0x16f3c8,0x16f40e-0x16f3c8))+'\n'
        for i,value in enumerate(expected):asm+=f' ldh r0,[r2,{2*i}]\n cmp r0,{value:#x}\n bne fail\n'
        asm+=' ldh r0,[r2,20]\n cmp r0,0xa5a5\n bne fail\n add r20,r20,1\n'
        # Entire original unmapped reader path, using an explicitly initialized
        # current-block sentinelFFFF and sectors-per-page4; no controller calls.
        asm+=(' mov r0,0x22004\n mov r1,0\n mov r12,0x1ecb0c\n jl [r12]\n cmp r0,0\n bne fail\n'
              ' mov r1,0x22004\n mov r2,512\ncheck_ff:\n ld.ab r0,[r1,4]\n cmp r0,-1\n bne fail\n'
              ' sub.f r2,r2,1\n bne check_ff\n mov r1,0x22000\n ld r0,[r1]\n cmp r0,0xa5a5a5a5\n bne fail\n'
              ' ld r0,[r1,2052]\n cmp r0,0xa5a5a5a5\n bne fail\n add r20,r20,1\n')
        total=len(test_samples)+3+1+1
        asm+=f' cmp r20,{total}\n bne fail\n mov r0,0\n b finish\nfail:\n mov r0,7\nfinish:\n mov r8,1\n trap_s 1\n'
        probe=compile_probe(r,'metadata_and_unmapped',asm)
        block0=next(b for b in BS if b['index']==0)
        options=[]
        for name,address,size in [('main0_original.bin',block0['load_address_candidate'],len(PS[0])),
            ('metadata_samples.bin',0x18000,16*len(test_samples)),('p1idstr.bin',0x1b000,244),
            ('geometry_lab.bin',0x50f52c,20),('unmapped_state_lab.bin',0x36b254,8),('ff_buffer_lab.bin',0x22000,2056)]:
            options+=['--memory-mapfile',f'/result/{name}','--memory-region',f'{address:#x},{size:#x}']
        options+=['--memory-fill','165','--memory-region','0x1c000,0x3000']
        case,log=r.run('metadata_and_unmapped',f'/result/{probe.name}',options,trace=True)
        assert case['exit_code']==0 and case['fault'] is None,log
        trace=(out/'metadata_and_unmapped.trace').read_text()
        assert not re.search(r'\b(?:ld|st)\w*\.di\b',trace)
        pcs={int(m[1],16) for m in re.finditer(r'^0x([0-9a-f]+) ',trace,re.M)}
        for a in pcs:
            if block0['load_address_candidate']<=a<block0['load_address_candidate']+len(PS[0]):check_span(a,8)
        assert (out/'main0_original.bin').read_bytes()==PS[0]
        assert (out/'metadata_samples.bin').read_bytes()==b''.join(x['data'] for x in test_samples)
        assert (out/'p1idstr.bin').read_bytes()==table
        assert (out/'geometry_lab.bin').read_bytes()==b'\xa5'*4+geometry
        assert (out/'unmapped_state_lab.bin').read_bytes()==b'\xa5'*4+b'\0\0\xff\xff\0\0\0\0'
        assert (out/'ff_buffer_lab.bin').read_bytes()==b'\xa5'*4+b'\xff'*2048+b'\xa5'*4
        case.update(observed_decoder_cases=295,invalid_decoder_cases=2,single_bit_disagreement_cases=2,
            encoder_cases=3,size_projection_cases=1,unmapped_reader_cases=1,total_asserted_cases=total,
            mmio_executed=False,synthetic_geometry=True,p3_guard_unchanged=True)
        (out/'verifier_snapshot.py').write_bytes(Path(__file__).read_bytes())
        r.results.update(status='PASS_COMPLETE_LOGICAL_PARTITION_EXPORT_RECONSTRUCTION',
            previous_evidence=str(previous.relative_to(ROOT)),gnu_windows=len(WINDOWS),
            original_main_spans_matching_supplied_main=spans,clean_logical_entries=295,
            physical_export_blocks=324,logical_slots=312,missing_logical_ids=missing,
            unmapped_FF_partition_blocks=16,unmapped_FF_partition_bytes=16*0x20000,
            reconstructed_exports=7,reconstructed_bytes=sum(p['bytes'] for p in parts),
            complete_export_matches=True,partition_formatter_labels_verified=11,
            laboratory_shared_map_mutation=dict(file='ff_buffer_lab.bin',initial_fill=165,
                guest_modified_slice=[4,2052],final_fill_in_slice=255,guards_preserved=True),
            nand_restore_certified=False,full_boot=False)
        r.finish()
    except Exception as exc:
        r.results.update(status='FAIL',error=repr(exc));raise
    finally:r.save()
    (out.parent/'latest.json').write_text(json.dumps(dict(evidence=str((out/'verified_evidence.json').relative_to(ROOT)),
        mapping=str((out/'logical_to_physical.json').relative_to(ROOT))),indent=2)+'\n')
    print('PASS:295 decoded logical IDs;7 exports reconstructed byte-exact;304 original CPU helper cases;',out)


if __name__=='__main__':main()
