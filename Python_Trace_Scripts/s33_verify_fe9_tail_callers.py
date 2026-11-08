#!/usr/bin/env python3
"""Bounded incoming B/BL census and full original FE9 tail-caller CPU probes."""
import json
import re
import shutil
import struct
from collections import Counter
from pathlib import Path
from types import SimpleNamespace
from s33_run_gnu_arc700 import ROOT, LEGACY, TOOLCHAIN, sha
from s33_verify_gnu_defined_memory import LAB, BUILD, known_sections
from s33_verify_ff7_transfer_windows import SeparatedRunner
from s33_verify_gnu_dsp_lab import compile_probe
from s33_trace_state_dispatch import verified_payloads
from s33_verify_sensor_mmio_dialog import aligned_window
from s33_verify_custom_aux_cfg import call_at, sx
from s33_integrate_ffc7000_table_tail import load, save

PARENT=ROOT/'Risultati/Processor_Registers/20261025T200238Z'
REUSED=ROOT/'outputs/gnu_arc700/20261025T200116Z_013aed64'
TARGETS={0x2ee760,0x2ee7b0,0x2ee800,0x2ee850,0x2ee8a0,0x2ee8f0,0x2ee924,0x2ee974,0x2ee9c4}


def branch_at(blob,off,base):
    """Superset scan: candidates at each halfword, including potential data."""
    h=struct.unpack_from('<H',blob,off)[0];pc=base+off
    if h&0xfe00 in [0xf000,0xf200,0xf400]:
        return dict(pc=pc,target=(pc&~3)+sx((h&511)<<1,10),size=2,encoding='B_s_simm10')
    if h&0xfe00==0xf600:
        return dict(pc=pc,target=(pc&~3)+sx((h&63)<<1,7),size=2,encoding='Bcc_s_simm7')
    if off+4>len(blob):return None
    bits=h<<16|struct.unpack_from('<H',blob,off+2)[0]
    if bits&0xf8010000 not in [0x00010000,0x00000000]:return None
    n=25 if bits&0x10000 else 21
    value=((bits>>17)&1023)<<1|((bits>>6)&1023)<<11
    if n==25:value|=(bits&15)<<21
    return dict(pc=pc,target=(pc&~3)+sx(value,n),size=4,encoding=f'B_simm{n}')


def main():
    ledger=load(PARENT/'sha256.json');assert all(sha(PARENT/k)==v for k,v in ledger.items())
    r=SeparatedRunner(SimpleNamespace(legacy_root=LEGACY,toolchain=TOOLCHAIN,output=None,action='fe9-original-tail-callers'))
    print('Evidence:',r.out,flush=True)
    try:
        r.prepare();r.known_ranges='';r.experimental_engine=LAB
        assert sha(LAB/'install/bin/arc-elf32-run')==load(BUILD)['engine_sha256']
        assert sha(REUSED/'observer')==load(REUSED/'verified_evidence.json')['files']['observer']
        shutil.copy2(REUSED/'observer',r.out/'observer');shutil.copy2(Path(__file__),r.out/Path(__file__).name)
        for q in [Path(__file__),PARENT/'sha256.json',BUILD,LAB/'install/bin/arc-elf32-run',REUSED/'observer',REUSED/'verified_evidence.json',
            ROOT/'work/binutils-2.45/opcodes/arc-tbl.h',ROOT/'work/binutils-2.45/opcodes/arc-fxi.h']:
            r.input_hashes[str(q)]=sha(q)
        for name in ['s33_verify_ff7_transfer_windows','s33_verify_gnu_defined_memory','s33_verify_gnu_dsp_lab','s33_run_gnu_arc700',
            's33_trace_state_dispatch','s33_verify_sensor_mmio_dialog','s33_verify_custom_aux_cfg','s33_integrate_ffc7000_table_tail']:
            q=Path(__file__).with_name(name+'.py');r.input_hashes[str(q)]=sha(q)
        blocks,payloads,directory=verified_payloads(ROOT);body=payloads[0];base=blocks[0]['load_address_candidate'];decoded={}
        def decode(pc):
            if pc not in decoded:
                owner=next(b for b in blocks if b['load_address_candidate']<=pc< b['load_address_candidate']+len(payloads[b['index']]))
                blob=payloads[owner['index']];start=owner['load_address_candidate'];text=aligned_window(blob,start,pc,pc+12)
                line=next(x for x in text.splitlines() if re.match(r'\s*'+f'{pc:x}:',x))
                m=re.match(r'\s*[0-9a-f]+:\s+((?:[0-9a-f]{4}\s+)+)\t(\S+)\s*(.*)',line)
                raw=b''.join(bytes.fromhex(w)[::-1] for w in m[1].split());assert raw==blob[pc-start:pc-start+len(raw)]
                decoded[pc]=dict(opcode=m[2],operands=m[3].strip(),bytes_hex=raw.hex(),size=len(raw))
            return decoded[pc]
        def exact(pc,op,operands):
            ins=decode(pc);assert (ins['opcode'],ins['operands'])==(op,operands),(hex(pc),ins)
        def word(a):
            b=next(z for z in blocks[:2] if z['load_address_candidate']<=a and a+4<=z['load_address_candidate']+len(payloads[z['index']]))
            return struct.unpack_from('<I',payloads[b['index']],a-b['load_address_candidate'])[0]
        # Positive controls cover short/long and conditional/unconditional B.
        controls=[]
        for pc in [0x2ed674,0x2ed67a,0x2ed688,0x2ed68e,0x2959a0,0x295ec0,0x309ce8,0x309d24,0x309d3e,0x309d9a]:
            c=branch_at(body,pc-base,base);ins=decode(pc)
            assert c and c['target']==int(re.search(r';(?:0x)?([0-9a-f]+)',ins['operands'])[1],16) and c['size']==ins['size']
            controls.append(dict(**c,gnu=ins))
        branches=[];calls=[];pointers=[];coverage=[]
        for b in blocks:
            blob=payloads[b['index']];start=b['load_address_candidate'];r.input_hashes[str(directory/b['file'])]=sha(directory/b['file'])
            for off in range(0,len(blob)-1,2):
                c=branch_at(blob,off,start)
                if c and c['target'] in TARGETS:
                    ins=decode(c['pc']);assert ins['size']==c['size'] and int(re.search(r';(?:0x)?([0-9a-f]+)',ins['operands'])[1],16)==c['target']
                    branches.append(dict(payload=b['index'],**c,gnu=ins,local_code_qualification=c['pc'] in [0x2959a0,0x295ec0]))
                if off+4<=len(blob):
                    c=call_at(blob,off,start)
                    if c and c['target'] in TARGETS:calls.append(dict(payload=b['index'],**c))
            for target in [0x2ee924,0x2ee974]:
                for order,needle in [('word_LE',struct.pack('<I',target)),('LIMM_halfwords_LE',struct.pack('<HH',target>>16,target&65535))]:
                    at=0
                    while (off:=blob.find(needle,at))>=0:
                        pointers.append(dict(payload=b['index'],address=hex(start+off),target=hex(target),encoding=order));at=off+1
            coverage.append(dict(payload=b['index'],base=hex(start),byte_size=len(blob),halfword_positions=len(blob)//2,sha256=sha(directory/b['file'])))
        assert len(branches)==5 and {(x['payload'],x['pc']) for x in branches}=={(0,0x2959a0),(0,0x295ec0),(1,0x39a1c6),(1,0x39a760),(1,0x39a8a0)}
        assert len(calls)==75
        assert {(x['payload'],x['address'],x['target'],x['encoding']) for x in pointers}=={
            (0,'0x303f0c','0x2ee924','word_LE'),(0,'0x303f10','0x2ee974','word_LE'),
            (0,'0x303f0e','0x2ee974','LIMM_halfwords_LE'),(11,'0x106cf12','0x2ee974','word_LE')}
        assert not any(x['target'] in [0x2ee924,0x2ee974] for x in branches+calls)
        for pc,op,operands in [(0x29599c,'mov_s','r2,r0'),(0x29599e,'mov_s','r0,0x6'),(0x2959a4,'mov_s','r1,0'),
            (0x295eb4,'cmp_s','r0,0x1'),(0x295eb6,'mov_s','r0,0xb'),(0x295eb8,'bne_s','6\t;0x295ebe'),
            (0x295eba,'mov_s','r1,0'),(0x295ebc,'b_s','4\t;0x295ec0'),(0x295ebe,'mov_s','r1,0x1'),(0x295ec4,'mov_s','r2,0x1')]:exact(pc,op,operands)
        census=dict(status='PASS_BOUNDED_FE9_B_BL_AND_POINTER_CENSUS',payload_coverage=coverage,branch_positive_controls=controls,branch_candidates=branches,
            BL_candidates=calls,pointer_candidates=pointers,independently_redecoded_instructions={hex(k):v for k,v in decoded.items()},
            coverage='Allhalfwordpositions in16originalpayloads forB_s/Bcc_s/Bsimm21/25 andBLfamilies;everybyte for2literalpointerencodings of924/974.',
            limits=['Not a disassembly of allcode;3payload1Bpatterns lack localcode qualification and are not admitted.',
                'ExcludesBRcc/BBIT/loopandregisterjumps,computed/encrypted pointers,interior-entryandexternalcode;no absenceofindirectcallers inferred.'])
        save(r.out/'incoming_census.json',census)
        assert word(0x303f0c)==0x2ee924 and word(0x303f10)==0x2ee974
        exact(0x303d62,'ld_s','r14,[pcl,0x1ac]\t;0x303f0c')
        exact(0x303e32,'ld_s','r13,[pcl,0xe0]\t;0x303f10')
        indirect_specs=[
            (0x2ee924,0x2eea60,0x309970,0x309bb4,
             [(0,1),(4,2),(8,2),(12,2),(16,1),(17,1),(20,2),(24,1),(25,1),(28,2),(32,1),(33,1),(36,2),(40,1),(42,2)],
             [0x303d66,0x303d6e,0x303d76,0x303d7e,0x303d90,0x303da2,0x303daa,0x303dbc,0x303dce,0x303dd6,0x303dea,0x303dfe,0x303e06,0x303e1a,0x303e22]),
            (0x2ee974,0x2eea70,0x30999c,0x309be0,
             [(0,1),(4,2),(8,2),(12,1),(13,1),(16,2),(20,1),(21,1),(24,2),(28,1),(30,2)],
             [0x303e36,0x303e3e,0x303e46,0x303e58,0x303e6a,0x303e72,0x303e84,0x303e96,0x303e9e,0x303eb0,0x303eb8])]
        for wrapper,pool,ha,hb,fields,pcs in indirect_specs:
            reg='r14' if wrapper==0x2ee924 else 'r13'
            for index,pc in enumerate(pcs):
                exact(pc-2,'mov_s',f'r0,{hex(index) if index else "0"}')
                exact(pc,'jl_s.d',f'[{reg}]');exact(pc+2,'mov_s','r2,r16')
        for pc,op,operands in [(0x303ec8,'ld_s','r0,[pcl,0x4c]\t;0x303f14'),(0x303eca,'ld_s','r1,[pcl,0x50]\t;0x303f18'),
            (0x303ecc,'mov_s','r2,0'),(0x303ece,'mov_s','r3,r2'),(0x303ed4,'ld_s','r0,[pcl,0x48]\t;0x303f1c'),
            (0x303ed6,'ld_s','r1,[pcl,0x4c]\t;0x303f20'),(0x303ed8,'mov_s','r2,0'),(0x303eda,'mov_s','r3,0x1')]:exact(pc,op,operands)
        for pc in [0x303ed0,0x303edc]:assert call_at(body,pc-base,base)['target']==0x303d4c
        save(r.out/'original_indirect_setup.json',dict(specs=indirect_specs,
            pointer_words={'0x303f0c':hex(word(0x303f0c)),'0x303f10':hex(word(0x303f10))},
            original_data_pointers={hex(p):hex(word(p)) for p in [0x303f14,0x303f18,0x303f1c,0x303f20]},
            independently_redecoded_instructions={hex(k):v for k,v in decoded.items()}))
        mappings=[];firmware=(ROOT/'OriginalSoftware_NikonS33_V1.1/firmware.bin').read_bytes()
        for i in [0,1]:
            q=r.out/f'payload{i}_mmap.bin';q.write_bytes(payloads[i]);off=firmware.find(payloads[i]);assert off>=0 and firmware.find(payloads[i],off+1)<0
            mappings.append(dict(index=i,base=blocks[i]['load_address_candidate'],size=len(payloads[i]),path=str(q),sha256=sha(q),firmware_offset=off))
        pairs=[];sentinels={i:i*0x01100110 for i in range(13,20)}
        for pattern,seed in enumerate([0xa55a,0x5aa5]):
            for argument in [0,1,2,0xffffffff]:
                scenario=f'tails_{pattern}_{argument:x}';bank=int(argument!=0);state={};initial={};events=[];calls=[]
                asm='mov r20,sp\n'+''.join(f'mov r{i},{v:#x}\n' for i,v in sentinels.items())
                for entry,wrapper,index,bank_use,value in [(0x29599c,0x2ee850,6,bank,0),(0x295eb4,0x2ee7b0,11,1,int(argument!=1))]:
                    pool=0x2eea38 if wrapper==0x2ee850 else 0x2eea18;p=word(pool+bank_use*8);mp=word(pool+bank_use*8+4)
                    address,mask=word(p+index*4),word(mp+index*4);old=state.setdefault(address,(seed^(address>>2))&65535);initial.setdefault(address,old)
                    helper=([0x309944,0x309b88][bank_use] if wrapper==0x2ee850 else 0x309afc)
                    if wrapper==0x2ee850:
                        assert mask==3;new=old&~3;rd,wr=12,34
                    else:
                        assert mask==0x800;new=(old&~mask)|(mask if value else 0);rd,wr=(36,44) if value else (16,24)
                    events.extend([(helper+rd,'read',address,old),(helper+wr,'write',address,new)]);state[address]=new
                    asm+=f'mov r0,{argument:#x}\nmov r1,0x76543210\nmov r2,0xdeadbeef\nmov r12,{entry:#x}\njl [r12]\n'
                    asm+='cmp sp,r20\nbne fail\n'+''.join(f'cmp r{i},{v:#x}\nbne fail\n' for i,v in sentinels.items())
                    calls.append(dict(entry=hex(entry),wrapper=hex(wrapper),index=index,channel=bank_use,value=value,address=hex(address),mask=hex(mask),
                        table_word=hex(p+index*4),mask_word=hex(mp+index*4)))
                for channel in [0,1]:
                    for which,(wrapper,pool,ha,hb,fields,pcs) in enumerate(indirect_specs):
                        source=word(0x303f14+channel*8+which*4)
                        for index,(offset,width) in enumerate(fields):
                            byte=word(source+offset) if width==2 else word(source+offset)&255
                            value=(byte&65535) if width==2 else int(byte==1)
                            p=word(pool+channel*8);mp=word(pool+channel*8+4);address,mask=word(p+index*4),word(mp+index*4)
                            old=state.setdefault(address,(seed^(address>>2))&65535);initial.setdefault(address,old)
                            shift=(mask&-mask).bit_length()-1;new=((old&~mask)|((value<<shift)&mask))&65535;helper=hb if channel else ha
                            events.extend([(helper+12,'read',address,old),(helper+34,'write',address,new)]);state[address]=new
                            calls.append(dict(entry='0x303ec4',wrapper=hex(wrapper),index=index,channel=channel,value=value,address=hex(address),mask=hex(mask),
                                table_word=hex(p+index*4),mask_word=hex(mp+index*4),indirect_call_pc=hex(pcs[index]),input_address=hex(source+offset),input_width=width))
                asm+='mov r12,0x303ec4\njl [r12]\ncmp sp,r20\nbne fail\n'+''.join(f'cmp r{i},{v:#x}\nbne fail\n' for i,v in sentinels.items())
                asm+='mov r0,0\nb finish\nfail:\nmov r0,7\nfinish:\nmov r8,1\ntrap_s 1\n';elf=compile_probe(r,scenario,asm);traces=[]
                for enabled in [False,True]:
                    name=scenario+('_observed' if enabled else '_reference');r.observe=enabled;options=[];fixtures={}
                    for m in mappings:options+=['--memory-mapfile','/result/'+Path(m['path']).name,'--memory-region',f"{m['base']:#x},{m['size']:#x}"]
                    for a in sorted(state):
                        before=bytearray(b'\xa5'*8);struct.pack_into('<H',before,a%8,initial[a]);q=r.out/f'{name}_{a:x}.bin';q.write_bytes(before)
                        fixtures[hex(a)]=dict(file=q.name,before=before.hex());options+=['--memory-mapfile','/result/'+q.name,'--memory-region',f'{a:#x},2']
                    r.range_override=known_sections(elf,False)+''.join(f",{m['base']:#x}:{m['size']:#x}" for m in mappings)
                    case,log=r.run(name,'/result/'+elf.name,options,trace=True,extract=True)
                    assert case['exit_code']==0 and case['fault'] is None,log[-4000:]
                    assert not any(x in log for x in ['S33_UNDEFINED','S33_AUX_UNKNOWN','runtime error:'])
                    raw=[json.loads(line.removeprefix('S33_MEM ')) for line in (r.out/(name+'.stderr.log')).read_text().splitlines() if line.startswith('S33_MEM ')]
                    done=[e for e in raw if e['stage']=='result'];assert len(raw)==2*len(done) and all(e['width_bytes']==2 for e in raw)
                    assert [(e['pc'],e['operation'],e['address'],e['value']) for e in done]==(events if enabled else [])
                    for key,f in fixtures.items():
                        a=int(key,0);off=a%8;before=bytes.fromhex(f['before']);after=(r.out/f['file']).read_bytes()
                        assert struct.unpack_from('<H',after,off)[0]==state[a] and all(before[j]==after[j] for j in range(8) if j not in [off,off+1]);f['after']=after.hex()
                    assert all(Path(m['path']).read_bytes()==payloads[m['index']] for m in mappings)
                    traces.append((r.out/(name+'.trace')).read_bytes())
                    case.update(pattern=pattern,seed=seed,argument=argument,observer_enabled=enabled,calls=calls,fixtures=fixtures,
                        completed_memory_events=done,original_tail_callers_executed=True)
                    print(name,'PASS',len(done),'events',flush=True)
                assert traces[0]==traces[1];pairs.append(dict(scenario=scenario,trace_identical=True,events=108))
        assert all(sha(PARENT/k)==v for k,v in ledger.items())
        r.results.update(status='PASS_FE9_ORIGINAL_TAIL_CALLERS',parent_atlas=str(PARENT),payloads=mappings,pairs=pairs,capture_streams_separate=True,
            census='incoming_census.json',hardware_access=False,gnu_modified=False,global_reachability_proven=False,
            metamorphic_scope='No metamorphic equivalence asserted;seed andoriginalr0arguments enumerated independently;r1/r2poison fixed andoverridden bycallers.',
            limits=['Twooriginaltailcallers and303EC4→303D4Cindirectinitializer executed completely,withoriginalwrappers/helpers/inputstructures/tables;globalreachability andallinputdomains remainunproved.',
                '295EB4forceschannelB;index11doesnot authorizebankAadmission.',
                'Stack,seeds,arguments,MMIObacking arefixtures;physicalmeaning/reset/permissions/IRQ/timing/atomicity unknown.'])
        r.finish()
    except Exception as exc:r.results.update(status='FAIL',error=repr(exc));raise
    finally:r.save()
    print(r.out/'verified_evidence.json',flush=True)


if __name__=='__main__':main()
