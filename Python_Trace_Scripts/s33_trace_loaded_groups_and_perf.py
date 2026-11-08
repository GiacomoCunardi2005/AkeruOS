#!/usr/bin/env python3
"""Map observed PerfLog load groups to TBM payloads and test original control flow.

CPU fixture: group wrappers and their pools are original and byte-verified.
Six external services are recording stubs in an isolated mutable Main0 copy:
profiling, lock, configure reader, read, publish event, unlock. No real transfer,
filesystem, synchronization, scheduler, NAND or physical memory is simulated.
"""
from pathlib import Path
from types import SimpleNamespace
from datetime import datetime,timezone
import hashlib,json,re,struct,sys
from s33_run_gnu_arc700 import ROOT,LEGACY,TOOLCHAIN,Runner,sha
from s33_verify_gnu_dsp_lab import compile_probe
sys.path.insert(0,str(ROOT/'S33-sections/analysis_codex'))
from static_common import BS,PS,raw,u32,locate,disasm

GROUPS=[dict(name='C2',entry=0xc5910,window_end=0xc5984,start_pool=0xc5984,end_pool=0xc59a8,
             indices=[2,3],triplet_pools=[0xc5990,0xc599c],event_bits=[4]),
        dict(name='C3',entry=0xc59ac,window_end=0xc5a28,start_pool=0xc5a28,end_pool=0xc5a4c,
             indices=[4,5],triplet_pools=[0xc5a30,0xc5a40],event_bits=[8,16]),
        dict(name='C4',entry=0xc5a50,window_end=0xc5acc,start_pool=0xc5acc,end_pool=0xc5af0,
             indices=[6,7],triplet_pools=[0xc5ad4,0xc5ae4],event_bits=[32,64]),
        dict(name='Resource',entry=0xc5af4,window_end=0xc5b50,start_pool=0xc5b50,end_pool=0xc5b64,
             indices=[9],triplet_pools=[0xc5b58],event_bits=[])]
SERVICES=[('profile',0x12cad4,1,24),('lock',0x1593ac,2,8),('configure',0x159550,3,32),
          ('read',0x159558,4,None),('event',0x158cbc,5,28),('unlock',0x1594a4,6,12)]


def main():
    out=ROOT/'Risultati/Dump_fotocamera/Gruppi_Caricamento'/datetime.now(timezone.utc).strftime('%Y%m%dT%H%M%SZ')
    r=Runner(SimpleNamespace(legacy_root=LEGACY,toolchain=TOOLCHAIN,output=out,
                            action='loaded-tbm-groups-perf-and-conditional-event-protocol'))
    print('Evidence:',out,flush=True)
    try:
        r.prepare()
        r.input_hashes[str(TOOLCHAIN/'arc-elf32-objcopy')]=sha(TOOLCHAIN/'arc-elf32-objcopy')
        r.results['assumptions']=['Original group wrappers/pools; six external service entries replaced only in laboratory image',
            'Recording stubs supply explicit return values; they do not transfer bytes or synchronize tasks',
            'Modes0x10/0x20/0 are laboratory inputs at0x928, not runtime values captured from camera',
            'Original restored register/return helpers run; source firmware and GNU trees read only']
        r.results['limits']=['No full boot, data-transfer/backend execution, filesystem, cache or concurrency validation',
            'Perf End proves selected local control flow only, not successful event delivery/unlock or global readiness',
            'Seven pool triplets map to supplied TBM bytes; Resource here is block9, not P1RES',
            'Blocks10..15 resumption/overlay residency and new AkeruOS task lifetime remain open']
        previous=ROOT/json.loads((ROOT/'Risultati/Dump_fotocamera/NAND_ECC/latest.json').read_text())['evidence']
        old=json.loads(previous.read_text());assert old['status']=='PASS_NAND_ECC_SCAN_AND_ORIGINAL_CORRECTION'
        for p,h in old['input_hashes'].items():assert sha(Path(p))==h,p;r.input_hashes[p]=h
        r.input_hashes[str(previous)]=sha(previous)
        perf_latest=json.loads((ROOT/'Risultati/Dump_fotocamera/Clock_Perf/latest.json').read_text())
        perf_path=ROOT/perf_latest['events'];events=json.loads(perf_path.read_text());r.input_hashes[str(perf_path)]=sha(perf_path)
        main=(ROOT/'DUMPS/MainCode.dmp').read_bytes();blocks={b['index']:b for b in BS}
        records=[struct.unpack_from('<HHHHII',main,0x10+i*16) for i in range(17)]
        assert [i for i,x in enumerate(records) if x[0]==1]==[0,1,8]
        assert records[16][0]==2 and struct.unpack_from('<I',main,0x114)[0]==0xbb540
        spans=[]

        def span(a,n):
            b,o=locate(a,n);d=raw(a,n);assert main[b['offset']+o:b['offset']+o+n]==d,(hex(a),n)
            spans.append(dict(address=hex(a),bytes=n,sha256=hashlib.sha256(d).hexdigest()))

        windows=[(g['entry'],g['window_end']) for g in GROUPS]+[(0xc58c8,0xc58f4),
                 (0x159550,0x159688),(0xc76c4,0xc76c8),(0x158cbc,0x158ce0)]
        listings=[]
        for a,b in windows:span(a,b-a);listings.append(disasm(a,b))
        (out/'gnu_verified.txt').write_text('\n'.join(listings))
        for a,v in {0xc5988:0x900,0xc598c:0x300008,0xc5a2c:0x300008,0xc5ad0:0x300008,
                    0xc5b54:0x300008,0xc586c:0x42700002,0xc5a3c:0x42700002,
                    0xc5ae0:0x42700002,0x159688:0x3672a4,0xc76c8:0x377db8}.items():
            span(a,4);assert u32(a)==v
        path=raw(0x377db8,32).split(b'\0')[0];assert path==b'B:\\TBM_SK501.BIN';span(0x377db8,len(path)+1)
        mapped=[]
        for g in GROUPS:
            reads=[]
            for index,pool in zip(g['indices'],g['triplet_pools']):
                span(pool,12);offset,size,dest=struct.unpack('<3I',raw(pool,12));b=blocks[index]
                assert (offset,size,dest)==(b['offset'],b['size'],b['load_address_candidate'])
                assert records[index][0]==0
                data=main[offset:offset+size];assert data==PS[index]
                assert sum(struct.unpack(f'<{size//4}I',data))&0xffffffff==records[index][5]
                reads.append(dict(index=index,offset=offset,bytes=size,destination=dest,sha256=hashlib.sha256(data).hexdigest()))
            ids=[];observed=[]
            for pool,suffix in [(g['start_pool'],'Start'),(g['end_pool'],'End')]:
                span(pool,4);ident=u32(pool);label=f'Load {g["name"]} {suffix}'
                match=[e for e in events if e['id']==hex(ident) and e['label']==label]
                assert len(match)==1;ids.append(ident);observed.append(match[0]['timestamp_word_pair'])
            assert observed[0]<observed[1]
            g.update(reads=reads,profile_ids=ids)
            mapped.append(dict(name=g['name'],entry=hex(g['entry']),reads=reads,
                event_handle='0x42700002' if g['event_bits'] else None,event_bits=g['event_bits'],
                profile_ids=[hex(v) for v in ids],observed_times=observed,
                delta_printed_units=observed[1]-observed[0]))
        (out/'group_mapping.json').write_text(json.dumps(mapped,indent=2)+'\n')
        # Construct test services at separate laboratory addresses. Short entry
        # trampolines do not overlap adjacent configure/read entries159550/558.
        patched=bytearray(PS[0]);origin=blocks[0]['load_address_candidate'];patches=[];stub_options=[]
        for i,(name,target,kind,return_off) in enumerate(SERVICES):
            address=0x2010000+i*0x200
            asm=(' mov r10,0x2000000\n ld r10,[r10]\n ld r11,[r10]\n asl r12,r11,4\n'
                f' add r12,r12,r10\n add r12,r12,64\n mov r9,{kind}\n st r9,[r12]\n'
                ' st r0,[r12,4]\n st r1,[r12,8]\n st r2,[r12,12]\n add r11,r11,1\n st r11,[r10]\n')
            if name=='read':
                asm+=' ld r11,[r10,4]\n add r12,r10,16\n ld.as r0,[r12,r11]\n add r11,r11,1\n st r11,[r10,4]\n'
            else:asm+=f' ld r0,[r10,{return_off}]\n'
            asm+=' j_s [blink]\n'
            elf=compile_probe(r,'record_'+name,asm);binary=out/('record_'+name+'.bin')
            p=r.command('extract_'+name,[TOOLCHAIN/'arc-elf32-objcopy','-O','binary','--only-section=.text',elf,binary]);assert p.returncode==0
            # GNU's decoder fetches8bytes from the current PC at the tail.
            # Pad only the fixture mapping, preserving the extracted code prefix.
            code=binary.read_bytes();binary.write_bytes(code+b'\0'*(8+(-len(code))%8))
            assert len(binary.read_bytes())<0x200
            stub_options+=['--memory-mapfile',f'/result/{binary.name}','--memory-region',f'{address:#x},{len(binary.read_bytes())}']
            tramp=compile_probe(r,'entry_'+name,f' mov_s r12,{address:#x}\n j_s [r12]\n')
            tramp_bin=out/('entry_'+name+'.bin')
            p=r.command('extract_entry_'+name,[TOOLCHAIN/'arc-elf32-objcopy','-O','binary','--only-section=.text',tramp,tramp_bin]);assert p.returncode==0
            code=tramp_bin.read_bytes();assert len(code)==8
            at=target-origin;before=bytes(patched[at:at+8]);patched[at:at+8]=code
            patches.append(dict(service=name,address=hex(target),laboratory_target=hex(address),original=before.hex(),replacement=code.hex()))
        for g in GROUPS:
            a=g['entry']-origin;b=g['window_end']-origin
            assert patched[a:b]==PS[0][a:b],g['name']
        (out/'main0_control_flow_fixture_NOT_FIRMWARE.bin').write_bytes(patched)
        (out/'laboratory_trampolines.json').write_text(json.dumps(patches,indent=2)+'\n')
        # Test only data-flow decisions, with no interpretation of stub outcomes
        # as actual camera reads, event delivery or successful release.
        cases=[]
        for g in GROUPS:
            outcomes=['success','lock_failure','first_read_failure','release_failure']
            if len(g['reads'])==2:outcomes+=['second_read_failure','event_failure']
            for mode in (0x10,0x20):
                for outcome in outcomes:cases.append((g,mode,outcome))
            cases.append((g,0,'success'))
        assert len(cases)==48
        states=bytearray(len(cases)*512);expected=[];caller=' mov r20,0x2000000\n'
        for i,(g,mode,outcome) in enumerate(cases):
            state=0x2001000+i*512;at=i*512
            returns=[0,0,0x123 if outcome=='lock_failure' else 0,0x234 if outcome=='release_failure' else 0,
                     0 if outcome=='first_read_failure' else 1,0 if outcome=='second_read_failure' else 1,0,
                     0x345 if outcome=='event_failure' else 0,0]
            struct.pack_into('<9I',states,at,*returns)
            calls=[dict(kind=1,args=[g['profile_ids'][0]]),dict(kind=2,args=[0x300008,0])]
            if outcome!='lock_failure':
                if mode in (0x10,0x20):calls.append(dict(kind=3,args=[0 if mode==0x10 else 0x377db8,0]))
                for j,read in enumerate(g['reads']):
                    calls.append(dict(kind=4,args=[read['offset'],read['bytes'],read['destination']]))
                    if (j==0 and outcome=='first_read_failure') or (j==1 and outcome=='second_read_failure'):break
                    if g['name'] in ('C3','C4'):
                        calls.append(dict(kind=5,args=[0x42700002,g['event_bits'][j]]))
                    elif g['name']=='C2' and j==1:calls.append(dict(kind=5,args=[0x42700002,4]))
                calls.append(dict(kind=6,args=[0x300008]))
                if outcome not in ('first_read_failure','second_read_failure'):calls.append(dict(kind=1,args=[g['profile_ids'][1]]))
            expected.append(dict(case=i,name=g['name'],mode=hex(mode),outcome=outcome,calls=calls))
            caller+=(f' mov r0,{state:#x}\n st r0,[r20]\n mov r1,0x928\n mov r0,{mode}\n stb r0,[r1]\n'
                     f' mov r12,{g["entry"]:#x}\n jl [r12]\n mov r1,{state:#x}\n st r0,[r1,36]\n')
        caller+=' mov r0,0\n mov r8,1\n trap_s 1\n'
        (out/'states_input.bin').write_bytes(states);(out/'states_mmap.bin').write_bytes(states)
        (out/'current_state.bin').write_bytes(b'\0'*8)
        # GNU's default low ELF mapping already covers0x900. The caller writes
        # its sole input byte0x928 before every case; a second map would overlap.
        elf=compile_probe(r,'group_protocol',caller)
        options=['--memory-mapfile','/result/main0_control_flow_fixture_NOT_FIRMWARE.bin','--memory-region',f'{origin:#x},{len(patched)}',
            '--memory-mapfile','/result/states_mmap.bin','--memory-region',f'0x2001000,{len(states)}',
            '--memory-mapfile','/result/current_state.bin','--memory-region','0x2000000,8']+stub_options
        case,log=r.run('group_protocol',f'/result/{elf.name}',options,trace=True)
        assert case['exit_code']==0 and case['fault'] is None,log
        got=(out/'states_mmap.bin').read_bytes()
        for i,spec in enumerate(expected):
            count=struct.unpack_from('<I',got,i*512)[0];assert count==len(spec['calls']),spec
            for j,want in enumerate(spec['calls']):
                values=struct.unpack_from('<4I',got,i*512+64+j*16)
                assert values[0]==want['kind'] and list(values[1:1+len(want['args'])])==want['args'],(spec,values,want)
            spec['observed_return']=struct.unpack_from('<I',got,i*512+36)[0]
        (out/'protocol_cases.json').write_text(json.dumps(expected,indent=2)+'\n')
        trace=(out/'group_protocol.trace').read_text();assert not re.search(r'\b(?:ld|st)\w*\.di\b',trace)
        # Include original shared return helpers in the byte provenance audit,
        # beyond the named static windows. Exclude only the six declared patches.
        pcs={int(m[1],16) for m in re.finditer(r'^0x([0-9a-f]+)\s',trace,re.M)}
        original_pcs=sorted(pc for pc in pcs if origin<=pc<origin+len(patched)
                            and not any(target<=pc<target+8 for _,target,_,_ in SERVICES))
        assert len(original_pcs)>100
        for pc in original_pcs:span(pc,8)
        (out/'executed_original_pcs.json').write_text(json.dumps([hex(pc) for pc in original_pcs],indent=2)+'\n')
        assert (out/'main0_control_flow_fixture_NOT_FIRMWARE.bin').read_bytes()==patched
        assert (out/'states_input.bin').read_bytes()==states
        case.update(protocol_cases=len(cases),six_services_are_recording_stubs=True,actual_transfers=False,actual_sync=False)
        (out/'verifier_snapshot.py').write_bytes(Path(__file__).read_bytes())
        r.results.update(status='PASS_GROUP_MAPPING_AND_CONDITIONAL_PROTOCOL',previous_evidence=str(previous.relative_to(ROOT)),
            groups=4,group_payloads=[2,3,4,5,6,7,9],initial_type1_payloads=[0,1,8],type2_entry='0x000BB540',
            gnu_windows=len(windows),original_main_spans=spans,protocol_cases=len(cases),
            executed_original_unique_pcs=len(original_pcs),
            partial_signals=dict(C3=8,C4=32),final_signals=dict(C2=4,C3=16,C4=64),
            event_handle='0x42700002',mutex_identifier='0x00300008',root_mode_runtime_observed=False,
            resource_block9_is_not_P1RES=True,physical_boot=False,AkeruOS_functional_progress_increased=False)
        r.finish()
    except Exception as exc:r.results.update(status='FAIL',error=repr(exc));raise
    finally:r.save()
    (out.parent/'latest.json').write_text(json.dumps(dict(evidence=str((out/'verified_evidence.json').relative_to(ROOT))),indent=2)+'\n')
    print('PASS:4Perf groups mapped to7TBM payloads;48conditional protocol cases; no actual transfer/synchronization;',out)


if __name__=='__main__':main()
