#!/usr/bin/env python3
"""Audit original FE9 initializer and tail callers, then extend the atlas."""
import argparse
import json
import re
import shutil
import struct
import subprocess
import sys
from collections import Counter,defaultdict
from datetime import datetime,timezone
from pathlib import Path
from s33_integrate_ffc7000_table_tail import ROOT,load,save,sha,geometry
from s33_trace_state_dispatch import verified_payloads
from s33_verify_sensor_mmio_dialog import aligned_window


def main():
    ap=argparse.ArgumentParser(description=__doc__);ap.add_argument('source',type=Path);src=ap.parse_args().source.resolve()
    d=load(src/'verified_evidence.json');assert d['status']=='PASS_FE9_ORIGINAL_TAIL_CALLERS'
    parent=Path(d['parent_atlas']);ledger=load(parent/'sha256.json');assert all(sha(parent/k)==v for k,v in ledger.items())
    inputs={**d['input_hashes'],str(src/'verified_evidence.json'):sha(src/'verified_evidence.json'),str(Path(__file__)):sha(Path(__file__))}
    assert all(sha(Path(k))==v for k,v in inputs.items()) and all(sha(src/k)==v for k,v in d['files'].items())
    blocks,payloads,_=verified_payloads(ROOT);base=blocks[0]['load_address_candidate'];body=payloads[0]
    firmware=(ROOT/'OriginalSoftware_NikonS33_V1.1/firmware.bin').read_bytes()
    for m in d['payloads']:
        q=Path(m['path']);assert sha(q)==m['sha256'] and q.read_bytes()==payloads[m['index']]==firmware[m['firmware_offset']:m['firmware_offset']+m['size']]
    def word(a):
        b=next(b for b in blocks[:2] if b['load_address_candidate']<=a and a+4<=b['load_address_candidate']+len(payloads[b['index']]))
        return struct.unpack_from('<I',payloads[b['index']],a-b['load_address_candidate'])[0]
    decoded={}
    def decode(pc):
        if pc not in decoded:
            owner=next(b for b in blocks if b['load_address_candidate']<=pc and pc+12<=b['load_address_candidate']+len(payloads[b['index']]))
            blob=payloads[owner['index']];start=owner['load_address_candidate']
            text=aligned_window(blob,start,pc,pc+12);line=next(x for x in text.splitlines() if re.match(r'\s*'+f'{pc:x}:',x))
            m=re.match(r'\s*[0-9a-f]+:\s+((?:[0-9a-f]{4}\s+)+)\t(\S+)\s*(.*)',line)
            raw=b''.join(bytes.fromhex(w)[::-1] for w in m[1].split());assert raw==blob[pc-start:pc-start+len(raw)]
            decoded[pc]=dict(opcode=m[2],operands=m[3].strip(),bytes_hex=raw.hex())
        return decoded[pc]
    setup=load(src/'original_indirect_setup.json');census=load(src/'incoming_census.json')
    assert len(census['branch_candidates'])==5 and len(census['BL_candidates'])==75 and len(census['pointer_candidates'])==4
    assert not any(c['target'] in [0x2ee924,0x2ee974] for c in census['branch_candidates']+census['BL_candidates'])
    # Static raw encodings are retained separately from qualified original code.
    assert sum(c['local_code_qualification'] for c in census['branch_candidates'])==2
    assert word(0x303f0c)==0x2ee924 and word(0x303f10)==0x2ee974
    for k,v in setup['independently_redecoded_instructions'].items():
        pc=int(k,0);ins=decode(pc);assert all(ins[key]==v[key] for key in ins)
    # Independent sequential decoding proves the actual source field loads.
    assert decode(0x303d52)['operands']=='r13,r0' and decode(0x303d52)['opcode']=='mov_s'
    assert decode(0x303d54)['operands']=='r0,[r0,0]' and decode(0x303d54)['opcode']=='ldb_s'
    source_fields={0x2ee924:[(0,1)],0x2ee974:[]};source_load_pcs={(0x2ee924,0):0x303d54}
    nav=aligned_window(body,base,0x303d4c,0x303ec4)
    for line in nav.splitlines():
        m=re.match(r'\s*([0-9a-f]+):.*\t(ldb_s|ldb|ldw_s)\s+r[01],\[(r13|r15),(0x[0-9a-f]+|[0-9]+)\]',line)
        if not m:continue
        pc=int(m[1],16);wrapper=0x2ee924 if m[3]=='r13' else 0x2ee974;width=2 if m[2]=='ldw_s' else 1
        idx=len(source_fields[wrapper]);source_fields[wrapper].append((int(m[4],0),width));source_load_pcs[wrapper,idx]=pc
        assert decode(pc)['opcode']==m[2]
    assert len(source_fields[0x2ee924])==15 and len(source_fields[0x2ee974])==11
    for wrapper,pool,ha,hb,fields,pcs in setup['specs']:assert [list(x) for x in source_fields[wrapper]]==fields
    specs={0x2ee850:(0x2eea38,0x309944,0x309b88),0x2ee7b0:(0x2eea18,0x3098e4,0x309afc),
        0x2ee924:(0x2eea60,0x309970,0x309bb4),0x2ee974:(0x2eea70,0x30999c,0x309be0)}
    prior=load(parent/'evidence/fe9_indexed_callers_audit.json')['independently_redecoded_instructions']
    rows=defaultdict(list);operations=defaultdict(dict);checks=[];groups={};total_loads=0;total_input_loads=0
    for case in d['cases']:
        assert case['exit_code']==0 and case['fault'] is None and case['original_tail_callers_executed']
        if not case['observer_enabled']:continue
        path=src/(case['name']+'.trace');trace=path.read_text();assert path.read_bytes()==(src/(case['name'].replace('_observed','_reference')+'.trace')).read_bytes()
        inputs[str(path)]=sha(path);expected=[];loads=[];entries=[];state={};input_reads=[];indirect=[]
        assert len(case['calls'])==54
        for n,c in enumerate(case['calls']):
            wrapper,index=int(c['wrapper'],0),c['index'];pool,ha,hb=specs[wrapper]
            if n==0:
                assert c['entry']=='0x29599c' and wrapper==0x2ee850 and index==6
                bank=int(case['argument']!=0);value=0
            elif n==1:
                assert c['entry']=='0x295eb4' and wrapper==0x2ee7b0 and index==11
                bank=1;value=int(case['argument']!=1)
            else:
                ordinal=n-2;bank=ordinal//26;within=ordinal%26
                assert c['entry']=='0x303ec4' and wrapper==(0x2ee924 if within<15 else 0x2ee974)
                assert index==(within if within<15 else within-15)
                which=int(wrapper==0x2ee974);source=word(0x303f14+bank*8+which*4);offset,width=source_fields[wrapper][index]
                raw=word(source+offset)&(65535 if width==2 else 255);value=raw if width==2 else int(raw==1)
                assert c['input_address']==hex(source+offset) and c['input_width']==width
                input_reads.append((source_load_pcs[wrapper,index],raw))
                pc=int(c['indirect_call_pc'],0);assert decode(pc)['opcode']=='jl_s.d';indirect.append((pc,wrapper))
            assert c['channel']==bank and c['value']==value
            p,mp=word(pool+bank*8),word(pool+bank*8+4);a,mask=word(p+4*index),word(mp+4*index);helper=hb if bank else ha
            assert (c['address'],c['mask'],c['table_word'],c['mask_word'])==(hex(a),hex(mask),hex(p+4*index),hex(mp+4*index))
            old=state.setdefault(a,(case['seed']^(a>>2))&65535);bit=next(i for i in range(16) if mask&(1<<i))
            if wrapper==0x2ee7b0:
                assert mask==0x800 and bank==1
                new=(old&~(1<<bit))|((1<<bit) if value else 0);rd,wr=(36,44) if value else (16,24)
            else:
                new=sum(((((value>>(i-bit))&1) if mask&(1<<i) else ((old>>i)&1))<<i) for i in range(16));rd,wr=12,34
            ev=[(helper+rd,'read',a,old),(helper+wr,'write',a,new)];state[a]=new;expected.extend(ev);entries.append(wrapper)
            loads.extend([(wrapper+(48 if bank else 28),a),(wrapper+(56 if bank else 36),mask)])
            desc=dict(wrapper=hex(wrapper),index=index,bank=bank,mask=hex(mask),first_low16_mask_bit=bit,
                original_caller=c['entry'],destination_table_word=hex(p+4*index),mask_table_word=hex(mp+4*index),physical_meaning='unknown')
            operations[a][wrapper,index,bank]=desc
            for pc,op,address,value_out in ev:
                assert decode(pc)['opcode']==('ldh.di' if op=='read' else 'sth.di') and decode(pc)['bytes_hex']==prior[hex(pc)]['bytes_hex']
                rows[a].append(dict(case=case['name'],pc=pc,operation=op,address=address,value=value_out,wrapper=hex(wrapper),index=index,original_caller=c['entry']))
        actual_loads=[];actual_mmio=[];actual_entries=[];actual_inputs=[];actual_indirect=[];original_entries=[]
        lp={p for p,v in loads};ep={p for p,o,a,v in expected};ip={p for p,v in input_reads};jp={p for p,t in indirect}
        for line in trace.splitlines():
            m=re.match(r'0x([0-9a-f]+)\s+(\S+)\s+(.*)',line)
            if not m:continue
            pc=int(m[1],16);op=m[2]
            if pc in specs:actual_entries.append(pc)
            if pc in [0x29599c,0x295eb4,0x303ec4,0x303d4c]:original_entries.append(pc)
            if pc in lp:
                assert op=='ld_s';actual_loads.append((pc,int(re.search(r'<- (0x[0-9a-f]+)',line)[1],16)))
            if pc in ep:
                assert op in ['ldw.di','stw.di'];actual_mmio.append((pc,'read' if op=='ldw.di' else 'write',int(re.search(r'<- (0x[0-9a-f]+)',line)[1],16)&65535))
            if pc in ip:actual_inputs.append((pc,int(re.search(r'<- (0x[0-9a-f]+)',line)[1],16)))
            if pc in jp:
                assert op=='jl_s.d';actual_indirect.append((pc,int(re.search(r'pc <- (0x[0-9a-f]+)',line)[1],16)))
            assert op not in ['lr','sr']
        assert actual_entries==entries and actual_loads==loads and actual_mmio==[(p,o,v) for p,o,a,v in expected]
        assert actual_inputs==input_reads and actual_indirect==indirect
        assert original_entries==[0x29599c,0x295eb4,0x303ec4,0x303d4c,0x303d4c]
        assert [(e['pc'],e['operation'],e['address'],e['value']) for e in case['completed_memory_events']]==expected
        log=src/(case['name']+'.stderr.log');inputs[str(log)]=sha(log)
        raw=[json.loads(line.removeprefix('S33_MEM ')) for line in log.read_text().splitlines() if line.startswith('S33_MEM ')]
        assert [e for e in raw if e['stage']=='result']==case['completed_memory_events'] and len(raw)==216
        for b,e in zip(raw[::2],raw[1::2]):
            assert b['stage']=='begin' and e['stage']=='result' and b['width_bytes']==e['width_bytes']==2
            assert all(b[k]==e[k] for k in ['id','pc','operation','address'])
        for key,f in case['fixtures'].items():
            a=int(key,0);off=a%8;before=bytes.fromhex(f['before']);after=(src/f['file']).read_bytes()
            assert struct.unpack_from('<H',before,off)[0]==(case['seed']^(a>>2))&65535
            assert struct.unpack_from('<H',after,off)[0]==state[a] and all(before[j]==after[j] for j in range(8) if j not in [off,off+1])
        checks.append(dict(case=case['name'],events=108,table_loads=len(loads),original_input_loads=len(input_reads),indirect_branches=len(indirect)))
        total_loads+=len(loads);total_input_loads+=len(input_reads)
    assert len(checks)==8 and sum(map(len,rows.values()))==864 and total_loads==864 and total_input_loads==416 and len(rows)==55
    old=load(parent/'register_map.json');known={(r['space'],r['number']) for r in old['records']};new={a for a in rows if ('soc_mmio',a) not in known};existing=set(rows)-new
    assert len(new)==52 and existing=={0xfe90144,0xfe98144,0xfe98138}
    audit=dict(status='PASS_FE9_ORIGINAL_INDIRECT_INIT_AUDIT',date='2026-10-25',checks=checks,events=864,original_table_load_checks=864,original_input_load_checks=416,
        indirect_branches_verified=416,new_addresses=list(map(hex,sorted(new))),enriched_addresses=list(map(hex,sorted(existing))),
        independently_redecoded_instructions={hex(k):v for k,v in decoded.items()},input_sha256=inputs,global_reachability_proven=False,complete_index_domains_proven=False,hardware_access=False)
    save(src/'indirect_init_independent_audit.json',audit)
    out=parent.parent/datetime.now(timezone.utc).strftime('%Y%m%dT%H%M%SZ');assert not out.exists();shutil.copytree(parent,out);(out/'sha256.json').unlink()
    save(out/'atlas_validation.json',dict(status='INCOMPLETE_FE9_INDIRECT_INIT'));ev=out/'evidence';scripts=ROOT/'Python_Trace_Scripts'
    for original,name in [(src/'verified_evidence.json','fe9_indirect_init_cpu.json'),(src/'indirect_init_independent_audit.json','fe9_indirect_init_audit.json'),
        (src/'incoming_census.json','fe9_incoming_census.json'),(src/'original_indirect_setup.json','fe9_indirect_setup.json')]+[(scripts/n,n) for n in ['s33_verify_fe9_tail_callers.py',Path(__file__).name]]:shutil.copy2(original,ev/name)
    mmio=load(ev/'mmio_documented.json');by_address={int(r['address'],0):r for r in mmio['records']}
    sources=[dict(file=str(ev/n),line=1) for n in ['fe9_indirect_init_cpu.json','fe9_indirect_init_audit.json','fe9_indirect_setup.json']]
    for a,events in sorted(rows.items()):
        fields=list(operations[a].values())
        if a in new:
            mmio['records'].append(dict(address=f'0x{a:08X}',namespace='soc_mmio',subsystem='fe9_original_indirect_initializer_physical_function_unknown',
                software_role='original_table_bound_halfword_access',width_bits=16,access='read/write_halfword_di',
                confidence='original_guest_indirect_caller_and_table_selection_audited_fixture',hardware_verified=False,fields=fields,observed_accesses=events,sources=sources,
                unknown=['Globalreachability,alllegalindices,physicalfunction,reset,permissions,W1C,IRQ,timingandatomicity unproved']))
        else:
            record=by_address[a];record.setdefault('fields',[]).extend(fields);record.setdefault('sources',[]).extend(sources);record['fe9_original_tail_caller_accesses']=events
    mmio['counts'].update(register_addresses=len(mmio['records']),direct_or_reported_accesses=len(mmio['records']));save(ev/'mmio_documented.json',mmio)
    metadata=load(out/'atlas_metadata.json');metadata.update(date='2026-10-25',parent_atlas=str(parent),parent_ledger_sha256=sha(parent/'sha256.json'),
        parent_ledger_files_verified=len(ledger),fe9_indirect_new_scalars=52,fe9_tail_enriched_scalars=3,fe9_indirect_cpu_events=864,whole_physical_map_complete=False);save(out/'atlas_metadata.json',metadata)
    completion=load(out/'completion_audit.json');completion.update(prior_turn_classification='progress',goal_complete=False)
    completion['requirements'][2]['limits'][0]='915 individual MMIO addresses and50 transfer windows do not delimit the physical register universe'
    completion['requirements'][2]['limits'][1]='Former4index0samples now haveoriginalindirectcallerCPUevidence;globalreachability andcompleteindexdomains remainunproved'
    completion['next_work']=['Continue AUXcode/data,BCR/SoCimplementation andnumericalhelper303A40/DSP',
        'Other MMIOgroups andcallerconstraints;do not infer fullindexdomains frominitializers',
        'Investigate unqualified pointerpattern106CF12 only withindependentcode/dataevidence;overlap303F0EisnotanindependentLIMMproof'];save(out/'completion_audit.json',completion)
    for name in ['s33_build_register_atlas.py','s33_verify_register_trace_sites.py']:subprocess.run([sys.executable,str(scripts/name),str(out)],check=True)
    subprocess.run(['/home/jack/.local/share/pipx/venvs/graphifyy/bin/python',str(scripts/'s33_build_register_graph.py'),str(out)],check=True)
    atlas=load(out/'register_map.json');keys={(r['space'],r['number']) for r in atlas['records']};by_key={(r['space'],r['number']):r for r in atlas['records']}
    assert len(atlas['records'])==1176 and Counter(r['space'] for r in atlas['records'])==dict(core=64,aux=197,soc_mmio=915)
    assert keys-known=={('soc_mmio',a) for a in new} and known<=keys and not atlas['goal_complete']
    for key in ['mmio_transfer_windows','mmio_window_overlaps','computed_mmio_families']:assert atlas[key]==old[key]
    def relocate(v):
        if isinstance(v,str):return v.replace(str(parent),str(out))
        if isinstance(v,list):return [relocate(x) for x in v]
        if isinstance(v,dict):return {k:relocate(x) for k,x in v.items()}
        return v
    for before in old['records']:
        after=by_key[before['space'],before['number']]
        if before['space']!='soc_mmio':assert after==relocate(before)
        elif before['number'] not in existing:assert after==before
        else:
            for k,v in before.items():assert after[k][:len(v)]==v if k in ['fields','sources'] else after[k]==v
    assert all(not r['hardware_verified'] for r in atlas['records']) and load(ev/'firmware_aux_trace.json')==load(parent/'evidence/firmware_aux_trace.json')
    assert len(load(out/'aux_trace_site_verification.json')['checks'])==172
    allgeo={geometry(w) for w in atlas['mmio_transfer_windows']};historical=[]
    for directory in sorted(parent.parent.iterdir()):
        if directory==out or not(directory/'atlas_validation.json').is_file() or not(directory/'sha256.json').is_file():continue
        if not load(directory/'atlas_validation.json').get('status','').startswith('PASS'):continue
        ld=load(directory/'sha256.json');assert all(sha(directory/k)==v for k,v in ld.items());prior=load(directory/'register_map.json')
        pk={(r['space'],r['number']) for r in prior['records']};pg={geometry(w) for w in prior.get('mmio_transfer_windows',[])};assert pk<=keys and pg<=allgeo
        historical.append(dict(path=str(directory),record_count=len(pk),window_geometry_count=len(pg),missing_in_merged_atlas=0,missing_window_geometries=0,
            ledger_sha256=sha(directory/'sha256.json'),ledger_files_verified=len(ld)))
    history=load(parent/'coverage_lineage_audit.json');history.update(historical_atlases=historical,union_records=len(keys),latest_parent_atlas=str(parent),
        latest_new_addresses=list(map(hex,sorted(new))),latest_new_window_count=0,latest_transfer_cell_addresses=[]);save(out/'coverage_lineage_audit.json',history)
    assert all(sha(Path(k))==v for k,v in inputs.items()) and all(sha(parent/k)==v for k,v in ledger.items())
    save(out/'atlas_validation.json',dict(status='PASS_FE9_ORIGINAL_INDIRECT_INIT_NO_COVERAGE_REGRESSION',total_records=1176,counts=atlas['counts'],new_scalar_mmio_addresses=52,
        enriched_scalar_mmio_addresses=3,completed_memory_events=864,reads=432,writes=432,selected_scenarios=8,trace_identical_pairs=8,
        original_table_load_checks=864,original_input_load_checks=416,indirect_branches_verified=416,original_tail_callers_executed=2,
        original_initializer='0x303ec4',index_domains_witnessed={'0x2ee924':list(range(15)),'0x2ee974':list(range(11))},
        four_former_sample_addresses_now_admitted=True,metamorphic_scope=d['metamorphic_scope'],parent_ledger_files_verified=len(ledger),historical_atlases_verified=len(historical),
        input_sha256=inputs,whole_physical_map_complete=False,gnu_original_inputs_unchanged=True,limits=d['limits']))
    for name in ['s33_build_register_atlas.py','s33_build_register_graph.py','s33_verify_register_trace_sites.py']:shutil.copy2(scripts/name,ev/name)
    save(out/'sha256.json',{str(p.relative_to(out)):sha(p) for p in sorted(out.rglob('*')) if p.is_file() and p!=out/'sha256.json'})
    print('PASS1176records,+52scalars/3enriched,864events/864tableloads/416inputloads;prioratlases',len(historical));print(out)


if __name__=='__main__':main()
