#!/usr/bin/env python3
"""Audit original FE9 remaining-index traces and conservatively extend atlas."""
import argparse
import re
import shutil
import struct
import subprocess
import sys
from collections import Counter, defaultdict
from datetime import datetime, timezone
from pathlib import Path
from s33_integrate_ffc7000_table_tail import ROOT, load, save, sha, geometry
from s33_trace_state_dispatch import verified_payloads
from s33_verify_sensor_mmio_dialog import aligned_window


def main():
    ap=argparse.ArgumentParser(description=__doc__);ap.add_argument('source',type=Path)
    src=ap.parse_args().source.resolve();d=load(src/'verified_evidence.json')
    assert d['status']=='PASS_FE9_REMAINING_ORIGINAL_INDICES'
    static_path=Path(d['static_evidence']);st=load(static_path);parent=Path(st['parent_atlas'])
    ledger=load(parent/'sha256.json');assert all(sha(parent/k)==v for k,v in ledger.items())
    inputs={**d['input_hashes'],str(src/'verified_evidence.json'):sha(src/'verified_evidence.json'),str(Path(__file__)):sha(Path(__file__))}
    assert all(sha(Path(k))==v for k,v in inputs.items()) and all(sha(src/k)==v for k,v in d['files'].items())
    blocks,payloads,_=verified_payloads(ROOT);base=blocks[0]['load_address_candidate'];body=payloads[0]
    firmware=(ROOT/'OriginalSoftware_NikonS33_V1.1/firmware.bin').read_bytes()
    for m in d['payloads']:
        q=Path(m['path']);assert sha(q)==m['sha256'] and q.read_bytes()==payloads[m['index']]==firmware[m['firmware_offset']:m['firmware_offset']+m['size']]
    decoded={}
    def decode(pc):
        if pc not in decoded:
            text=aligned_window(body,base,pc,pc+12);line=next(x for x in text.splitlines() if re.match(r'\s*'+f'{pc:x}:',x))
            m=re.match(r'\s*[0-9a-f]+:\s+((?:[0-9a-f]{4}\s+)+)\t(\S+)\s*(.*)',line)
            raw=b''.join(bytes.fromhex(w)[::-1] for w in m[1].split());assert raw==body[pc-base:pc-base+len(raw)]
            decoded[pc]=dict(opcode=m[2],operands=m[3].strip(),bytes_hex=raw.hex())
        return decoded[pc]
    def word(address):
        owners=[b for b in blocks[:2] if b['load_address_candidate']<=address and address+4<=b['load_address_candidate']+len(payloads[b['index']])]
        assert len(owners)==1;b=owners[0];return struct.unpack_from('<I',payloads[b['index']],address-b['load_address_candidate'])[0]
    rows=defaultdict(list);operations=defaultdict(dict);checks=[];groups={};table_count=0
    for case in d['cases']:
        assert case['exit_code']==0 and case['fault'] is None and case['original_calls_completed']
        if not case['observer_enabled']:continue
        path=src/(case['name']+'.trace');trace=path.read_text();assert path.read_bytes()==(src/(case['name'].replace('_observed','_reference')+'.trace')).read_bytes()
        inputs[str(path)]=sha(path);expected=[];loads=[];entries=[];state={};bank=int(case['channel']!=0)
        assert case['bank']==bank and len(case['calls'])==4
        for c in case['calls']:
            entry,index=int(c['entry'],0),c['index'];assert c['channel']==case['channel'] and c['value']==case['value']
            assert (entry,index) in [(0x2ee760,0),(0x2ee760,1),(0x2ee760,3),(0x2ee850,6)]
            pool=0x2eea08 if entry==0x2ee760 else 0x2eea38
            ha,hb=(0x3098b8,0x309ad0) if entry==0x2ee760 else (0x309944,0x309b88);helper=hb if bank else ha
            p=word(pool+bank*8);mp=word(pool+bank*8+4);address=word(p+4*index);mask=word(mp+4*index)
            selection=c['selection'];assert address==int(selection['address'],0) and mask==int(selection['mask'],0)
            assert selection in st['new_index_table_selections'] and mask>0
            bit=next(i for i in range(16) if mask&(1<<i));old=state.setdefault(address,(case['seed']^(address>>2))&65535)
            # Independent per-bit calculation rather than the producer formula.
            new=sum(((((case['value']>>(i-bit))&1) if mask&(1<<i) else ((old>>i)&1))<<i) for i in range(16))
            ev=[(helper+12,'read',address,old),(helper+34,'write',address,new)];state[address]=new;expected.extend(ev);entries.append(entry)
            loads.extend([(entry+(48 if bank else 28),address),(entry+(56 if bank else 36),mask)])
            assert [tuple(e) for e in c['events']]==ev
            for pc,op,a,value in ev:
                assert decode(pc)['opcode']==('ldh.di' if op=='read' else 'sth.di')
                prior=load(parent/'evidence/fe9_indexed_callers_audit.json')['independently_redecoded_instructions'][hex(pc)]
                assert prior['bytes_hex']==decode(pc)['bytes_hex']
                rows[a].append(dict(case=case['name'],pc=pc,operation=op,address=a,value=value,index=index,wrapper=hex(entry)))
            desc=dict(wrapper=hex(entry),index=index,bank=bank,mask=hex(mask),first_low16_mask_bit=bit,
                destination_table_word=hex(p+4*index),mask_table_word=hex(mp+4*index),physical_meaning='unknown')
            operations[address][(entry,index,bank)]=desc
        actual_loads=[];actual_mmio=[];actual_entries=[];lp={p for p,v in loads};ep={p for p,o,a,v in expected}
        for line in trace.splitlines():
            m=re.match(r'0x([0-9a-f]+)\s+(\S+)\s+(.*)',line)
            if not m:continue
            pc=int(m[1],16);op=m[2]
            if pc in [0x2ee760,0x2ee850]:actual_entries.append(pc)
            if pc in lp:
                assert op=='ld_s' and decode(pc)['opcode']=='ld_s'
                actual_loads.append((pc,int(re.search(r'<- (0x[0-9a-f]+)',line)[1],16)))
            if pc in ep:
                assert op in ['ldw.di','stw.di'];actual_mmio.append((pc,'read' if op=='ldw.di' else 'write',int(re.search(r'<- (0x[0-9a-f]+)',line)[1],16)&65535))
            assert op not in ['lr','sr']
        assert actual_entries==entries and actual_loads==loads and actual_mmio==[(p,o,v) for p,o,a,v in expected]
        assert [(e['pc'],e['operation'],e['address'],e['value']) for e in case['completed_memory_events']]==expected
        log=src/(case['name']+'.stderr.log');inputs[str(log)]=sha(log)
        raw=[__import__('json').loads(line.removeprefix('S33_MEM ')) for line in log.read_text().splitlines() if line.startswith('S33_MEM ')]
        assert [e for e in raw if e['stage']=='result']==case['completed_memory_events'] and len(raw)==16
        for b,e in zip(raw[::2],raw[1::2]):
            assert b['stage']=='begin' and e['stage']=='result' and b['width_bytes']==e['width_bytes']==2
            assert all(b[k]==e[k] for k in ['id','pc','operation','address'])
        for key,f in case['fixtures'].items():
            a=int(key,0);off=a%8;before=bytes.fromhex(f['before']);after=(src/f['file']).read_bytes()
            assert struct.unpack_from('<H',before,off)[0]==(case['seed']^(a>>2))&65535
            assert struct.unpack_from('<H',after,off)[0]==state[a]
            assert all(before[j]==after[j] for j in range(8) if j not in [off,off+1])
        key=(case['pattern'],bank)
        if key in groups:assert groups[key]==expected
        else:groups[key]=expected
        checks.append(dict(case=case['name'],events=len(expected),table_loads=len(loads)));table_count+=len(loads)
    assert len(checks)==8 and sum(map(len,rows.values()))==64 and table_count==64 and len(rows)==8
    old=load(parent/'register_map.json');known={(r['space'],r['number']) for r in old['records']};new={a for a in rows if ('soc_mmio',a) not in known}
    assert new=={int(a,0) for a in st['new_scalar_candidates']} and len(new)==6
    audit=dict(status='PASS_FE9_REMAINING_INDICES_AUDIT',checks=checks,events=64,table_load_checks=64,
        new_addresses=list(map(hex,sorted(new))),enriched_addresses=list(map(hex,sorted(set(rows)-new))),
        independently_redecoded_instructions={hex(k):v for k,v in decoded.items()},input_sha256=inputs,
        global_reachability_proven=False,complete_index_domains_proven=False,hardware_access=False,gnu_modified=False)
    save(src/'remaining_independent_audit.json',audit)
    out=parent.parent/datetime.now(timezone.utc).strftime('%Y%m%dT%H%M%SZ');assert not out.exists();shutil.copytree(parent,out)
    (out/'sha256.json').unlink();save(out/'atlas_validation.json',dict(status='INCOMPLETE_FE9_REMAINING'))
    ev=out/'evidence';scripts=ROOT/'Python_Trace_Scripts'
    for original,name in [(src/'verified_evidence.json','fe9_remaining_cpu.json'),(src/'remaining_independent_audit.json','fe9_remaining_audit.json'),
        (static_path,'fe9_remaining_static.json')]+[(scripts/n,n) for n in ['s33_verify_fe9_remaining_callers.py','s33_verify_fe9_remaining_cpu.py',Path(__file__).name]]:
        shutil.copy2(original,ev/name)
    mmio=load(ev/'mmio_documented.json');by_address={int(r['address'],0):r for r in mmio['records']}
    sources=[dict(file=str(ev/n),line=1) for n in ['fe9_remaining_static.json','fe9_remaining_cpu.json','fe9_remaining_audit.json']]
    for a,events in sorted(rows.items()):
        fields=list(operations[a].values())
        if a in new:
            mmio['records'].append(dict(address=f'0x{a:08X}',namespace='soc_mmio',subsystem='fe9_original_indexed_table_selection_physical_function_unknown',
                software_role='original_table_bound_halfword_access',width_bits=16,access='read/write_halfword_di',
                confidence='original_guest_table_selection_local_constant_index_witness_audited_fixture',hardware_verified=False,
                fields=fields,observed_accesses=events,sources=sources,
                unknown=['Globalreachability,completeindexdomains,physicalfunction,reset,permissions,W1C,IRQ,timing andatomicity unproved']))
        else:
            record=by_address[a];record.setdefault('fields',[]).extend(fields);record.setdefault('sources',[]).extend(sources)
            record['fe9_remaining_index_accesses']=events
    mmio['counts'].update(register_addresses=len(mmio['records']),direct_or_reported_accesses=len(mmio['records']));save(ev/'mmio_documented.json',mmio)
    metadata=load(out/'atlas_metadata.json');metadata.update(date='2026-10-25',parent_atlas=str(parent),parent_ledger_sha256=sha(parent/'sha256.json'),
        parent_ledger_files_verified=len(ledger),fe9_remaining_new_scalars=6,fe9_remaining_enriched_scalars=2,fe9_remaining_cpu_events=64,whole_physical_map_complete=False);save(out/'atlas_metadata.json',metadata)
    completion=load(out/'completion_audit.json');completion.update(prior_turn_classification='progress',goal_complete=False)
    completion['next_work']=['Continue original MMIOgroups beyond309CD0','Seek indirect/tailreferences to2EE924/974;seven previous BLlocal setups are now resolved,not globalreachability',
        'Resolve AUXcode/data,BCR/SoC implementation andnumerical helper303A40/DSP'];save(out/'completion_audit.json',completion)
    for name in ['s33_build_register_atlas.py','s33_verify_register_trace_sites.py']:
        subprocess.run([sys.executable,str(scripts/name),str(out)],check=True)
    subprocess.run(['/home/jack/.local/share/pipx/venvs/graphifyy/bin/python',str(scripts/'s33_build_register_graph.py'),str(out)],check=True)
    atlas=load(out/'register_map.json');keys={(r['space'],r['number']) for r in atlas['records']};by_key={(r['space'],r['number']):r for r in atlas['records']}
    assert len(atlas['records'])==1124 and Counter(r['space'] for r in atlas['records'])==dict(core=64,aux=197,soc_mmio=863)
    assert keys-known=={('soc_mmio',a) for a in new} and known<=keys and not atlas['goal_complete']
    for key in ['mmio_transfer_windows','mmio_window_overlaps','computed_mmio_families']:assert atlas[key]==old[key]
    def relocate(value):
        if isinstance(value,str):return value.replace(str(parent),str(out))
        if isinstance(value,list):return [relocate(x) for x in value]
        if isinstance(value,dict):return {k:relocate(v) for k,v in value.items()}
        return value
    for before in old['records']:
        after=by_key[(before['space'],before['number'])]
        if before['space']!='soc_mmio':assert after==relocate(before)
        elif before['number'] not in rows:assert after==before
        else:
            for key,value in before.items():
                assert after[key][:len(value)]==value if key in ['fields','sources'] else after[key]==value
    assert all(not r['hardware_verified'] for r in atlas['records'])
    assert load(ev/'firmware_aux_trace.json')==load(parent/'evidence/firmware_aux_trace.json')
    assert len(load(out/'aux_trace_site_verification.json')['checks'])==172
    allgeo={geometry(w) for w in atlas['mmio_transfer_windows']};historical=[]
    for directory in sorted(parent.parent.iterdir()):
        if directory==out or not(directory/'atlas_validation.json').is_file() or not(directory/'sha256.json').is_file():continue
        if not load(directory/'atlas_validation.json').get('status','').startswith('PASS'):continue
        ld=load(directory/'sha256.json');assert all(sha(directory/k)==v for k,v in ld.items())
        prior=load(directory/'register_map.json');pk={(r['space'],r['number']) for r in prior['records']};pg={geometry(w) for w in prior.get('mmio_transfer_windows',[])}
        assert pk<=keys and pg<=allgeo;historical.append(dict(path=str(directory),record_count=len(pk),window_geometry_count=len(pg),missing_in_merged_atlas=0,
            missing_window_geometries=0,ledger_sha256=sha(directory/'sha256.json'),ledger_files_verified=len(ld)))
    history=load(parent/'coverage_lineage_audit.json');history.update(historical_atlases=historical,union_records=len(keys),latest_parent_atlas=str(parent),
        latest_new_addresses=list(map(hex,sorted(new))),latest_new_window_count=0,latest_transfer_cell_addresses=[]);save(out/'coverage_lineage_audit.json',history)
    assert all(sha(Path(k))==v for k,v in inputs.items()) and all(sha(parent/k)==v for k,v in ledger.items())
    save(out/'atlas_validation.json',dict(status='PASS_FE9_REMAINING_NO_COVERAGE_REGRESSION',total_records=1124,counts=atlas['counts'],new_scalar_mmio_addresses=6,
        enriched_scalar_mmio_addresses=2,completed_memory_events=64,selected_scenarios=8,trace_identical_pairs=8,original_table_load_checks=64,
        local_BL_witnesses_resolved=7,indirect_JL_candidate='0x295f9e',indirect_JL_original_caller_executed=False,
        channel_equivalences=4,metamorphic_scope=d['metamorphic_scope'],parent_ledger_files_verified=len(ledger),historical_atlases_verified=len(historical),
        input_sha256=inputs,whole_physical_map_complete=False,gnu_original_inputs_unchanged=True,limits=d['limits']))
    for name in ['s33_build_register_atlas.py','s33_build_register_graph.py','s33_verify_register_trace_sites.py']:shutil.copy2(scripts/name,ev/name)
    save(out/'sha256.json',{str(p.relative_to(out)):sha(p) for p in sorted(out.rglob('*')) if p.is_file() and p!=out/'sha256.json'})
    print('PASS1124records,+6scalars/2enriched,64events/64tableloads;prioratlases',len(historical));print(out)


if __name__=='__main__':main()
