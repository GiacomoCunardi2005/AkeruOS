#!/usr/bin/env python3
"""Versioned accessor publisher: preserve coverage checks and use the evidence date."""
import shutil,subprocess,sys
from collections import Counter
from datetime import datetime,timezone
from pathlib import Path
from s33_integrate_ffc7000_table_tail import ROOT,load,save,sha,geometry


def publish(*,parent,source,copy_files,rows,operations,input_hashes,validation,scripts,next_work):
    ledger=load(parent/'sha256.json');assert all(sha(parent/k)==v for k,v in ledger.items())
    inputs={**input_hashes,str(Path(__file__)):sha(Path(__file__))}
    assert all(sha(Path(k))==v for k,v in inputs.items())
    old=load(parent/'register_map.json');known={(r['space'],r['number']) for r in old['records']}
    new={a for a in rows if ('soc_mmio',a) not in known};existing=set(rows)-new
    assert len(new)==validation['new_scalar_mmio_addresses'] and len(existing)==validation['enriched_scalar_mmio_addresses']
    out=parent.parent/datetime.now(timezone.utc).strftime('%Y%m%dT%H%M%SZ');assert not out.exists();shutil.copytree(parent,out);(out/'sha256.json').unlink()
    save(out/'atlas_validation.json',dict(status='PENDING_ACCESSOR_EVIDENCE'))
    try:
        ev=out/'evidence'
        for original,name in copy_files:shutil.copy2(original,ev/name)
        for p in [Path(__file__)]+scripts:shutil.copy2(p,ev/p.name)
        sources=[dict(file=str(ev/name),line=1) for original,name in copy_files if name.endswith('.json')]
        mmio=load(ev/'mmio_documented.json');by_address={int(r['address'],0):r for r in mmio['records']}
        for a,events in sorted(rows.items()):
            if a in new:
                mmio['records'].append(dict(address=f'0x{a:08X}',namespace='soc_mmio',subsystem='original_TBIB_accessor_physical_function_unknown',
                    software_role='fixed_halfword_accessor',width_bits=16,access='/'.join(sorted({e['operation'] for e in events}))+'_halfword_di',
                    confidence='original_CPU_accessor_independent_audit_fixture',hardware_verified=False,
                    fields=operations[a],observed_accesses=events,sources=sources,
                    unknown=['Physicalnames/reset/permissions/W1C/IRQ/timing,globalreachability andlegalcallerargumentdomains unknown']))
            else:
                r=by_address[a];r.setdefault('fields',[]).extend(operations[a]);r.setdefault('sources',[]).extend(sources)
                r.setdefault('additional_accessor_runs',[]).append(dict(source=str(source),events=events))
        mmio['counts'].update(register_addresses=len(mmio['records']),direct_or_reported_accesses=len(mmio['records']));save(ev/'mmio_documented.json',mmio)
        meta=load(out/'atlas_metadata.json');meta.update(date=validation.get('date',datetime.now(timezone.utc).date().isoformat()),parent_atlas=str(parent),parent_ledger_sha256=sha(parent/'sha256.json'),
            parent_ledger_files_verified=len(ledger),latest_accessor_validation=validation,whole_physical_map_complete=False);save(out/'atlas_metadata.json',meta)
        completion=load(out/'completion_audit.json');completion.update(prior_turn_classification='progress',goal_complete=False)
        completion['requirements'][2]['limits'][0]=f"{len(mmio['records'])} individual MMIO addresses do not delimit the physical register universe"
        completion['next_work']=next_work;save(out/'completion_audit.json',completion)
        for name in ['s33_build_register_atlas.py','s33_verify_register_trace_sites.py']:
            subprocess.run([sys.executable,str(ROOT/'Python_Trace_Scripts'/name),str(out)],check=True)
        subprocess.run(['/home/jack/.local/share/pipx/venvs/graphifyy/bin/python',str(ROOT/'Python_Trace_Scripts/s33_build_register_graph.py'),str(out)],check=True)
        atlas=load(out/'register_map.json');keys={(r['space'],r['number']) for r in atlas['records']};by_key={(r['space'],r['number']):r for r in atlas['records']}
        assert keys-known=={('soc_mmio',a) for a in new} and known<=keys
        def canonical(v):
            if isinstance(v,str):return v.replace(str(parent),'<ATLAS>').replace(str(out),'<ATLAS>')
            if isinstance(v,list):return [canonical(x) for x in v]
            if isinstance(v,dict):return {k:canonical(x) for k,x in v.items()}
            return v
        for before in old['records']:
            after=by_key[before['space'],before['number']]
            if before['space']=='aux':assert canonical(after)==canonical(before)
            elif before['space']!='soc_mmio' or before['number'] not in existing:assert after==before
            else:
                for k,v in before.items():assert after[k][:len(v)]==v if k in ['fields','sources'] else after[k]==v
        for k in ['mmio_transfer_windows','mmio_window_overlaps','computed_mmio_families']:assert atlas[k]==old[k]
        assert not atlas['goal_complete'] and all(not r['hardware_verified'] for r in atlas['records'])
        assert load(ev/'firmware_aux_trace.json')==load(parent/'evidence/firmware_aux_trace.json')
        assert len(load(out/'aux_trace_site_verification.json')['checks'])==len(load(parent/'aux_trace_site_verification.json')['checks'])
        assert atlas['aux_indices_with_guest_semantic_records']==old['aux_indices_with_guest_semantic_records']
        historical=[];geometries={geometry(w) for w in atlas['mmio_transfer_windows']}
        for directory in sorted(parent.parent.iterdir()):
            if directory==out or not(directory/'atlas_validation.json').is_file() or not(directory/'sha256.json').is_file():continue
            if not load(directory/'atlas_validation.json').get('status','').startswith('PASS'):continue
            ld=load(directory/'sha256.json');assert all(sha(directory/k)==v for k,v in ld.items());prior=load(directory/'register_map.json')
            pk={(r['space'],r['number']) for r in prior['records']};pg={geometry(w) for w in prior.get('mmio_transfer_windows',[])};assert pk<=keys and pg<=geometries
            historical.append(dict(path=str(directory),record_count=len(pk),window_geometry_count=len(pg),missing_in_merged_atlas=0,missing_window_geometries=0,
                ledger_sha256=sha(directory/'sha256.json'),ledger_files_verified=len(ld)))
        history=load(parent/'coverage_lineage_audit.json');history.update(historical_atlases=historical,union_records=len(keys),latest_parent_atlas=str(parent),
            latest_new_addresses=list(map(hex,sorted(new))),latest_new_aux_indices=[],latest_new_window_count=0,latest_transfer_cell_addresses=[]);save(out/'coverage_lineage_audit.json',history)
        assert all(sha(Path(k))==v for k,v in inputs.items()) and all(sha(parent/k)==v for k,v in ledger.items())
        save(out/'atlas_validation.json',dict(validation,total_records=len(keys),counts=atlas['counts'],input_sha256=inputs,
            parent_ledger_files_verified=len(ledger),historical_atlases_verified=len(historical),whole_physical_map_complete=False,gnu_original_inputs_unchanged=True))
        for name in ['s33_build_register_atlas.py','s33_build_register_graph.py','s33_verify_register_trace_sites.py']:shutil.copy2(ROOT/'Python_Trace_Scripts'/name,ev/name)
        save(out/'sha256.json',{str(p.relative_to(out)):sha(p) for p in sorted(out.rglob('*')) if p.is_file() and p!=out/'sha256.json'})
        print('PASS',len(keys),'records;',len(new),'new/',len(existing),'enriched;',len(historical),'prioratlases');print(out)
        return out
    except Exception as exc:
        save(out/'atlas_validation.json',dict(status='FAIL_NOT_ADMITTED',error=repr(exc),parent_atlas=str(parent)));raise

