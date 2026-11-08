#!/usr/bin/env python3
"""Admit original table selections with local constant-index witnesses; exclude synthetic index samples."""
import argparse, shutil, subprocess, sys
from collections import Counter, defaultdict
from datetime import datetime, timezone
from pathlib import Path
from s33_integrate_ffc7000_table_tail import ROOT, sha, load, save, geometry


def main():
    ap = argparse.ArgumentParser(description=__doc__)
    for arg in ['parent','source','audit']: ap.add_argument('--'+arg,type=Path,required=True)
    args = ap.parse_args(); parent, src, audit_path = args.parent.resolve(), args.source.resolve(), args.audit.resolve()
    ledger = load(parent/'sha256.json'); assert all(sha(parent/k) == v for k,v in ledger.items())
    assert load(parent/'atlas_validation.json')['status'] == 'PASS_FE9_FIXED_SELECTORS_NO_COVERAGE_REGRESSION'
    d, audit = load(src/'verified_evidence.json'), load(audit_path)
    assert d['status'] == 'PASS_FE9_ORIGINAL_INDEXED_CALLERS' and audit['status'] == 'PASS_FE9_ORIGINAL_INDEXED_CALLERS_AUDIT'
    inputs = {**d['input_hashes'],**audit['input_sha256']}
    helper = Path(__file__).with_name('s33_integrate_ffc7000_table_tail.py'); inputs[str(helper)] = sha(helper)
    assert all(sha(Path(k)) == v for k,v in inputs.items()) and all(sha(src/k) == v for k,v in d['files'].items())
    old = load(parent/'register_map.json'); known = {(r['space'],r['number']) for r in old['records']}
    addresses = {int(x,0) for x in audit['selected_addresses']}; samples = {int(x,0) for x in audit['sample_addresses_excluded']}
    new = {x for x in addresses if ('soc_mmio',x) not in known}; existing = addresses-new
    assert len(new) == 66 and existing == {0xfe9013c,0xfe90140,0xfe9813c,0xfe98140}
    assert not samples & addresses and not any(('soc_mmio',x) in known for x in samples)
    rows = defaultdict(list)
    for case in d['cases']:
        if not case['observer_enabled']: continue
        for call in case['original_calls']:
            if call['original_index_witness']:
                for event in call['events']:
                    rows[event['address']].append(dict(case=case['name'],entry=call['entry'],index=int(call['arguments'][0],0),**event))
    assert set(rows) == addresses and sum(map(len,rows.values())) == 1032
    cells = {int(w['base'],0)+w['stride_bytes']*i for w in old['mmio_transfer_windows'] for i in range(w['element_count'])}
    assert not cells & new
    out = parent.parent/datetime.now(timezone.utc).strftime('%Y%m%dT%H%M%SZ'); assert not out.exists()
    shutil.copytree(parent,out); (out/'sha256.json').unlink()
    save(out/'atlas_validation.json',dict(status='INCOMPLETE_NO_VALIDATION',parent_atlas=str(parent)))
    print('Candidate:',out,flush=True); ev, scripts = out/'evidence', ROOT/'Python_Trace_Scripts'
    try:
        for original,name in [(src/'verified_evidence.json','fe9_indexed_callers.json'),(audit_path,'fe9_indexed_callers_audit.json'),
            (src/'caller_index_witnesses.json','fe9_indexed_witnesses.json'),(src/'linear_navigation_only.txt','fe9_indexed_linear_navigation.txt'),
            (src/'s33_verify_fe9_indexed_callers.py','s33_verify_fe9_indexed_callers.py'),
            (scripts/'s33_audit_fe9_indexed_callers.py','s33_audit_fe9_indexed_callers.py'),(Path(__file__),Path(__file__).name)]:
            shutil.copy2(original,ev/name)
        sources = [dict(file=str(ev/name),line=1) for name in ['fe9_indexed_callers.json','fe9_indexed_callers_audit.json','fe9_indexed_witnesses.json']]
        mmio = load(ev/'mmio_documented.json'); by_address = {int(r['address'],0):r for r in mmio['records']}
        for address,events in sorted(rows.items()):
            ops = audit['address_software_operations'][hex(address)]
            fields = [dict(op,physical_meaning='unknown',evidence_type='original_table_selection_with_local_constant_index_witness') for op in ops]
            if address in existing:
                record = by_address[address]; record.setdefault('fields',[]).extend(fields); record.setdefault('sources',[]).extend(sources)
                record['fe9_indexed_accesses'] = events; record['fe9_indexed_software_operations'] = ops
            else:
                mmio['records'].append(dict(address=f'0x{address:08X}',namespace='soc_mmio',subsystem='fe9_original_indexed_table_selection_physical_function_unknown',
                    software_role='original_table_bound_halfword_access',width_bits=16,
                    access='/'.join(sorted({e['operation'] for e in events}))+'_halfword_di',
                    confidence='original_guest_table_selection_local_constant_index_witness_audited_fixture',hardware_verified=False,
                    fields=fields,observed_accesses=events,sources=sources,
                    evidence=['original_payload0_and_payload1_bytes_bound','local_constant_index_setup_in_original_caller',
                        'full_original_wrapper_and_helper_calls_completed','ordered_MMIO_and_original_table_load_audit','reference_observer_traces_identical'],
                    unknown=['Globalcaller reachability andcompleteindex/argument domains unproved',
                        'Physicalrole,reset,permissions,W1C,IRQ,timing andatomicity unknown;backing/values/stack/channel are fixtures']))
        mmio['counts'].update(register_addresses=len(mmio['records']),direct_or_reported_accesses=len(mmio['records']))
        save(ev/'mmio_documented.json',mmio)
        metadata = load(out/'atlas_metadata.json'); metadata.update(date='2026-10-25',parent_atlas=str(parent),
            parent_ledger_sha256=sha(parent/'sha256.json'),parent_ledger_files_verified=len(ledger),fe9_indexed_new_scalars=66,
            fe9_indexed_enriched_scalars=4,fe9_indexed_scenarios=12,fe9_indexed_events=1080,fe9_indexed_admission_events=1032,
            fe9_indexed_sample_events_excluded=48,fe9_indexed_complete_caller_domains_closed=False,whole_physical_map_complete=False)
        save(out/'atlas_metadata.json',metadata)
        completion = load(out/'completion_audit.json'); completion.update(prior_turn_classification='progress',goal_complete=False)
        completion['requirements'][2]['limits'] = ['857individual MMIOaddresses and50transferwindows do not delimit the physicalregister universe',
            'Only explicitly witnessed localconstant index selections are admitted;4sampleonly addresses excluded;globalreachability andcompleteindexdomains unproved',
            'Hardware/BCR/AUX code-data andprovisionalDSP numerical semantics remain unverified']
        completion['next_work'] = ['Trace remaining original caller indices andindirect/tail references to2EE924/974;donot infer bounds fromadjacent pools',
            'Continue original MMIOgroups beyond309CD0 andunresolved indexed/tail domains',
            'Resolve AUX code/data candidates,BCR/SoC implementation andnumerical helper303A40/DSP']
        save(out/'completion_audit.json',completion)
        for name in ['s33_build_register_atlas.py','s33_verify_register_trace_sites.py']:
            subprocess.run([sys.executable,str(scripts/name),str(out)],check=True)
        subprocess.run(['/home/jack/.local/share/pipx/venvs/graphifyy/bin/python',str(scripts/'s33_build_register_graph.py'),str(out)],check=True)
        atlas = load(out/'register_map.json'); keys = {(r['space'],r['number']) for r in atlas['records']}
        assert len(atlas['records']) == 1118 and Counter(r['space'] for r in atlas['records']) == dict(core=64,aux=197,soc_mmio=857)
        assert keys-known == {('soc_mmio',x) for x in new} and known <= keys
        assert not any(('soc_mmio',x) in keys for x in samples) and not atlas['goal_complete']
        for k in ['mmio_transfer_windows','mmio_window_overlaps','computed_mmio_families']: assert atlas[k] == old[k]
        assert all(not r['hardware_verified'] for r in atlas['records'])
        assert load(ev/'firmware_aux_trace.json') == load(parent/'evidence/firmware_aux_trace.json')
        assert len(load(out/'aux_trace_site_verification.json')['checks']) == 172 and len(atlas['aux_indices_with_guest_semantic_records']) == 22
        by_key = {(r['space'],r['number']):r for r in atlas['records']}
        for prior in old['records']:
            if prior['space'] != 'soc_mmio': continue
            record = by_key['soc_mmio',prior['number']]
            if prior['number'] not in existing: assert record == prior
            else:
                assert record['observed_accesses'] == prior['observed_accesses'] and record['access'] == prior['access']
                assert record['fields'][:len(prior['fields'])] == prior['fields'] and record['sources'][:len(prior['sources'])] == prior['sources']
                assert record['fe9_indexed_accesses'] == rows[prior['number']]
        allgeo = {geometry(w) for w in atlas['mmio_transfer_windows']}; historical = []
        for directory in sorted(parent.parent.iterdir()):
            if directory == out or not (directory/'atlas_validation.json').is_file() or not (directory/'sha256.json').is_file(): continue
            if not load(directory/'atlas_validation.json').get('status','').startswith('PASS'): continue
            ld = load(directory/'sha256.json'); assert all(sha(directory/k) == v for k,v in ld.items())
            prior = load(directory/'register_map.json'); pk = {(r['space'],r['number']) for r in prior['records']}; pg = {geometry(w) for w in prior.get('mmio_transfer_windows',[])}
            assert pk <= keys and pg <= allgeo
            historical.append(dict(path=str(directory),record_count=len(pk),window_geometry_count=len(pg),missing_in_merged_atlas=0,
                missing_window_geometries=0,ledger_sha256=sha(directory/'sha256.json'),ledger_files_verified=len(ld)))
        history = load(parent/'coverage_lineage_audit.json'); history.update(historical_atlases=historical,union_records=len(keys),latest_parent_atlas=str(parent),
            latest_new_addresses=list(map(hex,sorted(new))),latest_new_window_count=0,latest_transfer_cell_addresses=[],historical_window_geometry_coverage_verified=True)
        save(out/'coverage_lineage_audit.json',history)
        assert all(sha(Path(k)) == v for k,v in inputs.items()) and all(sha(parent/k) == v for k,v in ledger.items())
        save(out/'atlas_validation.json',dict(status='PASS_FE9_INDEXED_SELECTIONS_NO_COVERAGE_REGRESSION',total_records=1118,counts=atlas['counts'],
            new_scalar_mmio_addresses=66,enriched_scalar_mmio_addresses=4,new_transfer_windows=0,completed_memory_events=1080,
            admission_events=1032,admission_reads=456,admission_writes=576,sample_events_excluded=48,sample_addresses_excluded=audit['sample_addresses_excluded'],
            selected_scenarios=12,trace_identical_pairs=12,independently_redecoded_instructions=398,original_table_load_checks=1008,
            local_constant_index_witnesses=68,qualified_BL_candidates=75,complete_caller_domains_closed=False,global_reachability_proven=False,
            channel_equivalences=6,channel_equivalence_scope=audit['channel_equivalence_scope'],mode1_A_index11_extra_bit_cases=2,
            representative_aux_guest_indices=22,aux_run_pc_sites=172,parent_ledger_files_verified=len(ledger),historical_atlases_verified=len(historical),
            input_sha256=inputs,gnu_original_inputs_unchanged=True,whole_physical_map_complete=False,limits=d['limits']))
        for name in ['s33_build_register_atlas.py','s33_build_register_graph.py','s33_verify_register_trace_sites.py']: shutil.copy2(scripts/name,ev/name)
        save(out/'sha256.json',{str(p.relative_to(out)):sha(p) for p in sorted(out.rglob('*')) if p.is_file() and p != out/'sha256.json'})
        print('PASS1118records,+66scalars/4enriched;4sampleaddresses excluded;ledger',len(load(out/'sha256.json'))); print(out)
    except Exception as exc:
        save(out/'atlas_validation.json',dict(status='FAIL_NOT_ADMITTED',parent_atlas=str(parent),error=repr(exc))); raise


if __name__ == '__main__': main()
