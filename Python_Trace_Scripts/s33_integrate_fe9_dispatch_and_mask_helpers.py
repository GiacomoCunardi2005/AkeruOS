#!/usr/bin/env python3
"""Admit fixed FE9/FFC pools; retain generic helper tests without catalog promotion."""
import argparse, shutil, subprocess, sys
from collections import Counter, defaultdict
from datetime import datetime, timezone
from pathlib import Path
from s33_integrate_ffc7000_table_tail import ROOT, sha, load, save, geometry


def main():
    ap = argparse.ArgumentParser(description=__doc__)
    ap.add_argument('--parent', type=Path, required=True)
    ap.add_argument('--source', type=Path, required=True)
    ap.add_argument('--audit', type=Path, required=True)
    args = ap.parse_args()
    parent, src, audit_path = args.parent.resolve(), args.source.resolve(), args.audit.resolve()
    ledger = load(parent/'sha256.json')
    assert all(sha(parent/k) == v for k, v in ledger.items())
    assert load(parent/'atlas_validation.json')['status'] == 'PASS_FFC7000_SCALAR_TAIL_NO_COVERAGE_REGRESSION'
    d, audit = load(src/'verified_evidence.json'), load(audit_path)
    assert d['status'] == 'PASS_FE9_SELECTORS_UNBOUND_MASK_HELPERS'
    assert audit['status'] == 'PASS_FE9_SELECTORS_UNBOUND_MASK_HELPERS_AUDIT'
    inputs = {**d['input_hashes'], **audit['input_sha256']}
    helper = Path(__file__).with_name('s33_integrate_ffc7000_table_tail.py')
    inputs[str(helper)] = sha(helper)
    assert all(sha(Path(k)) == v for k, v in inputs.items())
    assert all(sha(src/k) == v for k, v in d['files'].items())
    old = load(parent/'register_map.json')
    known = {(r['space'], r['number']) for r in old['records']}
    addresses = {int(x, 0) for x in audit['new_bound_scalar_addresses']}
    samples = {int(x, 0) for x in audit['generic_sample_addresses_not_admitted']}
    assert addresses == {0xffc7070, 0xfe9013c, 0xfe90140, 0xfe9813c, 0xfe98140}
    assert not any(('soc_mmio', x) in known for x in addresses)
    assert samples == {0xffb8000, 0xffb8004} and not audit['generic_helper_address_domains_closed']
    rows = defaultdict(list)
    for case in d['cases']:
        if case['observer_enabled'] and case['group'] == 'fixed':
            assert case['address_binding'] == 'original_fixed_pool'
            for event in case['completed_memory_events']:
                rows[event['address']].append(dict(case=case['name'], **event))
    assert set(rows) == addresses and sum(map(len, rows.values())) == 136
    cells = {int(w['base'], 0)+w['stride_bytes']*i
             for w in old['mmio_transfer_windows'] for i in range(w['element_count'])}
    assert not cells & addresses
    out = parent.parent/datetime.now(timezone.utc).strftime('%Y%m%dT%H%M%SZ')
    assert not out.exists()
    shutil.copytree(parent, out)
    (out/'sha256.json').unlink()
    save(out/'atlas_validation.json', dict(status='INCOMPLETE_NO_VALIDATION', parent_atlas=str(parent)))
    print('Candidate:', out, flush=True)
    ev, scripts = out/'evidence', ROOT/'Python_Trace_Scripts'
    try:
        for original, name in [
            (src/'verified_evidence.json', 'fe9_dispatch_and_mask_helpers.json'),
            (audit_path, 'fe9_dispatch_and_mask_helpers_audit.json'),
            (src/'caller_census.json', 'fe9_caller_census.json'),
            (src/'linear_navigation_only.txt', 'fe9_linear_navigation.txt'),
            (src/'s33_verify_fe9_dispatch_and_mask_helpers.py', 's33_verify_fe9_dispatch_and_mask_helpers.py'),
            (scripts/'s33_audit_fe9_dispatch_and_mask_helpers.py', 's33_audit_fe9_dispatch_and_mask_helpers.py'),
            (Path(__file__), Path(__file__).name)]:
            shutil.copy2(original, ev/name)
        sources = [dict(file=str(ev/name), line=1) for name in
                   ['fe9_dispatch_and_mask_helpers.json', 'fe9_dispatch_and_mask_helpers_audit.json']]
        mmio = load(ev/'mmio_documented.json')
        for address, events in sorted(rows.items()):
            if address == 0xffc7070:
                fields = [dict(entry='0x309884', operation='read_full16')]
            else:
                entry = '0x309a2c' if address < 0xfe98000 else '0x309c44'
                table = audit['selector_tables'][entry]
                first = address == int(table['pool_addresses'][0], 0)
                fields = [dict(entry=entry, selector=0 if first else 2,
                               operation='read_modify_write_low_field',
                               low_field_width=table['low_field_width'],
                               preserve_other_bits=True),
                          dict(entry=entry, selector=1 if first else 3,
                               operation='read_full16' if first else 'read_modify_write_clear_full_argument_mask')]
            mmio['records'].append(dict(
                address=f'0x{address:08X}', namespace='soc_mmio',
                subsystem='fe9_fixed_selectors_or_ffc_read_physical_function_unknown',
                software_role='original_fixed_pool_halfword_access', width_bits=16,
                access='/'.join(sorted({e['operation'] for e in events}))+'_halfword_di',
                confidence='original_guest_fixed_pool_independently_audited_fixture',
                hardware_verified=False,
                fields=[dict(f, physical_meaning='unknown',
                             evidence_type='independently_reconstructed_original_software_operation') for f in fields],
                observed_accesses=events, sources=sources,
                evidence=['original_pool_and_instruction_bytes_bound', 'full_original_calls_completed',
                          'ordered_MMIO_and_selector_table_audit', 'reference_observer_traces_identical'],
                unknown=['Physical role,reset,permissions,W1C,IRQ,timing andatomicity unknown',
                         'Callers,MMIO seeds,backing andstack are fixtures;actualNikon input constraints unproved']))
        mmio['counts'].update(register_addresses=len(mmio['records']), direct_or_reported_accesses=len(mmio['records']))
        save(ev/'mmio_documented.json', mmio)
        metadata = load(out/'atlas_metadata.json')
        metadata.update(date='2026-10-25', parent_atlas=str(parent), parent_ledger_sha256=sha(parent/'sha256.json'),
                        parent_ledger_files_verified=len(ledger), fe9_selector_new_scalars=5,
                        fe9_original_entries=23, fe9_scenarios=12, fe9_events=4184,
                        fe9_admission_events=136, fe9_unbound_sample_events_excluded=4048,
                        fe9_parameterized_helper_domains_closed=False, whole_physical_map_complete=False)
        save(out/'atlas_metadata.json', metadata)
        completion = load(out/'completion_audit.json')
        completion.update(prior_turn_classification='progress', goal_complete=False)
        completion['requirements'][2]['limits'] = [
            '791individual MMIO addresses and50windows/3408memberships/3376unique cells do not delimit the physical register universe',
            'FE9fixed selector semantics and20generic helper contracts are software-only;4048generic events do not bind real caller domains',
            'Actual indexed caller constraints,BCR,AUX code/data,provisionalDSP mathematics andhardware semantics remain open']
        completion['next_work'] = [
            'Bind original caller tables in2EE760..2EE9C4 andchannel selector2ED448;prove index constraints before admitting destinations',
            'Continue original MMIO groups beyond309CD0 andunresolved indexed/tail domains',
            'Resolve AUX code/data candidates,BCR/SoC implementation andnumerical helper303A40/DSP']
        save(out/'completion_audit.json', completion)
        for name in ['s33_build_register_atlas.py', 's33_verify_register_trace_sites.py']:
            subprocess.run([sys.executable, str(scripts/name), str(out)], check=True)
        subprocess.run(['/home/jack/.local/share/pipx/venvs/graphifyy/bin/python',
                        str(scripts/'s33_build_register_graph.py'), str(out)], check=True)
        atlas = load(out/'register_map.json')
        keys = {(r['space'], r['number']) for r in atlas['records']}
        assert len(atlas['records']) == 1052 and Counter(r['space'] for r in atlas['records']) == dict(core=64, aux=197, soc_mmio=791)
        assert keys-known == {('soc_mmio', x) for x in addresses}
        assert known <= keys and not atlas['goal_complete'] and all(not r['hardware_verified'] for r in atlas['records'])
        for key in ['mmio_transfer_windows', 'mmio_window_overlaps', 'computed_mmio_families']:
            assert atlas[key] == old[key]
        assert load(ev/'firmware_aux_trace.json') == load(parent/'evidence/firmware_aux_trace.json')
        assert len(load(out/'aux_trace_site_verification.json')['checks']) == 172
        assert len(atlas['aux_indices_with_guest_semantic_records']) == 22
        by_key = {(r['space'], r['number']): r for r in atlas['records']}
        for prior in old['records']:
            if prior['space'] == 'soc_mmio':
                assert by_key[prior['space'], prior['number']] == prior
        allgeo = {geometry(w) for w in atlas['mmio_transfer_windows']}
        historical = []
        for directory in sorted(parent.parent.iterdir()):
            if directory == out or not (directory/'atlas_validation.json').is_file() or not (directory/'sha256.json').is_file():
                continue
            if not load(directory/'atlas_validation.json').get('status', '').startswith('PASS'):
                continue
            ld = load(directory/'sha256.json')
            assert all(sha(directory/k) == v for k, v in ld.items())
            prior = load(directory/'register_map.json')
            pk = {(r['space'], r['number']) for r in prior['records']}
            pg = {geometry(w) for w in prior.get('mmio_transfer_windows', [])}
            assert pk <= keys and pg <= allgeo
            historical.append(dict(path=str(directory), record_count=len(pk), window_geometry_count=len(pg),
                                   missing_in_merged_atlas=0, missing_window_geometries=0,
                                   ledger_sha256=sha(directory/'sha256.json'), ledger_files_verified=len(ld)))
        history = load(parent/'coverage_lineage_audit.json')
        history.update(historical_atlases=historical, union_records=len(keys), latest_parent_atlas=str(parent),
                       latest_new_addresses=list(map(hex, sorted(addresses))), latest_new_window_count=0,
                       latest_transfer_cell_addresses=[], historical_window_geometry_coverage_verified=True)
        save(out/'coverage_lineage_audit.json', history)
        assert all(sha(Path(k)) == v for k, v in inputs.items()) and all(sha(parent/k) == v for k, v in ledger.items())
        save(out/'atlas_validation.json', dict(
            status='PASS_FE9_FIXED_SELECTORS_NO_COVERAGE_REGRESSION', total_records=1052, counts=atlas['counts'],
            new_scalar_mmio_addresses=5, new_transfer_windows=0, completed_memory_events=4184,
            admission_events=136, admission_reads=88, admission_writes=48, unbound_sample_events_excluded=4048,
            selected_scenarios=12, trace_identical_pairs=12, independently_redecoded_instructions=206,
            generic_helper_address_domains_closed=False, qualified_BL_instruction_calls=36,
            BL_candidates_inside_LIMM_excluded=1, representative_aux_guest_indices=22, aux_run_pc_sites=172,
            parent_ledger_files_verified=len(ledger), historical_atlases_verified=len(historical),
            input_sha256=inputs, gnu_original_inputs_unchanged=True, whole_physical_map_complete=False, limits=d['limits']))
        for name in ['s33_build_register_atlas.py', 's33_build_register_graph.py', 's33_verify_register_trace_sites.py']:
            shutil.copy2(scripts/name, ev/name)
        save(out/'sha256.json', {str(p.relative_to(out)): sha(p) for p in sorted(out.rglob('*'))
                                if p.is_file() and p != out/'sha256.json'})
        print('PASS1052records,+5fixed scalars;4048sample events excluded;ledger', len(load(out/'sha256.json')))
        print(out)
    except Exception as exc:
        save(out/'atlas_validation.json', dict(status='FAIL_NOT_ADMITTED', parent_atlas=str(parent), error=repr(exc)))
        raise


if __name__ == '__main__':
    main()
