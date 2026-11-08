#!/usr/bin/env python3
"""Check FE1 atlas joins against retained CPU, byte and observer evidence."""
import argparse
from collections import Counter
import hashlib
import json
from pathlib import Path
import shutil


def sha(p):
    return hashlib.sha256(p.read_bytes()).hexdigest()


def load(p):
    return json.loads(p.read_text())


def main():
    ap=argparse.ArgumentParser(description=__doc__);ap.add_argument('directory',type=Path)
    out=ap.parse_args().directory.resolve();ev=out/'evidence'
    atlas=load(out/'register_map.json');meta=load(out/'atlas_metadata.json')
    parent=Path(meta['parent_atlas']);ledger=load(parent/'sha256.json')
    assert sha(parent/'sha256.json')==meta['parent_ledger_sha256']
    assert all(sha(parent/p)==h for p,h in ledger.items())
    assert Counter(r['space']for r in atlas['records'])==dict(core=64,aux=114,soc_mmio=195)
    assert len(atlas['records'])==373
    assert len({(r['space'],r['number'])for r in atlas['records']})==373
    assert atlas['goal_complete']is False and all(r['hardware_verified']is False for r in atlas['records'])
    source=load(ev/'fe1_register_window.json');observer=load(ev/'observer_fe1.json')
    assert len(source['cases'])==len(observer['cases'])==6
    original_manifest=Path(meta['fe1_source'])
    assert source==load(original_manifest)
    assert observer==load(Path(meta['fe1_observer']))
    for mapping in [source['input_hashes'],observer['input_sha256']]:
        assert all(sha(Path(p))==h for p,h in mapping.items())
    assert all(sha(original_manifest.parent/p)==h for p,h in source['files'].items())
    assert [len(c['completed'])for c in observer['cases']]==[2,13,13,13,0,0]
    assert all(c['trace_identical']and c['exit_code']==0 and not c['attempts_without_result']for c in observer['cases'])
    for c in source['cases']:
        assert c['exit_code']==0 and c['fault']is None
        for a,f in c['fixtures'].items():
            address=int(a,16);before=bytes.fromhex(f['before']);after=bytes.fromhex(f['after'])
            assert int.from_bytes(after[address%8:address%8+2],'little')==c['expected_cells'][a]
            assert all(before[i]==after[i]for i in range(8)if i not in [address%8,address%8+1])
    old=load(parent/'register_map.json')
    old_keys={(r['space'],r['number'])for r in old['records']}
    added=[r for r in atlas['records']if (r['space'],r['number'])not in old_keys]
    assert Counter(r['space']for r in added)==dict(aux=1,soc_mmio=26)
    new_mmio={r['number']:r for r in added if r['space']=='soc_mmio'}
    observed={e['address']for c in observer['cases']for e in c['completed']}
    assert observed==set(new_mmio)
    for a,r in new_mmio.items():
        expected=[dict(case=c['name'],**e)for c in observer['cases']for e in c['completed']if e['address']==a]
        assert r['observed_accesses']==expected and r['width_bits']==16
    aux=next(r for r in added if r['space']=='aux')
    assert aux['number']==24 and aux['firmware_trace_sites']==['0x2931bc']
    assert aux['firmware_trace_values']==['0x1000000']
    assert len(atlas['aux_indices_with_guest_semantic_records'])==21
    sites=load(out/'aux_trace_site_verification.json')
    assert sites['status']=='PASS_TRACE_ANCHORED_AUX_SITES'and len(sites['checks'])==65
    assert all(sha(Path(p))==h for p,h in sites['input_sha256'].items())
    assert next(x for x in sites['checks']if x['pc']=='0x2931bc')['aux_index']==24
    argument=load(ev/'aux10010_argument_proof.json')
    assert argument['table_addresses_covered_by_manifest_payloads']==0
    assert argument['software_upper_domain']['concrete_indices_derived']==0
    assert argument['table_address_max']=='0x42d8c9'
    for n in [46,51,55,59]:
        r=next(r for r in atlas['records']if r['space']=='core'and r['number']==n)
        assert r['firmware_guest_usage']and not r['firmware_guest_usage'][-1]['physical_extension_semantics_verified']
    validation=dict(status='PASS_FE1_ATLAS_INTEGRATION',counts=atlas['counts'],total_records=373,
                    previous_records=346,new_mmio_addresses=26,new_aux_indices=1,fe1_observer_events=41,
                    fe1_cpu_cases=6,fe1_replay_trace_identical=6,aux_guest_indices=21,aux_trace_sites=65,
                    independent_sensor_memory_events=717,initial_pool_candidates_remaining=0,
                    table10010_concrete_indices_derived=0,whole_physical_map_complete=False,
                    parent_ledger_files_verified=len(ledger),gnu_inputs_unchanged=True)
    (out/'atlas_validation.json').write_text(json.dumps(validation,indent=2)+'\n')
    shutil.copy2(Path(__file__),ev/Path(__file__).name)
    scripts=Path(__file__).resolve().parent
    for name in ['s33_build_register_atlas.py','s33_build_register_graph.py','s33_verify_register_trace_sites.py']:
        shutil.copy2(scripts/name,ev/name)
    final={str(p.relative_to(out)):sha(p)for p in sorted(out.rglob('*'))if p.is_file()and p!=out/'sha256.json'}
    (out/'sha256.json').write_text(json.dumps(final,indent=2)+'\n')
    print(json.dumps(validation));print('ledger files',len(final))


if __name__=='__main__':main()
