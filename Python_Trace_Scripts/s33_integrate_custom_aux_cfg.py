#!/usr/bin/env python3
"""Publish independently qualified static AUX access proofs in a new atlas."""
import argparse
from collections import Counter
from datetime import datetime,timezone
import hashlib
import json
from pathlib import Path
import re
import shutil
import subprocess
import sys

ROOT=Path(__file__).resolve().parents[1]


def sha(p):return hashlib.sha256(p.read_bytes()).hexdigest()
def load(p):return json.loads(p.read_text())
def save(p,d):p.write_text(json.dumps(d,indent=2)+'\n')


def main():
    ap=argparse.ArgumentParser(description=__doc__);ap.add_argument('--parent',type=Path,required=True)
    ap.add_argument('--evidence',type=Path,required=True);ap.add_argument('--output',type=Path)
    args=ap.parse_args();parent=args.parent.resolve();source=args.evidence.resolve()
    parent_ledger=load(parent/'sha256.json');assert all(sha(parent/p)==h for p,h in parent_ledger.items())
    proof=load(source/'verified_evidence.json');guest=load(source/'guest_call_decoder_audit.json')
    assert proof['status']=='PASS_BOUNDED_STATIC_CUSTOM_AUX_CFG'
    assert guest['status']=='PASS_RAW_BL_DECODER_GUEST_CROSSCHECK'and guest['records']==1783
    for d in [proof,guest]:assert all(sha(Path(p))==h for p,h in d['input_sha256'].items())
    main_bytes=Path(proof['source']['file']).read_bytes();base=int(proof['source']['base'],0)
    functions={f['entry']:f for f in proof['functions']};sites=set()
    for item in proof['qualified_indices']:
        index=int(item['index'],0);assert index>2047
        for event in item['proofs']:
            f=functions[event['entry']]
            assert f['contains_return']and not any(t['kind']=='invalid_decode'for t in f['terminals'])
            assert f['callers']and event['path'][0]==event['entry']and event['path'][-1]==event['pc']
            d=event['instruction'];pc=d['pc'];raw=bytes.fromhex(d['bytes_hex'])
            assert main_bytes[pc-base:pc-base+len(raw)]==raw
            assert d['opcode']in ['lr','sr']and f'[{hex(index)}]'in d['operands']
            assert event['operation']==('read'if d['opcode']=='lr'else'write')
            assert event['hardware_verified']is False
            for caller in f['callers']:
                boundary=proof['independent_linear_boundary_guard'][hex(caller['pc'])]
                assert boundary['opcode']==caller['instruction']['opcode']
                assert boundary['bytes_hex']==caller['instruction']['bytes_hex']
                assert hex(caller['target'])in proof['independent_linear_boundary_guard']
            sites.add((index,pc,event['operation']))
    # These fields are software transformations in three straight leafs.
    for index,entry in [(0x10030,'0x342c6c'),(0x10032,'0x342ca4'),(0x10034,'0x342cdc')]:
        f=functions[entry];ops=[(d['opcode'],d['operands'])for d in f['instructions']]
        for expected in [('lr',f'r1,[{hex(index)}]'),('and','r1,r1,-16'),
                         ('bmsk_s','r0,r0,0x3'),('or_s','r0,r0,r1'),('sr',f'r0,[{hex(index)}]')]:
            assert expected in ops,(entry,expected)
    old=load(parent/'register_map.json');old_keys={(r['space'],r['number'])for r in old['records']}
    new_indices=[int(i['index'],0)for i in proof['qualified_indices']if('aux',int(i['index'],0))not in old_keys]
    millicode=proof.get('cpu_verified_millicode_return')
    indirect=proof.get('cpu_verified_indirect_anchors')
    callback=proof.get('cpu_verified_callback_anchor')
    if callback:
        assert len(proof['qualified_indices'])==93 and new_indices==[0x10110]
        contract=load(source/'dispatch_contract.json');assert contract['status']=='PASS_STATIC_CUSTOM_DISPATCH_CONTRACT'
        assert len(contract['dispatch_bits'])==7 and len(contract['branches'])==2
        assert all(sha(Path(p))==h for p,h in contract['input_sha256'].items())
    elif indirect:
        assert len(proof['qualified_indices'])==92 and len(new_indices)==7
        assert set(new_indices)=={0x10036,0x10037,0x10803,0x10903,0x10a03,0x10b03,0x10c03}
        functions_by_entry={f['entry']:f for f in proof['functions']}
        instructions={d['pc']:d for d in functions_by_entry['0x339cdc']['instructions']}
        for index,pc in [(0x10803,0x339d1c),(0x10903,0x339dc0),(0x10a03,0x339e26),(0x10b03,0x339e8c),(0x10c03,0x339ef2)]:
            assert instructions[pc]['operands']==f'r0,[{hex(index)}]'
            assert instructions[pc-6]['opcode']=='and'and instructions[pc-6]['operands']=='r0,r0,-4'
            assert instructions[pc-2]['opcode']=='bset_s'and instructions[pc-2]['operands']=='r0,r0,0'
    elif millicode:
        previous=load(parent/'evidence/custom_aux_cfg.json')
        assert len(proof['qualified_indices'])==80 and len(new_indices)==16
        assert set(new_indices)=={int(i['index'],0)for i in previous['unqualified_indices']}
    else:
        assert len(proof['qualified_indices'])==64 and len(new_indices)==59
    stamp=datetime.now(timezone.utc).strftime('%Y%m%dT%H%M%SZ')
    out=args.output.resolve()if args.output else parent.parent/stamp
    assert not out.exists();shutil.copytree(parent,out);(out/'sha256.json').unlink()
    save(out/'atlas_validation.json',dict(status='PENDING_CUSTOM_CFG_ATLAS_VALIDATION'))
    ev=out/'evidence'
    for original,name in [(source/'verified_evidence.json','custom_aux_cfg.json'),
                          (source/'source_disassembly.txt','custom_aux_cfg_disassembly.txt'),
                          (source/'verifier_snapshot.py','s33_verify_custom_aux_cfg.py'),
                          (source/'guest_call_decoder_audit.json','guest_call_decoder_audit.json'),
                          (Path(__file__).with_name('s33_verify_call_decoder_against_guest.py'),'s33_verify_call_decoder_against_guest.py'),
                          (Path(__file__),'s33_integrate_custom_aux_cfg.py')]:shutil.copy2(original,ev/name)
    if millicode:
        path=Path(millicode['manifest']);data=load(path)
        assert data['status']=='PASS_ORIGINAL_REGISTER_MILLICODE'and len(data['cases'])==8
        for original,name in [(path,'millicode_return_cpu.json'),
                              (path.parent/'millicode_source_disassembly.txt','millicode_return_disassembly.txt'),
                              (path.parent/'verifier_snapshot.py','s33_verify_register_millicode.py')]:shutil.copy2(original,ev/name)
    if indirect:
        path=Path(indirect['manifest']);idata=load(path)
        assert idata['status']=='PASS_REGISTER_INDIRECT_ANCHORS_AND_MODEL_BOUNDARY'
        assert sum(c['full_routine_completed']for c in idata['cases'])==4
        assert all(c['custom_aux_semantic_result_observed']is False for c in idata['cases'])
        shutil.copy2(path,ev/'register_indirect_cpu.json');shutil.copy2(path.parent/'verifier_snapshot.py',ev/'s33_verify_register_indirect_anchors.py')
        (ev/'register_indirect_disassembly.txt').write_text('\n\n'.join(p.name+'\n'+p.read_text()for p in sorted(path.parent.glob('*_source_disassembly.txt'))))
    if callback:
        path=Path(callback['manifest']);cdata=load(path)
        assert cdata['status']=='PASS_REGISTER_DUAL_CALLBACK_AND_MODEL_BOUNDARY'and len(cdata['cases'])==3
        assert sum(c['full_routine_completed']for c in cdata['cases'])==2
        assert all(c['custom_aux_semantic_result_observed']is False for c in cdata['cases'])
        shutil.copy2(path,ev/'register_dual_callback_cpu.json');shutil.copy2(path.parent/'verifier_snapshot.py',ev/'s33_verify_register_dual_callback.py')
        (ev/'register_dual_callback_disassembly.txt').write_text('\n\n'.join(p.name+'\n'+p.read_text()for p in sorted(path.parent.glob('*_source_disassembly.txt'))))
        for p in [source/'dispatch_contract.json',source/'dispatch_contract.txt',ROOT/'Python_Trace_Scripts/s33_verify_custom_dispatch_contract.py']:shutil.copy2(p,ev/p.name)
    metadata=load(out/'atlas_metadata.json')
    metadata.update(date='2026-10-25',parent_atlas=str(parent),parent_ledger_sha256=sha(parent/'sha256.json'),
                    parent_ledger_files_verified=len(parent_ledger),custom_aux_cfg_source=str(source/'verified_evidence.json'),
                    custom_aux_cfg_qualified_indices=len(proof['qualified_indices']),new_custom_aux_cfg_indices=len(new_indices),custom_aux_cfg_direct_access_sites=len(sites),
                    custom_aux_cfg_functions=proof['counts']['functions'],custom_aux_cfg_unqualified_indices=len(proof['unqualified_indices']),
                    custom_aux_guest_call_decoder_records=1783,whole_physical_map_complete=False)
    if millicode:metadata.update(millicode_cpu_cases=8,millicode_cpu_instructions=sum(c['instructions']for c in data['cases']),
                                 custom_aux_cfg_previous_unqualified_resolved=16)
    if indirect:metadata.update(indirect_anchor_cpu_cases=13,indirect_anchor_completed_cases=4,indirect_anchor_guard_cases=9,
                                indirect_anchor_new_aux_indices=7)
    if callback:metadata.update(dual_callback_cpu_cases=3,dual_callback_completed_cases=2,dual_callback_guard_cases=1,
                                software_dispatch_bits=7,software_callback_branches=2)
    save(out/'atlas_metadata.json',metadata)
    audit=load(out/'completion_audit.json')
    audit['requirements'][0]['sources']+=['evidence/custom_aux_cfg.json','evidence/guest_call_decoder_audit.json']
    audit['requirements'][1]['limits']=[s for s in audit['requirements'][1]['limits']if not re.match(r'\d+customAUXindices',s)]
    audit['requirements'][1]['limits']+=[f"{len(proof['qualified_indices'])}customAUXindices with call/boundary/CFG static evidence;{len(proof['unqualified_indices'])}otherindices remain unqualified within the three windows; no physical implementation verified"]
    audit['next_work']=['Resolve remaining custom AUX code anchors, indirect calls and table producers',
                        'Extend MMIO evidence beyond195addresses without assuming an exhaustive physical universe',
                        'Seek actual processor/BCR/configuration evidence; do not treat emulator bank size as Nikon configuration']
    save(out/'completion_audit.json',audit)
    scripts=ROOT/'Python_Trace_Scripts'
    for name in ['s33_build_register_atlas.py','s33_verify_register_trace_sites.py']:
        subprocess.run([sys.executable,str(scripts/name),str(out)],check=True)
    subprocess.run(['/home/jack/.local/share/pipx/venvs/graphifyy/bin/python',str(scripts/'s33_build_register_graph.py'),str(out)],check=True)
    atlas=load(out/'register_map.json');actual=Counter(r['space']for r in atlas['records'])
    total=len(old['records'])+len(new_indices);expected_counts=dict(old['counts']);expected_counts['aux']+=len(new_indices)
    assert actual==expected_counts and len(atlas['records'])==total
    keys={(r['space'],r['number'])for r in atlas['records']};assert old_keys<=keys and len(keys)==total
    added=keys-old_keys;assert added=={('aux',i)for i in new_indices}
    assert all(r['hardware_verified']is False for r in atlas['records'])and atlas['goal_complete']is False
    assert len(atlas['aux_indices_with_guest_semantic_records'])==21
    if callback:
        aux_records={r['number']:r for r in atlas['records']if r['space']=='aux'}
        assert aux_records[0x10001]['software_dispatch_bits']==contract['dispatch_bits']
        assert [r['slot']for r in aux_records[0x10001]['software_dispatch_bits']]==['0x360ae0','0x360adc']+['0x360ad8']*5
        assert aux_records[0x10001]['structural_bit7_accessor']==contract['unreferenced_bit7_accessor']
        for index,bits in [(0x10110,{0,1}),(0x10111,{14,15})]:
            record=aux_records[index];assert record['software_callback_branches']==contract['branches']
            assert {f['lsb']for f in record['bit_fields']if f.get('source_file')==str(ev/'dispatch_contract.json')}==bits
        assert aux_records[0x10110]['classification']=='firmware_cpu_bound_callback_target_local_cfg_static'
        assert len([c for c in cdata['cases']if c['exit_code']==0 and c['full_routine_completed']])==2
        guard_case=next(c for c in cdata['cases']if not c['full_routine_completed'])
        assert guard_case['exit_code']==5 and guard_case['expected_guard_index']=='0x10111'
    for item in proof['qualified_indices']:
        r=next(r for r in atlas['records']if r['space']=='aux'and r['number']==int(item['index'],0))
        assert r['firmware_static_access_confirmed']and not r['firmware_observed']
        assert r['firmware_custom_cfg_access_sites']==sorted({e['pc']for e in item['proofs']})
    trace_sites=load(out/'aux_trace_site_verification.json');assert len(trace_sites['checks'])==65
    assert all(sha(parent/p)==h for p,h in parent_ledger.items())
    inputs={}
    for d in [proof,guest]:inputs.update(d['input_sha256'])
    if callback:inputs.update(contract['input_sha256'])
    prior=load(parent/'evidence/emulator_checks.json')
    for name,digest in prior['source_sha256'].items():
        if '/work/gnu_arc700_'in name or '/opt/arc700-'in name:inputs[name]=digest
    assert all(sha(Path(p))==h for p,h in inputs.items())
    validation=dict(status='PASS_CUSTOM_AUX_CFG_ATLAS_INTEGRATION',counts=dict(actual),total_records=total,
                    previous_records=len(old['records']),new_static_aux_indices=len(new_indices),qualified_custom_aux_indices=len(proof['qualified_indices']),
                    unique_custom_aux_access_sites=len(sites),custom_cfg_functions=proof['counts']['functions'],
                    unqualified_custom_aux_indices=len(proof['unqualified_indices']),aux_guest_indices=21,aux_guest_sites=65,
                    raw_decoder_guest_checks=1783,raw_decoder_distinct_guest_pc=guest['distinct_pc'],
                    raw_decoder_guest_encodings=guest['encodings'],parent_ledger_files_verified=len(parent_ledger),
                    original_and_gnu_inputs_unchanged=True,whole_physical_map_complete=False,
                    input_sha256=inputs,
                    limits=['Syntactic CFG paths and a modeled call-return fallthrough do not prove branch feasibility or global runtime reachability.',
                            'Only explicitly qualified indices promoted; computed domains and uncovered source regions not expanded.',
                            '1783branch checks reuse existing original-code GNU traces; no successful custom AUX result claimed.',
                            'Physical implementation/configuration/semantics remain unverified.'])
    if millicode and not indirect:validation.update(fresh_millicode_cpu_cases=8,fresh_millicode_cpu_instructions=sum(c['instructions']for c in data['cases']),
                                   previous_unqualified_indices_resolved=16,bxor_not_a_branch_correction=True)
    if indirect and not callback:validation.update(retained_millicode_cpu_cases=8,fresh_indirect_anchor_cpu_cases=13,
                                  completed_indirect_anchor_cpu_cases=4,expected_custom_aux_guard_cases=9,
                                  custom_aux_semantic_results_observed=0,indirect_target_anchors=3)
    if callback:validation.update(retained_millicode_cpu_cases=8,retained_indirect_anchor_cpu_cases=13,
                                  fresh_dual_callback_cpu_cases=3,completed_dual_callback_cpu_cases=2,expected_custom_aux_guard_cases=1,
                                  custom_aux_semantic_results_observed=0,indirect_target_anchors=4,software_dispatch_bits=7,software_callback_branches=2)
    save(out/'atlas_validation.json',validation)
    for name in ['s33_build_register_atlas.py','s33_verify_register_trace_sites.py','s33_build_register_graph.py']:
        shutil.copy2(scripts/name,ev/name)
    final={str(p.relative_to(out)):sha(p)for p in sorted(out.rglob('*'))if p.is_file()and p!=out/'sha256.json'}
    save(out/'sha256.json',final)
    print(json.dumps({k:v for k,v in validation.items()if k not in ['input_sha256','limits']}));print('ledger',len(final));print(out)


if __name__=='__main__':main()
