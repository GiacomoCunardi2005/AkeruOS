#!/usr/bin/env python3
"""Version the register atlas with byte-bound bounded FE6 computed addresses."""
import argparse,hashlib,json,shutil,subprocess,sys
from collections import Counter,defaultdict
from datetime import datetime,timezone
from pathlib import Path
ROOT=Path(__file__).resolve().parents[1]
def sha(p):return hashlib.sha256(p.read_bytes()).hexdigest()
def load(p):return json.loads(p.read_text())
def save(p,d):p.write_text(json.dumps(d,indent=2)+'\n')
def main():
    ap=argparse.ArgumentParser(description=__doc__);ap.add_argument('--parent',type=Path,required=True);ap.add_argument('--source',type=Path,required=True);ap.add_argument('--audit',type=Path,required=True);ap.add_argument('--callers',type=Path,required=True);args=ap.parse_args()
    parent=args.parent.resolve();src=args.source.resolve();audit_path=args.audit.resolve();ledger=load(parent/'sha256.json');assert all(sha(parent/p)==h for p,h in ledger.items())
    d=load(src/'verified_evidence.json');audit=load(audit_path);assert d['status']=='PASS_FE6_COMPUTED_ACCESSOR_DOMAINS'and audit['status']=='PASS_FE6_EFFECTIVE_ADDRESS_AND_BYTE_AUDIT'
    for mapping in [d['input_hashes'],audit['input_sha256']]:assert all(sha(Path(p))==h for p,h in mapping.items())
    assert all(sha(src/p)==h for p,h in d['files'].items());old=load(parent/'register_map.json');known={(r['space'],r['number'])for r in old['records']}
    callers_path=args.callers.resolve();callers=load(callers_path/'verified_evidence.json');assert callers['status']=='PASS_FE6_ORIGINAL_CONDITIONAL_CALLERS'
    assert all(sha(Path(p))==h for p,h in callers['input_sha256'].items())
    events=defaultdict(list)
    for c in d['cases']:
        if c['observer_enabled']:
            assert c['exit_code']==0 and c['full_selected_paths_completed']
            for e in c['completed_memory_events']:events[e['address']].append(dict(case=c['name'],**e))
    assert len(events)==96 and sum(map(len,events.values()))==530 and not any(('soc_mmio',a)in known for a in events)
    out=parent.parent/datetime.now(timezone.utc).strftime('%Y%m%dT%H%M%SZ');assert not out.exists();shutil.copytree(parent,out);(out/'sha256.json').unlink();ev=out/'evidence';scripts=ROOT/'Python_Trace_Scripts'
    for original,name in [(src/'verified_evidence.json','fe6_computed_registers.json'),(audit_path,'fe6_computed_registers_audit.json'),(src/'original_windows.txt','fe6_computed_registers_disassembly.txt'),(src/'s33_verify_fe6_computed_registers.py','s33_verify_fe6_computed_registers.py'),(scripts/'s33_audit_fe6_computed_registers.py','s33_audit_fe6_computed_registers.py'),(Path(__file__),Path(__file__).name)]:shutil.copy2(original,ev/name)
    for original,name in [(callers_path/'verified_evidence.json','fe6_original_callers.json'),(callers_path/'original_callers_disassembly.txt','fe6_original_callers_disassembly.txt'),(callers_path/'verifier_snapshot.py','s33_verify_fe6_original_callers.py')]:shutil.copy2(original,ev/name)
    fields={0:['Full writer composes bits0..1,2,4,6,10..11,12..13,14..15 and clears other bits','Separate RMW replaces bits10..15, preserves bits0..9'],4:['Conditional setter modifies bit8 only, preserving other bits','Separate getter returns value&0x200 (bit9 mask), not a normalized boolean or the bit8 setter state'],8:['Argument r2 low16 written','Special separate routine writes argument r1 low16 only for selector0x29'],12:['Argument r1 bit0 becomes bit15; argument r3 bits0..13 retained; bit14 cleared']}
    mmio=load(ev/'mmio_documented.json')
    for a,rows in sorted(events.items()):
        selector=(a-0xfe60000)//16;offset=(a-0xfe60000)%16;assert selector in list(range(32,52))+list(range(64,68))and offset in fields
        mmio['records'].append(dict(address=f'0x{a:08X}',namespace='soc_mmio',subsystem='fe6_computed_selector_bank_physical_function_unknown',width_bits=16,access='/'.join(sorted({e['operation']for e in rows}))+'_halfword_di',confidence='original_guest_computed_address_explicit_selector_domain',hardware_verified=False,software_selector=hex(selector),software_offset=hex(offset),fields=[dict(meaning=s,evidence_type='software_operation',physical_meaning='unknown')for s in fields[offset]],observed_accesses=rows,observed_write_values=sorted({hex(e['value'])for e in rows if e['operation']=='write'}),sources=[dict(file=str(ev/'fe6_computed_registers.json'),line=1),dict(file=str(ev/'fe6_computed_registers_audit.json'),line=1)],evidence=['original_bytes_bound','full_selected_accessor_paths','computed_effective_addresses_observed','synthetic_caller_domain'],unknown=['Physical name, access permission, reset, IRQ, timing, hardware effects and actual Nikon caller values unknown.','Exhaustive software selector-domain probe is not a physical register census.']))
    for row in mmio['records']:
        if row.get('subsystem')=='fe6_computed_selector_bank_physical_function_unknown':
            row['sources'].append(dict(file=str(ev/'fe6_original_callers.json'),line=1))
            row['conditional_original_literal_selector_calls']=[c for c in callers['literal_selector_calls'] if c['selector']==row['software_selector']]
    mmio['counts'].update(register_addresses=len(mmio['records']),direct_or_reported_accesses=len(mmio['records']));save(ev/'mmio_documented.json',mmio)
    metadata=load(out/'atlas_metadata.json');metadata.update(date='2026-10-25',parent_atlas=str(parent),parent_ledger_sha256=sha(parent/'sha256.json'),parent_ledger_files_verified=len(ledger),fe6_computed_new_addresses=96,fe6_completed_memory_events=530,fe6_scenarios=3,fe6_trace_identical_pairs=3,fe6_valid_selector_domain=d['valid_selectors'],fe6_invalid_selectors_tested=d['invalid_selectors_tested'],fe6_static_literal_selector_calls=8,fe6_static_literal_selectors=callers['literal_selectors'],fe6_actual_nikon_runtime_caller_values_known=False,whole_physical_map_complete=False);save(out/'atlas_metadata.json',metadata)
    completion=load(out/'completion_audit.json');completion['requirements'][2]['limits']=['318 software-level MMIO addresses do not delimit the physical universe or prove hardware semantics','96 FE6 addresses observed across all24 accepted selectors of six isolated accessors; actual Nikon caller values/physical implementation unknown']
    completion['next_work']=['Trace actual Nikon callers/selectors of FE6 and expand the other computed MMIO families beyond the initial census','Resolve remaining AUX code/data candidates and parametric families','Obtain actual BCR/SoC configuration evidence without promoting fixture values'];save(out/'completion_audit.json',completion)
    for name in ['s33_build_register_atlas.py','s33_verify_register_trace_sites.py']:subprocess.run([sys.executable,str(scripts/name),str(out)],check=True)
    subprocess.run(['/home/jack/.local/share/pipx/venvs/graphifyy/bin/python',str(scripts/'s33_build_register_graph.py'),str(out)],check=True)
    atlas=load(out/'register_map.json');assert len(atlas['records'])==579 and Counter(r['space']for r in atlas['records'])==dict(core=64,aux=197,soc_mmio=318)
    assert len(atlas['aux_indices_with_guest_semantic_records'])==22 and len(load(out/'aux_trace_site_verification.json')['checks'])==74
    assert not atlas['goal_complete'] and all(not r['hardware_verified']for r in atlas['records'])
    assert {(r['space'],r['number'])for r in atlas['records']}-known=={('soc_mmio',a)for a in events}
    inputs={**d['input_hashes'],**audit['input_sha256'],**callers['input_sha256'],str(callers_path/'verified_evidence.json'):sha(callers_path/'verified_evidence.json')};assert all(sha(Path(p))==h for p,h in inputs.items());assert all(sha(parent/p)==h for p,h in ledger.items())
    save(out/'atlas_validation.json',dict(status='PASS_FE6_COMPUTED_ADDRESS_INTEGRATION',total_records=579,counts=atlas['counts'],new_mmio_addresses=96,completed_memory_events=530,selected_scenarios=3,trace_identical_pairs=3,original_conditional_static_calls=8,original_literal_selectors=callers['literal_selectors'],valid_selectors_exercised=24,invalid_selectors_exercised=8,original_calls_across_unique_scenarios=448,representative_aux_guest_indices=22,aux_run_pc_sites=74,parent_ledger_files_verified=len(ledger),input_sha256=inputs,gnu_original_inputs_unchanged=True,whole_physical_map_complete=False,limits=d['limits']))
    for name in ['s33_build_register_atlas.py','s33_build_register_graph.py','s33_verify_register_trace_sites.py']:shutil.copy2(scripts/name,ev/name)
    files={str(p.relative_to(out)):sha(p)for p in sorted(out.rglob('*'))if p.is_file()and p!=out/'sha256.json'};save(out/'sha256.json',files)
    print('PASS579records,96new MMIO,530events,3pairs; ledger',len(files));print(out)
if __name__=='__main__':main()
