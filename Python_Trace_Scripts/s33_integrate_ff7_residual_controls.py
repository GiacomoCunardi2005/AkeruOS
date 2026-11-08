#!/usr/bin/env python3
"""Add FF7 scalar operations while preserving prior records, windows and trace evidence."""
import argparse,hashlib,json,shutil,subprocess,sys
from collections import Counter,defaultdict
from datetime import datetime,timezone
from pathlib import Path
ROOT=Path(__file__).resolve().parents[1]
def sha(p):return hashlib.sha256(p.read_bytes()).hexdigest()
def load(p):return json.loads(p.read_text())
def save(p,d):p.write_text(json.dumps(d,indent=2)+'\n')
def unique(rows):
 result=[];seen=set()
 for row in rows:
  key=json.dumps(row,sort_keys=True)
  if key not in seen:result.append(row);seen.add(key)
 return result

def main():
 ap=argparse.ArgumentParser(description=__doc__);ap.add_argument('--parent',type=Path,required=True);ap.add_argument('--source',type=Path,required=True);ap.add_argument('--audit',type=Path,required=True);a=ap.parse_args();parent=a.parent.resolve();src=a.source.resolve();audit_path=a.audit.resolve();ledger=load(parent/'sha256.json');assert all(sha(parent/k)==v for k,v in ledger.items());d=load(src/'verified_evidence.json');audit=load(audit_path);assert d['status']=='PASS_FF7_RESIDUAL_SCALAR_CONTROLS'and audit['status']=='PASS_FF7_RESIDUAL_CONTROLS_INDEPENDENT_AUDIT';inputs={**d['input_hashes'],**audit['input_sha256']};assert all(sha(Path(k))==v for k,v in inputs.items())and all(sha(src/k)==v for k,v in d['files'].items())
 old=load(parent/'register_map.json');known={(r['space'],r['number'])for r in old['records']};rows=defaultdict(list)
 for c in d['cases']:
  if c['observer_enabled']:
   assert c['full_original_calls_completed']and c['exit_code']==0
   for e in c['completed_memory_events']:rows[e['address']].append(dict(case=c['name'],**e))
 new={x for x in rows if('soc_mmio',x)not in known};enriched=set(rows)-new;assert len(rows)==23 and len(new)==21 and enriched=={0xff74000,0xff76098}and sum(map(len,rows.values()))==1216 and audit['new_aux_sr_sites']==0
 out=parent.parent/datetime.now(timezone.utc).strftime('%Y%m%dT%H%M%SZ');assert not out.exists();shutil.copytree(parent,out);(out/'sha256.json').unlink();save(out/'atlas_validation.json',dict(status='INCOMPLETE_FF7_RESIDUAL_NOT_VALIDATED'));ev=out/'evidence';scripts=ROOT/'Python_Trace_Scripts'
 for original,name in[(src/'verified_evidence.json','ff7_residual_controls.json'),(audit_path,'ff7_residual_controls_audit.json'),(src/'linear_navigation_only.txt','ff7_residual_controls_linear_navigation.txt'),(src/'s33_verify_ff7_residual_controls.py','s33_verify_ff7_residual_controls.py'),(scripts/'s33_audit_ff7_residual_controls.py','s33_audit_ff7_residual_controls.py'),(Path(__file__),Path(__file__).name)]:shutil.copy2(original,ev/name)
 sources=[dict(file=str(ev/'ff7_residual_controls.json'),line=1),dict(file=str(ev/'ff7_residual_controls_audit.json'),line=1)];mmio=load(ev/'mmio_documented.json');indexed={int(r['address'],0):r for r in mmio['records']}
 for address,events in sorted(rows.items()):
  fields=[dict(op,evidence_type='independently_reconstructed_original_software_operation')for op in audit['software_operations'].values()if hex(address)in op['addresses']];assert fields
  record=dict(address=f'0x{address:08X}',namespace='soc_mmio',subsystem='ff7_scalar_control_or_halfword_parameter_physical_function_unknown',software_role='scalar_control_or_split_argument_destination',width_bits=16,access='/'.join(sorted({e['operation']for e in events}))+'_halfword_di',confidence='original_guest_residual_control_formula_fixture',hardware_verified=False,fields=fields,observed_accesses=events,sources=sources,evidence=['original_bytes_bound','full_original_calls_completed','independent_masks_getter_return_and_order_audit'],unknown=['Physical function/reset/access permissions/IRQ/timing not established.','Constant0x20store does not prove acknowledgment orW1C.','Ordered halfword stores do not prove physical32bit atomicity;actual caller domains unknown.'])
  if address in new:mmio['records'].append(record);indexed[address]=record
  else:
   target=indexed[address];assert target['width_bits']==16 and target['hardware_verified']is False;target['additional_documentation']=unique(target.get('additional_documentation',[])+[record])
   for key in['fields','sources','evidence','unknown','observed_accesses']:target[key]=unique(target.get(key,[])+record[key])
 mmio['counts'].update(register_addresses=len(mmio['records']),direct_or_reported_accesses=len(mmio['records']));save(ev/'mmio_documented.json',mmio)
 metadata=load(out/'atlas_metadata.json');metadata.update(date='2026-10-25',parent_atlas=str(parent),parent_ledger_sha256=sha(parent/'sha256.json'),parent_ledger_files_verified=len(ledger),ff7_residual_controls_new_scalars=21,ff7_residual_controls_enriched_scalars=2,ff7_residual_controls_original_entries=26,ff7_residual_controls_scenarios=8,ff7_residual_controls_events=1216,whole_physical_map_complete=False);save(out/'atlas_metadata.json',metadata)
 completion=load(out/'completion_audit.json');completion.update(prior_turn_classification='progress',goal_complete=False);completion['requirements'][2]['limits']=['726 individually cataloged MMIO addresses and22windows/3118memberships/3086unique cell addresses do not delimit all firmware or physical registers','FF7 masked getters and argument-independent RMW setters describe software operations only','Computed FFB helper mathematics and physical register identities/reset/permissions/IRQ/timing remain unverified'];completion['next_work']=['Census remaining MMIO routines and dataflow outside the bounded groups already verified;retain real caller-domain unknowns','Independently validate numerical helper303A40 and provisional DSP instructions','Resolve remaining AUX code/data candidates,parametric domains,BCR and actual SoC implementation'];save(out/'completion_audit.json',completion)
 for name in['s33_build_register_atlas.py','s33_verify_register_trace_sites.py']:subprocess.run([sys.executable,str(scripts/name),str(out)],check=True)
 subprocess.run(['/home/jack/.local/share/pipx/venvs/graphifyy/bin/python',str(scripts/'s33_build_register_graph.py'),str(out)],check=True)
 atlas=load(out/'register_map.json');keys={(r['space'],r['number'])for r in atlas['records']};assert len(atlas['records'])==987 and Counter(r['space']for r in atlas['records'])==dict(core=64,aux=197,soc_mmio=726)and keys-known=={('soc_mmio',x)for x in new};assert known<=keys and len(atlas['mmio_transfer_windows'])==22 and len(atlas['computed_mmio_families'])==2 and atlas['mmio_window_overlaps']==old['mmio_window_overlaps'];assert len(atlas['aux_indices_with_guest_semantic_records'])==22 and len(load(out/'aux_trace_site_verification.json')['checks'])==146;assert not atlas['goal_complete']and all(not r['hardware_verified']for r in atlas['records'])and all(w['concrete_control_registers_admitted_from_window_cells']==0 and not w['hardware_verified']for w in atlas['mmio_transfer_windows'])
 for filename in['mmio_transfer_windows.json','mmio_window_overlaps.json','firmware_aux_trace.json']:assert sha(ev/filename)==sha(parent/'evidence'/filename)
 historical=[]
 for directory in sorted(parent.parent.iterdir()):
  if directory==out or not(directory/'atlas_validation.json').is_file()or not(directory/'sha256.json').is_file():continue
  if not load(directory/'atlas_validation.json').get('status','').startswith('PASS'):continue
  ld=load(directory/'sha256.json');assert all(sha(directory/k)==v for k,v in ld.items());prior={(r['space'],r['number'])for r in load(directory/'register_map.json')['records']};assert prior<=keys;historical.append(dict(path=str(directory),record_count=len(prior),ledger_sha256=sha(directory/'sha256.json'),ledger_files_verified=len(ld),missing_in_merged_atlas=0))
 history=load(parent/'coverage_lineage_audit.json');history.update(historical_atlases=historical,union_records=len(keys),latest_parent_atlas=str(parent),latest_new_addresses=list(map(hex,sorted(new))),latest_enriched_addresses=list(map(hex,sorted(enriched))),latest_new_window_count=0);save(out/'coverage_lineage_audit.json',history);assert all(sha(Path(k))==v for k,v in inputs.items())and all(sha(parent/k)==v for k,v in ledger.items())
 save(out/'atlas_validation.json',dict(status='PASS_FF7_RESIDUAL_SCALAR_CONTROLS_NO_COVERAGE_REGRESSION',total_records=987,counts=atlas['counts'],new_scalar_mmio_addresses=21,enriched_scalar_mmio_addresses=2,selected_original_entries=26,selected_scenarios=8,original_calls_observed=664,original_calls_including_replay=1328,completed_memory_events=1216,new_address_events=736,enriched_address_events=480,trace_identical_pairs=8,independently_redecoded_instructions=len(audit['independently_redecoded_instructions']),transfer_windows_unchanged=True,window_overlap_summary=old['mmio_window_overlaps'],representative_aux_guest_indices=22,aux_run_pc_sites=146,new_aux_sr_sites=0,parent_ledger_files_verified=len(ledger),historical_atlases_verified=len(historical),input_sha256=inputs,gnu_original_inputs_unchanged=True,whole_physical_map_complete=False,limits=d['limits']))
 for name in['s33_build_register_atlas.py','s33_build_register_graph.py','s33_verify_register_trace_sites.py']:shutil.copy2(scripts/name,ev/name)
 files={str(p.relative_to(out)):sha(p)for p in sorted(out.rglob('*'))if p.is_file()and p!=out/'sha256.json'};save(out/'sha256.json',files);print('PASS987records,+21scalars/2enriched,1216events,146AUXsites unchanged;ledger',len(files));print(out)
if __name__=='__main__':main()
