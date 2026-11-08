#!/usr/bin/env python3
"""Add original FFC7000 masked fields while preserving historical coverage and transfer windows."""
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
 ap=argparse.ArgumentParser(description=__doc__);ap.add_argument('--parent',type=Path,required=True);ap.add_argument('--source',type=Path,required=True);ap.add_argument('--audit',type=Path,required=True);a=ap.parse_args();parent=a.parent.resolve();src=a.source.resolve();audit_path=a.audit.resolve();ledger=load(parent/'sha256.json');assert all(sha(parent/k)==v for k,v in ledger.items());d=load(src/'verified_evidence.json');audit=load(audit_path);assert d['status']=='PASS_FFC7000_MASKED_FIELDS'and audit['status']=='PASS_FFC7000_FIELDS_INDEPENDENT_AUDIT';inputs={**d['input_hashes'],**audit['input_sha256']};assert all(sha(Path(k))==v for k,v in inputs.items())and all(sha(src/k)==v for k,v in d['files'].items())
 old=load(parent/'register_map.json');known={(r['space'],r['number'])for r in old['records']};rows=defaultdict(list)
 for c in d['cases']:
  if c['observer_enabled']:
   assert c['full_original_calls_completed']and c['exit_code']==0
   for e in c['completed_memory_events']:rows[e['address']].append(dict(case=c['name'],**e))
 new={x for x in rows if('soc_mmio',x)not in known};enriched=set(rows)-new;assert len(rows)==24 and len(new)==24 and not enriched and sum(map(len,rows.values()))==376 and audit['new_aux_sr_sites']==0
 out=parent.parent/datetime.now(timezone.utc).strftime('%Y%m%dT%H%M%SZ');assert not out.exists();shutil.copytree(parent,out);(out/'sha256.json').unlink();save(out/'atlas_validation.json',dict(status='INCOMPLETE_FF7_RESIDUAL_NOT_VALIDATED'));ev=out/'evidence';scripts=ROOT/'Python_Trace_Scripts'
 for original,name in[(src/'verified_evidence.json','ffc7000_fields.json'),(audit_path,'ffc7000_fields_audit.json'),(src/'linear_navigation_only.txt','ffc7000_fields_linear_navigation.txt'),(src/'s33_verify_ffc7000_fields.py','s33_verify_ffc7000_fields.py'),(scripts/'s33_audit_ffc7000_fields.py','s33_audit_ffc7000_fields.py'),(Path(__file__),Path(__file__).name)]:shutil.copy2(original,ev/name)
 sources=[dict(file=str(ev/'ffc7000_fields.json'),line=1),dict(file=str(ev/'ffc7000_fields_audit.json'),line=1)];mmio=load(ev/'mmio_documented.json');indexed={int(r['address'],0):r for r in mmio['records']}
 for address,events in sorted(rows.items()):
  fields=[dict(entry=op['entry'],software_field_width_bits=f['width_bits'],argument=f['argument'],logical_shift=f['logical_shift'],keep_mask=f['keep_mask'],subtract_before_mask=f['subtract_before_mask'],read_pc=f['read_pc'],write_pc=f['write_pc'],evidence_type='independently_reconstructed_original_software_operation',hardware_semantics='unknown')for op in audit['software_operations'].values()for f in op['fields']if int(f['address'],0)==address];assert fields
  record=dict(address=f'0x{address:08X}',namespace='soc_mmio',subsystem='ffc7000_masked_argument_field_physical_function_unknown',software_role='masked_argument_field_destination',width_bits=16,access='/'.join(sorted({e['operation']for e in events}))+'_halfword_di',confidence='original_guest_ffc7000_masked_field_fixture',hardware_verified=False,fields=fields,observed_accesses=events,sources=sources,evidence=['original_bytes_bound','full_original_calls_completed','independent_masks_argument_halves_and_subtract_one_audit'],unknown=['Physical function/reset/access permissions/IRQ/timing not established.','Software field widths12/13 do not describe transaction width,which is16bits.','Ordered halfword stores do not prove physical32bit atomicity;actual caller domains unknown.'])
  if address in new:mmio['records'].append(record);indexed[address]=record
  else:
   target=indexed[address];assert target['width_bits']==16 and target['hardware_verified']is False;target['additional_documentation']=unique(target.get('additional_documentation',[])+[record])
   for key in['fields','sources','evidence','unknown','observed_accesses']:target[key]=unique(target.get(key,[])+record[key])
 mmio['counts'].update(register_addresses=len(mmio['records']),direct_or_reported_accesses=len(mmio['records']));save(ev/'mmio_documented.json',mmio)
 metadata=load(out/'atlas_metadata.json');metadata.update(date='2026-10-25',parent_atlas=str(parent),parent_ledger_sha256=sha(parent/'sha256.json'),parent_ledger_files_verified=len(ledger),ffc7000_fields_new_scalars=24,ffc7000_fields_original_entries=11,ffc7000_fields_scenarios=8,ffc7000_fields_events=376,whole_physical_map_complete=False);save(out/'atlas_metadata.json',metadata)
 completion=load(out/'completion_audit.json');completion.update(prior_turn_classification='progress',goal_complete=False);completion['requirements'][2]['limits']=['750 individually cataloged MMIO addresses and22windows/3118memberships/3086unique cell addresses do not delimit all firmware or physical registers','FFC7000 software fields12/13 and subtract-one wrappers do not establish physical peripheral identity or legal caller ranges','Computed FFB helper mathematics and physical register identities/reset/permissions/IRQ/timing remain unverified'];completion['next_work']=['Continue later FFC7000 accessors starting at3087BC,and remaining firmware MMIO groups;retain actual caller-domain unknowns','Independently validate numerical helper303A40 and provisional DSP instructions','Resolve remaining AUX code/data candidates,parametric domains,BCR and actual SoC implementation'];save(out/'completion_audit.json',completion)
 for name in['s33_build_register_atlas.py','s33_verify_register_trace_sites.py']:subprocess.run([sys.executable,str(scripts/name),str(out)],check=True)
 subprocess.run(['/home/jack/.local/share/pipx/venvs/graphifyy/bin/python',str(scripts/'s33_build_register_graph.py'),str(out)],check=True)
 atlas=load(out/'register_map.json');keys={(r['space'],r['number'])for r in atlas['records']};assert len(atlas['records'])==1011 and Counter(r['space']for r in atlas['records'])==dict(core=64,aux=197,soc_mmio=750)and keys-known=={('soc_mmio',x)for x in new};assert known<=keys and not any(int(w['base'],0)+w['stride_bytes']*i in new for w in atlas['mmio_transfer_windows']for i in range(w['element_count'])) and len(atlas['mmio_transfer_windows'])==22 and len(atlas['computed_mmio_families'])==2 and atlas['mmio_window_overlaps']==old['mmio_window_overlaps'];assert len(atlas['aux_indices_with_guest_semantic_records'])==22 and len(load(out/'aux_trace_site_verification.json')['checks'])==146;assert not atlas['goal_complete']and all(not r['hardware_verified']for r in atlas['records'])and all(w['concrete_control_registers_admitted_from_window_cells']==0 and not w['hardware_verified']for w in atlas['mmio_transfer_windows'])
 for filename in['mmio_transfer_windows.json','mmio_window_overlaps.json','firmware_aux_trace.json']:assert sha(ev/filename)==sha(parent/'evidence'/filename)
 historical=[]
 for directory in sorted(parent.parent.iterdir()):
  if directory==out or not(directory/'atlas_validation.json').is_file()or not(directory/'sha256.json').is_file():continue
  if not load(directory/'atlas_validation.json').get('status','').startswith('PASS'):continue
  ld=load(directory/'sha256.json');assert all(sha(directory/k)==v for k,v in ld.items());prior={(r['space'],r['number'])for r in load(directory/'register_map.json')['records']};assert prior<=keys;historical.append(dict(path=str(directory),record_count=len(prior),ledger_sha256=sha(directory/'sha256.json'),ledger_files_verified=len(ld),missing_in_merged_atlas=0))
 history=load(parent/'coverage_lineage_audit.json');history.update(historical_atlases=historical,union_records=len(keys),latest_parent_atlas=str(parent),latest_new_addresses=list(map(hex,sorted(new))),latest_enriched_addresses=list(map(hex,sorted(enriched))),latest_new_window_count=0);save(out/'coverage_lineage_audit.json',history);assert all(sha(Path(k))==v for k,v in inputs.items())and all(sha(parent/k)==v for k,v in ledger.items())
 save(out/'atlas_validation.json',dict(status='PASS_FFC7000_FIELDS_NO_COVERAGE_REGRESSION',total_records=1011,counts=atlas['counts'],new_scalar_mmio_addresses=24,enriched_scalar_mmio_addresses=0,selected_original_entries=11,selected_scenarios=8,original_calls_observed=88,original_calls_including_replay=176,completed_memory_events=376,reads=184,writes=192,trace_identical_pairs=8,independently_redecoded_instructions=len(audit['independently_redecoded_instructions']),transfer_windows_unchanged=True,window_overlap_summary=old['mmio_window_overlaps'],representative_aux_guest_indices=22,aux_run_pc_sites=146,new_aux_sr_sites=0,parent_ledger_files_verified=len(ledger),historical_atlases_verified=len(historical),input_sha256=inputs,gnu_original_inputs_unchanged=True,whole_physical_map_complete=False,limits=d['limits']))
 for name in['s33_build_register_atlas.py','s33_build_register_graph.py','s33_verify_register_trace_sites.py']:shutil.copy2(scripts/name,ev/name)
 files={str(p.relative_to(out)):sha(p)for p in sorted(out.rglob('*'))if p.is_file()and p!=out/'sha256.json'};save(out/'sha256.json',files);print('PASS1011records,+24scalars,376events,146AUXsites unchanged;ledger',len(files));print(out)
if __name__=='__main__':main()
