#!/usr/bin/env python3
"""Reconcile validated atlas branches without dropping keys, contracts or trace evidence."""
import argparse,hashlib,json,shutil,subprocess,sys
from collections import Counter
from datetime import datetime,timezone
from pathlib import Path
ROOT=Path(__file__).resolve().parents[1]
def sha(p):return hashlib.sha256(p.read_bytes()).hexdigest()
def load(p):return json.loads(p.read_text())
def save(p,d):p.parent.mkdir(parents=True,exist_ok=True);p.write_text(json.dumps(d,indent=2)+'\n')
def unique(rows):
 out=[];seen=set()
 for x in rows:
  key=json.dumps(x,sort_keys=True)
  if key not in seen:out.append(x);seen.add(key)
 return out

def main():
 ap=argparse.ArgumentParser(description=__doc__);ap.add_argument('--primary',type=Path,required=True);ap.add_argument('--secondary',type=Path,required=True);a=ap.parse_args();primary=a.primary.resolve();secondary=a.secondary.resolve();parents=[primary,secondary];ledgers={};inputs={};resolved_sources=[];snapshot_index={}
 for name in ['s33_verify_register_memory_observer.py','s33_register_memory_observer.c']:
  for snapshot in sorted((ROOT/'Risultati/Processor_Registers').rglob(name)):
   snapshot_index.setdefault((name,sha(snapshot)),snapshot)
 for p in parents:
  ledger=load(p/'sha256.json');assert all(sha(p/k)==v for k,v in ledger.items());assert load(p/'atlas_validation.json')['status'].startswith('PASS');ledgers[str(p)]=dict(files=len(ledger),sha256=sha(p/'sha256.json'))
  for f in[p/'atlas_validation.json',*sorted((p/'evidence').glob('*.json'))]:
   d=load(f)
   if not isinstance(d,dict):continue
   for mapping in[d.get('input_sha256',{}),d.get('input_hashes',{})]:
    for k,v in mapping.items():
     path=Path(k)
     if not path.is_file()or sha(path)!=v:
      snapshot=snapshot_index.get((path.name,v));assert snapshot is not None,(str(f),k,v)
      resolved_sources.append(dict(manifest=str(f),original_path=k,retained_snapshot=str(snapshot),sha256=v));path=snapshot
     assert str(path) not in inputs or inputs[str(path)]==v;inputs[str(path)]=v
 old=[load(p/'register_map.json')for p in parents];expected=set().union(*[{(r['space'],r['number'])for r in d['records']}for d in old]);assert len(expected)==929
 out=primary.parent/datetime.now(timezone.utc).strftime('%Y%m%dT%H%M%SZ');assert not out.exists();shutil.copytree(primary,out);(out/'sha256.json').unlink();ev=out/'evidence';save(out/'atlas_validation.json',dict(status='INCOMPLETE_MERGE_NOT_VALIDATED'))
 # Keep differing canonical inputs from both branches, plus all uniquely named proof files.
 for p in parents:
  for name in['atlas_metadata.json','atlas_validation.json','evidence/mmio_documented.json','evidence/mmio_transfer_windows.json','evidence/firmware_aux_trace.json']:
   dest=ev/'lineage_branches'/p.name/name;dest.parent.mkdir(parents=True,exist_ok=True);shutil.copy2(p/name,dest)
 for p in (secondary/'evidence').rglob('*'):
  if not p.is_file():continue
  target=ev/p.relative_to(secondary/'evidence')
  if not target.exists():target.parent.mkdir(parents=True,exist_ok=True);shutil.copy2(p,target)
  elif sha(target)!=sha(p):
   assert str(p.relative_to(secondary/'evidence'))in['firmware_aux_trace.json','mmio_documented.json','mmio_transfer_windows.json','s33_build_register_atlas.py']
 mmio=load(primary/'evidence/mmio_documented.json');indexed={int(r['address'],0):r for r in mmio['records']};enriched=[];new=[]
 for row in load(secondary/'evidence/mmio_documented.json')['records']:
  address=int(row['address'],0)
  if address not in indexed:mmio['records'].append(row);indexed[address]=row;new.append(hex(address));continue
  target=indexed[address]
  if target==row:continue
  assert target['width_bits']==row['width_bits']and not target['hardware_verified']and not row['hardware_verified']
  target['additional_documentation']=unique(target.get('additional_documentation',[])+[row])
  for key in['fields','sources','evidence','unknown','observed_accesses']:
   if isinstance(target.get(key,[]),list)and isinstance(row.get(key,[]),list):target[key]=unique(target.get(key,[])+row.get(key,[]))
  enriched.append(hex(address))
 assert len(new)==37;mmio['counts'].update(register_addresses=len(mmio['records']),direct_or_reported_accesses=len(mmio['records']));save(ev/'mmio_documented.json',mmio)
 windows=load(primary/'evidence/mmio_transfer_windows.json');signature=lambda w:(int(w['base'],0),w['element_count'],w['stride_bytes'],w['store_width_bits']);by_shape={signature(w):w for w in windows['windows']};aliases={};new_windows=[]
 for row in load(secondary/'evidence/mmio_transfer_windows.json')['windows']:
  shape=signature(row)
  if shape not in by_shape:windows['windows'].append(row);by_shape[shape]=row;new_windows.append(row['name']);continue
  target=by_shape[shape];aliases[row['name']]=target['name']
  if target==row:continue
  target['alternative_names']=sorted(set(target.get('alternative_names',[])+[row['name']]))
  target['additional_writer_contracts']=unique(target.get('additional_writer_contracts',[])+[row])
  target['sources']=unique(target.get('sources',[])+row.get('sources',[]))
 assert len(windows['windows'])==18 and set(new_windows)=={'nibble15','sparse5'};save(ev/'mmio_transfer_windows.json',windows)
 cells={w['name']:{int(w['base'],0)+w['stride_bytes']*i for i in range(w['element_count'])}for w in windows['windows']};names=list(cells);pairs=[]
 for i,name in enumerate(names):
  for other in names[i+1:]:
   hit=cells[name]&cells[other]
   if hit:pairs.append(dict(left=name,right=other,cell_count=len(hit),addresses=list(map(hex,sorted(hit)))))
 scalars=set(indexed);scalar_overlap=[dict(window=name,address=hex(addr))for name in names for addr in sorted(cells[name]&scalars)];overlap=dict(schema='akeruos_software_window_overlaps_v1',window_count=len(names),summed_cell_offsets=sum(map(len,cells.values())),unique_cell_addresses=len(set().union(*cells.values())),duplicate_cell_occurrences=sum(map(len,cells.values()))-len(set().union(*cells.values())),window_pairs=pairs,scalar_overlaps=scalar_overlap,physical_aliases_inferred=0,meaning='Exact equal software addresses used by distinct original routines; no physical alias or simultaneous configuration proof')
 assert overlap['summed_cell_offsets']==3021 and overlap['unique_cell_addresses']==2989 and overlap['duplicate_cell_occurrences']==32 and len(pairs)==2 and len(scalar_overlap)==1;save(ev/'mmio_window_overlaps.json',overlap)
 trace=load(primary/'evidence/firmware_aux_trace.json');runs={r['path']:r for r in trace['runs']}
 for r in load(secondary/'evidence/firmware_aux_trace.json')['runs']:
  if r['path']in runs:assert runs[r['path']]==r
  else:trace['runs'].append(r);runs[r['path']]=r
 indices=sorted({e['aux_index']for r in trace['runs']for e in r['semantic_result_observed_records']});trace['distinct_aux_indices']=len(indices);trace['distinct_aux_hex']=list(map(hex,indices));save(ev/'firmware_aux_trace.json',trace)
 metadata=load(primary/'atlas_metadata.json');other=load(secondary/'atlas_metadata.json')
 for k,v in other.items():
  if k not in metadata:metadata[k]=v
 metadata.update(date='2026-10-25',parent_atlas=str(primary),merged_parent_atlases=ledgers,branch_reconciliation=True,branch_recovered_vs_previous_checkpoint=129,new_branch_records_vs_primary=37,window_name_aliases=aliases,mmio_window_overlap_summary={k:overlap[k]for k in['window_count','summed_cell_offsets','unique_cell_addresses','duplicate_cell_occurrences']},whole_physical_map_complete=False);save(out/'atlas_metadata.json',metadata)
 completion=load(primary/'completion_audit.json');completion.update(prior_turn_classification='progress',goal_complete=False);completion['requirements'][2]['limits']=['668 individually cataloged MMIO addresses and18windows/3021summed offsets/2989unique addresses do not delimit the physical universe','32 repeated window-cell memberships and scalarFF74088 overlap are explicit; no physical aliases inferred','Unresolved indexed domains, actual peripheral semantics/reset/interrupt/timing and all-firmware coverage remain open'];completion['next_work']=['CPU verify raw FF7 entries2E10F0/2E1298/2E12D8;four earlier candidate entries already have reusable CPU evidence','Continue remaining FF7/FFB/FFC and indexed caller domains','Resolve AUX code/data candidates, BCR and actual SoC implementation'];save(out/'completion_audit.json',completion)
 shutil.copy2(Path(__file__),ev/Path(__file__).name);scripts=ROOT/'Python_Trace_Scripts'
 for name in['s33_build_register_atlas.py','s33_verify_register_trace_sites.py']:subprocess.run([sys.executable,str(scripts/name),str(out)],check=True)
 subprocess.run(['/home/jack/.local/share/pipx/venvs/graphifyy/bin/python',str(scripts/'s33_build_register_graph.py'),str(out)],check=True)
 atlas=load(out/'register_map.json');actual={(r['space'],r['number'])for r in atlas['records']};assert actual==expected and Counter(r['space']for r in atlas['records'])==dict(core=64,aux=197,soc_mmio=668);assert len(atlas['mmio_transfer_windows'])==18 and len(atlas['computed_mmio_families'])==2 and len(atlas['aux_indices_with_guest_semantic_records'])==22;site_checks=load(out/'aux_trace_site_verification.json')['checks'];assert len(site_checks)==136;assert not atlas['goal_complete']and all(not r['hardware_verified']for r in atlas['records']);assert all(w['concrete_control_registers_admitted_from_window_cells']==0 and not w['hardware_verified']for w in atlas['mmio_transfer_windows'])
 historical=[]
 for p in sorted(primary.parent.iterdir()):
  if p==out or not (p/'atlas_validation.json').is_file()or not (p/'sha256.json').is_file():continue
  validation=load(p/'atlas_validation.json')
  if not validation.get('status','').startswith('PASS'):continue
  ld=load(p/'sha256.json');assert all(sha(p/k)==v for k,v in ld.items());keys={(r['space'],r['number'])for r in load(p/'register_map.json')['records']};missing=keys-actual;assert not missing,(p,missing);historical.append(dict(path=str(p),ledger_sha256=sha(p/'sha256.json'),ledger_files_verified=len(ld),record_count=len(keys),missing_in_merged_atlas=0))
 save(out/'coverage_lineage_audit.json',dict(status='PASS_ALL_VALIDATED_HISTORICAL_REGISTER_KEYS_PRESERVED',merged_parents=ledgers,historical_atlases=historical,union_records=len(expected),primary_only_records=129,secondary_only_records=37,enriched_common_addresses=enriched,retained_source_resolutions=resolved_sources,window_name_aliases=aliases,unique_geometry_windows=18,all_parent_trace_paths_preserved=all(set(r['path']for r in load(p/'evidence/firmware_aux_trace.json')['runs'])<=set(runs)for p in parents),physical_map_complete=False))
 assert all(sha(Path(k))==v for k,v in inputs.items());assert all(sha(p/k)==v for p in parents for k,v in load(p/'sha256.json').items());save(out/'atlas_validation.json',dict(status='PASS_REGISTER_ATLAS_BRANCH_UNION_NO_COVERAGE_REGRESSION',total_records=929,counts=atlas['counts'],merged_parents=ledgers,recovered_records_vs_previous_checkpoint=129,retained_records_only_in_previous_checkpoint=37,window_overlap_summary=overlap,trace_run_count=len(trace['runs']),aux_run_pc_sites=len(site_checks),representative_aux_guest_indices=22,historical_atlases_verified=len(historical),input_sha256=inputs,gnu_original_inputs_unchanged=True,whole_physical_map_complete=False))
 for name in['s33_build_register_atlas.py','s33_build_register_graph.py','s33_verify_register_trace_sites.py']:shutil.copy2(scripts/name,ev/name)
 save(out/'sha256.json',{str(p.relative_to(out)):sha(p)for p in sorted(out.rglob('*'))if p.is_file()and p!=out/'sha256.json'});print('PASS929records,18windows,3021memberships/2989unique,136AUXsites;historical maps',len(historical));print(out)
if __name__=='__main__':main()
