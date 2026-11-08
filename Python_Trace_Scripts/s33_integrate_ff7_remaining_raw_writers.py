#!/usr/bin/env python3
"""Integrate remaining raw FF7 windows after validated branch reconciliation."""
import argparse,hashlib,json,re,shutil,subprocess,sys
from collections import Counter,defaultdict
from datetime import datetime,timezone
from pathlib import Path
ROOT=Path(__file__).resolve().parents[1]
def sha(p):return hashlib.sha256(p.read_bytes()).hexdigest()
def load(p):return json.loads(p.read_text())
def save(p,d):p.write_text(json.dumps(d,indent=2)+'\n')
def main():
 ap=argparse.ArgumentParser(description=__doc__);ap.add_argument('--parent',type=Path,required=True);ap.add_argument('--source',type=Path,required=True);ap.add_argument('--audit',type=Path,required=True);args=ap.parse_args();parent=args.parent.resolve();src=args.source.resolve();audit_path=args.audit.resolve();ledger=load(parent/'sha256.json');assert all(sha(parent/p)==h for p,h in ledger.items());d=load(src/'verified_evidence.json');audit=load(audit_path);assert d['status']=='PASS_FF7_REMAINING_RAW_WRITERS'and audit['status']=='PASS_FF7_REMAINING_RAW_WRITERS_INDEPENDENT_AUDIT'
 for mapping in[d['input_hashes'],audit['input_sha256']]:assert all(sha(Path(p))==h for p,h in mapping.items())
 assert all(sha(src/p)==h for p,h in d['files'].items());old=load(parent/'register_map.json');known={(r['space'],r['number'])for r in old['records']};specs={s['name']:s for s in d['specs']};params=defaultdict(list);window_events=0
 for c in d['cases']:
  if not c['observer_enabled']:continue
  assert c['exit_code']==0 and c['full_original_writer_completed'];spec=specs[c['spec_name']]
  for e in c['completed_memory_events']:
   if e['pc']==spec['pc']:window_events+=1
   else:params[e['address']].append(dict(case=c['name'],**e))
 assert len(params)==2 and sum(map(len,params.values()))==8 and window_events==236 and not any(('soc_mmio',a)in known for a in params)
 out=parent.parent/datetime.now(timezone.utc).strftime('%Y%m%dT%H%M%SZ');assert not out.exists();shutil.copytree(parent,out);(out/'sha256.json').unlink();ev=out/'evidence';scripts=ROOT/'Python_Trace_Scripts'
 for original,name in[(src/'verified_evidence.json','ff7_remaining_raw_writers.json'),(audit_path,'ff7_remaining_raw_writers_audit.json'),(src/'original_windows.txt','ff7_remaining_raw_writers_disassembly.txt'),(src/'s33_verify_ff7_remaining_raw_writers.py','s33_verify_ff7_remaining_raw_writers.py'),(scripts/'s33_audit_ff7_remaining_raw_writers.py','s33_audit_ff7_remaining_raw_writers.py'),(Path(__file__),Path(__file__).name)]:shutil.copy2(original,ev/name)
 sources=[dict(file=str(ev/'ff7_remaining_raw_writers.json'),line=1),dict(file=str(ev/'ff7_remaining_raw_writers_audit.json'),line=1)];mmio=load(ev/'mmio_documented.json')
 for address,rows in sorted(params.items()):
  assert address in[0xff760f4,0xff760f8];argument='r1'if address==0xff760f4 else'r2'
  mmio['records'].append(dict(address=f'0x{address:08X}',namespace='soc_mmio',subsystem='ff7_raw9_tail_parameter_physical_function_unknown',software_role='tail_parameter_after_raw9',width_bits=16,access='write_halfword_di',confidence='original_guest_raw9_tail_fixture',hardware_verified=False,fields=[dict(entry='0x2e10f0',meaning=argument+' low16 copied after nine raw halfwords; FF760F4 before FF760F8',physical_meaning='unknown')],observed_accesses=rows,observed_write_values=sorted({hex(e['value'])for e in rows}),sources=sources,evidence=['original_bytes_bound','full_original_writer','independent_raw_buffer_order_oracle'],unknown=['Physical role/reset/access permissions/timing unknown.','Synthetic argument values do not prove actual Nikon caller domains.']))
 mmio['counts'].update(register_addresses=len(mmio['records']),direct_or_reported_accesses=len(mmio['records']));save(ev/'mmio_documented.json',mmio)
 windows=load(ev/'mmio_transfer_windows.json')
 for w in audit['transfer_windows']:
  assert not any(x['name']==w['name']for x in windows['windows']);windows['windows'].append(dict(w,sources=sources,full_transfer_cases=[c['name']for c in d['cases']if c['observer_enabled']and specs[c['spec_name']]['window']==w['name']],limits=d['limits']))
 save(ev/'mmio_transfer_windows.json',windows)
 cells={w['name']:{int(w['base'],0)+w['stride_bytes']*i for i in range(w['element_count'])}for w in windows['windows']};names=list(cells);pairs=[]
 for i,name in enumerate(names):
  for other in names[i+1:]:
   common=cells[name]&cells[other]
   if common:pairs.append(dict(left=name,right=other,cell_count=len(common),addresses=list(map(hex,sorted(common)))))
 scalar_keys={int(r['address'],0)for r in mmio['records']};scalar_overlap=[dict(window=name,address=hex(a))for name in names for a in sorted(cells[name]&scalar_keys)];overlap=dict(schema='akeruos_software_window_overlaps_v1',window_count=len(names),summed_cell_offsets=sum(map(len,cells.values())),unique_cell_addresses=len(set().union(*cells.values())),duplicate_cell_occurrences=sum(map(len,cells.values()))-len(set().union(*cells.values())),window_pairs=pairs,scalar_overlaps=scalar_overlap,physical_aliases_inferred=0,meaning='Equal software addresses across original routines; no physical aliasing inferred');assert overlap['window_count']==21 and overlap['summed_cell_offsets']==3080 and overlap['unique_cell_addresses']==3048 and overlap['duplicate_cell_occurrences']==32 and len(pairs)==2 and len(scalar_overlap)==1;save(ev/'mmio_window_overlaps.json',overlap)
 trace=load(ev/'firmware_aux_trace.json');fw=Path(trace['firmware_path']).read_bytes();info=d['payload'];elf=ROOT/'outputs/gnu_arc700/20261024T232600Z_2fcbbcac/main_source.elf'
 for spec in d['specs']:
  case_name=spec['name']+'_0_observed';path=src/(case_name+'.trace');records=[]
  for no,line in enumerate(path.read_text().splitlines(),1):
   m=re.match(r'0x([0-9a-f]+)\s+sr\s+.*?\[([^\]]+)\].*? - .*?<- (0x[0-9a-f]+)',line)
   if not m or int(m[1],16)not in spec['aux_pcs']:continue
   pc=int(m[1],16);idx=int(m[2],0);value=int(m[3],16);off=info['firmware_offset']+pc-info['base'];records.append(dict(trace_line=no,pc=pc,pc_hex=hex(pc),operation='write',aux_index=idx,aux_hex=hex(idx),trace_text=line,semantic_result_observed=True,retirement_proven_by_this_record=False,firmware_offset=off,firmware_offset_hex=hex(off),original_firmware_bytes_next8=fw[off:off+8].hex(),trace_value=value,trace_value_hex=hex(value),value_meaning='Original LP start/end setter operand, not measured post-set AUX state'))
  assert len(records)==2 and {r['aux_index']for r in records}=={2,3};actual=src/(case_name.removesuffix('_observed')+'.elf');trace['runs'].append(dict(name='ff7_packed_'+case_name,path=str(path),sha256=sha(path),run_manifest=str(src/'verified_evidence.json'),run_manifest_sha256=sha(src/'verified_evidence.json'),elf=str(elf),elf_sha256=sha(elf),elf_role='source_mmap_ELF_for_static_verification',actual_runtime_harness_elf=str(actual),actual_runtime_harness_sha256=sha(actual),runtime_original_code_mmap=info,semantic_result_observed_records=records,limits=['Isolated packed writer; explicit buffer/MMIO fixtures and SR operands, not physical AUX verification.']))
 indices=sorted({e['aux_index']for run in trace['runs']for e in run['semantic_result_observed_records']});trace['distinct_aux_indices']=len(indices);trace['distinct_aux_hex']=list(map(hex,indices));save(ev/'firmware_aux_trace.json',trace)
 metadata=load(out/'atlas_metadata.json');metadata.update(date='2026-10-25',parent_atlas=str(parent),parent_ledger_sha256=sha(parent/'sha256.json'),parent_ledger_files_verified=len(ledger),ff7_remaining_raw_new_windows=3,ff7_remaining_raw_new_cells=59,ff7_remaining_raw_new_parameters=2,ff7_remaining_raw_scenarios=12,ff7_remaining_raw_events=244,mmio_window_overlap_summary={k:overlap[k]for k in['window_count','summed_cell_offsets','unique_cell_addresses','duplicate_cell_occurrences']},whole_physical_map_complete=False);save(out/'atlas_metadata.json',metadata)
 completion=load(out/'completion_audit.json');completion['requirements'][2]['limits']=['670 individually cataloged MMIO addresses and21bounded windows with3080memberships/3048unique cell addresses do not delimit the physical universe','32 repeated cell memberships plus scalarFF74088 role overlap are preserved explicitly','Actual caller domains, peripheral identity/reset/permissions/timing/IRQ and BCR remain unproven'];completion['next_work']=['Continue remaining FF7 scalar controls,FFB/FFC groups and runtime-dependent caller domains','Resolve remaining AUX code/data candidates and parametric families','Obtain actual BCR/SoC implementation and hardware evidence'];save(out/'completion_audit.json',completion)
 for name in['s33_build_register_atlas.py','s33_verify_register_trace_sites.py']:subprocess.run([sys.executable,str(scripts/name),str(out)],check=True)
 subprocess.run(['/home/jack/.local/share/pipx/venvs/graphifyy/bin/python',str(scripts/'s33_build_register_graph.py'),str(out)],check=True)
 atlas=load(out/'register_map.json');assert len(atlas['records'])==931 and Counter(r['space']for r in atlas['records'])==dict(core=64,aux=197,soc_mmio=670);keys={(r['space'],r['number'])for r in atlas['records']};assert keys-known=={('soc_mmio',a)for a in params};assert len(atlas['mmio_transfer_windows'])==21 and atlas['mmio_window_overlaps']==overlap and len(atlas['computed_mmio_families'])==2
 assert all(not w['hardware_verified']and w['concrete_control_registers_admitted_from_window_cells']==0 for w in atlas['mmio_transfer_windows']);assert len(atlas['aux_indices_with_guest_semantic_records'])==22 and len(load(out/'aux_trace_site_verification.json')['checks'])==142;assert not atlas['goal_complete']and all(not r['hardware_verified']for r in atlas['records']);graph=load(out/'graph.json');assert sum(n.get('file_type')=='mmio_write_window'for n in graph['nodes'])==21
 history=load(parent/'coverage_lineage_audit.json');historical=[]
 for p in sorted(parent.parent.iterdir()):
  if p==out or not (p/'atlas_validation.json').is_file()or not (p/'sha256.json').is_file():continue
  if not load(p/'atlas_validation.json').get('status','').startswith('PASS'):continue
  ld=load(p/'sha256.json');assert all(sha(p/k)==v for k,v in ld.items());prior={(r['space'],r['number'])for r in load(p/'register_map.json')['records']};assert prior<=keys;historical.append(dict(path=str(p),record_count=len(prior),ledger_sha256=sha(p/'sha256.json'),ledger_files_verified=len(ld),missing_in_merged_atlas=0))
 history.update(historical_atlases=historical,union_records=len(keys),latest_parent_atlas=str(parent),latest_new_addresses=list(map(hex,sorted(params))),latest_new_window_count=3);save(out/'coverage_lineage_audit.json',history)
 inputs={**d['input_hashes'],**audit['input_sha256']};assert all(sha(Path(p))==h for p,h in inputs.items());assert all(sha(parent/p)==h for p,h in ledger.items());save(out/'atlas_validation.json',dict(status='PASS_FF7_REMAINING_RAW_WRITERS_NO_COVERAGE_REGRESSION',total_records=931,counts=atlas['counts'],new_parameter_mmio_addresses=2,new_transfer_windows=3,new_window_cells=59,window_overlap_summary=overlap,window_cells_admitted_as_independent_registers=0,completed_memory_events=244,window_write_events=236,parameter_events=8,selected_scenarios=12,trace_identical_pairs=12,representative_aux_guest_indices=22,aux_run_pc_sites=142,parent_ledger_files_verified=len(ledger),historical_atlases_verified=len(historical),input_sha256=inputs,gnu_original_inputs_unchanged=True,whole_physical_map_complete=False,limits=d['limits']))
 for name in['s33_build_register_atlas.py','s33_build_register_graph.py','s33_verify_register_trace_sites.py']:shutil.copy2(scripts/name,ev/name)
 files={str(p.relative_to(out)):sha(p)for p in sorted(out.rglob('*'))if p.is_file()and p!=out/'sha256.json'};save(out/'sha256.json',files);print('PASS931records,2new addresses,3new windows/59cells,142AUXsites;ledger',len(files));print(out)
if __name__=='__main__':main()
