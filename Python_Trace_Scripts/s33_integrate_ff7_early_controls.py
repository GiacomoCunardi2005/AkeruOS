#!/usr/bin/env python3
"""Integrate source-bound FF7 early controls, split halfword stores and small windows."""
import argparse,hashlib,json,re,shutil,subprocess,sys
from collections import Counter,defaultdict
from datetime import datetime,timezone
from pathlib import Path
ROOT=Path(__file__).resolve().parents[1]
def sha(p):return hashlib.sha256(p.read_bytes()).hexdigest()
def load(p):return json.loads(p.read_text())
def save(p,d):p.write_text(json.dumps(d,indent=2)+'\n')
def main():
 ap=argparse.ArgumentParser(description=__doc__);ap.add_argument('--parent',type=Path,required=True);ap.add_argument('--source',type=Path,required=True);ap.add_argument('--audit',type=Path,required=True);args=ap.parse_args();parent=args.parent.resolve();src=args.source.resolve();audit_path=args.audit.resolve();ledger=load(parent/'sha256.json');assert all(sha(parent/p)==h for p,h in ledger.items());d=load(src/'verified_evidence.json');audit=load(audit_path);assert d['status']=='PASS_FF7_EARLY_CONTROLS_SPLITS_AND_SMALL_WINDOWS'and audit['status']=='PASS_FF7_EARLY_FIELDS_SPLITS_BUFFER_TRACE_AUDIT'
 for mapping in[d['input_hashes'],audit['input_sha256']]:assert all(sha(Path(p))==h for p,h in mapping.items())
 assert all(sha(src/p)==h for p,h in d['files'].items());old=load(parent/'register_map.json');known={(r['space'],r['number'])for r in old['records']};specs={s['name']:s for s in d['small_windows']};params=defaultdict(list);window_events=0
 for c in d['cases']:
  if not c['observer_enabled']:continue
  assert c['exit_code']==0 and c['full_original_paths_completed']
  for e in c['completed_memory_events']:
   if c['window_name']:window_events+=1
   else:params[e['address']].append(dict(case=c['name'],**e))
 assert len(params)==37 and sum(map(len,params.values()))==304 and window_events==27 and not any(('soc_mmio',a)in known for a in params)
 out=parent.parent/datetime.now(timezone.utc).strftime('%Y%m%dT%H%M%SZ');assert not out.exists();shutil.copytree(parent,out);(out/'sha256.json').unlink();ev=out/'evidence';scripts=ROOT/'Python_Trace_Scripts'
 for original,name in[(src/'verified_evidence.json','ff7_early_controls.json'),(audit_path,'ff7_early_controls_audit.json'),(src/'original_windows.txt','ff7_early_controls_disassembly.txt'),(src/'s33_verify_ff7_early_controls.py','s33_verify_ff7_early_controls.py'),(scripts/'s33_audit_ff7_early_controls.py','s33_audit_ff7_early_controls.py'),(Path(__file__),Path(__file__).name)]:shutil.copy2(original,ev/name)
 sources=[dict(file=str(ev/'ff7_early_controls.json'),line=1),dict(file=str(ev/'ff7_early_controls_audit.json'),line=1)];mmio=load(ev/'mmio_documented.json')
 operations={
  0xff70800:[('0x2e0040','RMW: set bit0 unconditionally; argument r0 ignored')],
  0xff70838:[('0x2e005c','RMW: bit0 set only when r0==1, otherwise cleared')],
  0xff70844:[('0x2e0090','RMW: bit0 set only when r0==1, otherwise cleared')],
  0xff70c00:[('0x2e00c4','RMW: replace bits0..1 with r0&3'),('0x2e00ec','RMW: replace bits2..3 with (r0<<2)&0xC')],
  0xff70c60:[('0x2e0118','Store uint16(r0|(r1<<8)); unmasked operands may overlap')],
  0xff70c64:[('0x2e0130','RMW: replace bits4..5 with (r0<<4)&0x30'),('0x2e015c','RMW: replace low4 with r0&15, then store r1 low16 at FF70CC4')],
  0xff70cc4:[('0x2e015c','Store r1 low16 after the FF70C64 RMW')],
  0xff70cc8:[('0x2e0194','First store uint16(r0|(r1<<4)); unmasked operands may overlap')],
  0xff70ccc:[('0x2e0194','Second store uint16(r2|(r3<<8)); unmasked operands may overlap')],
  0xff71000:[('0x2e0258','RMW: bit0 set only when r0==1, otherwise cleared')],
  0xff71004:[('0x2e028c','First store r0 low16')],
  0xff71008:[('0x2e028c','Second store r1 low16')],
 }
 relations={}
 for single in d['single_halfword_entries']:operations[int(single['address'],0)]=[(single['entry'],'Store r0 low16')]
 for pair in d['split_argument_entries']:
  lo,hi=int(pair['low_address'],0),int(pair['high_address'],0)
  for address,role,order,other in[(lo,'low16',1,hi),(hi,'logical_shift_right16',2,lo)]:
   operations[address]=[(pair['entry'],'Store r0 '+role+'; halfword order '+str(order)+' of2')]
   relations[address]=dict(argument_register='r0',pair_other_address=hex(other),software_half=role,store_order=order,physical_32bit_atomicity_proven=False)
 assert set(operations)==set(params)
 for address,rows in sorted(params.items()):
  meanings=[dict(entry=entry,meaning=meaning,evidence_type='software_operation',physical_meaning='unknown')for entry,meaning in operations[address]]
  record=dict(address=f'0x{address:08X}',namespace='soc_mmio',subsystem='ff7_early_controls_or_halfword_parameters_physical_function_unknown',software_role='control_rmw_or_halfword_parameter',width_bits=16,access='read_write_halfword_di'if any(e['operation']=='read'for e in rows)else'write_halfword_di',confidence='original_guest_early_controls_split_store_fixture',hardware_verified=False,fields=meanings,observed_accesses=rows,observed_write_values=sorted({hex(e['value'])for e in rows if e['operation']=='write'}),sources=sources,evidence=['original_bytes_bound','full_original_paths','independent_masks_packing_order_oracles'],unknown=['Physical role/implementation/reset/access permissions/timing unknown.','Actual Nikon caller argument domains are not established by synthetic inputs.','Two ordered halfword stores do not establish an atomic physical32bit register.'])
  if address in relations:record['software_split_argument']=relations[address]
  mmio['records'].append(record)
 mmio['counts'].update(register_addresses=len(mmio['records']),direct_or_reported_accesses=len(mmio['records']));save(ev/'mmio_documented.json',mmio)
 windows=load(ev/'mmio_transfer_windows.json')
 for w in audit['transfer_windows']:
  assert not any(x['name']==w['name']for x in windows['windows']);windows['windows'].append(dict(w,sources=sources,full_transfer_cases=[c['name']for c in d['cases']if c['observer_enabled']and c['window_name']==w['name']],limits=['Nibble15 packs15 low nibbles with cell0 low4 forced0; sparse5 reads only byte offsets0/2/4/6/8 and r1 low3.','Store16/stride4 and synthetic padding do not establish peripheral identity or physical32bit registers.','Actual caller argument and input-buffer domains remain unverified.']))
 save(ev/'mmio_transfer_windows.json',windows)
 trace=load(ev/'firmware_aux_trace.json');fw=Path(trace['firmware_path']).read_bytes();info=d['payload'];elf=ROOT/'outputs/gnu_arc700/20261024T232600Z_2fcbbcac/main_source.elf'
 for spec in d['small_windows']:
  case_name=spec['name']+'_0_observed';path=src/(case_name+'.trace');records=[]
  for no,line in enumerate(path.read_text().splitlines(),1):
   m=re.match(r'0x([0-9a-f]+)\s+sr\s+.*?\[([^\]]+)\].*? - .*?<- (0x[0-9a-f]+)',line)
   if not m or int(m[1],16)not in spec['aux_pcs']:continue
   pc=int(m[1],16);idx=int(m[2],0);value=int(m[3],16);off=info['firmware_offset']+pc-info['base'];records.append(dict(trace_line=no,pc=pc,pc_hex=hex(pc),operation='write',aux_index=idx,aux_hex=hex(idx),trace_text=line,semantic_result_observed=True,retirement_proven_by_this_record=False,firmware_offset=off,firmware_offset_hex=hex(off),original_firmware_bytes_next8=fw[off:off+8].hex(),trace_value=value,trace_value_hex=hex(value),value_meaning='Original LP start/end setter operand, not measured post-set AUX state'))
  assert len(records)==2 and {r['aux_index']for r in records}=={2,3};actual=src/(case_name.removesuffix('_observed')+'.elf');trace['runs'].append(dict(name='ff7_packed_'+case_name,path=str(path),sha256=sha(path),run_manifest=str(src/'verified_evidence.json'),run_manifest_sha256=sha(src/'verified_evidence.json'),elf=str(elf),elf_sha256=sha(elf),elf_role='source_mmap_ELF_for_static_verification',actual_runtime_harness_elf=str(actual),actual_runtime_harness_sha256=sha(actual),runtime_original_code_mmap=info,semantic_result_observed_records=records,limits=['Isolated early packed writer; explicit buffer/MMIO fixtures and SR operands, not physical AUX verification.']))
 indices=sorted({e['aux_index']for run in trace['runs']for e in run['semantic_result_observed_records']});trace['distinct_aux_indices']=len(indices);trace['distinct_aux_hex']=list(map(hex,indices));save(ev/'firmware_aux_trace.json',trace)
 metadata=load(out/'atlas_metadata.json');metadata.update(date='2026-10-25',parent_atlas=str(parent),parent_ledger_sha256=sha(parent/'sha256.json'),parent_ledger_files_verified=len(ledger),ff7_early_controls_new_scalars=37,ff7_early_new_windows=2,ff7_early_new_cells=7,ff7_early_scalar_events=304,ff7_early_window_events=27,ff7_early_scenarios=11,ff7_early_trace_identical_pairs=11,whole_physical_map_complete=False);save(out/'atlas_metadata.json',metadata)
 completion=load(out/'completion_audit.json');completion['requirements'][2]['limits']=['539 individually cataloged MMIO addresses plus14 bounded windows/2937cell offsets do not delimit the physical universe','Nine argument32 split writers issue ordered low16/high16 stores, not proven physical atomic32bit registers','Two indexed families still have unresolved actual caller domains; physical meaning/reset/access/timing unknown'];completion['next_work']=['Expand remaining FF7,FFB/FFC groups and unresolved caller domains using original bytes and CPU evidence','Resolve remaining AUX code/data candidates and parametric families','Obtain actual BCR/SoC configuration evidence without promoting fixture values'];save(out/'completion_audit.json',completion)
 for name in['s33_build_register_atlas.py','s33_verify_register_trace_sites.py']:subprocess.run([sys.executable,str(scripts/name),str(out)],check=True)
 subprocess.run(['/home/jack/.local/share/pipx/venvs/graphifyy/bin/python',str(scripts/'s33_build_register_graph.py'),str(out)],check=True)
 atlas=load(out/'register_map.json');assert len(atlas['records'])==800 and Counter(r['space']for r in atlas['records'])==dict(core=64,aux=197,soc_mmio=539);keys={(r['space'],r['number'])for r in atlas['records']};assert keys-known=={('soc_mmio',a)for a in params};assert len(atlas['mmio_transfer_windows'])==14 and sum(w['element_count']for w in atlas['mmio_transfer_windows'])==2937 and len(atlas['computed_mmio_families'])==2
 for w in atlas['mmio_transfer_windows']:assert not w['hardware_verified']and w['concrete_control_registers_admitted_from_window_cells']==0 and not any(('soc_mmio',int(w['base'],0)+4*i)in keys for i in range(w['element_count']))
 assert len(atlas['aux_indices_with_guest_semantic_records'])==22 and len(load(out/'aux_trace_site_verification.json')['checks'])==108;assert not atlas['goal_complete']and all(not r['hardware_verified']for r in atlas['records']);graph=load(out/'graph.json');assert sum(n.get('file_type')=='mmio_write_window'for n in graph['nodes'])==14
 inputs={**d['input_hashes'],**audit['input_sha256']};assert all(sha(Path(p))==h for p,h in inputs.items());assert all(sha(parent/p)==h for p,h in ledger.items());save(out/'atlas_validation.json',dict(status='PASS_FF7_EARLY_CONTROLS_SPLITS_WINDOWS_INTEGRATION',total_records=800,counts=atlas['counts'],new_scalar_mmio_addresses=37,new_transfer_windows=2,new_window_cells=7,total_windows=14,total_window_cells=2937,window_cells_admitted_as_independent_registers=0,completed_memory_events=331,window_write_events=27,scalar_events=304,selected_scenarios=11,trace_identical_pairs=11,ignored_bits_equivalences=3,split_argument_functions=9,single_halfword_functions=7,representative_aux_guest_indices=22,aux_run_pc_sites=108,parent_ledger_files_verified=len(ledger),input_sha256=inputs,gnu_original_inputs_unchanged=True,whole_physical_map_complete=False,limits=d['limits']))
 for name in['s33_build_register_atlas.py','s33_build_register_graph.py','s33_verify_register_trace_sites.py']:shutil.copy2(scripts/name,ev/name)
 files={str(p.relative_to(out)):sha(p)for p in sorted(out.rglob('*'))if p.is_file()and p!=out/'sha256.json'};save(out/'sha256.json',files);print('PASS800records,37new addresses,2new windows/7cells,108AUXsites;ledger',len(files));print(out)
if __name__=='__main__':main()
