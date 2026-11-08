#!/usr/bin/env python3
"""Extend window contracts with variant-specific packing, without inflating register counts."""
import argparse,hashlib,json,re,shutil,subprocess,sys
from collections import Counter,defaultdict
from datetime import datetime,timezone
from pathlib import Path
ROOT=Path(__file__).resolve().parents[1]
def sha(p):return hashlib.sha256(p.read_bytes()).hexdigest()
def load(p):return json.loads(p.read_text())
def save(p,d):p.write_text(json.dumps(d,indent=2)+'\n')
def main():
 ap=argparse.ArgumentParser(description=__doc__);ap.add_argument('--parent',type=Path,required=True);ap.add_argument('--source',type=Path,required=True);ap.add_argument('--audit',type=Path,required=True);args=ap.parse_args();parent=args.parent.resolve();src=args.source.resolve();audit_path=args.audit.resolve();ledger=load(parent/'sha256.json');assert all(sha(parent/p)==h for p,h in ledger.items());d=load(src/'verified_evidence.json');audit=load(audit_path);assert d['status']=='PASS_FF7_PACKED_WRITER_CONTRACTS'and audit['status']=='PASS_FF7_PACKED_BUFFER_BYTE_TRACE_AUDIT'
 for mapping in[d['input_hashes'],audit['input_sha256']]:assert all(sha(Path(p))==h for p,h in mapping.items())
 assert all(sha(src/p)==h for p,h in d['files'].items());old=load(parent/'register_map.json');known={(r['space'],r['number'])for r in old['records']};specs={s['name']:s for s in d['specs']};params=defaultdict(list);window_events=0
 for c in d['cases']:
  if not c['observer_enabled']:continue
  assert c['exit_code']==0 and c['full_original_writer_completed'];spec=specs[c['spec_name']]
  for e in c['completed_memory_events']:
   if e['pc']==spec['pc']:window_events+=1
   else:params[e['address']].append(dict(case=c['name'],**e))
 assert len(params)==10 and sum(map(len,params.values()))==40 and window_events==415 and not any(('soc_mmio',a)in known for a in params)
 out=parent.parent/datetime.now(timezone.utc).strftime('%Y%m%dT%H%M%SZ');assert not out.exists();shutil.copytree(parent,out);(out/'sha256.json').unlink();ev=out/'evidence';scripts=ROOT/'Python_Trace_Scripts'
 for original,name in[(src/'verified_evidence.json','ff7_packed_writers.json'),(audit_path,'ff7_packed_writers_audit.json'),(src/'original_windows.txt','ff7_packed_writers_disassembly.txt'),(src/'s33_verify_ff7_packed_writers.py','s33_verify_ff7_packed_writers.py'),(scripts/'s33_audit_ff7_packed_writers.py','s33_audit_ff7_packed_writers.py'),(Path(__file__),Path(__file__).name)]:shutil.copy2(original,ev/name)
 sources=[dict(file=str(ev/'ff7_packed_writers.json'),line=1),dict(file=str(ev/'ff7_packed_writers_audit.json'),line=1)];mmio=load(ev/'mmio_documented.json')
 for address,rows in sorted(params.items()):
  meanings=[]
  for s in d['specs']:
   if address not in s['param_addresses']:continue
   i=s['param_addresses'].index(address)
   if s['kind']=='pair7_wide':meaning='Transferred uint16((argumentr1<<10)|argumentr2); r2 high bits are not cleared, so upper field bits can overlap'
   elif s['name']=='raw12':meaning='Argumentr'+str(i+1)+' low16 copied'
   else:meaning='Argumentr'+str(2 if i==0 else 1)+' low16 copied; r1/r2 are data operands, not a skip flag'
   meanings.append(dict(entry=hex(s['entry']),meaning=meaning,evidence_type='software_operation',physical_meaning='unknown'))
  mmio['records'].append(dict(address=f'0x{address:08X}',namespace='soc_mmio',subsystem='ff7_packed_writer_parameter_physical_function_unknown',software_role='writer_parameter',width_bits=16,access='write_halfword_di',confidence='original_guest_packed_writer_parameter_fixture',hardware_verified=False,fields=meanings,observed_accesses=rows,observed_write_values=sorted({hex(e['value'])for e in rows}),sources=sources,evidence=['original_bytes_bound','full_original_writer','packing_and_metamorphic_oracles'],unknown=['Physical parameter role/implementation/reset/access permissions/timing unknown.','Permitted argument domain of actual Nikon callers is not established by synthetic inputs.']))
 mmio['counts'].update(register_addresses=len(mmio['records']),direct_or_reported_accesses=len(mmio['records']));save(ev/'mmio_documented.json',mmio)
 windows=load(ev/'mmio_transfer_windows.json')
 for w in audit['transfer_windows']:
  assert not any(x['name']==w['name']for x in windows['windows']);windows['windows'].append(dict(w,sources=sources,full_transfer_cases=[c['name']for c in d['cases']if c['observer_enabled']and specs[c['spec_name']]['window']==w['name']],limits=['Packing rules apply to first16cells; cell16 has a separate raw16/raw8 tail contract.','No physical32bit register width follows from store16/stride4; gaps are only verified model padding.','Mapper file prefix base%8 does not change the guest address or represent a physical offset.']))
 save(ev/'mmio_transfer_windows.json',windows)
 trace=load(ev/'firmware_aux_trace.json');fw=Path(trace['firmware_path']).read_bytes();info=d['payload'];elf=ROOT/'outputs/gnu_arc700/20261024T232600Z_2fcbbcac/main_source.elf'
 for spec in d['specs']:
  case_name=spec['name']+'_0_observed';path=src/(case_name+'.trace');records=[]
  for no,line in enumerate(path.read_text().splitlines(),1):
   m=re.match(r'0x([0-9a-f]+)\s+sr\s+.*?\[([^\]]+)\].*? - .*?<- (0x[0-9a-f]+)',line)
   if not m or int(m[1],16)not in spec['aux_pcs']:continue
   pc=int(m[1],16);idx=int(m[2],0);value=int(m[3],16);off=info['firmware_offset']+pc-info['base'];records.append(dict(trace_line=no,pc=pc,pc_hex=hex(pc),operation='write',aux_index=idx,aux_hex=hex(idx),trace_text=line,semantic_result_observed=True,retirement_proven_by_this_record=False,firmware_offset=off,firmware_offset_hex=hex(off),original_firmware_bytes_next8=fw[off:off+8].hex(),trace_value=value,trace_value_hex=hex(value),value_meaning='Original LP start/end setter operand, not measured post-set AUX state'))
  assert len(records)==2 and {r['aux_index']for r in records}=={2,3};actual=src/(case_name.removesuffix('_observed')+'.elf');trace['runs'].append(dict(name='ff7_packed_'+case_name,path=str(path),sha256=sha(path),run_manifest=str(src/'verified_evidence.json'),run_manifest_sha256=sha(src/'verified_evidence.json'),elf=str(elf),elf_sha256=sha(elf),elf_role='source_mmap_ELF_for_static_verification',actual_runtime_harness_elf=str(actual),actual_runtime_harness_sha256=sha(actual),runtime_original_code_mmap=info,semantic_result_observed_records=records,limits=['Isolated packed writer; explicit buffer/MMIO fixtures and SR operands, not physical AUX verification.']))
 indices=sorted({e['aux_index']for run in trace['runs']for e in run['semantic_result_observed_records']});trace['distinct_aux_indices']=len(indices);trace['distinct_aux_hex']=list(map(hex,indices));save(ev/'firmware_aux_trace.json',trace)
 metadata=load(out/'atlas_metadata.json');metadata.update(date='2026-10-25',parent_atlas=str(parent),parent_ledger_sha256=sha(parent/'sha256.json'),parent_ledger_files_verified=len(ledger),ff7_packed_windows_new=7,ff7_packed_new_cell_offsets=114,ff7_packed_new_parameter_addresses=10,ff7_packed_window_write_events=415,ff7_packed_parameter_events=40,ff7_packed_scenarios=25,ff7_packed_trace_identical_pairs=25,ff7_packed_metamorphic_checks=8,whole_physical_map_complete=False);save(out/'atlas_metadata.json',metadata)
 completion=load(out/'completion_audit.json');completion['requirements'][2]['limits']=['502 individually cataloged MMIO addresses plus12 bounded windows/2930cell offsets do not delimit the physical universe','Shared output windows have distinct wide/compact tail contracts; physical function and actual caller constraints unknown'];completion['next_work']=['Expand remaining FF7 scalar controls and earlier packed writers, then FFB/FFC and unresolved caller domains','Resolve remaining AUX code/data candidates and parametric families','Obtain actual BCR/SoC configuration evidence without promoting fixture values'];save(out/'completion_audit.json',completion)
 for name in['s33_build_register_atlas.py','s33_verify_register_trace_sites.py']:subprocess.run([sys.executable,str(scripts/name),str(out)],check=True)
 subprocess.run(['/home/jack/.local/share/pipx/venvs/graphifyy/bin/python',str(scripts/'s33_build_register_graph.py'),str(out)],check=True)
 atlas=load(out/'register_map.json');assert len(atlas['records'])==763 and Counter(r['space']for r in atlas['records'])==dict(core=64,aux=197,soc_mmio=502);keys={(r['space'],r['number'])for r in atlas['records']};assert keys-known=={('soc_mmio',a)for a in params};assert len(atlas['mmio_transfer_windows'])==12 and sum(w['element_count']for w in atlas['mmio_transfer_windows'])==2930 and len(atlas['computed_mmio_families'])==2
 for w in atlas['mmio_transfer_windows']:assert not w['hardware_verified']and w['concrete_control_registers_admitted_from_window_cells']==0 and not any(('soc_mmio',int(w['base'],0)+4*i)in keys for i in range(w['element_count']))
 assert len(atlas['aux_indices_with_guest_semantic_records'])==22 and len(load(out/'aux_trace_site_verification.json')['checks'])==104;assert not atlas['goal_complete']and all(not r['hardware_verified']for r in atlas['records']);graph=load(out/'graph.json');assert sum(n.get('file_type')=='mmio_write_window'for n in graph['nodes'])==12
 inputs={**d['input_hashes'],**audit['input_sha256']};assert all(sha(Path(p))==h for p,h in inputs.items());assert all(sha(parent/p)==h for p,h in ledger.items());save(out/'atlas_validation.json',dict(status='PASS_FF7_PACKED_CONTRACTS_WINDOWS_INTEGRATION',total_records=763,counts=atlas['counts'],new_parameter_mmio_addresses=10,new_transfer_windows=7,new_window_cells=114,total_windows=12,total_window_cells=2930,window_cells_admitted_as_independent_registers=0,completed_memory_events=455,window_write_events=415,parameter_events=40,selected_scenarios=25,trace_identical_pairs=25,ignored_bits_equivalences=5,wide_compact_tail_comparisons=3,representative_aux_guest_indices=22,aux_run_pc_sites=104,parent_ledger_files_verified=len(ledger),input_sha256=inputs,gnu_original_inputs_unchanged=True,whole_physical_map_complete=False,limits=d['limits']))
 for name in['s33_build_register_atlas.py','s33_build_register_graph.py','s33_verify_register_trace_sites.py']:shutil.copy2(scripts/name,ev/name)
 files={str(p.relative_to(out)):sha(p)for p in sorted(out.rglob('*'))if p.is_file()and p!=out/'sha256.json'};save(out/'sha256.json',files);print('PASS763records,10new addresses,7new windows/114cells,104AUXsites;ledger',len(files));print(out)
if __name__=='__main__':main()
