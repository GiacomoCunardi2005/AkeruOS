#!/usr/bin/env python3
"""Integrate scalar FF7 addresses and bounded apertures in distinct atlas collections."""
import argparse,hashlib,json,re,shutil,subprocess,sys
from collections import Counter,defaultdict
from datetime import datetime,timezone
from pathlib import Path
ROOT=Path(__file__).resolve().parents[1]
def sha(p):return hashlib.sha256(p.read_bytes()).hexdigest()
def load(p):return json.loads(p.read_text())
def save(p,d):p.write_text(json.dumps(d,indent=2)+'\n')
def main():
 ap=argparse.ArgumentParser(description=__doc__);ap.add_argument('--parent',type=Path,required=True);ap.add_argument('--source',type=Path,required=True);ap.add_argument('--audit',type=Path,required=True);args=ap.parse_args();parent=args.parent.resolve();src=args.source.resolve();audit_path=args.audit.resolve();ledger=load(parent/'sha256.json');assert all(sha(parent/p)==h for p,h in ledger.items())
 d=load(src/'verified_evidence.json');audit=load(audit_path);assert d['status']=='PASS_FF7_BOUNDED_TRANSFER_WINDOWS'and audit['status']=='PASS_FF7_TRANSFER_WINDOW_BYTES_BUFFER_TRACE_AUDIT'and d['capture_streams_separate']
 for mapping in[d['input_hashes'],audit['input_sha256']]:assert all(sha(Path(p))==h for p,h in mapping.items())
 assert all(sha(src/p)==h for p,h in d['files'].items());old=load(parent/'register_map.json');known={(r['space'],r['number'])for r in old['records']};scalar=defaultdict(list);window_events=0;specs={s['name']:s for s in d['specs']}
 for c in d['cases']:
  if not c['observer_enabled']:continue
  assert c['exit_code']==0 and c['full_original_writer_completed'];spec=specs[c['spec_name']]
  for e in c['completed_memory_events']:
   if e['pc']==spec['store_pc']:window_events+=1
   else:scalar[e['address']].append(dict(case=c['name'],**e))
 assert len(scalar)==18 and sum(map(len,scalar.values()))==100 and window_events==5632 and not any(('soc_mmio',a)in known for a in scalar)
 out=parent.parent/datetime.now(timezone.utc).strftime('%Y%m%dT%H%M%SZ');assert not out.exists();shutil.copytree(parent,out);(out/'sha256.json').unlink();ev=out/'evidence';scripts=ROOT/'Python_Trace_Scripts'
 for original,name in[(src/'verified_evidence.json','ff7_transfer_windows.json'),(audit_path,'ff7_transfer_windows_audit.json'),(src/'original_windows.txt','ff7_transfer_windows_disassembly.txt'),(src/'s33_verify_ff7_transfer_windows.py','s33_verify_ff7_transfer_windows.py'),(scripts/'s33_audit_ff7_transfer_windows.py','s33_audit_ff7_transfer_windows.py'),(Path(__file__),Path(__file__).name)]:shutil.copy2(original,ev/name)
 sources=[dict(file=str(ev/'ff7_transfer_windows.json'),line=1),dict(file=str(ev/'ff7_transfer_windows_audit.json'),line=1)];mmio=load(ev/'mmio_documented.json')
 for address,rows in sorted(scalar.items()):
  controls=[s for s in d['specs']if s['control']==address];parameters=[(s,i)for s in d['specs']for i,a in enumerate(s['tails'])if a==address]
  if controls:meanings=[f'Original writer{s["name"]} software sets bit{s["bit"]} before bulk and clears it after; other bits preserved'for s in controls]
  else:meanings=[f'Original writer{s["name"]} copies input element{s["count"]+i}({s["input_bits"]}bits) via a halfword store; parameters also written on bulk-skip path'for s,i in parameters]
  mmio['records'].append(dict(address=f'0x{address:08X}',namespace='soc_mmio',subsystem='ff7_transfer_control_or_parameter_physical_function_unknown',software_role='transfer_control_flag'if controls else'transfer_parameter',width_bits=16,access='/'.join(sorted({e['operation']for e in rows}))+'_halfword_di',confidence='original_guest_bounded_writer_controls_parameters_fixture',hardware_verified=False,fields=[dict(meaning=s,evidence_type='software_operation',physical_meaning='unknown')for s in meanings],observed_accesses=rows,observed_write_values=sorted({hex(e['value'])for e in rows if e['operation']=='write'}),sources=sources,evidence=['original_bytes_bound','full_original_writer_and_skip_paths','separate_observer_stderr'],unknown=['Physical peripheral name, reset, access permissions, side effects and timing unknown.','Control seeds, input buffers and aperture backing are explicit fixtures.']))
 mmio['counts'].update(register_addresses=len(mmio['records']),direct_or_reported_accesses=len(mmio['records']));save(ev/'mmio_documented.json',mmio)
 windows=load(ev/'mmio_transfer_windows.json')if(ev/'mmio_transfer_windows.json').exists()else dict(schema='akeruos_bounded_write_windows_v1',windows=[])
 for w in audit['transfer_windows']:
  assert not any(old['name']==w['name']for old in windows['windows']);cases=[c for c in d['cases']if c['observer_enabled']and c['spec_name']==w['name']];windows['windows'].append(dict(w,sources=sources,full_transfer_cases=[c['name']for c in cases if not c['parameters_only']],parameters_only_cases=[c['name']for c in cases if c['parameters_only']],limits=['Cell offset coverage is a software write aperture, not a physical register census.','Store16/stride4 does not establish32bit register layout; model gaps do not establish reserved bits.']))
 save(ev/'mmio_transfer_windows.json',windows)
 # Retain one full-case run per writer, with original SR operands and source bytes.
 trace=load(ev/'firmware_aux_trace.json');fw=Path(trace['firmware_path']).read_bytes();info=d['payload'];elf=ROOT/'outputs/gnu_arc700/20261024T232600Z_2fcbbcac/main_source.elf'
 for spec in d['specs']:
  case_name=spec['name']+'_0_bulk_observed';path=src/(case_name+'.trace');records=[]
  for line_no,line in enumerate(path.read_text().splitlines(),1):
   m=re.match(r'0x([0-9a-f]+)\s+sr\s+.*?\[([^\]]+)\].*? - .*?<- (0x[0-9a-f]+)',line)
   if not m or int(m[1],16)not in spec['aux_pcs']:continue
   pc=int(m[1],16);index=int(m[2],0);value=int(m[3],16);offset=info['firmware_offset']+pc-info['base'];records.append(dict(trace_line=line_no,pc=pc,pc_hex=hex(pc),operation='write',aux_index=index,aux_hex=hex(index),trace_text=line,semantic_result_observed=True,retirement_proven_by_this_record=False,firmware_offset=offset,firmware_offset_hex=hex(offset),original_firmware_bytes_next8=fw[offset:offset+8].hex(),trace_value=value,trace_value_hex=hex(value),value_meaning='Original loop-start/end setter operand; not a physical post-set register value'))
  assert len(records)==2 and {r['aux_index']for r in records}=={2,3}
  actual=src/(case_name.removesuffix('_observed')+'.elf');trace['runs'].append(dict(name='ff7_'+case_name,path=str(path),sha256=sha(path),run_manifest=str(src/'verified_evidence.json'),run_manifest_sha256=sha(src/'verified_evidence.json'),elf=str(elf),elf_sha256=sha(elf),elf_role='source_mmap_ELF_for_static_verification',actual_runtime_harness_elf=str(actual),actual_runtime_harness_sha256=sha(actual),runtime_original_code_mmap=info,semantic_result_observed_records=records,limits=['Isolated original writer with explicit input/MMIO fixtures; SR trace contains setter operands only.']))
 indices=sorted({e['aux_index']for run in trace['runs']for e in run['semantic_result_observed_records']});trace['distinct_aux_indices']=len(indices);trace['distinct_aux_hex']=list(map(hex,indices));save(ev/'firmware_aux_trace.json',trace)
 metadata=load(out/'atlas_metadata.json');metadata.update(date='2026-10-25',parent_atlas=str(parent),parent_ledger_sha256=sha(parent/'sha256.json'),parent_ledger_files_verified=len(ledger),ff7_transfer_windows=5,ff7_transfer_window_cells=2816,ff7_transfer_window_write_events=5632,ff7_new_scalar_addresses=18,ff7_scalar_events=100,ff7_scenarios=20,ff7_trace_identical_pairs=20,ff7_capture_streams_separate=True,whole_physical_map_complete=False);save(out/'atlas_metadata.json',metadata)
 completion=load(out/'completion_audit.json');completion['requirements'][2]['limits']=['492 individually cataloged MMIO addresses plus5 bounded write windows/2816cell offsets do not delimit the physical universe','Write apertures are separate from independent control registers; physical kind and access side effects unknown'];completion['next_work']=['Expand remaining packed FF7 writers/control fields, FFB/FFC and computed/tail caller domains','Resolve remaining AUX code/data candidates and parametric families','Obtain actual BCR/SoC configuration evidence without promoting fixture values'];save(out/'completion_audit.json',completion)
 for name in['s33_build_register_atlas.py','s33_verify_register_trace_sites.py']:subprocess.run([sys.executable,str(scripts/name),str(out)],check=True)
 subprocess.run(['/home/jack/.local/share/pipx/venvs/graphifyy/bin/python',str(scripts/'s33_build_register_graph.py'),str(out)],check=True)
 atlas=load(out/'register_map.json');assert len(atlas['records'])==753 and Counter(r['space']for r in atlas['records'])==dict(core=64,aux=197,soc_mmio=492);keys={(r['space'],r['number'])for r in atlas['records']};assert keys-known=={('soc_mmio',a)for a in scalar}
 assert len(atlas['mmio_transfer_windows'])==5 and sum(w['element_count']for w in atlas['mmio_transfer_windows'])==2816;assert all(w['concrete_control_registers_admitted_from_window_cells']==0 and not w['hardware_verified']for w in atlas['mmio_transfer_windows']);assert len(atlas['computed_mmio_families'])==2
 for w in atlas['mmio_transfer_windows']:assert not any(('soc_mmio',int(w['base'],0)+4*i)in keys for i in range(w['element_count']))
 assert len(atlas['aux_indices_with_guest_semantic_records'])==22 and len(load(out/'aux_trace_site_verification.json')['checks'])==84;assert not atlas['goal_complete']and all(not r['hardware_verified']for r in atlas['records']);graph=load(out/'graph.json');assert sum(n.get('file_type')=='mmio_write_window'for n in graph['nodes'])==5
 inputs={**d['input_hashes'],**audit['input_sha256']};assert all(sha(Path(p))==h for p,h in inputs.items());assert all(sha(parent/p)==h for p,h in ledger.items())
 save(out/'atlas_validation.json',dict(status='PASS_FF7_TRANSFER_WINDOWS_SEPARATE_SCALAR_INTEGRATION',total_records=753,counts=atlas['counts'],new_scalar_mmio_addresses=18,transfer_windows=5,window_cell_offsets=2816,window_cells_admitted_as_independent_registers=0,completed_memory_events=5732,window_write_events=5632,scalar_events=100,selected_scenarios=20,trace_identical_pairs=20,stdout_stderr_captured_separately=True,representative_aux_guest_indices=22,aux_run_pc_sites=84,parent_ledger_files_verified=len(ledger),input_sha256=inputs,gnu_original_inputs_unchanged=True,whole_physical_map_complete=False,limits=d['limits']))
 for name in['s33_build_register_atlas.py','s33_build_register_graph.py','s33_verify_register_trace_sites.py']:shutil.copy2(scripts/name,ev/name)
 files={str(p.relative_to(out)):sha(p)for p in sorted(out.rglob('*'))if p.is_file()and p!=out/'sha256.json'};save(out/'sha256.json',files);print('PASS753records,18new addresses,5windows/2816cells,84AUX sites;ledger',len(files));print(out)
if __name__=='__main__':main()
