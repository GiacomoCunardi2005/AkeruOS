#!/usr/bin/env python3
"""Add audited FF7 packed apertures and scalar evidence without counting cells as controls."""
import argparse,hashlib,json,re,shutil,subprocess,sys
from collections import Counter,defaultdict
from datetime import datetime,timezone
from pathlib import Path
ROOT=Path(__file__).resolve().parents[1]
def sha(p):return hashlib.sha256(p.read_bytes()).hexdigest()
def load(p):return json.loads(p.read_text())
def save(p,d):p.write_text(json.dumps(d,indent=2)+'\n')

def main():
 ap=argparse.ArgumentParser(description=__doc__);ap.add_argument('--parent',type=Path,required=True);ap.add_argument('--source',type=Path,required=True);ap.add_argument('--audit',type=Path,required=True);a=ap.parse_args();parent=a.parent.resolve();src=a.source.resolve();audit_path=a.audit.resolve();ledger=load(parent/'sha256.json');assert all(sha(parent/p)==h for p,h in ledger.items())
 d=load(src/'verified_evidence.json');audit=load(audit_path);assert d['status']=='PASS_FF7_PACKED_TABLES'and audit['status']=='PASS_FF7_PACKED_TABLES_AUDIT'and d['capture_streams_separate'];inputs={**d['input_hashes'],**audit['input_sha256']};assert all(sha(Path(p))==h for p,h in inputs.items());assert all(sha(src/p)==h for p,h in d['files'].items())
 old=load(parent/'register_map.json');known={(r['space'],r['number'])for r in old['records']};scalar=defaultdict(list);window_cells={int(w['base'],0)+4*i for w in audit['transfer_windows']for i in range(w['element_count'])};store_pcs={s['store_pc']for s in d['specs']}
 for c in d['cases']:
  if not c['observer_enabled']:continue
  for e in c['completed_memory_events']:
   if e['pc']not in store_pcs:scalar[e['address']].append(dict(case=c['name'],**e))
 assert len(scalar)==23 and sum(map(len,scalar.values()))==134 and {x for x in scalar if('soc_mmio',x)in known}=={0xff74000};assert len(window_cells)==85 and not any(('soc_mmio',x)in known for x in window_cells)
 out=parent.parent/datetime.now(timezone.utc).strftime('%Y%m%dT%H%M%SZ');assert not out.exists();shutil.copytree(parent,out);(out/'sha256.json').unlink();save(out/'atlas_validation.json',dict(status='INCOMPLETE_NO_VALIDATION',parent_atlas=str(parent)));ev=out/'evidence';scripts=ROOT/'Python_Trace_Scripts'
 for original,name in[(src/'verified_evidence.json','ff7_packed_tables.json'),(audit_path,'ff7_packed_tables_audit.json'),(src/'original_windows_candidates.txt','ff7_packed_tables_linear_candidates.txt'),(src/'s33_verify_ff7_packed_tables.py','s33_verify_ff7_packed_tables.py'),(scripts/'s33_audit_ff7_packed_tables.py','s33_audit_ff7_packed_tables.py'),(Path(__file__),Path(__file__).name)]:shutil.copy2(original,ev/name)
 sources=[dict(file=str(ev/'ff7_packed_tables.json'),line=1),dict(file=str(ev/'ff7_packed_tables_audit.json'),line=1)];mmio=load(ev/'mmio_documented.json');by_address={int(r['address'],0):r for r in mmio['records']}
 for address,rows in sorted(scalar.items()):
  if address==0xff74000:
   r=by_address[address];r.setdefault('fields',[]).append(dict(bits=[5,6],meaning='Original2E0600/2E0634 set their bit only for argument==1, otherwise clear; all other bits preserved',evidence_type='original_guest_software_RMW',physical_meaning='unknown'));r.setdefault('sources',[]).extend(sources);r['ff7_packed_control_accesses']=rows
  else:
   if address in[0xff74014,0xff74018,0xff7401c]:meaning='Full halfword store of(uint32(arg0 OR(arg1<<4)))&FFFF; no independent nibble masking'
   elif address in[0xff74088,0xff740d0]:meaning='Full halfword store of(uint32(arg2 OR(arg1<<10)))&FFFF after17packed table writes; no independent field masking'
   else:meaning='Original function stores a caller parameter truncated to low16bits; physical parameter meaning unknown'
   r=dict(address=f'0x{address:08X}',namespace='soc_mmio',subsystem='ff7_packed_table_scalar_physical_function_unknown',software_role='packed_or_truncated_parameter',width_bits=16,access='write_halfword_di',confidence='original_guest_packed_table_writer_fixture',fields=[dict(meaning=meaning,evidence_type='software_operation',physical_meaning='unknown')],hardware_verified=False,observed_accesses=rows,sources=sources,evidence=['original_bytes_bound','full_original_calls_completed','independent_buffer_packing_audit','separate_observer_stderr'],unknown=['Physical function, reset, access permissions, IRQ and timing not established','Input and MMIO backing are fixtures; nominal Nikon argument ranges not established']);mmio['records'].append(r)
 mmio['counts'].update(register_addresses=len(mmio['records']),direct_or_reported_accesses=len(mmio['records']));save(ev/'mmio_documented.json',mmio)
 windows=load(ev/'mmio_transfer_windows.json');assert len(windows['windows'])==5
 for w in audit['transfer_windows']:
  assert not any(w['name']==v['name']for v in windows['windows']);windows['windows'].append(dict(w,sources=sources,input_packing='First16outputs pack two7bitmasked halfwords, two strided bytes, or two contiguous bytes as specified per writer;17th copied separately without7bitmask',limits=d['limits']))
 save(ev/'mmio_transfer_windows.json',windows)
 trace=load(ev/'firmware_aux_trace.json');fw=Path(trace['firmware_path']).read_bytes();info=d['payload'];source_elf=ROOT/'outputs/gnu_arc700/20261024T232600Z_2fcbbcac/main_source.elf'
 for spec in d['specs']:
  name=spec['name']+'_0_observed';path=src/(name+'.trace');records=[]
  for line_no,line in enumerate(path.read_text().splitlines(),1):
   m=re.match(r'0x([0-9a-f]+)\s+sr\s+.*?\[([^\]]+)\].*? - .*?<- (0x[0-9a-f]+)',line)
   if not m or int(m[1],16)not in spec['aux_pcs']:continue
   pc=int(m[1],16);index=int(m[2],0);value=int(m[3],16);offset=info['firmware_offset']+pc-info['base'];records.append(dict(trace_line=line_no,pc=pc,pc_hex=hex(pc),operation='write',aux_index=index,aux_hex=hex(index),trace_text=line,semantic_result_observed=True,retirement_proven_by_this_record=False,firmware_offset=offset,firmware_offset_hex=hex(offset),original_firmware_bytes_next8=fw[offset:offset+8].hex(),trace_value=value,trace_value_hex=hex(value),value_meaning='Original loop-start/end setter operand, not physical post-set readback'))
  assert len(records)==2 and {r['aux_index']for r in records}=={2,3};harness=src/(spec['name']+'_0.elf');trace['runs'].append(dict(name='ff7_packed_'+name,path=str(path),sha256=sha(path),run_manifest=str(src/'verified_evidence.json'),run_manifest_sha256=sha(src/'verified_evidence.json'),elf=str(source_elf),elf_sha256=sha(source_elf),elf_role='source_mmap_ELF_for_static_verification',actual_runtime_harness_elf=str(harness),actual_runtime_harness_sha256=sha(harness),runtime_original_code_mmap=info,semantic_result_observed_records=records,limits=['Isolated original writer with synthetic inputs/backing; no physical register state inferred.']))
 indices=sorted({e['aux_index']for run in trace['runs']for e in run['semantic_result_observed_records']});trace['distinct_aux_indices']=len(indices);trace['distinct_aux_hex']=list(map(hex,indices));save(ev/'firmware_aux_trace.json',trace)
 metadata=load(out/'atlas_metadata.json');metadata.update(date='2026-10-25',parent_atlas=str(parent),parent_ledger_sha256=sha(parent/'sha256.json'),parent_ledger_files_verified=len(ledger),ff7_packed_writers=8,ff7_packed_new_scalar_addresses=22,ff7_packed_existing_controls=1,ff7_packed_new_windows=5,ff7_packed_window_cells=85,ff7_packed_events=678,ff7_packed_scenarios=34,ff7_packed_trace_identical_pairs=34,whole_physical_map_complete=False);save(out/'atlas_metadata.json',metadata)
 completion=load(out/'completion_audit.json');completion['requirements'][2]['limits']=['514 individually cataloged MMIO addresses plus10 bounded windows/2901cell offsets do not delimit the physical universe','Window cells are not admitted as independent control registers; physical functions and effects remain unknown'];completion['next_work']=['Continue remaining FF7 direct tables, FFB/FFC, indexed/tail caller domains','Resolve custom AUX code/data candidates and parameterized domains','Obtain actual BCR and SoC physical-configuration evidence'];save(out/'completion_audit.json',completion)
 for name in['s33_build_register_atlas.py','s33_verify_register_trace_sites.py']:subprocess.run([sys.executable,str(scripts/name),str(out)],check=True)
 subprocess.run(['/home/jack/.local/share/pipx/venvs/graphifyy/bin/python',str(scripts/'s33_build_register_graph.py'),str(out)],check=True)
 atlas=load(out/'register_map.json');assert len(atlas['records'])==775 and Counter(r['space']for r in atlas['records'])==dict(core=64,aux=197,soc_mmio=514);new_keys={(r['space'],r['number'])for r in atlas['records']};assert new_keys-known=={('soc_mmio',x)for x in scalar if x!=0xff74000};assert len(atlas['mmio_transfer_windows'])==10 and sum(w['element_count']for w in atlas['mmio_transfer_windows'])==2901
 assert all(w['concrete_control_registers_admitted_from_window_cells']==0 and not w['hardware_verified']for w in atlas['mmio_transfer_windows']);assert not any(('soc_mmio',x)in new_keys for x in window_cells);assert len(atlas['computed_mmio_families'])==2 and len(atlas['aux_indices_with_guest_semantic_records'])==22 and len(load(out/'aux_trace_site_verification.json')['checks'])==100;assert not atlas['goal_complete']and all(not r['hardware_verified']for r in atlas['records']);assert sum(n.get('file_type')=='mmio_write_window'for n in load(out/'graph.json')['nodes'])==10
 assert all(sha(Path(p))==h for p,h in inputs.items())and all(sha(parent/p)==h for p,h in ledger.items());save(out/'atlas_validation.json',dict(status='PASS_FF7_PACKED_TABLES_INTEGRATION',total_records=775,counts=atlas['counts'],new_scalar_addresses=22,enriched_existing_controls=1,new_windows=5,new_window_cells=85,total_windows=10,total_window_cells=2901,completed_memory_events=678,trace_identical_pairs=34,representative_aux_guest_indices=22,aux_run_pc_sites=100,parent_ledger_files_verified=len(ledger),input_sha256=inputs,gnu_original_inputs_unchanged=True,whole_physical_map_complete=False,limits=d['limits']))
 for name in['s33_build_register_atlas.py','s33_build_register_graph.py','s33_verify_register_trace_sites.py']:shutil.copy2(scripts/name,ev/name)
 files={str(p.relative_to(out)):sha(p)for p in sorted(out.rglob('*'))if p.is_file()and p!=out/'sha256.json'};save(out/'sha256.json',files);print('PASS775records,22new scalar addresses,10windows/2901cells,100AUX sites;ledger',len(files));print(out)
if __name__=='__main__':main()
