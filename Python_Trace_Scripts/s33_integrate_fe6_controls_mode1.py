#!/usr/bin/env python3
"""Version nominal address evidence while excluding signed-only attempted cells."""
import argparse,hashlib,json,shutil,subprocess,sys
from collections import Counter,defaultdict
from datetime import datetime,timezone
from pathlib import Path
ROOT=Path(__file__).resolve().parents[1]
def sha(p):return hashlib.sha256(p.read_bytes()).hexdigest()
def load(p):return json.loads(p.read_text())
def save(p,d):p.write_text(json.dumps(d,indent=2)+'\n')
def main():
 ap=argparse.ArgumentParser(description=__doc__);ap.add_argument('--parent',type=Path,required=True);ap.add_argument('--source',type=Path,required=True);ap.add_argument('--audit',type=Path,required=True);args=ap.parse_args()
 parent=args.parent.resolve();src=args.source.resolve();audit_path=args.audit.resolve();ledger=load(parent/'sha256.json');assert all(sha(parent/p)==h for p,h in ledger.items())
 d=load(src/'verified_evidence.json');audit=load(audit_path);assert d['status']=='PASS_FE6_CONTROLS_MODE1_AND_SIGNED_BOUNDARY'and audit['status']=='PASS_FE6_CONTROLS_MODE1_BYTE_TRACE_SCOPE_AUDIT'
 for mapping in[d['input_hashes'],audit['input_sha256']]:assert all(sha(Path(p))==h for p,h in mapping.items())
 assert all(sha(src/p)==h for p,h in d['files'].items());old=load(parent/'register_map.json');known={(r['space'],r['number'])for r in old['records']};nominal=defaultdict(list);aliases=defaultdict(list);attempts=[]
 for c in d['cases']:
  if not c['observer_enabled']:continue
  if c['scope_kind']=='out_of_domain_fault':assert not c['completed_memory_events'];attempts.extend(dict(case=c['name'],**e)for e in c['attempts_without_result']);continue
  assert c['exit_code']==0 and c['full_selected_paths_completed'];target=aliases if c['scope_kind']=='out_of_domain_alias'else nominal
  for e in c['completed_memory_events']:target[e['address']].append(dict(case=c['name'],**e))
 new={a for a in nominal if('soc_mmio',a)not in known};assert len(nominal)==48 and len(new)==42 and sum(map(len,nominal.values()))==720 and sum(map(len,aliases.values()))==8 and len(attempts)==2
 excluded={e['address']for e in attempts};assert excluded=={0xfe645e0,0xfe64680}and not(excluded&set(nominal))
 out=parent.parent/datetime.now(timezone.utc).strftime('%Y%m%dT%H%M%SZ');assert not out.exists();shutil.copytree(parent,out);(out/'sha256.json').unlink();ev=out/'evidence';scripts=ROOT/'Python_Trace_Scripts'
 for original,name in[(src/'verified_evidence.json','fe6_controls_mode1.json'),(audit_path,'fe6_controls_mode1_audit.json'),(src/'original_windows.txt','fe6_controls_mode1_disassembly.txt'),(src/'s33_verify_fe6_controls_mode1.py','s33_verify_fe6_controls_mode1.py'),(scripts/'s33_audit_fe6_controls_mode1.py','s33_audit_fe6_controls_mode1.py'),(Path(__file__),Path(__file__).name)]:shutil.copy2(original,ev/name)
 sources=[dict(file=str(ev/'fe6_controls_mode1.json'),line=1),dict(file=str(ev/'fe6_controls_mode1_audit.json'),line=1)];mmio=load(ev/'mmio_documented.json');by_addr={int(r['address'],0):r for r in mmio['records']}
 for a,rows in sorted(nominal.items()):
  control=0xfe64600<=a<=0xfe646c8
  if control:
   off=a&31;meanings={0:['Set/clear bits1/2/3; separate RMW replaces bits0/4 preserving all others'],4:['Returns low15bits and writes bit15 as a byte to the synthetic caller output pointer'],8:['Returns mask0x10 (bit4), not normalized']}[off]
   group='fe6_nominal_control_branches_physical_function_unknown'
  else:meanings=['Mode1-only RMW replaces bits12..13 from argument low2 and preserves all other halfword bits'];group='fe6_mode1_bounded_array_physical_function_unknown'
  if a in new:
   r=dict(address=f'0x{a:08X}',namespace='soc_mmio',subsystem=group,width_bits=16,access='/'.join(sorted({e['operation']for e in rows}))+'_halfword_di',confidence='original_guest_nominal_control_or_mode1_array_fixture',hardware_verified=False,fields=[dict(meaning=s,evidence_type='software_operation',physical_meaning='unknown')for s in meanings],observed_accesses=rows,observed_write_values=sorted({hex(e['value'])for e in rows if e['operation']=='write'}),sources=sources,evidence=['original_bytes_bound','nominal_control_or_unsigned_bounded_array','delegating_memory_observer'],unknown=['Physical name/implementation, reset, access permissions, IRQ/timing unknown.','Mode cache, MMIO seeds and caller/output RAM are explicit fixtures.']);mmio['records'].append(r)
  else:
   r=by_addr[a];r.setdefault('observed_accesses',[]).extend(rows);r.setdefault('additional_software_operations',[]).extend(dict(meaning=s,source_file=str(ev/'fe6_controls_mode1.json'))for s in meanings);r['sources'].extend(sources)
   r['observed_write_values']=sorted(set(r.get('observed_write_values',[]))|{hex(e['value'])for e in rows if e['operation']=='write'});r['access']='read/write_halfword_di'
  if a in aliases:r['software_argument_wrap_observations']=aliases[a];r['software_argument_wrap_warning']='Signed negative inputs alias the same virtual cell by arithmetic; no physical alias or actual Nikon negative caller proven.'
 mmio['counts'].update(register_addresses=len(mmio['records']),direct_or_reported_accesses=len(mmio['records']));save(ev/'mmio_documented.json',mmio)
 metadata=load(out/'atlas_metadata.json');metadata.update(date='2026-10-25',parent_atlas=str(parent),parent_ledger_sha256=sha(parent/'sha256.json'),parent_ledger_files_verified=len(ledger),fe6_controls_mode1_new_addresses=42,fe6_controls_mode1_nominal_addresses=48,fe6_controls_mode1_nominal_events=720,fe6_controls_mode1_signed_alias_events=8,fe6_controls_mode1_incomplete_attempts=2,fe6_controls_mode1_scenarios=7,fe6_controls_mode1_trace_identical_pairs=7,fe6_controls_mode1_excluded_attempt_addresses=list(map(hex,sorted(excluded))),whole_physical_map_complete=False);save(out/'atlas_metadata.json',metadata)
 completion=load(out/'completion_audit.json');completion['requirements'][2]['limits']=['468software-level MMIO addresses do not delimit the physical universe or prove hardware semantics','Signed-negative arithmetic can reach cells outside nominal software branches; attempted model accesses are not physical register evidence']
 completion['next_work']=['Follow ordinary caller domains of remaining FE6 indexed controls and computed FF7/FFB/FFC families','Resolve remaining AUX code/data candidates and parametric families','Obtain actual BCR/SoC configuration evidence without promoting fixture values'];save(out/'completion_audit.json',completion)
 for name in['s33_build_register_atlas.py','s33_verify_register_trace_sites.py']:subprocess.run([sys.executable,str(scripts/name),str(out)],check=True)
 subprocess.run(['/home/jack/.local/share/pipx/venvs/graphifyy/bin/python',str(scripts/'s33_build_register_graph.py'),str(out)],check=True)
 atlas=load(out/'register_map.json');assert len(atlas['records'])==729 and Counter(r['space']for r in atlas['records'])==dict(core=64,aux=197,soc_mmio=468);keys={(r['space'],r['number'])for r in atlas['records']};assert keys-known=={('soc_mmio',a)for a in new}and not any(('soc_mmio',a)in keys for a in excluded)
 assert len(atlas['aux_indices_with_guest_semantic_records'])==22 and len(load(out/'aux_trace_site_verification.json')['checks'])==74;assert not atlas['goal_complete']and all(not r['hardware_verified']for r in atlas['records']);inputs={**d['input_hashes'],**audit['input_sha256']};assert all(sha(Path(p))==h for p,h in inputs.items());assert all(sha(parent/p)==h for p,h in ledger.items())
 save(out/'atlas_validation.json',dict(status='PASS_FE6_CONTROLS_MODE1_SCOPE_INTEGRATION',total_records=729,counts=atlas['counts'],new_mmio_addresses=42,nominal_addresses=48,nominal_completed_events=720,signed_alias_events=8,incomplete_attempts_excluded_from_admission=2,excluded_attempt_addresses=list(map(hex,sorted(excluded))),selected_scenarios=7,trace_identical_pairs=7,expected_fault_scenarios=2,representative_aux_guest_indices=22,aux_run_pc_sites=74,parent_ledger_files_verified=len(ledger),input_sha256=inputs,gnu_original_inputs_unchanged=True,whole_physical_map_complete=False,limits=d['limits']))
 for name in['s33_build_register_atlas.py','s33_build_register_graph.py','s33_verify_register_trace_sites.py']:shutil.copy2(scripts/name,ev/name)
 files={str(p.relative_to(out)):sha(p)for p in sorted(out.rglob('*'))if p.is_file()and p!=out/'sha256.json'};save(out/'sha256.json',files);print('PASS729records,42newMMIO;720nominal+8alias events,2attempts excluded;ledger',len(files));print(out)
if __name__=='__main__':main()
