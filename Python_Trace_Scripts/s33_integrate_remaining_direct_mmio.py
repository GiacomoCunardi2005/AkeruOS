#!/usr/bin/env python3
"""Version the atlas with five original-path MMIO addresses and eight AUX sites."""
import argparse,hashlib,json,re,shutil,subprocess,sys
from collections import Counter,defaultdict
from datetime import datetime,timezone
from pathlib import Path
ROOT=Path(__file__).resolve().parents[1]
def sha(p):return hashlib.sha256(p.read_bytes()).hexdigest()
def load(p):return json.loads(p.read_text())
def save(p,d):p.write_text(json.dumps(d,indent=2)+'\n')
def main():
    ap=argparse.ArgumentParser(description=__doc__);ap.add_argument('--parent',type=Path,required=True);ap.add_argument('--source',type=Path,required=True);ap.add_argument('--audit',type=Path,required=True);args=ap.parse_args()
    parent=args.parent.resolve();src=args.source.resolve();audit_path=args.audit.resolve();ledger=load(parent/'sha256.json')
    assert all(sha(parent/p)==h for p,h in ledger.items());d=load(src/'verified_evidence.json');audit=load(audit_path)
    assert d['status']=='PASS_REMAINING_DIRECT_MMIO_ORIGINAL_PATHS' and audit['status']=='PASS_REMAINING_DIRECT_MMIO_BYTES_AND_TRACE_AUDIT'
    for inputs in [d['input_hashes'],audit['input_sha256']]:assert all(sha(Path(p))==h for p,h in inputs.items())
    assert all(sha(src/p)==h for p,h in d['files'].items())
    old=load(parent/'register_map.json');known={(r['space'],r['number']) for r in old['records']};events=defaultdict(list)
    for c in d['cases']:
        if c['observer_enabled']:
            assert c['exit_code']==0 and c['full_selected_path_completed']
            for e in c['completed_memory_events']:events[e['address']].append(dict(case=c['name'],**e))
    assert len(events)==5 and sum(map(len,events.values()))==18 and not any(('soc_mmio',a) in known for a in events)
    out=parent.parent/datetime.now(timezone.utc).strftime('%Y%m%dT%H%M%SZ');assert not out.exists();shutil.copytree(parent,out);(out/'sha256.json').unlink();ev=out/'evidence';scripts=ROOT/'Python_Trace_Scripts'
    for original,name in [(src/'verified_evidence.json','remaining_direct_mmio.json'),(audit_path,'remaining_direct_mmio_audit.json'),(src/'original_windows.txt','remaining_direct_mmio_disassembly.txt'),(src/'s33_verify_remaining_direct_mmio.py','s33_verify_remaining_direct_mmio.py'),(src/'s33_register_profile_observer.c','s33_register_profile_observer.c'),(scripts/'s33_audit_remaining_direct_mmio.py','s33_audit_remaining_direct_mmio.py'),(Path(__file__),Path(__file__).name)]:shutil.copy2(original,ev/name)
    fields={0xfef000c:['Read by two synchronization wrappers; incremented value in r10 is not used as the fixed loop count'],0xfef0050:['Software bit6 controls optional vector fallback path'],0xfef0328:['Software bit4 controls optional vector fallback path'],0xfef00e8:['Software read-modify-write clears bit0 when FEF0050bit6 is set'],0xfef00f8:['Software read-modify-write clears bit0 when FEF0328bit4 is set']}
    mmio=load(ev/'mmio_documented.json')
    for address,rows in sorted(events.items()):
        mmio['records'].append(dict(address=f'0x{address:08X}',namespace='soc_mmio',subsystem='synchronization_or_vector_path_physical_function_unknown',width_bits=16,access='/'.join(sorted({e['operation'] for e in rows}))+'_halfword_di',confidence='original_guest_delegating_observer_explicit_state',hardware_verified=False,fields=[dict(meaning=s,evidence_type='software_operation',physical_meaning='unknown') for s in fields[address]],observed_accesses=rows,observed_write_values=sorted({hex(e['value']) for e in rows if e['operation']=='write'}),sources=[dict(file=str(ev/'remaining_direct_mmio.json'),line=1),dict(file=str(ev/'remaining_direct_mmio_audit.json'),line=1)],evidence=['original_bytes_bound','selected_original_paths_executed','delegating_memory_observer'],unknown=['No physical name, reset, access permission, IRQ acknowledgment, W1C or timing proof.','Caller/context RAM/vector base/saved SP/ilink and initial MMIO values are synthetic fixtures.']))
    mmio['counts'].update(register_addresses=len(mmio['records']),direct_or_reported_accesses=len(mmio['records']));save(ev/'mmio_documented.json',mmio)
    trace=load(ev/'firmware_aux_trace.json');fw=Path(trace['firmware_path']).read_bytes();info=d['payload'];source_elf=ROOT/'outputs/gnu_arc700/20261024T232600Z_2fcbbcac/main_source.elf'
    for case in ['vector_265214_1_0_observed','vector_265f60_1_0_observed']:
        path=src/(case+'.trace');records=[]
        for line_no,line in enumerate(path.read_text().splitlines(),1):
            m=re.match(r'0x([0-9a-f]+)\s+(lr|sr)\s+.*?\[([^\]]+)\].*? - .*?<- (0x[0-9a-f]+)',line)
            if not m or not 0x265214<=int(m[1],16)<0x265fe8:continue
            pc=int(m[1],16);index=int(m[3],0);value=int(m[4],16);offset=info['firmware_offset']+pc-info['base']
            records.append(dict(trace_line=line_no,pc=pc,pc_hex=hex(pc),operation='read' if m[2]=='lr' else 'write',aux_index=index,aux_hex=hex(index),trace_text=line,semantic_result_observed=True,retirement_proven_by_this_record=False,firmware_offset=offset,firmware_offset_hex=hex(offset),original_firmware_bytes_next8=fw[offset:offset+8].hex(),trace_value=value,trace_value_hex=hex(value),value_meaning='Explicit vector-base seed or original setter operand; no physical cache/IRQ effect proved'))
        assert len(records)==4
        trace['runs'].append(dict(name='remaining_'+case,path=str(path),sha256=sha(path),run_manifest=str(src/'verified_evidence.json'),run_manifest_sha256=sha(src/'verified_evidence.json'),elf=str(source_elf),elf_sha256=sha(source_elf),elf_role='source_mmap_ELF_for_static_verification',actual_runtime_harness_elf=str(src/(case.removesuffix('_observed')+'.elf')),actual_runtime_harness_sha256=sha(src/(case.removesuffix('_observed')+'.elf')),runtime_original_code_mmap=info,semantic_result_observed_records=records,limits=['Selected vector fallback path with explicit base/ilink/saved-stack fixtures; not full physical interrupt dispatch.']))
    indices=sorted({e['aux_index'] for run in trace['runs'] for e in run['semantic_result_observed_records']});trace['distinct_aux_indices']=len(indices);trace['distinct_aux_hex']=list(map(hex,indices))
    trace['limits'].append('Full-run remaining-direct-MMIO cases have single result rows; earlier paired step-trace duplication warning is local to the direct178D08 experiment.');save(ev/'firmware_aux_trace.json',trace)
    metadata=load(out/'atlas_metadata.json');metadata.update(date='2026-10-25',parent_atlas=str(parent),parent_ledger_sha256=sha(parent/'sha256.json'),parent_ledger_files_verified=len(ledger),remaining_direct_mmio_new_addresses=5,remaining_direct_mmio_events=18,remaining_direct_mmio_scenarios=10,remaining_direct_mmio_trace_identical_pairs=10,direct_low_literal_candidates_remaining=0,direct_low_literal_candidates_covered=47,direct_low_literal_candidates_total=47,whole_physical_map_complete=False);save(out/'atlas_metadata.json',metadata)
    completion=load(out/'completion_audit.json');completion['requirements'][2]['limits']=['222 software-level MMIO addresses do not delimit the full physical universe or prove hardware semantics/timing/aliases','Initial low direct candidate census47/47 covered; FEF0328 discovered outside that census after aligned decoding']
    completion['next_work']=['Expand code-anchored direct/computed MMIO across the remaining original firmware paths; do not equate initial census closure with whole-map completion','Resolve remaining AUX code/data candidates and parametric families','Obtain actual BCR/SoC configuration evidence without promoting fixture values'];save(out/'completion_audit.json',completion)
    for name in ['s33_build_register_atlas.py','s33_verify_register_trace_sites.py']:subprocess.run([sys.executable,str(scripts/name),str(out)],check=True)
    subprocess.run(['/home/jack/.local/share/pipx/venvs/graphifyy/bin/python',str(scripts/'s33_build_register_graph.py'),str(out)],check=True)
    atlas=load(out/'register_map.json');sites=load(out/'aux_trace_site_verification.json');assert len(atlas['records'])==483 and Counter(r['space'] for r in atlas['records'])==dict(core=64,aux=197,soc_mmio=222)
    assert len(atlas['aux_indices_with_guest_semantic_records'])==22 and len(sites['checks'])==74
    assert not atlas['goal_complete'] and all(not r['hardware_verified'] for r in atlas['records'])
    inv=load(out/'inventory.json');direct={int(r['constant'],0) for r in inv['instruction_constants'] if r['mnemonic'].startswith(('ld','st')) and re.search(r'\[0x'+f"{int(r['constant'],0):x}"+r'\]',r['listing'])};mapped={r['number'] for r in atlas['records'] if r['space']=='soc_mmio'};assert len(direct)==47 and direct<=mapped
    inputs={**d['input_hashes'],**audit['input_sha256']};assert all(sha(Path(p))==h for p,h in inputs.items());assert all(sha(parent/p)==h for p,h in ledger.items())
    save(out/'atlas_validation.json',dict(status='PASS_REMAINING_DIRECT_MMIO_INTEGRATION',total_records=483,counts=atlas['counts'],new_mmio_addresses=5,completed_memory_events=18,selected_original_path_scenarios=10,trace_identical_pairs=10,representative_aux_guest_indices=22,aux_run_pc_sites=74,initial_low_direct_census_covered=47,initial_low_direct_census_total=47,parent_ledger_files_verified=len(ledger),input_sha256=inputs,gnu_original_inputs_unchanged=True,whole_physical_map_complete=False,limits=d['limits']))
    for name in ['s33_build_register_atlas.py','s33_build_register_graph.py','s33_verify_register_trace_sites.py']:shutil.copy2(scripts/name,ev/name)
    files={str(p.relative_to(out)):sha(p) for p in sorted(out.rglob('*')) if p.is_file() and p!=out/'sha256.json'};save(out/'sha256.json',files)
    print('PASS483 records, five new MMIO,22 AUX guest/74 run-PC sites; ledger',len(files));print(out)
if __name__=='__main__':main()
