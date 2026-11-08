#!/usr/bin/env python3
"""Join original loop evidence, preserving synthetic raw-input limits and parent ledger."""
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
    d=load(src/'verified_evidence.json');audit=load(audit_path);assert d['status']=='PASS_FE6_ORIGINAL_LOOP_AND_MODE_PRODUCER'and audit['status']=='PASS_FE6_ORIGINAL_LOOP_BYTE_AND_TRACE_AUDIT'
    for mapping in [d['input_hashes'],audit['input_sha256']]:assert all(sha(Path(p))==h for p,h in mapping.items())
    assert all(sha(src/p)==h for p,h in d['files'].items());old=load(parent/'register_map.json');known={(r['space'],r['number'])for r in old['records']};events=defaultdict(list)
    for c in d['cases']:
        if c['observer_enabled']:
            assert c['exit_code']==0 and c['full_original_caller_completed']
            for e in c['completed_memory_events']:events[e['address']].append(dict(case=c['name'],**e))
    new={a for a in events if ('soc_mmio',a)not in known};assert len(events)==34 and len(new)==32 and sum(map(len,events.values()))==208
    out=parent.parent/datetime.now(timezone.utc).strftime('%Y%m%dT%H%M%SZ');assert not out.exists();shutil.copytree(parent,out);(out/'sha256.json').unlink();ev=out/'evidence';scripts=ROOT/'Python_Trace_Scripts'
    for original,name in [(src/'verified_evidence.json','fe6_original_loop.json'),(audit_path,'fe6_original_loop_audit.json'),(src/'original_windows.txt','fe6_original_loop_disassembly.txt'),(src/'s33_verify_fe6_original_loop.py','s33_verify_fe6_original_loop.py'),(scripts/'s33_audit_fe6_original_loop.py','s33_audit_fe6_original_loop.py'),(Path(__file__),Path(__file__).name)]:shutil.copy2(original,ev/name)
    sources=[dict(file=str(ev/'fe6_original_loop.json'),line=1),dict(file=str(ev/'fe6_original_loop_audit.json'),line=1)]
    mmio=load(ev/'mmio_documented.json');by_addr={int(r['address'],0):r for r in mmio['records']}
    fields={0xfef0020:['Read into RAMcache423F00; code compares((raw>>4)&0xFF)with0xA and dispatches on low4bits, not a physical identification proof'],0xfe800bc:['Software tests bits10..11; nonzero path supplies cache secondword0'],0xfed3000:['Software tests bits14..15; nonzero path supplies cache secondword0'],0xfed3800:['Halfword copied into RAMcache423F02 when preceding gates clear; mode producer tests low nibble']}
    for a,rows in sorted(events.items()):
        if a in new:
            loop=a not in fields
            r=dict(address=f'0x{a:08X}',namespace='soc_mmio',subsystem='fe6_original_loop_bank_physical_function_unknown'if loop else'mode_cache_input_physical_function_unknown',width_bits=16,access='/'.join(sorted({e['operation']for e in rows}))+'_halfword_di',confidence='original_guest_caller_computed_selectors_explicit_raw_inputs',hardware_verified=False,fields=[dict(meaning=s,evidence_type='software_operation',physical_meaning='unknown')for s in (['Bits12..13 from original caller argument low2; other bits cleared; selector produced by original28-iteration loop']if loop else fields[a])],observed_accesses=rows,observed_write_values=sorted({hex(e['value'])for e in rows if e['operation']=='write'}),sources=sources,evidence=['original_bytes_bound','original_mode_producer_and_caller_executed','delegating_memory_observer'],unknown=['Raw MMIO words/cache flags/caller arguments are explicit fixtures, not real ID/reset/mode/peripheral state.','Physical name, implementation, access permissions, IRQ and timing unknown.'])
            if loop:r.update(software_selector=hex((a-0xfe60000)//16),software_offset='0x0')
            mmio['records'].append(r)
        else:
            r=by_addr[a];r.setdefault('additional_original_caller_observations',[]).extend(rows);r['sources'].extend(sources)
            r.setdefault('notes',[]).append('Original23A270 caller executed with mode computed by original producer; statusbit9 explicitly seeded, not a hardware completion.')
    mmio['counts'].update(register_addresses=len(mmio['records']),direct_or_reported_accesses=len(mmio['records']));save(ev/'mmio_documented.json',mmio)
    metadata=load(out/'atlas_metadata.json');metadata.update(date='2026-10-25',parent_atlas=str(parent),parent_ledger_sha256=sha(parent/'sha256.json'),parent_ledger_files_verified=len(ledger),fe6_original_loop_new_addresses=32,fe6_original_loop_memory_events=208,fe6_original_loop_scenarios=11,fe6_original_loop_trace_identical_pairs=11,fe6_original_loop_cases=6,fe6_original_loop_writes=168,whole_physical_map_complete=False);save(out/'atlas_metadata.json',metadata)
    completion=load(out/'completion_audit.json');completion['requirements'][2]['limits']=['350 software-level MMIO addresses do not delimit the full physical universe or prove hardware semantics','Original mode producer and caller loops execute with declared raw/cache fixtures; actual physical mode/configuration unknown']
    completion['next_work']=['Expand remaining computed FE6/FF7/FFB/FFC paths and follow real producers of raw mode/cache state','Resolve remaining AUX code/data candidates and parametric families','Obtain actual BCR/SoC configuration evidence without promoting fixture values'];save(out/'completion_audit.json',completion)
    for name in ['s33_build_register_atlas.py','s33_verify_register_trace_sites.py']:subprocess.run([sys.executable,str(scripts/name),str(out)],check=True)
    subprocess.run(['/home/jack/.local/share/pipx/venvs/graphifyy/bin/python',str(scripts/'s33_build_register_graph.py'),str(out)],check=True)
    atlas=load(out/'register_map.json');assert len(atlas['records'])==611 and Counter(r['space']for r in atlas['records'])==dict(core=64,aux=197,soc_mmio=350)
    assert {(r['space'],r['number'])for r in atlas['records']}-known=={('soc_mmio',a)for a in new}
    assert len(atlas['aux_indices_with_guest_semantic_records'])==22 and len(load(out/'aux_trace_site_verification.json')['checks'])==74
    assert not atlas['goal_complete']and all(not r['hardware_verified']for r in atlas['records'])
    inputs={**d['input_hashes'],**audit['input_sha256']};assert all(sha(Path(p))==h for p,h in inputs.items());assert all(sha(parent/p)==h for p,h in ledger.items())
    save(out/'atlas_validation.json',dict(status='PASS_FE6_ORIGINAL_LOOP_INTEGRATION',total_records=611,counts=atlas['counts'],new_mmio_addresses=32,distinct_observed_addresses=34,completed_memory_events=208,selected_scenarios=11,trace_identical_pairs=11,original28_iteration_loop_cases=6,original_loop_writes=168,original_selector24_caller_completed=True,representative_aux_guest_indices=22,aux_run_pc_sites=74,parent_ledger_files_verified=len(ledger),input_sha256=inputs,gnu_original_inputs_unchanged=True,whole_physical_map_complete=False,limits=d['limits']))
    for name in ['s33_build_register_atlas.py','s33_build_register_graph.py','s33_verify_register_trace_sites.py']:shutil.copy2(scripts/name,ev/name)
    files={str(p.relative_to(out)):sha(p)for p in sorted(out.rglob('*'))if p.is_file()and p!=out/'sha256.json'};save(out/'sha256.json',files);print('PASS611records,32newMMIO,208events,11pairs; ledger',len(files));print(out)
if __name__=='__main__':main()
