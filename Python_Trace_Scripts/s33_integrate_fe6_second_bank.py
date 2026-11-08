#!/usr/bin/env python3
"""Version the atlas with the second FE6 bounded bank and original caller evidence."""
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
    d=load(src/'verified_evidence.json');audit=load(audit_path);assert d['status']=='PASS_FE6_SECOND_BANK_AND_ORIGINAL_CALLER'and audit['status']=='PASS_FE6_SECOND_BANK_BYTE_TRACE_DOMAIN_AUDIT'
    for mapping in[d['input_hashes'],audit['input_sha256']]:assert all(sha(Path(p))==h for p,h in mapping.items())
    assert all(sha(src/p)==h for p,h in d['files'].items());old=load(parent/'register_map.json');known={(r['space'],r['number'])for r in old['records']};events=defaultdict(list)
    for c in d['cases']:
        if c['observer_enabled']:
            assert c['exit_code']==0 and c['full_selected_paths_completed']
            for e in c['completed_memory_events']:events[e['address']].append(dict(case=c['name'],**e))
    new={a for a in events if('soc_mmio',a)not in known};assert len(events)==80 and len(new)==76 and sum(map(len,events.values()))==540
    out=parent.parent/datetime.now(timezone.utc).strftime('%Y%m%dT%H%M%SZ');assert not out.exists();shutil.copytree(parent,out);(out/'sha256.json').unlink();ev=out/'evidence';scripts=ROOT/'Python_Trace_Scripts'
    for original,name in[(src/'verified_evidence.json','fe6_second_bank.json'),(audit_path,'fe6_second_bank_audit.json'),(src/'original_windows.txt','fe6_second_bank_disassembly.txt'),(src/'s33_verify_fe6_second_bank.py','s33_verify_fe6_second_bank.py'),(scripts/'s33_audit_fe6_second_bank.py','s33_audit_fe6_second_bank.py'),(Path(__file__),Path(__file__).name)]:shutil.copy2(original,ev/name)
    sources=[dict(file=str(ev/'fe6_second_bank.json'),line=1),dict(file=str(ev/'fe6_second_bank_audit.json'),line=1)]
    fields={0:['Full writer composes bits0..1 and10..15; other bits cleared','Separate RMW replaces bits10..15, preserves0..9'],4:['Conditional setter changes bit8 only; argument1 sets, other argument values clear','Separate getter returns value&0x200, not normalized and not the bit8 setter state'],8:['Argumentr2 low16 written','Special2C6928 writesr1 low16 only for selectors4A/4C'],12:['Bit15 from argumentr1 bit0; bits0..13 fromr3; bit14zero']}
    mmio=load(ev/'mmio_documented.json');by_addr={int(r['address'],0):r for r in mmio['records']}
    for a,rows in sorted(events.items()):
        if a in new:
            selector=(a-0xfe64000)//16;offset=(a-0xfe64000)%16;assert selector in list(range(52,62))+list(range(68,77))and offset in fields
            mmio['records'].append(dict(address=f'0x{a:08X}',namespace='soc_mmio',subsystem='fe6_second_computed_bank_physical_function_unknown',width_bits=16,access='/'.join(sorted({e['operation']for e in rows}))+'_halfword_di',confidence='original_guest_bounded_domain_and_higher_caller_explicit_fixtures',hardware_verified=False,software_selector=hex(selector),software_offset=hex(offset),fields=[dict(meaning=s,evidence_type='software_operation',physical_meaning='unknown')for s in fields[offset]],observed_accesses=rows,observed_write_values=sorted({hex(e['value'])for e in rows if e['operation']=='write'}),sources=sources,evidence=['original_bytes_bound','19selector_software_domain_exercised','original239F2C_higher_caller_completed','delegating_memory_observer'],unknown=['Physical name, implementation, reset, access permissions, IRQ and timing unknown.','Raw words/cache/flags/caller arguments and statusbit9 are explicit fixtures.','The higher caller uses offsets0/4; offsets8/C are supported by isolated original helpers, not that caller.']))
        else:
            r=by_addr[a];r.setdefault('additional_original_caller_observations',[]).extend(rows);r['sources'].extend(sources)
    mmio['counts'].update(register_addresses=len(mmio['records']),direct_or_reported_accesses=len(mmio['records']));save(ev/'mmio_documented.json',mmio)
    metadata=load(out/'atlas_metadata.json');metadata.update(date='2026-10-25',parent_atlas=str(parent),parent_ledger_sha256=sha(parent/'sha256.json'),parent_ledger_files_verified=len(ledger),fe6_second_bank_new_addresses=76,fe6_second_bank_memory_events=540,fe6_second_bank_scenarios=4,fe6_second_bank_trace_identical_pairs=4,fe6_second_bank_valid_selectors=d['valid_selectors'],fe6_second_bank_invalid_selectors=d['invalid_selectors_tested'],fe6_second_bank_original_higher_calls=19,whole_physical_map_complete=False);save(out/'atlas_metadata.json',metadata)
    completion=load(out/'completion_audit.json');completion['requirements'][2]['limits']=['426 software-level MMIO addresses do not delimit the physical universe or prove hardware semantics','The second FE6 bank is covered over19 bounded selector inputs, with original higher caller executed for offsets0/4; actual camera runtime arguments and physical implementation unknown']
    completion['next_work']=['Expand the remaining FE6 control paths and computed FF7/FFB/FFC families','Resolve remaining AUX code/data candidates and parametric families','Obtain actual BCR/SoC configuration evidence without promoting fixture values'];save(out/'completion_audit.json',completion)
    for name in['s33_build_register_atlas.py','s33_verify_register_trace_sites.py']:subprocess.run([sys.executable,str(scripts/name),str(out)],check=True)
    subprocess.run(['/home/jack/.local/share/pipx/venvs/graphifyy/bin/python',str(scripts/'s33_build_register_graph.py'),str(out)],check=True)
    atlas=load(out/'register_map.json');assert len(atlas['records'])==687 and Counter(r['space']for r in atlas['records'])==dict(core=64,aux=197,soc_mmio=426)
    assert {(r['space'],r['number'])for r in atlas['records']}-known=={('soc_mmio',a)for a in new}
    assert len(atlas['aux_indices_with_guest_semantic_records'])==22 and len(load(out/'aux_trace_site_verification.json')['checks'])==74
    assert not atlas['goal_complete']and all(not r['hardware_verified']for r in atlas['records']);inputs={**d['input_hashes'],**audit['input_sha256']}
    assert all(sha(Path(p))==h for p,h in inputs.items());assert all(sha(parent/p)==h for p,h in ledger.items())
    save(out/'atlas_validation.json',dict(status='PASS_FE6_SECOND_BANK_INTEGRATION',total_records=687,counts=atlas['counts'],new_mmio_addresses=76,distinct_observed_addresses=80,completed_memory_events=540,selected_scenarios=4,trace_identical_pairs=4,valid_selectors_exercised=19,invalid_selectors_exercised=8,original_higher_caller_invocations=19,original_calls_across_unique_scenarios=387,representative_aux_guest_indices=22,aux_run_pc_sites=74,parent_ledger_files_verified=len(ledger),input_sha256=inputs,gnu_original_inputs_unchanged=True,whole_physical_map_complete=False,limits=d['limits']))
    for name in['s33_build_register_atlas.py','s33_build_register_graph.py','s33_verify_register_trace_sites.py']:shutil.copy2(scripts/name,ev/name)
    files={str(p.relative_to(out)):sha(p)for p in sorted(out.rglob('*'))if p.is_file()and p!=out/'sha256.json'};save(out/'sha256.json',files);print('PASS687records,76newMMIO,540events,4pairs; ledger',len(files));print(out)
if __name__=='__main__':main()
