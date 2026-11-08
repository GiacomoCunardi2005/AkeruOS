#!/usr/bin/env python3
"""Version the atlas with byte-bound direct MMIO observations and fixture limits."""
import argparse,hashlib,json,re,shutil,subprocess,sys
from collections import Counter,defaultdict
from datetime import datetime,timezone
from pathlib import Path
ROOT=Path(__file__).resolve().parents[1]


def sha(p):return hashlib.sha256(p.read_bytes()).hexdigest()
def load(p):return json.loads(p.read_text())
def save(p,d):p.write_text(json.dumps(d,indent=2)+'\n')


def main():
    ap=argparse.ArgumentParser(description=__doc__);ap.add_argument('--parent',type=Path,required=True);ap.add_argument('--source',type=Path,required=True);ap.add_argument('--audit',type=Path,required=True)
    args=ap.parse_args();parent=args.parent.resolve();src=args.source.resolve();audit_path=args.audit.resolve()
    ledger=load(parent/'sha256.json');assert all(sha(parent/p)==h for p,h in ledger.items())
    d=load(src/'verified_evidence.json');audit=load(audit_path)
    assert d['status']=='PASS_DIRECT_MMIO_SEQUENCE_EXTERNAL_FIXTURES'and audit['status']=='PASS_DIRECT_MMIO_BYTES_AND_STEP_TRACE_AUDIT'
    for mapping in [d['input_hashes'],audit['input_sha256']]:assert all(sha(Path(p))==h for p,h in mapping.items())
    assert all(sha(src/p)==h for p,h in d['files'].items())
    assert len(d['pairs'])==5 and all(p['trace_identical']for p in d['pairs'])
    old=load(parent/'register_map.json');known={(r['space'],r['number'])for r in old['records']}
    events=defaultdict(list)
    for c in d['cases']:
        if not c['observer_enabled']or not c['full_routine_completed']:continue
        assert c['exit_code']==0
        for e in c['completed_memory_events']:events[e['address']].append(dict(case=c['name'],**e))
    assert len(events)==22 and sum(map(len,events.values()))==483
    assert not any(('soc_mmio',a)in known for a in events)
    out=parent.parent/datetime.now(timezone.utc).strftime('%Y%m%dT%H%M%SZ');assert not out.exists();shutil.copytree(parent,out);(out/'sha256.json').unlink()
    ev=out/'evidence'
    for original,name in [(src/'verified_evidence.json','direct_mmio_sequence.json'),(audit_path,'direct_mmio_step_audit.json'),
                          (src/'original_sequence_disassembly.txt','direct_mmio_sequence_disassembly.txt'),
                          (src/'s33_verify_direct_mmio_sequence.py','s33_verify_direct_mmio_sequence.py'),
                          (src/'s33_register_step_observer.c','s33_register_step_observer.c'),
                          (src/'s33_register_memory_observer.c','s33_register_memory_observer.c'),
                          (Path(__file__).with_name('s33_audit_direct_mmio_sequence.py'),'s33_audit_direct_mmio_sequence.py'),
                          (Path(__file__),'s33_integrate_direct_mmio_sequence.py')]:shutil.copy2(original,ev/name)
    fields={0xfe20000:['Software bset bits1,2'],0xfe20008:['Firmware writes2 then4; tests bits1,4,2; bit4 transition supplied by fixture'],
            0xfe20018:['Argument6 low16'],0xfe2014c:['Software polls bits0,1,2,4; fixture initial0x17'],
            0xfe80040:['Software sets then clears bits15,0'],0xfe80144:['Software sets then clears bit2'],
            0xfe800f8:['Software sets then clears bit8'],0xfe80148:['Write1 then clear bit0'],
            0xfe80118:['Argument1 bits31:16'],0xfe8011c:['Argument1 bits15:0'],0xfe80120:['Argument2 bits15:0'],
            0xfef0348:['Write0x10 and test bit4'],0xffe40044:['Software repeat flag: writes0/1; nonzero read causes clear and repeat'],
            0xffe2014c:['Tests bit5 clear; compares(value>>13) with1/2; initial/transition values are fixture state']}
    mmio=load(ev/'mmio_documented.json')
    for address,rows in sorted(events.items()):
        mmio['records'].append(dict(address=f'0x{address:08X}',namespace='soc_mmio',subsystem='direct_configuration_sequence_unknown_physical_function',
                                   width_bits=16,access='/'.join(sorted({e['operation']for e in rows}))+'_halfword_di',
                                   confidence='original_guest_external_step_observer_explicit_fixtures',hardware_verified=False,
                                   fields=[dict(meaning=s,evidence_type='software_operation',physical_meaning='unknown')for s in fields.get(address,['Literal write sequence; hardware field meanings unknown'])],
                                   observed_accesses=rows,observed_write_values=sorted({hex(e['value'])for e in rows if e['operation']=='write'}),
                                   sources=[dict(file=str(ev/'direct_mmio_sequence.json'),line=1),dict(file=str(ev/'direct_mmio_step_audit.json'),line=1)],
                                   evidence=['original_bytes_bound','guest_execution_with_external_fixture_transitions','delegating_memory_observer'],
                                   unknown=['Physical name, reset, access permissions, timing and side effects unknown.',
                                            'High FFE and low FE are distinct modeled cells; no physical alias relationship inferred.',
                                            'Optional script values/addresses are synthetic caller data; all admitted addresses also have direct absolute source accesses.']))
    mmio['counts'].update(register_addresses=len(mmio['records']),direct_or_reported_accesses=len(mmio['records']))
    save(ev/'mmio_documented.json',mmio)
    # One representative AUX result record. The step trace emits paired result
    # lines; those are not counted as two accesses or retirement evidence.
    trace=load(ev/'firmware_aux_trace.json');pc=0x178d18;payload=d['payloads']['0']
    text_path=src/'plain_observed.trace';lines=text_path.read_text().splitlines()
    line_no,line=next((i+1,s)for i,s in enumerate(lines)if re.match(r'0x0*178d18\s+lr\b',s)and 'cr <- 0x0'in s)
    offset=payload['firmware_offset']+pc-payload['base'];fw=Path(trace['firmware_path']).read_bytes()
    event=dict(trace_line=line_no,pc=pc,pc_hex=hex(pc),operation='read',aux_index=72,aux_hex='0x48',trace_text=line,
               semantic_result_observed=True,retirement_proven_by_this_record=False,firmware_offset=offset,firmware_offset_hex=hex(offset),
               original_firmware_bytes_next8=fw[offset:offset+8].hex(),trace_value=0,trace_value_hex='0x0',
               value_meaning='Explicit synthetic DC_CTRL seed0 read by original code; representative record, not multiplicity count')
    source_elf=ROOT/'outputs/gnu_arc700/20261024T232600Z_2fcbbcac/main_source.elf'
    trace['runs'].append(dict(name='direct_mmio_plain_step_seeded',path=str(text_path),sha256=sha(text_path),
                              run_manifest=str(src/'verified_evidence.json'),run_manifest_sha256=sha(src/'verified_evidence.json'),
                              elf=str(source_elf),elf_sha256=sha(source_elf),elf_role='source_mmap_ELF_for_static_verification',
                              actual_runtime_harness_elf=str(src/'plain.elf'),actual_runtime_harness_sha256=sha(src/'plain.elf'),
                              runtime_original_code_mmap=payload,synthetic_aux48_initial='0x0',semantic_result_observed_records=[event],
                              limits=['External step/fixture frontend; paired trace lines, representative site/value record only.']))
    trace['limits']=[s for s in trace['limits']if not s.startswith('MMIO only previously established')]
    trace['limits'].append('Boot-prefix MMIO fixtures retain their original scope; isolated FE1/direct-MMIO runs use only the separate explicit fixtures declared in their manifests.')
    trace['limits'].append('Step-run DC_CTRL result uses an explicit seed; trace/profile counters are not retirement or physical cache timing evidence.')
    save(ev/'firmware_aux_trace.json',trace)
    extra=load(ev/'cpu_aux_extended.json');extra['records'].append(dict(space='aux',number=72,number_hex='0x48',name='DC_CTRL',width_bits=32,
         access='original_guest_read_explicit_seed',classification='original_guest_software_bit8_gate',hardware_verified=False,
         bit_fields=[dict(name='software_wait_until_bit8_clear',lsb=8,msb=8,physical_meaning='unknown')],
         sources=[dict(file=str(ev/'direct_mmio_sequence.json'),line=1)],
         notes=['Seed0 passes original bit8 polling; seed0x100 stays there until step budget. This is modeled storage, not measured reset/cache state.']))
    save(ev/'cpu_aux_extended.json',extra)
    metadata=load(out/'atlas_metadata.json');metadata.update(date='2026-10-25',parent_atlas=str(parent),parent_ledger_sha256=sha(parent/'sha256.json'),
        parent_ledger_files_verified=len(ledger),direct_mmio_new_addresses=22,direct_mmio_positive_events=483,direct_mmio_all_observer_events=614,
        direct_mmio_scenarios=5,direct_mmio_trace_identical_pairs=5,direct_mmio_source=str(src/'verified_evidence.json'),
        whole_physical_map_complete=False,direct_low_literal_candidates_remaining=4)
    save(out/'atlas_metadata.json',metadata)
    completion=load(out/'completion_audit.json');completion['requirements'][2]['limits']=['217software-level MMIOaddresses do not delimit the full physical universe or prove hardware semantics/timing/aliases']
    completion['next_work']=['Resolve four remaining direct low-range literal MMIO candidates and computed addresses',
                              'Resolve remaining AUX code/data candidates and parametric families',
                              'Obtain actual BCR/SoC configuration evidence without promoting fixture values']
    save(out/'completion_audit.json',completion)
    scripts=ROOT/'Python_Trace_Scripts'
    for name in ['s33_build_register_atlas.py','s33_verify_register_trace_sites.py']:subprocess.run([sys.executable,str(scripts/name),str(out)],check=True)
    subprocess.run(['/home/jack/.local/share/pipx/venvs/graphifyy/bin/python',str(scripts/'s33_build_register_graph.py'),str(out)],check=True)
    atlas=load(out/'register_map.json');assert Counter(r['space']for r in atlas['records'])==dict(core=64,aux=197,soc_mmio=217)
    assert len(atlas['records'])==478 and atlas['goal_complete']is False and all(r['hardware_verified']is False for r in atlas['records'])
    new={(r['space'],r['number'])for r in atlas['records']}-known;assert new=={('soc_mmio',a)for a in events}
    assert len(atlas['aux_indices_with_guest_semantic_records'])==21
    sites=load(out/'aux_trace_site_verification.json');assert len(sites['checks'])==66 and any(c['pc']=='0x178d18'for c in sites['checks'])
    inputs={**d['input_hashes'],**audit['input_sha256']};assert all(sha(Path(p))==h for p,h in inputs.items())
    assert all(sha(parent/p)==h for p,h in ledger.items())
    save(out/'atlas_validation.json',dict(status='PASS_DIRECT_MMIO_SEQUENCE_ATLAS_INTEGRATION',counts=atlas['counts'],total_records=478,
         previous_records=456,new_mmio_addresses=22,positive_memory_events=483,all_memory_events_including_negative_prefix=614,
         full_scenarios=3,negative_budget_scenarios=2,trace_identical_pairs=5,representative_aux_guest_indices=21,aux_run_pc_sites=66,
         direct_low_literal_candidates_remaining=4,parent_ledger_files_verified=len(ledger),input_sha256=inputs,
         gnu_original_inputs_unchanged=True,whole_physical_map_complete=False,
         limits=['Fixture transitions and negative prefixes are distinct from firmware writes and full routine completion.',
                 'Step traces duplicate memory records; low16 comparison has independent width proof. Profile counters are not retirement counts.',
                 'Virtual FFE/FE cells are modeled separately; no physical alias/reset/timing/IRQ inference.']))
    for name in ['s33_build_register_atlas.py','s33_build_register_graph.py','s33_verify_register_trace_sites.py']:shutil.copy2(scripts/name,ev/name)
    final={str(p.relative_to(out)):sha(p)for p in sorted(out.rglob('*'))if p.is_file()and p!=out/'sha256.json'};save(out/'sha256.json',final)
    print('PASS478records,22newMMIO,66AUXrun-PCsites;ledger',len(final));print(out)


if __name__=='__main__':main()
