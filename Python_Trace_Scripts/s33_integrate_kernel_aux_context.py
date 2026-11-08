#!/usr/bin/env python3
"""Audit context-prefix AUX transport and preserve prior atlas coverage."""
import argparse,json,re,struct,shutil,subprocess,sys
from collections import Counter
from datetime import datetime,timezone
from pathlib import Path
from s33_integrate_ffc7000_table_tail import ROOT,load,save,sha,geometry
from s33_trace_state_dispatch import verified_payloads
from s33_verify_sensor_mmio_dialog import aligned_window


def main():
    ap=argparse.ArgumentParser(description=__doc__);ap.add_argument('source',type=Path);src=ap.parse_args().source.resolve()
    d=load(src/'verified_evidence.json');assert d['status']=='PASS_ORIGINAL_KERNEL_AUX_CONTEXT_PREFIX'
    parent=Path(d['parent_atlas']);ledger=load(parent/'sha256.json');assert all(sha(parent/k)==v for k,v in ledger.items())
    inputs={**d['input_hashes'],str(src/'verified_evidence.json'):sha(src/'verified_evidence.json'),str(Path(__file__)):sha(Path(__file__))}
    assert all(sha(Path(k))==v for k,v in inputs.items()) and all(sha(src/k)==v for k,v in d['files'].items())
    blocks,payloads,directory=verified_payloads(ROOT);body=payloads[0];base=blocks[0]['load_address_candidate'];fw=ROOT/'OriginalSoftware_NikonS33_V1.1/firmware.bin'
    fw_bytes=fw.read_bytes();fw_off=fw_bytes.find(body);assert fw_off>=0 and fw_bytes.find(body,fw_off+1)<0
    decoded={}
    def decode(pc):
        if pc not in decoded:
            text=aligned_window(body,base,pc,pc+12);line=next(x for x in text.splitlines() if re.match(r'\s*'+f'{pc:x}:',x))
            m=re.match(r'\s*[0-9a-f]+:\s+((?:[0-9a-f]{4}\s+)+)\t(\S+)\s*(.*)',line)
            raw=b''.join(bytes.fromhex(w)[::-1] for w in m[1].split());assert raw==body[pc-base:pc-base+len(raw)]
            decoded[pc]=dict(opcode=m[2],operands=m[3].strip(),bytes_hex=raw.hex())
        return decoded[pc]
    for pc,op,operands in [(0xb2e12,'ld','r0,[r3,108]'),(0xb2e16,'and.f','0,r0,0x8'),(0xb2e1a,'bne','1280\t;0xb3318'),
        (0xb3318,'ld','r0,[r2,36]'),(0xb3320,'beq.d','64\t;0xb3360'),(0xb3324,'ld','r10,[r0,200]'),
        (0xb3328,'sub.f','0,r3,r0'),(0xb332c,'beq','-1294\t;0xb2e1e'),(0xb3330,'ld','r11,[r0,108]'),
        (0xb333c,'and.f','0,r11,0x20000'),(0xb3358,'or','r11,r11,256'),(0xb335c,'st','r11,[r0,108]'),
        (0xb3364,'st','r3,[r2,36]'),(0xb3368,'and.f','0,r12,0x100'),(0xb3380,'and.f','0,r12,0x20000'),
        (0xb339c,'bic','r12,r12,256'),(0xb33a4,'st','r12,[r3,108]')]:
        assert (decode(pc)['opcode'],decode(pc)['operands'])==(op,operands)
    sites={0xb3334:('read',47),0xb3348:('read',50),0xb3350:('read',51),0xb337c:('write',47),0xb3390:('write',50),0xb3398:('write',51)}
    for pc,(op,index) in sites.items():
        assert decode(pc)['opcode']==('lr' if op=='read' else 'sr') and f'[{hex(index)}]' in decode(pc)['operands']
    checks=[];guest_runs=[];events_total=[];null_reads=[]
    for c in d['cases']:
        before=bytes.fromhex(c['fixture_before']);expected=bytearray(before);start=0x700000;incoming=start+0x400
        def word(a):return struct.unpack_from('<I',before,a-start)[0]
        def store(a,v):struct.pack_into('<I',expected,a-start,v)
        current=word(start+36);flags=word(incoming+108);ev=[]
        if flags&8 and current!=incoming:
            if current:
                buf=word(current+200);oldflags=word(current+108)
                for n,index in enumerate([47,50,51][:3 if oldflags&0x20000 else 1]):
                    pc=[0xb3334,0xb3348,0xb3350][n];v=c['seed_aux_values'][n];ev.append((pc,'read',index,v));store(buf+4*n,v)
                store(current+108,oldflags|0x100)
            store(start+36,incoming)
            if flags&0x100:
                buf=word(incoming+200)
                for n,index in enumerate([47,50,51][:3 if flags&0x20000 else 1]):ev.append(([0xb337c,0xb3390,0xb3398][n],'write',index,word(buf+4*n)))
            store(incoming+108,flags&~0x100)
        assert bytes(expected)==(src/c['fixture']).read_bytes()==bytes.fromhex(c['fixture_after'])
        trace_path=src/(c['name']+'.trace');inputs[str(trace_path)]=sha(trace_path);text=trace_path.read_text();records=[];actual=[]
        for line_n,line in enumerate(text.splitlines(),1):
            m=re.match(r'0x([0-9a-f]+)\s+(lr|sr)\s+.*?<- (0x[0-9a-f]+)',line)
            if m and int(m[1],16) in sites:
                pc=int(m[1],16);op,index=sites[pc];v=int(m[3],16);actual.append((pc,op,index,v));fo=fw_off+pc-base
                records.append(dict(trace_line=line_n,pc=pc,pc_hex=hex(pc),operation=op,aux_index=index,aux_hex=hex(index),trace_text=line,
                    semantic_result_observed=True,retirement_proven_by_this_record=False,firmware_offset=fo,firmware_offset_hex=hex(fo),
                    original_firmware_bytes_next8=fw_bytes[fo:fo+8].hex(),trace_value=v,trace_value_hex=hex(v),
                    value_meaning='Declared model AUX seed or restore operand;not Nikon reset state,physicalreadorpost-SRmeasurement'))
        assert actual==ev==[tuple(e) for e in c['actual_aux_events']]
        err=src/(c['name']+'.stderr.log');inputs[str(err)]=sha(err)
        assert c['exit_code']==5 and c['fault'] is None and 'first=000b2e22 operation=decoder_fetch' in err.read_text()
        assert not c['complete_scheduler_switch']
        if not current and flags&8:
            assert c['null_delay_input_kind']=='declared_guest_harness_store'
            assert re.search(r'0x0*b3324\s+ld\s+.*?<- '+hex(c['null_delay_value'])+r'\b',text)
            null_reads.append(dict(case=c['name'],pc='0xb3324',address='0xc8',value=hex(c['null_delay_value'])))
        events_total.extend(ev);checks.append(dict(case=c['name'],AUX_events=len(ev),whole_RAM_fixture_bytes_checked=len(before),declared_boundary=True))
        if records:guest_runs.append((c,trace_path,records))
    assert len(checks)==16 and len(events_total)==32 and len(null_reads)==4 and len(guest_runs)==10
    assert Counter(e[1] for e in events_total)==dict(read=16,write=16)
    for chunk in d['original_chunks']:
        a,n=chunk['base'],chunk['size'];p=src/f'original_{a:x}.bin';assert sha(p)==chunk['sha256'] and p.read_bytes()==body[a-base:a-base+n]
    aliases=[dict(index='0x2f',name='aux_fbf_store_16',applicability='ARC_OPCODE_ARC600'),
        dict(index='0x32',name='aux_crc_poly',applicability='ARC_OPCODE_NONE'),dict(index='0x33',name='aux_crc_mode',applicability='ARC_OPCODE_NONE')]
    regs=ROOT/'work/binutils-2.45/opcodes/arc-regs.h';inputs[str(regs)]=sha(regs)
    for a in aliases:assert re.search(r'DEF\s*\(\s*'+a['index']+r',\s*'+a['applicability']+r',\s*NONE,\s*'+a['name']+r'\)',regs.read_text())
    audit=dict(status='PASS_KERNEL_AUX_CONTEXT_PREFIX_AUDIT',date='2026-10-25',checks=checks,events=32,reads=16,writes=16,new_aux_indices=[47,50,51],
        null_delay_reads=null_reads,toolchain_aliases_not_nikon_names=aliases,independently_redecoded_instructions={hex(k):v for k,v in decoded.items()},
        input_sha256=inputs,hardware_access=False,physical_semantics_proven=False,complete_scheduler_switch=False,limits=d['limits'])
    save(src/'kernel_context_independent_audit.json',audit)
    old=load(parent/'register_map.json');known={(r['space'],r['number']) for r in old['records']};assert all(('aux',i) not in known for i in [47,50,51])
    out=parent.parent/datetime.now(timezone.utc).strftime('%Y%m%dT%H%M%SZ');assert not out.exists();shutil.copytree(parent,out);(out/'sha256.json').unlink()
    save(out/'atlas_validation.json',dict(status='INCOMPLETE_KERNEL_AUX_CONTEXT'));evdir=out/'evidence';scripts=ROOT/'Python_Trace_Scripts'
    for original,name in [(src/'verified_evidence.json','kernel_aux_context_cpu.json'),(src/'kernel_context_independent_audit.json','kernel_aux_context_audit.json'),
        (src/'original_windows.txt','kernel_aux_context_disassembly.txt'),(scripts/'s33_verify_kernel_aux_context.py','s33_verify_kernel_aux_context.py'),(Path(__file__),Path(__file__).name)]:shutil.copy2(original,evdir/name)
    aux=load(evdir/'aux_firmware_expansion.json')
    for index in [47,50,51]:
        aux['documented_register_sites'].append(dict(index=hex(index),name=f'KERNEL_AUX_{index:02X}_PHYSICAL_UNKNOWN',pcs=[hex(pc) for pc,(op,i) in sites.items() if i==index],
            proof='Originalkernelcontextprefix CPU accesses andRAMsave/restore checked under declared32bitAUXseeds;not architectural namingorphysicalproof',
            kernel_context_proof=str(evdir/'kernel_aux_context_audit.json')))
    save(evdir/'aux_firmware_expansion.json',aux)
    sourceelf=evdir/'kernel_context_source.elf';chunk=next(c for c in d['original_chunks'] if c['base']==0xb3318);payload=src/'original_b3318.bin'
    subprocess.run([str(ROOT/'work/build-arc/binutils/objcopy'),'-I','binary','-O','elf32-littlearc','-B','arc','--rename-section','.data=.text,alloc,load,readonly,code,contents',
        '--change-section-vma','.data=0xb3318','--strip-all',str(payload),str(sourceelf)],check=True,capture_output=True)
    info=dict(base=0xb3318,size=chunk['size'],path=str(payload),sha256=sha(payload),firmware_offset=fw_off+0xb3318-base)
    trace=load(evdir/'firmware_aux_trace.json');oldruns=list(trace['runs'])
    for c,path,records in guest_runs:
        elf=src/(c['name']+'.elf')
        trace['runs'].append(dict(name='kernel_context_'+c['name'],path=str(path),sha256=sha(path),run_manifest=str(src/'verified_evidence.json'),
            run_manifest_sha256=sha(src/'verified_evidence.json'),elf=str(sourceelf),elf_sha256=sha(sourceelf),elf_role='source_mmap_ELF_for_static_verification',
            actual_runtime_harness_elf=str(elf),actual_runtime_harness_sha256=sha(elf),runtime_original_code_mmap=info,
            semantic_result_observed_records=records,limits=d['limits']))
    indices=sorted({e['aux_index'] for r in trace['runs'] for e in r['semantic_result_observed_records']});assert len(indices)==25
    trace['distinct_aux_indices']=len(indices);trace['distinct_aux_hex']=list(map(hex,indices));save(evdir/'firmware_aux_trace.json',trace)
    metadata=load(out/'atlas_metadata.json');metadata.update(date='2026-10-25',parent_atlas=str(parent),parent_ledger_sha256=sha(parent/'sha256.json'),
        parent_ledger_files_verified=len(ledger),kernel_context_new_aux_indices=[47,50,51],kernel_context_prefix_scenarios=16,kernel_context_new_guest_events=32,
        kernel_context_physical_names_proven=False,whole_physical_map_complete=False);save(out/'atlas_metadata.json',metadata)
    completion=load(out/'completion_audit.json');completion.update(prior_turn_classification='progress',goal_complete=False)
    completion['requirements'][1]['limits'].append('Three lowAUXindices qualified throughoriginalkernelprefix;Nikon CRC/FBF naming andphysicalimplementation notproven')
    completion['next_work']=['Other AUXcode/datacandidates outsidequalifiedwindows andruntime-dependentindices','BCR/SoCimplementation andDSPphysicalsemantics',
        'OtherMMIOgroups andactualcallerconstraints;wholephysicalmapunproven'];save(out/'completion_audit.json',completion)
    for name in ['s33_build_register_atlas.py','s33_verify_register_trace_sites.py']:subprocess.run([sys.executable,str(scripts/name),str(out)],check=True)
    subprocess.run(['/home/jack/.local/share/pipx/venvs/graphifyy/bin/python',str(scripts/'s33_build_register_graph.py'),str(out)],check=True)
    atlas=load(out/'register_map.json');keys={(r['space'],r['number']) for r in atlas['records']};by_key={(r['space'],r['number']):r for r in atlas['records']}
    assert Counter(r['space'] for r in atlas['records'])==dict(core=64,aux=200,soc_mmio=915) and len(keys)==1179
    assert keys-known=={('aux',i) for i in [47,50,51]} and known<=keys and not atlas['goal_complete']
    def relocate(v):
        if isinstance(v,str):return v.replace(str(parent),str(out))
        if isinstance(v,list):return [relocate(x) for x in v]
        if isinstance(v,dict):return {k:relocate(x) for k,x in v.items()}
        return v
    for before in old['records']:
        after=by_key[before['space'],before['number']]
        assert after==(relocate(before) if before['space']=='aux' else before)
    for k in ['mmio_transfer_windows','mmio_window_overlaps','computed_mmio_families']:assert atlas[k]==old[k]
    assert all(not r['hardware_verified'] for r in atlas['records']) and trace['runs'][:len(oldruns)]==oldruns
    assert len(load(out/'aux_trace_site_verification.json')['checks'])==204 and len(atlas['aux_indices_with_guest_semantic_records'])==25
    for i in [47,50,51]:assert by_key['aux',i]['firmware_observed'] and by_key['aux',i]['firmware_static_access_confirmed']
    historical=[];geo={geometry(w) for w in atlas['mmio_transfer_windows']}
    for directory in sorted(parent.parent.iterdir()):
        if directory==out or not(directory/'atlas_validation.json').is_file() or not(directory/'sha256.json').is_file():continue
        if not load(directory/'atlas_validation.json').get('status','').startswith('PASS'):continue
        ld=load(directory/'sha256.json');assert all(sha(directory/k)==v for k,v in ld.items());prior=load(directory/'register_map.json')
        pk={(r['space'],r['number']) for r in prior['records']};pg={geometry(w) for w in prior.get('mmio_transfer_windows',[])};assert pk<=keys and pg<=geo
        historical.append(dict(path=str(directory),record_count=len(pk),window_geometry_count=len(pg),missing_in_merged_atlas=0,missing_window_geometries=0,
            ledger_sha256=sha(directory/'sha256.json'),ledger_files_verified=len(ld)))
    history=load(parent/'coverage_lineage_audit.json');history.update(historical_atlases=historical,union_records=len(keys),latest_parent_atlas=str(parent),
        latest_new_addresses=[],latest_new_aux_indices=list(map(hex,[47,50,51])),latest_new_window_count=0,latest_transfer_cell_addresses=[]);save(out/'coverage_lineage_audit.json',history)
    assert all(sha(Path(k))==v for k,v in inputs.items()) and all(sha(parent/k)==v for k,v in ledger.items())
    save(out/'atlas_validation.json',dict(status='PASS_KERNEL_CONTEXT_AUX_NO_COVERAGE_REGRESSION',total_records=1179,counts=atlas['counts'],new_aux_indices=[47,50,51],
        prefix_scenarios=16,guest_aux_events=32,reads=16,writes=16,guest_aux_indices=25,aux_run_pc_sites=204,null_delay_read_cases=4,
        historical_atlases_verified=len(historical),parent_ledger_files_verified=len(ledger),input_sha256=inputs,
        complete_scheduler_switch=False,whole_physical_map_complete=False,gnu_original_inputs_unchanged=True,limits=d['limits']))
    for name in ['s33_build_register_atlas.py','s33_build_register_graph.py','s33_verify_register_trace_sites.py']:shutil.copy2(scripts/name,evdir/name)
    save(out/'sha256.json',{str(p.relative_to(out)):sha(p) for p in sorted(out.rglob('*')) if p.is_file() and p!=out/'sha256.json'})
    print('PASS1179records,+3AUX,25guestindices/204sites,32events;prioratlases',len(historical));print(out)


if __name__=='__main__':main()
