#!/usr/bin/env python3
"""Audit numeric comparisons, original store operands and bounded DSP value flow."""
import argparse
import json
import re
import struct
import shutil
from datetime import datetime,timezone
from pathlib import Path
from s33_integrate_ffc7000_table_tail import ROOT,load,save,sha
from s33_verify_ffb_numeric_reference import reference
from s33_verify_sensor_mmio_dialog import aligned_window


def main():
    ap=argparse.ArgumentParser(description=__doc__);ap.add_argument('source',type=Path);src=ap.parse_args().source.resolve()
    d=load(src/'verified_evidence.json');assert d['status']=='PASS_FFB_INDEPENDENT_INTEGER_REFERENCE_SAMPLES'
    assert all(sha(Path(k))==v for k,v in d['input_hashes'].items()) and all(sha(src/k)==v for k,v in d['files'].items())
    parent=Path(d['parent_atlas']);ledger=load(parent/'sha256.json');assert all(sha(parent/k)==v for k,v in ledger.items())
    inputs={**d['input_hashes'],str(src/'verified_evidence.json'):sha(src/'verified_evidence.json'),str(Path(__file__)):sha(Path(__file__))}
    for q in [ROOT/'work/build-arc/binutils/objdump',ROOT/'work/build-arc/binutils/objcopy',Path(__file__).with_name('s33_verify_sensor_mmio_dialog.py')]:inputs[str(q)]=sha(q)
    info=d['payload'];body=Path(info['path']).read_bytes();base=info['base'];fw=ROOT/'OriginalSoftware_NikonS33_V1.1/firmware.bin'
    inputs[str(fw)]=sha(fw);assert body==fw.read_bytes()[info['firmware_offset']:info['firmware_offset']+len(body)] and sha(Path(info['path']))==info['sha256']
    decoded={}
    def decode(pc):
        if pc not in decoded:
            text=aligned_window(body,base,pc,pc+12);line=next(x for x in text.splitlines() if re.match(r'\s*'+f'{pc:x}:',x))
            m=re.match(r'\s*[0-9a-f]+:\s+((?:[0-9a-f]{4}\s+)+)\t(\S+)\s*(.*)',line)
            raw=b''.join(bytes.fromhex(w)[::-1] for w in m[1].split());assert raw==body[pc-base:pc-base+len(raw)]
            decoded[pc]=dict(opcode=m[2],operands=m[3].strip(),bytes_hex=raw.hex())
        return decoded[pc]
    for pc,op,operands in [(0x2e2a1a,'mov_s','r0,0x1'),(0x2e2a1c,'stb_s','r0,[sp,0x24]'),
        (0x303aec,'ldb','r0,[r13,36]'),(0x303afc,'cmp_s','r0,0x1'),(0x303b06,'bne_s','10\t;0x303b0e'),
        (0x303b08,'mov_s','r0,0'),(0x303b0a,'mov_s','r2,r0'),(0x303b0c,'b_s','26\t;0x303b26'),
        (0x303d36,'ld_s','r0,[sp,0x18]'),(0x303d3c,'stw_s','r0,[r13,0x2a]'),
        (0x303d3e,'ld_s','r0,[sp,0x1c]'),(0x303d40,'stw_s','r0,[r13,0x2c]')]:
        assert (decode(pc)['opcode'],decode(pc)['operands'])==(op,operands)
    assert decode(0x303ae8)['opcode']==decode(0x303af8)['opcode']=='muldw'
    assert decode(0x303ade)['opcode']=='sr' and decode(0x303ade)['operands']=='0,[aux_macmode]'
    offsets=set();events_expected=[]
    for slot in d['slots']:
        pc=slot['source_pc'];ins=decode(pc);assert ins['opcode']=='ldh'
        offset=int(re.fullmatch(r'r0,\[sp,(\d+)\]',ins['operands'])[1]);assert offset==slot['structure_offset'];offsets.add(offset)
        store=slot['store_pc'];assert decode(store)['opcode']=='sth.di'
        assert struct.unpack_from('<I',body,store-4-base)[0]==slot['address']
    assert len(offsets)==38 and not offsets&{42,44}
    checks=[];dsp_checks=[]
    for c in d['cases']:
        assert c['exit_code']==0 and c['fault'] is None
        fields=c['fields'];prediction=reference(fields);assert prediction=={int(k):v for k,v in c['predicted_output_by_offset'].items()}
        raw_input=(src/c['input_file']).read_bytes();assert list(struct.unpack('<6H9B',raw_input))==fields
        if not c['observer_enabled']:continue
        trace_path=src/(c['name']+'.trace');trace=trace_path.read_text();inputs[str(trace_path)]=sha(trace_path)
        assert trace_path.read_bytes()==(src/(c['name'].replace('_observed','_reference')+'.trace')).read_bytes()
        helper_writes={};path=[];mode_writes=[];entries=[]
        for line in trace.splitlines():
            m=re.match(r'0x([0-9a-f]+)\s+(\S+)\s+(.*)',line)
            if not m:continue
            pc=int(m[1],16);op=m[2]
            if pc in [0x2e29b4,0x303a40]:entries.append(pc)
            if pc in [0x303aec,0x303b06,0x303b08,0x303b0a,0x303b0c,0x303b0e,0x303b10,0x303b26]:path.append(pc)
            if pc==0x303ade:
                assert op=='sr' and re.search(r'auxr <- 0x0$',line);mode_writes.append(0)
            z=re.match(r'0x([0-9a-f]+)\s+stw(?:_s)?\s+[^,]+,\[r13,(0x[0-9a-f]+|\d+)\].*?memory <- (0x[0-9a-f]+)',line)
            if z and 0x303a40<=pc<0x303d4c:
                assert decode(pc)['opcode'] in ['sth','stw_s'];offset=int(z[2],0)
                assert offset not in helper_writes;helper_writes[offset]=int(z[3],16)&65535
        assert entries==[0x2e29b4,0x303a40] and mode_writes==[0]
        assert path==[0x303aec,0x303b06,0x303b08,0x303b0a,0x303b0c,0x303b26]
        x,y=prediction[38],prediction[40]
        expected_local={**prediction,42:(x*fields[0])&65535,44:(y*fields[1])&65535,46:fields[4],48:fields[5],126:fields[0]-1,128:fields[1]-1}
        assert len(expected_local)==44 and helper_writes==expected_local
        expected=[(s['store_pc'],'write',s['address'],prediction[s['structure_offset']]) for s in d['slots']]
        err=src/(c['name']+'.stderr.log');inputs[str(err)]=sha(err)
        raw=[json.loads(line.removeprefix('S33_MEM ')) for line in err.read_text().splitlines() if line.startswith('S33_MEM ')]
        done=[e for e in raw if e['stage']=='result'];assert done==c['completed_memory_events'] and len(raw)==76
        assert [(e['pc'],e['operation'],e['address'],e['value']) for e in done]==expected
        for b,e in zip(raw[::2],raw[1::2]):
            assert b['stage']=='begin' and e['stage']=='result' and b['width_bytes']==e['width_bytes']==2
            assert all(b[k]==e[k] for k in ['id','pc','operation','address'])
        products=[]
        for line in err.read_text().splitlines():
            m=re.fullmatch(r'S33_DSP_LAB pc=([0-9a-f]+) word=([0-9a-f]+) left=([0-9a-f]+) right=([0-9a-f]+) r56=([0-9a-f]+) r57=([0-9a-f]+) provisional=1',line)
            if m:products.append(tuple(int(v,16) for v in m.groups()))
        assert products==[(0x303ae8,0x2f0c103e,x,fields[0],0,x*fields[0]),(0x303af8,0x2e0c14fe,y,fields[1],0,y*fields[1])]
        dsp_checks.append(dict(case=c['name'],products=products,provisional=True,product_outputs_not_copied_offsets=[42,44]))
        for key,f in c['fixtures'].items():
            a=int(key,0);slot=next(s for s in d['slots'] if s['address']==a);after=(src/f['file']).read_bytes();off=a%8
            assert struct.unpack_from('<H',after,off)[0]==prediction[slot['structure_offset']]
            assert all(after[j]==0xa5 for j in range(8) if j not in [off,off+1])
        checks.append(dict(case=c['name'],output_comparisons=38,helper_local_halfword_comparisons=44,mode65_write=0,original_flag36=1))
    assert len(checks)==8
    assert all(sha(Path(k))==v for k,v in inputs.items()) and all(sha(parent/k)==v for k,v in ledger.items())
    out=ROOT/'Risultati/Processor_Register_FFB_Numeric'/datetime.now(timezone.utc).strftime('%Y%m%dT%H%M%SZ');out.mkdir(parents=True,exist_ok=False)
    for p in [Path(__file__),Path(__file__).with_name('s33_verify_ffb_numeric_reference.py')]:shutil.copy2(p,out/p.name)
    save(out/'verified_evidence.json',dict(status='PASS_FFB_NUMERIC_REFERENCE_AND_BOUNDED_VALUE_FLOW',date='2026-10-25',source_manifest=str(src/'verified_evidence.json'),
        parent_atlas=str(parent),parent_ledger_files_verified=len(ledger),historical_output_comparisons=152,new_output_comparisons=304,total_output_comparisons=456,
        new_original_local_halfword_comparisons=352,checks=checks,dsp_model_checks=dsp_checks,independently_redecoded_instructions={hex(k):v for k,v in decoded.items()},
        input_sha256=inputs,atlas_modified=False,new_register_addresses=0,full_mathematics_domain_proven=False,physical_DSP_semantics_proven=False,
        value_flow_scope='Fororiginalwrapperflag36=1andselectedcompletedruns,DSPproducts storedat42/44 are excludedfrom38MMIOcopyslots;doesnotproveabsenceofphysicalinstructioneffects.',
        hardware_access=False,gnu_modified=False,limits=d['limits']))
    save(out/'sha256.json',{p.name:sha(p) for p in sorted(out.iterdir()) if p.is_file()})
    print('PASS456outputcomparisons/352localhalfwords;16provisionalDSPproducts;atlas unchanged');print(out)


if __name__=='__main__':main()
