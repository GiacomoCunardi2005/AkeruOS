#!/usr/bin/env python3
"""Independent bitwise audit of original TBIB FED20 calls and atlas extension."""
import argparse,json,re,struct,shutil,subprocess,sys
from collections import Counter,defaultdict
from datetime import datetime,timezone
from pathlib import Path
from s33_integrate_ffc7000_table_tail import ROOT,load,save,sha,geometry
from s33_verify_sensor_mmio_dialog import aligned_window
from s33_verify_tbib_fed20 import SPECS


def main():
    ap=argparse.ArgumentParser(description=__doc__);ap.add_argument('source',type=Path);src=ap.parse_args().source.resolve()
    d=load(src/'verified_evidence.json');assert d['status']=='PASS_ORIGINAL_TBIB_FED20_ACCESSORS'
    parent=Path(d['parent_atlas']);ledger=load(parent/'sha256.json');assert all(sha(parent/k)==v for k,v in ledger.items())
    inputs={**d['input_hashes'],str(src/'verified_evidence.json'):sha(src/'verified_evidence.json'),str(Path(__file__)):sha(Path(__file__))}
    assert all(sha(Path(k))==v for k,v in inputs.items()) and all(sha(src/k)==v for k,v in d['files'].items())
    fw=ROOT/'OriginalSoftware_NikonS33_V1.1/firmware.bin';raw=fw.read_bytes();info=d['payload'];body=Path(info['path']).read_bytes();base=info['base']
    assert body==raw[0x7c:0x7c+info['size']] and sha(Path(info['path']))==info['sha256']
    assert sum(x[0] for x in struct.iter_unpack('<I',body))&0xffffffff==info['checksum']
    for q in [ROOT/'work/build-arc/binutils/objdump',ROOT/'work/build-arc/binutils/objcopy',Path(__file__).with_name('s33_verify_sensor_mmio_dialog.py')]:inputs[str(q)]=sha(q)
    decoded={}
    def decode(pc):
        if pc not in decoded:
            text=aligned_window(body,base,pc,pc+12);line=next(x for x in text.splitlines() if re.match(r'\s*'+f'{pc:x}:',x))
            m=re.match(r'\s*[0-9a-f]+:\s+((?:[0-9a-f]{4}\s+)+)\t(\S+)\s*(.*)',line)
            b=b''.join(bytes.fromhex(w)[::-1] for w in m[1].split());assert b==body[pc-base:pc-base+len(b)]
            decoded[pc]=dict(opcode=m[2],operands=m[3].strip(),bytes_hex=b.hex())
        return decoded[pc]
    def exact(pc,op,args):assert (decode(pc)['opcode'],decode(pc)['operands'])==(op,args),(hex(pc),decode(pc))
    # Check the source contracts, including inverse flag polarity and return slots.
    for e,kind,a,bit in SPECS:
        exact(e,'push_s','blink')
        if kind in ['toggle','inverse_toggle']:
            exact(e+4,'cmp_s','r0,0');exact(e+6,'beq.d',f'32\t;{hex(e+36)}');exact(e+10,'mov_s',f'r1,{hex(bit) if bit else "0"}')
            exact(e+24,'bclr' if kind=='inverse_toggle' else 'bset','r10,r10,r1')
            exact(e+40,'bset' if kind=='inverse_toggle' else 'bclr','r10,r10,r1')
        elif kind=='set':exact(e+4,'mov_s',f'r0,{hex(bit) if bit else "0"}');exact(e+16,'bset','r10,r10,r0')
        elif kind=='masked_split':
            exact(e+20,'and','r0,r0,0xffff000f');exact(e+28,'and','r1,r16,0xfff0');exact(e+36,'or_s','r0,r0,r1');exact(e+46,'lsr','r14,r16,0x10')
        elif kind=='split':exact(e+8,'extw_s','r0,r0');exact(e+22,'lsr_s','r13,r13,0x10')
        elif kind=='bit':
            exact(e+22 if bit else e+20,'bmsk_s','r0,r0,0')
            if bit:exact(e+16,'lsr_s','r0,r0' if bit==1 else f'r0,r0,{hex(bit)}')
        elif kind=='or_mask':exact(e+20,'bic_s','r0,r0,r14');exact(e+22,'or_s','r14,r14,r0')
        elif kind=='clear_mask':exact(e+20,'bic_s','r0,r0,r14')
    # Fixed literal bindings are audited by pool values plus actual callback address.
    rows=defaultdict(list);operations=defaultdict(dict);checks=[];counts=Counter();pool_checks=[];read48_results=[]
    for case in d['cases']:
        assert case['exit_code']==0 and case['fault'] is None and case['original_calls_completed']
        if not case['observer_enabled']:continue
        trace_path=src/(case['name']+'.trace');inputs[str(trace_path)]=sha(trace_path);trace=trace_path.read_text()
        assert trace_path.read_bytes()==(src/(case['name'].replace('_observed','_reference')+'.trace')).read_bytes()
        assembly=(src/(case['name'].removesuffix('_observed')+'.s')).read_text()
        state={int(a,0):struct.unpack_from('<H',bytes.fromhex(f['before']),int(a,0)%8)[0] for a,f in case['fixtures'].items()}
        expected=[];entries=[];return_checks=0;buffer={};call_specs=[]
        for c,(e,kind,a,bit) in zip(case['original_calls'],SPECS):
            assert (int(c['entry'],0),c['kind'],int(c['address'],0),c['bit'])==(e,kind,a,bit)
            args=c['arguments'];v=case['value'];ret=None;ret1=None;ev=[]
            def rd(pc,aa):ev.append((pc,'read',aa,state[aa]));return state[aa]
            def wr(pc,aa,value):state[aa]=value&65535;ev.append((pc,'write',aa,state[aa]))
            if kind in ['toggle','inverse_toggle']:
                assert args==[v];on=(not not v) if kind=='toggle' else not v;off=20 if v else 36;old=rd(e+off,a)
                wr(e+off+8,a,sum((int(on) if i==bit else ((old>>i)&1))<<i for i in range(16)))
            elif kind=='set':assert args==[v];old=rd(e+12,a);wr(e+20,a,old if old&(1<<bit) else old+(1<<bit))
            elif kind=='masked_split':
                assert args==[v];old=rd(e+16,a);wr(e+40,a,sum((((v if i>=4 else old)>>i)&1)<<i for i in range(16)));wr(e+56,a+4,v//65536)
            elif kind=='split':assert args==[v];wr(e+16,a,v%65536);wr(e+32,a+4,v//65536)
            elif kind=='store':assert args==[v];wr(e+12,a,v)
            elif kind in ['read','bit']:
                assert args==[v];r=rd(e+12,a);ret=r if kind=='read' else int(bool(r&(1<<bit)))
            elif kind=='pair_to_RAM':
                assert args==[0x700000,0x700004];first=rd(e+20,a);second=rd(e+36,a+4);buffer={0x700000:second,0x700004:first}
            elif kind in ['or_mask','clear_mask']:
                assert args==[v];old=rd(e+16,a);n=sum((int(bool((old|v)&(1<<i))) if kind=='or_mask' else int(bool(old&(1<<i)) and not bool(v&(1<<i))))<<i for i in range(16))
                wr(e+(26 if kind=='or_mask' else 24),a,n)
            elif kind=='write48':
                assert args==[v,v^0xa5a55a5a];old=rd(0x100352c,0xfed2010);wr(0x1003534,0xfed2010,old|1)
                packed=(args[1]<<32)+args[0]
                for pc,aa,shift in [(0x100355c,0xfed2024,32),(0x1003568,0xfed2020,16),(0x1003578,0xfed201c,0)]:wr(pc,aa,(packed>>shift)&65535)
                old=rd(0x1003584,0xfed2014);wr(0x1003592,0xfed2014,(old//256)*256+219)
            elif kind=='read48':
                assert args==[v];old=rd(0x10035ac,a);wr(0x10035b4,a,old|1)
                high=rd(0x10035c0,0xfed2024);mid=rd(0x10035d0,0xfed2020);low=rd(0x10035e0,0xfed201c)
                old=rd(0x10035e6,a);wr(0x10035ee,a,old-(old&1));ret=mid*65536+low;ret1=high
                read48_results.append(dict(case=case['name'],low32=ret,high16=ret1,software_bits=48,physical_snapshot_proven=False))
            else:raise AssertionError(kind)
            assert ev==[tuple(x) for x in c['events']] and (ret,ret1)==(c['return0'],c['return1'])
            harness=assembly.split(f'mov r12,{e:#x}\njl [r12]\n',1)[1]
            if ret is not None:assert harness.startswith(f'cmp r0,{ret:#x}\nbne fail\n');return_checks+=1
            if ret1 is not None:assert f'cmp r1,{ret1:#x}\nbne fail\n' in harness[:100];return_checks+=1
            expected.extend(ev);entries.append(e)
            for pc,op,aa,value in ev:
                assert decode(pc)['opcode']==('ldh.di' if op=='read' else 'sth.di')
                rows[aa].append(dict(case=case['name'],entry=hex(e),kind=kind,pc=pc,operation=op,address=aa,value=value));counts[op]+=1
                operations[aa][e]=dict(entry=hex(e),software_operation=kind,software_bit=bit if kind in ['toggle','inverse_toggle','set','bit'] else None,
                    namespace='original_TBIB',physical_meaning='unknown')
        assert len(case['original_calls'])==len(SPECS)==31
        actual_entries=[];actual_mmio=[];pool_loads=[];aux=[]
        for line in trace.splitlines():
            m=re.match(r'0x([0-9a-f]+)\s+(\S+)\s+(.*)',line)
            if not m:continue
            pc=int(m[1],16);op=m[2]
            if pc in entries:actual_entries.append(pc)
            if op in ['lr','sr']:aux.append(line)
            if op in ['ldw.di','stw.di']:
                value=int(re.search(r'<- (0x[0-9a-f]+)',line)[1],16)&65535
                actual_mmio.append((pc,'read' if op=='ldw.di' else 'write',value))
            if 0x10031d8<=pc<0x10036a4 and op=='ld_s' and '[pcl,' in decode(pc)['operands']:
                pp=int(re.search(r';(?:0x)?([0-9a-f]+)',decode(pc)['operands'])[1],16);word=struct.unpack_from('<I',body,pp-base)[0]
                assert int(re.search(r'<- (0x[0-9a-f]+)',line)[1],16)==word;pool_loads.append(dict(pc=hex(pc),pool=hex(pp),value=hex(word)))
        assert actual_entries==entries and actual_mmio==[(p,o,v) for p,o,a,v in expected] and not aux
        assert len(pool_loads)==41 and all(int(p['value'],0) in rows for p in pool_loads)
        err=src/(case['name']+'.stderr.log');inputs[str(err)]=sha(err)
        raw_events=[json.loads(line.removeprefix('S33_MEM ')) for line in err.read_text().splitlines() if line.startswith('S33_MEM ')]
        done=[e for e in raw_events if e['stage']=='result'];assert done==case['completed_memory_events'] and len(raw_events)==116
        assert [(e['pc'],e['operation'],e['address'],e['value']) for e in done]==expected
        for b,e in zip(raw_events[::2],raw_events[1::2]):
            assert b['stage']=='begin' and e['stage']=='result' and b['width_bytes']==e['width_bytes']==2
            assert all(b[k]==e[k] for k in ['id','pc','operation','address'])
        for key,f in case['fixtures'].items():
            aa=int(key,0);off=aa%8;before=bytes.fromhex(f['before']);after=(src/f['file']).read_bytes()
            assert struct.unpack_from('<H',before,off)[0]==(case['seed']^(aa>>2))&65535
            assert struct.unpack_from('<H',after,off)[0]==state[aa] and all(before[j]==after[j] for j in range(8) if j not in [off,off+1])
        expected_buf=bytearray(b'\xa5'*8)
        for aa,v in buffer.items():struct.pack_into('<H',expected_buf,aa-0x700000,v)
        assert (src/case['buffer_file']).read_bytes()==expected_buf
        checks.append(dict(case=case['name'],events=58,return_register_checks=return_checks,original_pool_loads=len(pool_loads)));pool_checks.extend(pool_loads)
    assert len(checks)==18 and sum(counts.values())==1044 and len(rows)==25
    old=load(parent/'register_map.json');known={(r['space'],r['number']) for r in old['records']};new={a for a in rows if ('soc_mmio',a) not in known};existing=set(rows)-new
    assert len(new)==21 and existing=={0xfed2018,0xfed201c,0xfed2020,0xfed2024}
    audit=dict(status='PASS_ORIGINAL_TBIB_FED20_AUDIT',date='2026-10-25',checks=checks,counts=dict(counts),pool_load_checks=pool_checks,
        read48_results=read48_results,new_addresses=list(map(hex,sorted(new))),enriched_addresses=list(map(hex,sorted(existing))),
        independently_redecoded_instructions={hex(k):v for k,v in decoded.items()},input_sha256=inputs,hardware_access=False,
        full_TBIB_boot_proven=False,whole_TBIB_linear_census_repaired=False,limits=d['limits'])
    save(src/'tbib_fed20_independent_audit.json',audit)
    out=parent.parent/datetime.now(timezone.utc).strftime('%Y%m%dT%H%M%SZ');assert not out.exists();shutil.copytree(parent,out);(out/'sha256.json').unlink()
    save(out/'atlas_validation.json',dict(status='INCOMPLETE_TBIB_FED20'));evdir=out/'evidence';scripts=ROOT/'Python_Trace_Scripts'
    for original,name in [(src/'verified_evidence.json','tbib_fed20_cpu.json'),(src/'tbib_fed20_independent_audit.json','tbib_fed20_audit.json'),
        (scripts/'s33_verify_tbib_fed20.py','s33_verify_tbib_fed20.py'),(Path(__file__),Path(__file__).name)]:shutil.copy2(original,evdir/name)
    mmio=load(evdir/'mmio_documented.json');by_address={int(r['address'],0):r for r in mmio['records']};sources=[dict(file=str(evdir/n),line=1) for n in ['tbib_fed20_cpu.json','tbib_fed20_audit.json']]
    for a,events in sorted(rows.items()):
        fields=list(operations[a].values())
        if a in new:
            mmio['records'].append(dict(address=f'0x{a:08X}',namespace='soc_mmio',subsystem='original_TBIB_FED20_physical_function_unknown',
                software_role='fixed_halfword_accessor',width_bits=16,access='/'.join(sorted({e['operation'] for e in events}))+'_halfword_di',
                confidence='original_TBIB_CPU_accessor_and_independent_bitwise_audit_fixture',hardware_verified=False,
                fields=fields,observed_accesses=events,sources=sources,unknown=['Realcallerargumentdomains,globalreachability,physicalnames/reset/permissions,W1C,IRQ,timing,latchatomicity unknown']))
        else:
            r=by_address[a];r.setdefault('fields',[]).extend(fields);r.setdefault('sources',[]).extend(sources);r['original_tbib_fed20_accesses']=events
    mmio['counts'].update(register_addresses=len(mmio['records']),direct_or_reported_accesses=len(mmio['records']));save(evdir/'mmio_documented.json',mmio)
    metadata=load(out/'atlas_metadata.json');metadata.update(date='2026-10-25',parent_atlas=str(parent),parent_ledger_sha256=sha(parent/'sha256.json'),
        parent_ledger_files_verified=len(ledger),tbib_fed20_new_scalars=21,tbib_fed20_enriched_scalars=4,tbib_fed20_scenarios=18,
        tbib_fed20_guest_events=1044,tbib_original_bytes_preserved=True,whole_physical_map_complete=False);save(out/'atlas_metadata.json',metadata)
    completion=load(out/'completion_audit.json');completion.update(prior_turn_classification='progress',goal_complete=False)
    completion['requirements'][2]['limits'][0]='936 individual MMIO addresses and50 transfer windows do not delimit the physical register universe'
    completion['next_work']=['Continue originalTBIB groups after10036A4 andcandidate literalbindings;globalcensusOOBremainsunrepaired',
        'AUXindirectinputs/overlays/BCR/SoC andphysicalDSPsemantics','Resolve actualcallerconstraints;software48bittransportdoesnotprovephysicalsnapshot'];save(out/'completion_audit.json',completion)
    for n in ['s33_build_register_atlas.py','s33_verify_register_trace_sites.py']:subprocess.run([sys.executable,str(scripts/n),str(out)],check=True)
    subprocess.run(['/home/jack/.local/share/pipx/venvs/graphifyy/bin/python',str(scripts/'s33_build_register_graph.py'),str(out)],check=True)
    atlas=load(out/'register_map.json');keys={(r['space'],r['number']) for r in atlas['records']};by_key={(r['space'],r['number']):r for r in atlas['records']}
    assert len(keys)==1200 and Counter(r['space'] for r in atlas['records'])==dict(core=64,aux=200,soc_mmio=936)
    assert keys-known=={('soc_mmio',a) for a in new} and known<=keys and not atlas['goal_complete']
    def canonical(v):
        # Builder-generated references relocate; retained historical proof
        # fields can still point to the immutable parent. Compare both forms.
        if isinstance(v,str):return v.replace(str(parent),'<SAME_ATLAS>').replace(str(out),'<SAME_ATLAS>')
        if isinstance(v,list):return [canonical(x) for x in v]
        if isinstance(v,dict):return {k:canonical(x) for k,x in v.items()}
        return v
    for r in old['records']:
        after=by_key[r['space'],r['number']]
        if r['space']=='aux':assert canonical(after)==canonical(r)
        elif r['space']!='soc_mmio' or r['number'] not in existing:assert after==r
        else:
            for k,v in r.items():assert after[k][:len(v)]==v if k in ['fields','sources'] else after[k]==v
    for k in ['mmio_transfer_windows','mmio_window_overlaps','computed_mmio_families']:assert atlas[k]==old[k]
    assert all(not r['hardware_verified'] for r in atlas['records']) and load(evdir/'firmware_aux_trace.json')==load(parent/'evidence/firmware_aux_trace.json')
    assert len(load(out/'aux_trace_site_verification.json')['checks'])==204 and len(atlas['aux_indices_with_guest_semantic_records'])==25
    historical=[];geo={geometry(w) for w in atlas['mmio_transfer_windows']}
    for directory in sorted(parent.parent.iterdir()):
        if directory==out or not(directory/'atlas_validation.json').is_file() or not(directory/'sha256.json').is_file():continue
        if not load(directory/'atlas_validation.json').get('status','').startswith('PASS'):continue
        ld=load(directory/'sha256.json');assert all(sha(directory/k)==v for k,v in ld.items());p=load(directory/'register_map.json')
        pk={(r['space'],r['number']) for r in p['records']};pg={geometry(w) for w in p.get('mmio_transfer_windows',[])};assert pk<=keys and pg<=geo
        historical.append(dict(path=str(directory),record_count=len(pk),window_geometry_count=len(pg),missing_in_merged_atlas=0,missing_window_geometries=0,
            ledger_sha256=sha(directory/'sha256.json'),ledger_files_verified=len(ld)))
    history=load(parent/'coverage_lineage_audit.json');history.update(historical_atlases=historical,union_records=len(keys),latest_parent_atlas=str(parent),
        latest_new_addresses=list(map(hex,sorted(new))),latest_new_aux_indices=[],latest_new_window_count=0,latest_transfer_cell_addresses=[]);save(out/'coverage_lineage_audit.json',history)
    assert all(sha(Path(k))==v for k,v in inputs.items()) and all(sha(parent/k)==v for k,v in ledger.items())
    save(out/'atlas_validation.json',dict(status='PASS_ORIGINAL_TBIB_FED20_NO_COVERAGE_REGRESSION',total_records=1200,counts=atlas['counts'],
        new_scalar_mmio_addresses=21,enriched_scalar_mmio_addresses=4,guest_MMIO_events=1044,operation_counts=dict(counts),original_routines=31,
        selected_scenarios=18,trace_identical_pairs=18,original_pool_load_checks=len(pool_checks),read48_checks=18,
        parent_ledger_files_verified=len(ledger),historical_atlases_verified=len(historical),input_sha256=inputs,
        full_TBIB_boot_proven=False,whole_TBIB_linear_census_repaired=False,whole_physical_map_complete=False,gnu_original_inputs_unchanged=True,limits=d['limits']))
    for n in ['s33_build_register_atlas.py','s33_build_register_graph.py','s33_verify_register_trace_sites.py']:shutil.copy2(scripts/n,evdir/n)
    save(out/'sha256.json',{str(p.relative_to(out)):sha(p) for p in sorted(out.rglob('*')) if p.is_file() and p!=out/'sha256.json'})
    print('PASS1200records,+21MMIO/4enriched,1044events;prioratlases',len(historical));print(out)


if __name__=='__main__':main()
