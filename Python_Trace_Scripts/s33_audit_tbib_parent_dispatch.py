#!/usr/bin/env python3
"""Audit the original parent indirect dispatch with paired pending-bit fixtures."""
import argparse,json,re,struct,subprocess
from collections import Counter,defaultdict
from pathlib import Path
from s33_integrate_ffc7000_table_tail import ROOT,load,save,sha
from s33_verify_sensor_mmio_dialog import aligned_window
from s33_audit_tbib_selector_tables import elf_symbols
from s33_publish_mmio_accessor_evidence_v3 import publish

def main():
    ap=argparse.ArgumentParser(description=__doc__);ap.add_argument('source',type=Path);src=ap.parse_args().source.resolve()
    d=load(src/'verified_evidence.json');assert d['status']=='PASS_ORIGINAL_TBIB_PARENT_DISPATCH'
    parent=Path(d['parent_atlas']);info=d['payload'];body=Path(info['path']).read_bytes();base=info['base'];fw=ROOT/'OriginalSoftware_NikonS33_V1.1/firmware.bin';rawfw=fw.read_bytes()
    assert body==rawfw[0x7c:0x7c+info['size']]
    inputs={**d['input_hashes'],str(src/'verified_evidence.json'):sha(src/'verified_evidence.json'),str(Path(__file__)):sha(Path(__file__))}
    dep=d['reused_plan_dependency'];assert sha(Path(dep['path']))==dep['sha256'];inputs[dep['path']]=dep['sha256']
    assert all(sha(Path(k))==v for k,v in inputs.items()) and all(sha(src/k)==v for k,v in d['files'].items())
    objcopy=ROOT/'work/build-arc/binutils/objcopy';objdump=ROOT/'work/build-arc/binutils/objdump'
    for p in [objcopy,objdump,Path(__file__).with_name('s33_verify_sensor_mmio_dialog.py'),Path(__file__).with_name('s33_audit_tbib_selector_tables.py')]:inputs[str(p)]=sha(p)
    decoded={}
    def decode(pc):
        if pc not in decoded:
            line=next(x for x in aligned_window(body,base,pc,pc+12).splitlines() if re.match(r'\s*'+f'{pc:x}:',x))
            m=re.match(r'\s*[0-9a-f]+:\s+((?:[0-9a-f]{4}\s+)+)\t(\S+)\s*(.*)',line)
            raw=b''.join(bytes.fromhex(w)[::-1] for w in m[1].split());assert raw==body[pc-base:pc-base+len(raw)]
            decoded[pc]=dict(opcode=m[2],operands=m[3].strip(),bytes_hex=raw.hex())
        return decoded[pc]
    def exact(pc,op,args):assert (decode(pc)['opcode'],decode(pc)['operands'])==(op,args),(hex(pc),decode(pc))
    def word(p):return struct.unpack_from('<I',body,p-base)[0]
    assert body[0x10411e4-base]==0 and word(0x1040628)==word(0x104126c)==word(0x1041390)==0
    assert word(0x1014d84)==0x1014d6c and word(0x1004bb4)==0x1040618
    parent_desc=struct.unpack_from('<HBBI',body,0x1040624-base);assert parent_desc==(0x610,15,15,0)
    for pc in [0x1004a8a,0x10049e2,0x1004a3a]:exact(pc,'lr','r2,[identity]')
    for x in [(0x1004b62,'st.di','r1,[r14,16]'),(0x1004a00,'sth','r2,[sp,8]'),(0x1004a58,'sth','r2,[sp,8]'),
        (0x1014d94,'ld.di','r0,[r15,4]'),(0x1014d98,'ldh.di','r0,[r0]'),
        (0x1014dac,'ld.di','r0,[r15]'),(0x1014db0,'ldh.di','r0,[r0]'),(0x1014dc0,'ld.di','r0,[r14,16]'),
        (0x1014dde,'sth.di','r0,[r2]'),(0x1014df6,'ld.di','r0,[r15,144]'),(0x1014dfa,'ldh.di','r0,[r0]'),
        (0x1014e0e,'ld.di','r0,[r15,140]'),(0x1014e12,'ldh.di','r0,[r0]'),(0x1014e22,'ld.di','r0,[r14,156]'),
        (0x1014e40,'sth.di','r0,[r2]'),(0x101499e,'ld.di','r0,[0x104061c]'),(0x10149a6,'ldh.di','r5,[r0]'),
        (0x10149ae,'ld.di','r2,[0x1040618]'),(0x10149b6,'ldh.di','r3,[r2]'),(0x10149be,'ldh.di','r6,[0x1040620]'),
        (0x10149e6,'ld.di','r0,[r1,4]'),(0x1014a06,'jl','[r0]'),(0x1014a2a,'sth.di','r0,[r2]'),
        (0x1014a2e,'bclr','r3,r3,r4')]:exact(*x)
    parent_ack,parent_mask,parent_count=struct.unpack_from('<IIH',body,0x1040618-base)
    assert (parent_ack,parent_mask,parent_count)==(0xfef0074,0xfef0028,16)
    parent_records=[struct.unpack_from('<HBBI',body,0x1040624-base+8*i) for i in range(parent_count)]
    assert parent_records[0]==(0x610,15,15,0) and all(r[3]==0 for r in parent_records)
    # Bind the ordinary-low-bank identity value to the unchanged model source.
    engine=ROOT/'work/gnu_arc700_defined_memory_v2/source/gnu-arc700-sim-src/sim/arc/cpu7.h';inputs[str(engine)]=sha(engine)
    model=engine.read_text();assert 's33_i >= 64 && !CPU (h_s33_aux_valid[s33_i])' in model and 's33_value = CPU (h_auxr[s33_i]);' in model
    tables=[];keys=[]
    for group,ptr in enumerate([0x1040800,0x104088c]):
        ack,mask,n=struct.unpack_from('<IIH',body,ptr-base);records=[]
        for i in range(n):
            key,ab,mb,cb=struct.unpack_from('<HBBI',body,ptr-base+12+8*i);assert ab==mb and cb==0
            r=dict(key=key,group=group,index=i,ack_bit=ab,mask_bit=mb,callback=cb);records.append(r);keys.append(r)
        tables.append(dict(pointer=ptr,ack=ack,mask=mask,count=n,records=records))
    analysis=src/'parent_dispatch_original_source.elf'
    subprocess.run([str(objcopy),'-I','binary','-O','elf32-littlearc','-B','arc','--rename-section','.data=.text,alloc,load,readonly,code,contents',
                    '--change-section-vma',f'.data={base:#x}','--strip-all',info['path'],str(analysis)],check=True,capture_output=True)
    inputs[str(analysis)]=sha(analysis)
    rows=defaultdict(list);operations=defaultdict(dict);checks=[];counts=Counter();aux_runs=[];pending_checks=[];pair_shapes=defaultdict(dict)
    for c in d['cases']:
        assert c['exit_code']==0 and c['fault'] is None and c['original_calls_completed'] and c['runtime_global_restored']
        if not c['observer_enabled']:continue
        tp=src/(c['name']+'.trace');inputs[str(tp)]=sha(tp)
        assert tp.read_bytes()==(src/(c['name'].replace('_observed','_reference')+'.trace')).read_bytes()
        stem=c['name'].removesuffix('_observed');elf=src/(stem+'.elf');asm=(src/(stem+'.s')).read_text();b,ss,syms=elf_symbols(elf)
        ctx,si=syms['context'];task,ti=syms['task'];nest,ni=syms['nesting'];s=ss[si];depth=c['nesting_depth'];off=s[4]+ctx-s[3]
        assert si==ti==ni and task==ctx+32 and nest==task+104 and s[1]==1 and depth in [1,2,7]
        assert b[off:off+140]==bytes(24)+struct.pack('<HHI',1,0,task)+bytes(104)+struct.pack('<I',depth)
        pair_shapes[c['seed']][c['flag']]=dict(depth=depth,fixtures={k:v['before'] for k,v in c['fixtures'].items()},
            allocated=[(s[1],s[2],s[3],s[5],b[s[4]:s[4]+s[5]].hex() if s[1]!=8 else None) for s in ss if s[2]&2])
        seq=[(0x1014bcc,r) for r in keys]+[(0x1014998,None)]+[(0x1014c64,r) for r in keys]+[(0x1004a78,None)]
        assert [x['entry'] for x in c['original_calls']]==[e for e,r in seq]
        chunks=[];aux_records=[];ctxstores=[];gate_stores=[];gate_initial=[]
        for line_no,line in enumerate(tp.read_text().splitlines(),1):
            m=re.match(r'0x([0-9a-f]+)\s+(\S+)\s+(.*)',line)
            if not m:continue
            pc=int(m[1],16);op=m[2];operand=m[3];v=re.search(r'<- (0x[0-9a-f]+)',line);v=int(v[1],16) if v else None
            # 1004A78 appears inside the first outer call and once as the final cleanup.
            if pc in [0x1014bcc,0x1014c64,0x1014998] or pc==0x1004a78 and len(chunks)==31:chunks.append([])
            if chunks:chunks[-1].append((pc,op,v))
            assert op not in ['sr','flag']
            if op=='lr':
                assert pc in [0x1004a8a,0x10049e2,0x1004a3a] and v==0 and '[0x4]' in operand
                fo=0x7c+pc-base
                aux_records.append(dict(trace_line=line_no,pc=pc,pc_hex=hex(pc),operation='read',aux_index=4,aux_hex='0x4',trace_text=line,
                    semantic_result_observed=True,retirement_proven_by_this_record=False,firmware_offset=fo,firmware_offset_hex=hex(fo),
                    original_firmware_bytes_next8=rawfw[fo:fo+8].hex(),trace_value=0,trace_value_hex='0x0',
                    value_meaning='GNU ordinary-low-bank model state,not a Nikon IDENTITY/reset/BCR reading'))
            if base<=pc<base+len(body):
                decode(pc)
                if op.startswith('st'):
                    assert pc in [0x1004b62,0x10049d4,0x1004a2c,0x1004a00,0x1004a58,0x10048f4,0x10049b6,
                        0x1014c34,0x1014c50,0x1014ca4,0x1014cc6,0x1014b58,0x1014bb0,0x1014bc0,0x1014dde,0x1014e40,
                        0x10149ee,0x10149f2,0x10149f6,0x10149fa,0x10149fe,0x1014a02,0x1014a2a,
                        0x1013d52,0x1013e14,0x103e0dc,0x103e0e0,0x103e0e4,0x103e0e8,0x103efb0,0x103efb4,0x103efb8,0x103efc6],hex(pc)
            elif op=='st':assert 'r0,[0x0104126c,0]' in operand;ctxstores.append(v)
            elif op=='stb':assert 'r0,[0x010411e4,0]' in operand;gate_stores.append(v)
        assert len(chunks)==32 and ctxstores==[ctx,0] and gate_stores==[1,0]
        assert [r['pc'] for r in aux_records]==[0x1004a8a,0x10049e2,0x1004a3a,0x1004a8a]
        state={int(k,0):struct.unpack_from('<H',bytes.fromhex(f['before']),int(k,0)%8)[0] for k,f in c['fixtures'].items()};active=[set(),set()];expected=[];nested_pairs=0
        for ordinal,(call,chunk,(entry,r)) in enumerate(zip(c['original_calls'],chunks,seq)):
            ev=[];registration=False;on=entry==0x1014bcc
            if r:
                assert call['arguments']==[r['key']] and call['return0']==0
                if on:registration=not any(active);active[r['group']].add(r['key'])
                else:active[r['group']].discard(r['key']);registration=not any(active)
                if registration:
                    a=0xfef0028;old=state[a];new=sum((int(on) if bit==15 else ((old>>bit)&1))<<bit for bit in range(16));pc=0x10048ec if on else 0x10049ae
                    ev.extend([(pc,'read',a,old),(pc+8,'write',a,new)]);state[a]=new
                t=tables[r['group']]
                if r['group']==0:ev.append((0x1014b58,'write',t['ack'],2**r['ack_bit']));state[t['ack']]=2**r['ack_bit']
                a=t['mask'];old=state[a];new=sum((int(on) if bit==r['mask_bit'] else ((old>>bit)&1))<<bit for bit in range(16));pc=0x1014ba8 if on else 0x1014bb8
                ev.extend([(pc,'read',a,old),(pc+8,'write',a,new)]);state[a]=new
                assert [(p,v) for p,o,v in chunk if p==0x1004b62]==([(0x1004b62,0x1014d6c)] if registration and on else [])
                assert [p for p,o,v in chunk if p in [0x1004a78,0x10049c8,0x1004a20]]==([0x1004a78,0x10049c8] if registration and on else [0x1004a20] if registration else [])
                target_values=[v for p,o,v in chunk if p in [0x1004796,0x10048e0]]
                if registration:assert target_values==[0xfef0028]
            elif entry==0x1014998:
                assert call['arguments']==[] and call['return0']==depth
                mode=c['flag'];assert mode in [0,1] and call['expected_child_calls']==mode
                mask=state[parent_mask];parent_pending=state[parent_ack]
                assert mask&0x8000 and bool(parent_pending&0x8000)==bool(mode)
                ev.extend([(0x10149a6,'read',parent_mask,mask),(0x10149b6,'read',parent_ack,parent_pending)])
                before=state[tables[1]['ack']];matched=[]
                for group,t in (enumerate(tables) if mode else []):
                    for rr in t['records']:
                        enabled=state[t['mask']];ev.append((0x1014d98 if group==0 else 0x1014dfa,'read',t['mask'],enabled))
                        if not (enabled//(2**rr['mask_bit']))%2:continue
                        pending=state[t['ack']];ev.append((0x1014db0 if group==0 else 0x1014e12,'read',t['ack'],pending))
                        if not (pending//(2**rr['ack_bit']))%2:continue
                        value=2**rr['ack_bit'];ev.append((0x1014dde if group==0 else 0x1014e40,'write',t['ack'],value));state[t['ack']]=value;matched.append(rr['key'])
                assert [(p,v) for p,o,v in chunk if p in [0x1014dc0,0x1014e22]]==([(0x1014dc0,0),(0x1014e22,0)] if mode else [])
                assert not any(p in [0x1014dcc,0x1014e2e] for p,o,v in chunk)
                assert [(p,v) for p,o,v in chunk if p==0x1014a06]==([(0x1014a06,0x1014d6c)] if mode else [])
                assert sum(p==0x1014d6c for p,o,v in chunk)==mode
                assert [(p,v) for p,o,v in chunk if p in [0x10149a6,0x10149b6]]==[(0x10149a6,mask),(0x10149b6,parent_pending)]
                expected_slots=[0x1014d6c if i==0 else 0 for i,(key,ab,mb,cb) in enumerate(parent_records) if (mask>>mb)&1 and (parent_pending>>ab)&1]
                assert [v for p,o,v in chunk if p==0x10149e6]==expected_slots
                if mode:
                    ev.append((0x1014a2a,'write',parent_ack,0x8000));state[parent_ack]=0x8000
                    assert [(p,v) for p,o,v in chunk if p==0x1014a2e]==[(0x1014a2e,parent_pending&0x7fff)]
                pending_checks.append(dict(case=c['name'],parent_mask=hex(mask),parent_pending_snapshot=hex(parent_pending),parent_pending_final=hex(state[parent_ack]),
                    original_indirect_target='0x1014d6c' if mode else None,parent_callback_calls=mode,
                    second_pending_before=hex(before),second_pending_after=hex(state[tables[1]['ack']]),matched_selectors=list(map(hex,matched)),model='ordinary_storage_not_W1C'))
            else:
                assert entry==0x1004a78 and call['arguments']==[0x610,0] and call['return0']==0
                assert [(p,v) for p,o,v in chunk if p==0x1004b62]==[(0x1004b62,0)]
            assert ev==[tuple(x) for x in call['events']]
            mmio_pcs={0x10048ec,0x10048f4,0x10049ae,0x10049b6,0x1014b58,0x1014ba8,0x1014bb0,0x1014bb8,0x1014bc0,
                      0x1014d98,0x1014db0,0x1014dde,0x1014dfa,0x1014e12,0x1014e40,0x10149a6,0x10149b6,0x1014a2a}
            actual=[(p,'read' if o=='ldw.di' else 'write',v&65535) for p,o,v in chunk if p in mmio_pcs]
            assert actual==[(p,o,v) for p,o,a,v in ev]
            # Original descriptor RAM .di accesses are ld.di/ldb.di, not the
            # halfword MMIO records selected above.
            level=depth;enters=exits=0
            for p,o,v in chunk:
                if p in [0x1013d40,0x1013d4e]:assert v==level
                elif p==0x1013d52:assert v==level+1;level+=1;enters+=1
                elif p==0x1013d54:assert v==1
                elif p==0x1013e06:assert v==level
                elif p==0x1013e14:assert v==level-1;level-=1;exits+=1
            expected_pairs=(3 if registration else 2) if r else (1 if entry==0x1014998 else 0)
            assert level==depth and enters==exits==expected_pairs
            nested_pairs+=enters
            for pc,op,a,v in ev:
                counts[op]+=1;rows[a].append(dict(case=c['name'],entry=hex(entry),call_ordinal=ordinal,pc=pc,operation=op,address=a,value=v))
                operations[a][entry]=dict(entry=hex(entry),software_operation='original_parent_indirect_dispatch' if entry==0x1014998 else 'registration_enabled_outer',
                    callback_installed_by_original_api='0x1014d6c',original_parent_indirect_pc='0x1014a06',identity_model_value='0x0_not_hardware',physical_meaning='unknown')
            expected.extend(ev)
        assert active==[set(),set()] and nested_pairs==63 and len(expected)==(113 if c['flag'] else 80)
        jl=re.findall(r'mov r12,(0x[0-9a-f]+)\njl \[r12\]\ncmp r0,(0x[0-9a-f]+)\nbne fail',asm)
        assert [(int(e,0),int(v,0)) for e,v in jl]==[(x['entry'],x['return0']) for x in c['original_calls']]
        assert asm.count('stb r0,[0x10411e4]')==2 and 'ld r0,[0x1040628]\ncmp r0,0\nbne fail' in asm
        err=src/(c['name']+'.stderr.log');inputs[str(err)]=sha(err)
        events=[json.loads(x.removeprefix('S33_MEM ')) for x in err.read_text().splitlines() if x.startswith('S33_MEM ')];done=[e for e in events if e['stage']=='result']
        assert done==c['completed_memory_events'] and len(events)==2*len(expected) and [(e['pc'],e['operation'],e['address'],e['value']) for e in done]==expected
        for b,e in zip(events[::2],events[1::2]):
            assert b['stage']=='begin' and e['stage']=='result' and b['width_bytes']==e['width_bytes']==2
            assert all(b[k]==e[k] for k in ['id','pc','operation','address'])
        for k,f in c['fixtures'].items():
            a=int(k,0);off=a%8;before=bytes.fromhex(f['before']);after=(src/f['file']).read_bytes()
            initial=((c['seed']^(a>>2))&0x7fff)|(0x8000 if c['flag'] else 0) if a==parent_ack else (c['seed']^(a>>2))&65535
            assert struct.unpack_from('<H',before,off)[0]==initial
            assert struct.unpack_from('<H',after,off)[0]==state[a] and all(before[j]==after[j] for j in range(8) if j not in [off,off+1])
        checks.append(dict(case=c['name'],outer_calls=30,parent_calls=1,registered_callback_calls=c['flag'],original_cleanup_calls=1,identity_reads=4,nested_pairs=63,mmio_events=len(expected)))
        aux_runs.append(dict(name='parent_dispatch_'+stem,path=str(tp),sha256=sha(tp),run_manifest=str(src/'verified_evidence.json'),run_manifest_sha256=sha(src/'verified_evidence.json'),
            elf=str(analysis),elf_sha256=sha(analysis),elf_role='source_mmap_ELF_for_static_verification',actual_runtime_harness_elf=str(elf),actual_runtime_harness_sha256=sha(elf),
            runtime_original_code_mmap=info,semantic_result_observed_records=aux_records,limits=d['limits']))
    assert len(checks)==6 and counts==dict(read=294,write=285) and set(rows)=={0xfef0028,0xfef0074,0xfed3814,0xfed3818,0xfed3830,0xfed3834}
    known={r['number'] for r in load(parent/'register_map.json')['records'] if r['space']=='soc_mmio'};assert not set(rows)-known
    paired_checks=[]
    for seed,modes in pair_shapes.items():
        assert set(modes)=={0,1};a,b=modes[0],modes[1]
        assert a['depth']==b['depth'] and a['allocated']==b['allocated'] and set(a['fixtures'])==set(b['fixtures'])
        for k,v in a['fixtures'].items():
            if int(k,0)!=parent_ack:assert v==b['fixtures'][k]
            else:
                left,right=bytes.fromhex(v),bytes.fromhex(b['fixtures'][k]);off=parent_ack%8
                assert left[:off]==right[:off] and left[off+2:]==right[off+2:] and struct.unpack_from('<H',left,off)[0]^struct.unpack_from('<H',right,off)[0]==0x8000
        paired_checks.append(dict(seed=seed,only_changed_input='FEF0074bit15',allocated_harness_sections_identical=True,context_depth=a['depth']))
    assert len(paired_checks)==3
    save(src/'tbib_parent_dispatch_audit.json',dict(status='PASS_TBIB_PARENT_DISPATCH_AUDIT',date='2026-10-26',checks=checks,operation_counts=dict(counts),
        pending_model_checks=pending_checks,paired_input_checks=paired_checks,aux_runs=aux_runs,instructions={hex(k):v for k,v in decoded.items()},input_sha256=inputs,hardware_access=False,limits=d['limits']))
    publish(parent=parent,source=src,copy_files=[(src/'verified_evidence.json','tbib_parent_dispatch_cpu.json'),(src/'tbib_parent_dispatch_audit.json','tbib_parent_dispatch_audit.json'),(analysis,analysis.name)],
        rows=rows,operations={a:list(v.values()) for a,v in operations.items()},input_hashes=inputs,aux_runs=aux_runs,
        scripts=[Path(__file__),Path(__file__).with_name('s33_verify_tbib_parent_dispatch.py'),Path(__file__).with_name('s33_tbib_nested_context_harness_v2.py')],
        validation=dict(date='2026-10-26',status='PASS_TBIB_PARENT_DISPATCH_NO_COVERAGE_REGRESSION',new_scalar_mmio_addresses=0,enriched_scalar_mmio_addresses=6,
            selected_scenarios=6,trace_identical_pairs=6,guest_MMIO_events=579,operation_counts=dict(counts),original_outer_calls=180,original_callback_calls=3,original_parent_calls=6,
            nested_service_pairs=378,new_guest_aux_indices=[],identity_read_events=24,identity_is_model_value=True,paired_input_checks=paired_checks,limits=d['limits']),
        next_work=['Trace nonzero childcallback registration andotherparentcategories;retainmodelidentity0 andplainstorage pending limits.',
                   'Othercategorydelegates/init100559C,invalidouter lifetime,AUX/BCR/SoC/DSPphysicalmap remainopen.'])

if __name__=='__main__':main()
