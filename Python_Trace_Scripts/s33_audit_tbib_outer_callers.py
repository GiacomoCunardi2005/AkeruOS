#!/usr/bin/env python3
"""Audit complete outer calls: registration failure, RAM masks, nested services and MMIO."""
import argparse,json,re,struct
from collections import Counter,defaultdict
from pathlib import Path
from s33_integrate_ffc7000_table_tail import ROOT,load,save,sha
from s33_verify_sensor_mmio_dialog import aligned_window
from s33_audit_tbib_selector_tables import elf_symbols
from s33_publish_mmio_accessor_evidence_v2 import publish

def main():
    ap=argparse.ArgumentParser(description=__doc__);ap.add_argument('source',type=Path);src=ap.parse_args().source.resolve()
    d=load(src/'verified_evidence.json');assert d['status']=='PASS_ORIGINAL_TBIB_OUTER_CALLERS'
    parent=Path(d['parent_atlas']);info=d['payload'];body=Path(info['path']).read_bytes();base=info['base']
    assert body==(ROOT/'OriginalSoftware_NikonS33_V1.1/firmware.bin').read_bytes()[0x7c:0x7c+info['size']]
    inputs={**d['input_hashes'],str(src/'verified_evidence.json'):sha(src/'verified_evidence.json'),str(Path(__file__)):sha(Path(__file__))}
    assert all(sha(Path(k))==v for k,v in inputs.items()) and all(sha(src/k)==v for k,v in d['files'].items())
    for p in [ROOT/'work/build-arc/binutils/objdump',ROOT/'work/build-arc/binutils/objcopy',Path(__file__).with_name('s33_verify_sensor_mmio_dialog.py'),Path(__file__).with_name('s33_audit_tbib_selector_tables.py')]:inputs[str(p)]=sha(p)
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
    assert body[0x10411e4-base]==0 and body[0x1041390-base:0x1041390-base+4]==bytes(4)
    assert word(0x1004bac)==0x10411e4 and word(0x1004bb0)==0x200604 and word(0x1014d80)==0x1041390
    tables=[];lookup={}
    for j,ptr in enumerate([0x1040800,0x104088c]):
        ack,mask,n=struct.unpack_from('<IIH',body,ptr-base);records=[]
        for i in range(n):
            k,ab,mb,cb=struct.unpack_from('<HBBI',body,ptr-base+12+8*i);assert ab==mb and cb==0
            r=dict(key=k,group=j,index=i,ack_bit=ab,mask_bit=mb,table=ptr,ack=ack,mask=mask);lookup[k]=r;records.append(r)
        tables.append(records)
    keys=list(lookup);assert len(keys)==15
    for x in [(0x1014c04,'bl.d','-65932\t;0x1004a78'),(0x1014c10,'bl.d','-66120\t;0x10049c8'),
        (0x1014bf0,'ld_s','r14,[pcl,0x190]\t;0x1014d80'),(0x1014c84,'ld_s','r1,[pcl,0xfc]\t;0x1014d80'),
        (0x1014c34,'stw_s','r0,[r14,0]'),(0x1014c50,'stw_s','r1,[r14,0x2]'),
        (0x1014c54,'bl.d','-332\t;0x1014b08'),(0x1014c58,'mov_s','r1,0x1'),(0x1014c62,'mov_s','r0,r15'),
        (0x1014ca4,'stw_s','r3,[r1,0]'),(0x1014cc6,'stw_s','r0,[r1,0x2]'),
        (0x1014cdc,'bl.d','-66236\t;0x1004a20'),(0x1014ce6,'bl.d','-476\t;0x1014b08'),
        (0x1014cea,'mov_s','r1,0'),(0x1014cf4,'mov_s','r0,r14'),
        (0x1004a80,'ldb_s','r2,[r2,0]'),(0x10049d2,'ldb_s','r2,[r2,0]'),(0x1004a2a,'ldb_s','r2,[r2,0]')]:exact(*x)
    rows=defaultdict(list);operations=defaultdict(dict);checks=[];counts=Counter();statuses=Counter();failed_events=0;total_disabled=0;ram_checks=[]
    for c in d['cases']:
        assert c['exit_code']==0 and c['fault'] is None and c['original_calls_completed'] and c['runtime_global_restored']
        if not c['observer_enabled']:continue
        tp=src/(c['name']+'.trace');inputs[str(tp)]=sha(tp)
        assert tp.read_bytes()==(src/(c['name'].replace('_observed','_reference')+'.trace')).read_bytes()
        stem=c['name'].removesuffix('_observed');asm=(src/(stem+'.s')).read_text();b,sections,symbols=elf_symbols(src/(stem+'.elf'))
        ctx,si=symbols['context'];task,ti=symbols['task'];nest,ni=symbols['nesting'];s=sections[si];depth=c['nesting_depth'];off=s[4]+ctx-s[3]
        assert si==ti==ni and task==ctx+32 and nest==task+104 and s[1]==1 and depth in [1,2,7]
        assert b[off:off+140]==bytes(24)+struct.pack('<HHI',1,0,task)+bytes(104)+struct.pack('<I',depth)
        pattern=c['flag']
        seq=[(k,on) for k in keys for on in [True,False]] if pattern==0 else [(k,True) for k in keys]*(2 if pattern==2 else 1)+[(k,False) for k in (keys[::-1] if pattern==0xffffffff else keys)]
        assert [(x['arguments'][0],x['entry']==0x1014bcc) for x in c['original_calls']]==seq
        chunks=[];gstores=[];initial=[]
        for line in tp.read_text().splitlines():
            m=re.match(r'0x([0-9a-f]+)\s+(\S+)\s+(.*)',line)
            if not m:continue
            pc=int(m[1],16);op=m[2];operand=m[3];assert op not in ['flag','lr','sr']
            v=re.search(r'<- (0x[0-9a-f]+)',line);v=int(v[1],16) if v else None
            if pc in [0x1014bcc,0x1014c64]:chunks.append([])
            if chunks:chunks[-1].append((pc,op,v))
            if base<=pc<base+len(body):
                decode(pc)
                if op.startswith('st'):
                    assert pc in [0x1014c34,0x1014c50,0x1014ca4,0x1014cc6,0x1014b58,0x1014bb0,0x1014bc0,0x1013d52,0x1013e14,
                                  0x10049d4,0x1004a2c,0x103e0dc,0x103e0e0,0x103e0e4,0x103e0e8,0x103efb0,0x103efb4,0x103efb8,0x103efc6],hex(pc)
            elif op=='st':assert 'r0,[0x0104126c,0]' in operand;gstores.append(v)
            elif op=='ld' and '[0x0104126c,0]' in operand:initial.append(v)
        assert initial==[0] and gstores==[ctx,0] and len(chunks)==len(seq)
        state={int(k,0):struct.unpack_from('<H',bytes.fromhex(f['before']),int(k,0)%8)[0] for k,f in c['fixtures'].items()};active=[set(),set()];expected=[];disabled_count=0;failed_count=0
        for ordinal,(call,chunk,(key,on)) in enumerate(zip(c['original_calls'],chunks,seq)):
            r=lookup[key];group=r['group'];before=[sum(2**((k&31)-1) for k in a) for a in active]
            if on:registration=not any(active);active[group].add(key)
            else:active[group].discard(key);registration=not any(active)
            after=[sum(2**((k&31)-1) for k in a) for a in active];ret=0x200604 if registration else 0
            assert call['return0']==ret and call['ram_masks_before']==before and call['ram_masks_after']==after
            ev=[]
            if group==0:ev.append((0x1014b58,'write',r['ack'],2**r['ack_bit']))
            a=r['mask'];old=state[a];v=sum((int(on) if bit==r['mask_bit'] else ((old>>bit)&1))<<bit for bit in range(16));pc=0x1014ba8 if on else 0x1014bb8
            ev.extend([(pc,'read',a,old),(pc+8,'write',a,v)]);assert ev==[tuple(e) for e in call['events']]
            actual=[(p,'read' if o=='ldw.di' else 'write',v&65535) for p,o,v in chunk if p in [0x1014b58,0x1014ba8,0x1014bb0,0x1014bb8,0x1014bc0]]
            assert actual==[(p,o,v) for p,o,a,v in ev]
            ram_pc=(0x1014c34 if group==0 else 0x1014c50) if on else (0x1014ca4 if group==0 else 0x1014cc6)
            assert [(p,v) for p,o,v in chunk if p in [0x1014c34,0x1014c50,0x1014ca4,0x1014cc6]]==[(ram_pc,after[group])]
            assert [(p,v) for p,o,v in chunk if p in [0x1014bf0,0x1014c84]]==[(0x1014bf0 if on else 0x1014c84,0x1041390)]
            assert [(p,v) for p,o,v in chunk if p in [0x1014c62,0x1014cf4]]==[(0x1014c62 if on else 0x1014cf4,ret)]
            expected_disabled=[0x1004a78,0x10049c8] if registration and on else [0x1004a20] if registration else []
            assert [p for p,o,v in chunk if p in [0x1004a78,0x10049c8,0x1004a20]]==expected_disabled
            gate_pcs={0x1004a78:0x1004a80,0x10049c8:0x10049d2,0x1004a20:0x1004a2a}
            assert [(p,v) for p,o,v in chunk if p in gate_pcs.values()]==[(gate_pcs[p],0) for p in expected_disabled]
            service=[(p,v) for p,o,v in chunk if p in [0x1013d40,0x1013d4e,0x1013d52,0x1013d54,0x1013e06,0x1013e14]]
            enter=lambda n:[(0x1013d40,n),(0x1013d4e,n),(0x1013d52,n+1),(0x1013d54,1)]
            assert service==enter(depth)+enter(depth+1)+[(0x1013e06,depth+2),(0x1013e14,depth+1),(0x1013e06,depth+1),(0x1013e14,depth)]
            assert [p for p,o,v in chunk if p==0x1014b08]==[0x1014b08]
            target_loads=[(p,v) for p,o,v in chunk if p in [0x1014b48,0x1014b4c,0x1014b5e,0x1014b62,0x1014b9c,0x1014ba0]]
            assert target_loads==([(0x1014b48,r['ack']),(0x1014b4c,r['ack_bit']),(0x1014b5e,r['mask']),(0x1014b62,r['mask_bit'])] if group==0 else [(0x1014b9c,r['mask']),(0x1014ba0,r['mask_bit'])])
            disabled_count+=len(expected_disabled);statuses[ret]+=1
            if ret:failed_count+=1;failed_events+=len(ev)
            ram_checks.append(dict(case=c['name'],ordinal=ordinal,selector=hex(key),on=on,before=before,after=after,return0=hex(ret),mmio_events=len(ev)))
            for p,op,a,v in ev:
                if op=='write':state[a]=v
                counts[op]+=1;rows[a].append(dict(case=c['name'],call_ordinal=ordinal,entry=hex(call['entry']),selector=hex(key),return0=hex(ret),pc=p,operation=op,address=a,value=v))
                operations[a][call['entry'],key]=dict(entry=hex(call['entry']),selector=hex(key),software_operation='outer_with_registrationdisabled',
                    registration_failure_does_not_prevent_mmio=True,physical_meaning='unknown')
            expected.extend(ev)
        assert active==[set(),set()]
        jl=re.findall(r'mov r12,(0x[0-9a-f]+)\njl \[r12\]\ncmp r0,(0x[0-9a-f]+)\nbne fail',asm)
        assert [(int(e,0),int(v,0)) for e,v in jl]==[(x['entry'],x['return0']) for x in c['original_calls']]
        err=src/(c['name']+'.stderr.log');inputs[str(err)]=sha(err)
        raw=[json.loads(x.removeprefix('S33_MEM ')) for x in err.read_text().splitlines() if x.startswith('S33_MEM ')];done=[x for x in raw if x['stage']=='result']
        assert done==c['completed_memory_events'] and len(raw)==2*len(expected) and [(x['pc'],x['operation'],x['address'],x['value']) for x in done]==expected
        for b,e in zip(raw[::2],raw[1::2]):
            assert b['stage']=='begin' and e['stage']=='result' and b['width_bytes']==e['width_bytes']==2
            assert all(b[k]==e[k] for k in ['id','pc','operation','address'])
        for key,f in c['fixtures'].items():
            a=int(key,0);off=a%8;before=bytes.fromhex(f['before']);after=(src/f['file']).read_bytes()
            assert struct.unpack_from('<H',before,off)[0]==(c['seed']^(a>>2))&65535
            assert struct.unpack_from('<H',after,off)[0]==state[a] and all(before[j]==after[j] for j in range(8) if j not in [off,off+1])
        total_disabled+=disabled_count;checks.append(dict(case=c['name'],calls=len(seq),failed_calls_with_mmio=failed_count,disabled_registration_services=disabled_count,mmio_events=len(expected)))
    assert len(checks)==12 and statuses=={0:297,0x200604:108} and sum(counts.values())==999 and failed_events==270 and total_disabled==162,(len(checks),statuses,counts,failed_events,total_disabled)
    assert set(rows)=={0xfed3814,0xfed3818,0xfed3830}
    save(src/'tbib_outer_callers_audit.json',dict(status='PASS_TBIB_OUTER_CALLERS_AUDIT',date='2026-10-26',checks=checks,ram_checks=ram_checks,
        operation_counts=dict(counts),return_counts={hex(k):v for k,v in statuses.items()},failed_call_mmio_events=failed_events,disabled_services=total_disabled,
        instructions={hex(k):v for k,v in decoded.items()},input_sha256=inputs,hardware_access=False,limits=d['limits']))
    publish(parent=parent,source=src,copy_files=[(src/'verified_evidence.json','tbib_outer_callers_cpu.json'),(src/'tbib_outer_callers_audit.json','tbib_outer_callers_audit.json')],
        rows=rows,operations={a:list(v.values()) for a,v in operations.items()},input_hashes=inputs,scripts=[Path(__file__),Path(__file__).with_name('s33_verify_tbib_outer_callers.py')],
        validation=dict(date='2026-10-26',status='PASS_TBIB_OUTER_CALLERS_NO_COVERAGE_REGRESSION',new_scalar_mmio_addresses=0,enriched_scalar_mmio_addresses=3,
            selected_scenarios=12,trace_identical_pairs=12,complete_outer_calls=405,nested_service_pairs=810,guest_MMIO_events=999,operation_counts=dict(counts),
            failed_outer_calls_with_mmio=108,failed_call_mmio_events=270,disabled_registration_services=162,limits=d['limits']),
        next_work=['Trace registrationenabled original1004A78/49C8/4A20 andidentitybinding;othercategorydelegates/init100559C.',
                   'Invalidouterselectors mayfollow differentlifetime paths;do notgeneralize valid15selector proof;AUX/BCR/SoC/DSPphysicalmap incomplete.'])

if __name__=='__main__':main()
