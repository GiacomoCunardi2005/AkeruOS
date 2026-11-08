#!/usr/bin/env python3
"""Audit both original1014B08 table searches and admit only actually accessed cells."""
import argparse,json,re,struct
from collections import Counter,defaultdict
from pathlib import Path
from s33_integrate_ffc7000_table_tail import ROOT,load,save,sha
from s33_verify_sensor_mmio_dialog import aligned_window
from s33_audit_tbib_selector_tables import elf_symbols
from s33_publish_mmio_accessor_evidence_v2 import publish

def main():
    ap=argparse.ArgumentParser(description=__doc__);ap.add_argument('source',type=Path);src=ap.parse_args().source.resolve()
    d=load(src/'verified_evidence.json');assert d['status']=='PASS_ORIGINAL_TBIB_DELEGATED_TABLE'
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
    def word(p):return int.from_bytes(body[p-base:p-base+4],'little')
    assert word(0x1014b40)==word(0x1014b78)==0x1040800 and word(0x104126c)==0
    tables=[];by_key={}
    for j,ptr in enumerate([0x1040800,0x104088c]):
        ack,mask,count=struct.unpack_from('<IIH',body,ptr-base);records=[]
        for i in range(count):
            k,ab,mb,cb=struct.unpack_from('<HBBI',body,ptr-base+12+8*i)
            assert ab==mb and ab<16 and cb==0
            r=dict(key=k,ack_bit=ab,mask_bit=mb,index=i,group=j,table=ptr,address=ptr+12+8*i,firmware_offset=0x7c+ptr-base+12+8*i)
            records.append(r);assert k not in by_key;by_key[k]=r
        tables.append(dict(pointer=ptr,ack=ack,mask=mask,count=count,records=records))
    assert [t['count'] for t in tables]==[7,8] and len(by_key)==15
    for x in [(0x1014b0e,'and.f','0,r0,0x3000'),(0x1014b1e,'ld_s','r14,[pcl,0x24]\t;0x1014b40'),
        (0x1014b26,'ldh.di','r2,[r14,8]'),(0x1014b30,'add3','r13,r14,r1'),(0x1014b34,'ldh.di','r2,[r13,12]'),
        (0x1014b48,'ld.di','r2,[r14]'),(0x1014b4c,'ldb.di','r1,[r13,14]'),(0x1014b50,'mov_s','r0,0'),
        (0x1014b52,'bset','r0,r0,r1'),(0x1014b56,'extw_s','r0,r0'),(0x1014b58,'sth.di','r0,[r2]'),
        (0x1014b5c,'cmp_s','r15,0'),(0x1014b5e,'ld.di','r1,[r14,4]'),(0x1014b62,'ldb.di','r0,[r13,15]'),
        (0x1014b6c,'btst_s','r0,0xe'),(0x1014b72,'ld_s','r14,[pcl,0x8]\t;0x1014b78'),
        (0x1014b80,'ldh.di','r1,[r14,148]'),(0x1014b8a,'add3','r13,r14,r2'),(0x1014b8e,'ldh.di','r1,[r13,152]'),
        (0x1014b9c,'ld.di','r1,[r14,144]'),(0x1014ba0,'ldb.di','r0,[r13,155]'),
        (0x1014ba8,'ldh.di','r10,[r1]'),(0x1014bac,'bset','r10,r10,r0'),(0x1014bb0,'sth.di','r10,[r1]'),
        (0x1014bb8,'ldh.di','r10,[r1]'),(0x1014bbc,'bclr','r10,r10,r0'),(0x1014bc0,'sth.di','r10,[r1]'),
        (0x1014bc4,'bl','-3528\t;0x1013dfc'),(0x1014bc8,'b','169344\t;0x103e148'),
        (0x1014c54,'bl.d','-332\t;0x1014b08'),(0x1014c58,'mov_s','r1,0x1'),
        (0x1014ce6,'bl.d','-476\t;0x1014b08'),(0x1014cea,'mov_s','r1,0')]:exact(*x)
    rows=defaultdict(list);operations=defaultdict(dict);checks=[];counts=Counter();raw_operands=[];contexts=[];total_loads=0
    for c in d['cases']:
        assert c['exit_code']==0 and c['fault'] is None and c['original_calls_completed'] and c['runtime_global_restored']
        if not c['observer_enabled']:continue
        tp=src/(c['name']+'.trace');inputs[str(tp)]=sha(tp)
        assert tp.read_bytes()==(src/(c['name'].replace('_observed','_reference')+'.trace')).read_bytes()
        stem=c['name'].removesuffix('_observed');asm=(src/(stem+'.s')).read_text();b,sections,symbols=elf_symbols(src/(stem+'.elf'))
        ctx,si=symbols['context'];task,ti=symbols['task'];nest,ni=symbols['nesting'];s=sections[si];depth=c['nesting_depth']
        assert si==ti==ni and task==ctx+32 and nest==task+104 and depth in [1,2,7]
        off=s[4]+ctx-s[3];assert s[1]==1 and b[off:off+140]==bytes(24)+struct.pack('<HHI',1,0,task)+bytes(104)+struct.pack('<I',depth)
        contexts.append(dict(case=c['name'],context=hex(ctx),task=hex(task),nesting=hex(nest),depth=depth,global_restored=0))
        chunks=[];global_stores=[];initial=[]
        for line in tp.read_text().splitlines():
            m=re.match(r'0x([0-9a-f]+)\s+(\S+)\s+(.*)',line)
            if not m:continue
            pc=int(m[1],16);op=m[2];operand=m[3];assert op not in ['flag','lr','sr']
            v=re.search(r'<- (0x[0-9a-f]+)',line);v=int(v[1],16) if v else None
            if pc==0x1014b08:chunks.append([])
            if chunks:chunks[-1].append((pc,op,v))
            if base<=pc<base+len(body):
                decode(pc)
                if op.startswith('st'):assert pc in [0x1014b58,0x1014bb0,0x1014bc0,0x1013d52,0x1013e14,0x103e0e0,0x103e0e4,0x103e0e8],hex(pc)
            elif op=='st':assert 'r0,[0x0104126c,0]' in operand;global_stores.append(v)
            elif op=='ld' and '[0x0104126c,0]' in operand:initial.append(v)
        assert initial==[0] and global_stores==[ctx,0] and len(chunks)==len(c['original_calls'])==20
        state={int(k,0):struct.unpack_from('<H',bytes.fromhex(f['before']),int(k,0)%8)[0] for k,f in c['fixtures'].items()}
        expected=[];seen=[];load_count=0
        for ordinal,(call,chunk) in enumerate(zip(c['original_calls'],chunks)):
            key,flag=call['arguments'];assert call['entry']==0x1014b08 and flag==c['flag'];r=by_key.get(key);ev=[];loads=[]
            if key&0x3000:
                t=tables[0];loads.append((0x1014b1e,0x1040800));n=r['index']+1 if r else t['count']+1
                for i in range(n):
                    loads.append((0x1014b26,t['count']))
                    if i<t['count']:loads.append((0x1014b34,t['records'][i]['key']))
                if r:
                    assert r['group']==0;a=t['ack'];v=2**r['ack_bit'];ev.append((0x1014b58,'write',a,v))
                    loads.extend([(0x1014b48,a),(0x1014b4c,r['ack_bit']),(0x1014b5e,t['mask']),(0x1014b62,r['mask_bit'])])
            elif key&(1<<14):
                t=tables[1];loads.append((0x1014b72,0x1040800));n=r['index']+1 if r else t['count']+1
                for i in range(n):
                    loads.append((0x1014b80,t['count']))
                    if i<t['count']:loads.append((0x1014b8e,t['records'][i]['key']))
                if r:
                    assert r['group']==1;loads.extend([(0x1014b9c,t['mask']),(0x1014ba0,r['mask_bit'])])
            if r:
                a=t['mask'];old=state[a];new=sum((int(flag!=0) if i==r['mask_bit'] else ((old>>i)&1))<<i for i in range(16));pc=0x1014ba8 if flag else 0x1014bb8
                ev.extend([(pc,'read',a,old),(pc+8,'write',a,new)]);seen.append(key)
                assert call['table']==r['table'] and call['record_index']==r['index']
            assert call['return0']==(depth if r else key) and ev==[tuple(x) for x in call['events']]
            tablepcs={0x1014b1e,0x1014b26,0x1014b34,0x1014b48,0x1014b4c,0x1014b5e,0x1014b62,0x1014b72,0x1014b80,0x1014b8e,0x1014b9c,0x1014ba0}
            assert [(p,v) for p,o,v in chunk if p in tablepcs]==loads;load_count+=len(loads)
            service=[(p,v) for p,o,v in chunk if p in [0x1013d40,0x1013d4e,0x1013d52,0x1013d54,0x1013e06,0x1013e14]]
            assert service==([(0x1013d40,depth),(0x1013d4e,depth),(0x1013d52,depth+1),(0x1013d54,1),(0x1013e06,depth+1),(0x1013e14,depth)] if r else [])
            mmio=[(p,'read' if o=='ldw.di' else 'write',v&65535) for p,o,v in chunk if p in [0x1014b58,0x1014ba8,0x1014bb0,0x1014bb8,0x1014bc0]]
            assert mmio==[(p,o,v) for p,o,a,v in ev]
            for pc,op,a,v in ev:
                if op=='write':state[a]=v
                counts[op]+=1;rows[a].append(dict(case=c['name'],call_ordinal=ordinal,entry='0x1014b08',selector=hex(key),pc=pc,operation=op,address=a,value=v))
                operations[a][key]=dict(entry='0x1014b08',selector=hex(key),original_table=hex(r['table']),record_index=r['index'],
                                        software_operation='one_hot_store' if a==tables[0]['ack'] else 'nonzero_set_zero_clear',bit=r['ack_bit'] if a==tables[0]['ack'] else r['mask_bit'],physical_meaning='unknown')
            expected.extend(ev)
        assert set(seen)==set(by_key) and len(seen)==15
        assert [x['arguments'][0] for x in c['original_calls'][-5:]]==[0,0x3000,0x3008,0x4000,0x4009]
        jl=re.findall(r'mov r12,(0x[0-9a-f]+)\njl \[r12\]\ncmp r0,(0x[0-9a-f]+)\nbne fail',asm)
        assert [(int(e,0),int(v,0)) for e,v in jl]==[(x['entry'],x['return0']) for x in c['original_calls']]
        err=src/(c['name']+'.stderr.log');inputs[str(err)]=sha(err)
        raw=[json.loads(x.removeprefix('S33_MEM ')) for x in err.read_text().splitlines() if x.startswith('S33_MEM ')]
        done=[x for x in raw if x['stage']=='result'];assert done==c['completed_memory_events'] and len(raw)==74
        assert [(x['pc'],x['operation'],x['address'],x['value']) for x in done]==expected
        for b,e in zip(raw[::2],raw[1::2]):
            assert b['stage']=='begin' and e['stage']=='result' and b['width_bytes']==e['width_bytes']==2
            assert all(b[k]==e[k] for k in ['id','pc','operation','address'])
        for key,f in c['fixtures'].items():
            a=int(key,0);off=a%8;before=bytes.fromhex(f['before']);after=(src/f['file']).read_bytes()
            assert struct.unpack_from('<H',before,off)[0]==(c['seed']^(a>>2))&65535
            assert struct.unpack_from('<H',after,off)[0]==state[a] and all(before[j]==after[j] for j in range(8) if j not in [off,off+1])
        total_loads+=load_count;checks.append(dict(case=c['name'],valid_selectors=15,no_match_selectors=5,original_calls=20,mmio_events=37,table_loads=load_count,nested_services_completed=15))
    assert len(checks)==12 and counts==dict(write=264,read=180) and set(rows)=={0xfed3818,0xfed3814,0xfed3830}
    known={r['number'] for r in load(parent/'register_map.json')['records'] if r['space']=='soc_mmio'};assert not set(rows)&known
    save(src/'tbib_delegated_table_audit.json',dict(status='PASS_TBIB_DELEGATED_TABLE_AUDIT',date='2026-10-26',checks=checks,tables=tables,
        contexts=contexts,table_load_checks=total_loads,operation_counts=dict(counts),unused_header_address_not_admitted='0xfed3834',
        outer_caller_executed=False,instructions={hex(k):v for k,v in decoded.items()},input_sha256=inputs,hardware_access=False,limits=d['limits']))
    publish(parent=parent,source=src,copy_files=[(src/'verified_evidence.json','tbib_delegated_table_cpu.json'),(src/'tbib_delegated_table_audit.json','tbib_delegated_table_audit.json')],
        rows=rows,operations={a:list(v.values()) for a,v in operations.items()},input_hashes=inputs,
        scripts=[Path(__file__),Path(__file__).with_name('s33_verify_tbib_delegated_table.py'),Path(__file__).with_name('s33_tbib_nested_context_harness.py')],
        validation=dict(date='2026-10-26',status='PASS_TBIB_DELEGATED_TABLE_NO_COVERAGE_REGRESSION',new_scalar_mmio_addresses=3,enriched_scalar_mmio_addresses=0,
                        selected_scenarios=12,trace_identical_pairs=12,original_table_records=15,original_calls_per_scenario=20,guest_MMIO_events=444,
                        operation_counts=dict(counts),table_load_checks=total_loads,nested_services_completed=180,outer_caller_executed=False,limits=d['limits']),
        next_work=['Complete originalouter1014BCC/4C64 andothercategorydelegates;distinguish RAMcallbackslots fromMMIO andtrace real registration paths.',
                   'FullTBIBcensusOOBgap,AUXindirect/overlay,BCR/SoC/DSPphysicalmap remainopen.'])

if __name__=='__main__':main()
