#!/usr/bin/env python3
"""Audit original selector searches, nested services and effective MMIO targets."""
import argparse,json,re,struct
from collections import Counter,defaultdict
from pathlib import Path
from s33_integrate_ffc7000_table_tail import ROOT,load,save,sha
from s33_verify_sensor_mmio_dialog import aligned_window
from s33_publish_mmio_accessor_evidence import publish

def elf_symbols(path):
    b=path.read_bytes();h=struct.unpack_from('<16sHHIIIIIHHHHHH',b)
    sections=[struct.unpack_from('<10I',b,h[6]+i*h[11]) for i in range(h[12])];symbols={}
    for s in sections:
        if s[1]!=2:continue
        strings=sections[s[6]];names=b[strings[4]:strings[4]+strings[5]]
        for o in range(s[4],s[4]+s[5],s[9]):
            n,value,size,info,other,index=struct.unpack_from('<IIIBBH',b,o)
            if n:symbols[names[n:names.index(0,n)].decode()]=(value,index)
    return b,sections,symbols

def main():
    ap=argparse.ArgumentParser(description=__doc__);ap.add_argument('source',type=Path);src=ap.parse_args().source.resolve()
    d=load(src/'verified_evidence.json');assert d['status']=='PASS_ORIGINAL_TBIB_SELECTOR_TABLES'
    parent=Path(d['parent_atlas']);info=d['payload'];body=Path(info['path']).read_bytes();base=info['base']
    assert body==(ROOT/'OriginalSoftware_NikonS33_V1.1/firmware.bin').read_bytes()[0x7c:0x7c+info['size']]
    inputs={**d['input_hashes'],str(src/'verified_evidence.json'):sha(src/'verified_evidence.json'),str(Path(__file__)):sha(Path(__file__))}
    assert all(sha(Path(k))==v for k,v in inputs.items()) and all(sha(src/k)==v for k,v in d['files'].items())
    for p in [ROOT/'work/build-arc/binutils/objdump',ROOT/'work/build-arc/binutils/objcopy',Path(__file__).with_name('s33_verify_sensor_mmio_dialog.py')]:inputs[str(p)]=sha(p)
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
    assert word(0x100478c)==0x1043480 and word(0x104126c)==0
    tables=[];by_key={}
    for j,pointer in enumerate(struct.unpack_from('<4I',body,0x1043480-base)):
        ack,mask,count=struct.unpack_from('<IIH',body,pointer-base);records=[]
        for i in range(count):
            key,ab,mb,callback=struct.unpack_from('<HBBI',body,pointer-base+12+8*i)
            record=dict(key=key,ack_bit=ab,mask_bit=mb,callback=callback,index=i,table_index=j,table=pointer,
                        address=pointer+12+8*i,firmware_offset=0x7c+pointer-base+12+8*i)
            assert ab==mb and ab<16 and callback==0 and key not in by_key
            by_key[key]=record;records.append(record)
        tables.append(dict(pointer=pointer,ack=ack,mask=mask,count=count,records=records))
    assert [t['count'] for t in tables]==[16,6,16,14] and len(by_key)==52
    assert {k&0xff00 for k in by_key}=={0x400,0x500,0x600,0x900}
    mask_pools={0x400:0x100489c,0x500:0x10048a0,0x600:0x1004802,0x900:0x10048a4}
    for key,pc in mask_pools.items():
        ins=decode(pc);p=int(re.search(r';0x([0-9a-f]+)',ins['operands'])[1],16)
        assert ins['opcode']=='ld_s' and word(p)==next(r['table'] for k,r in by_key.items() if k&0xff00==key)
    exacts=[(0x100474a,'mov_s','r1,0'),(0x100474c,'mov_s','r2,0x4'),(0x100474e,'mov_s','r14,0'),
        (0x1004758,'add2_s','r13,r13,r1'),(0x100475a,'ld_s','r3,[r13,0]'),(0x100475c,'ldh.di','r15,[r3,8]'),
        (0x1004766,'add3_s','r3,r3,r14'),(0x1004768,'ldh.di','r3,[r3,12]'),(0x100476c,'cmp_s','r0,r3'),
        (0x1004794,'ld_s','r0,[r13,0]'),(0x1004796,'ld.di','r2,[r0]'),(0x100479a,'add3_s','r0,r0,r14'),
        (0x100479c,'ldb.di','r1,[r0,14]'),(0x10047a0,'mov_s','r0,0'),(0x10047a2,'bset','r0,r0,r1'),
        (0x10047a6,'extw_s','r0,r0'),(0x10047a8,'sth.di','r0,[r2]'),
        (0x10047d0,'and','r1,r0,0xff00'),(0x10048c4,'ldh.di','r1,[r13,8]'),(0x10048ce,'add3','r14,r13,r2'),
        (0x10048d2,'ldh.di','r1,[r14,12]'),(0x10048d6,'cmp_s','r0,r1'),(0x10048de,'cmp_s','r15,0'),
        (0x10048e0,'ld.di','r1,[r13,4]'),(0x10048e4,'ldb.di','r0,[r14,15]'),(0x10048ec,'ldh.di','r10,[r1]'),
        (0x10048f0,'bset','r10,r10,r0'),(0x10048f4,'sth.di','r10,[r1]'),
        (0x10049ae,'ldh.di','r10,[r1]'),(0x10049b2,'bclr','r10,r10,r0'),(0x10049b6,'sth.di','r10,[r1]'),
        (0x1013d3c,'ld_s','r1,[r1,0]'),(0x1013d3e,'ld_s','r2,[r1,0x1c]'),(0x1013d40,'ld_s','r2,[r2,0x68]'),
        (0x1013d42,'cmp_s','r2,0'),(0x1013d4e,'ld_s','r0,[r2,0x68]'),(0x1013d50,'add_s','r0,r0,0x1'),
        (0x1013d52,'st_s','r0,[r2,0x68]'),(0x1013d54,'ldw_s','r0,[r1,0x18]'),
        (0x1013e06,'ld_s','r0,[r2,0x68]'),(0x1013e0c,'sub.f','r0,r0,0x1'),(0x1013e14,'st_s','r0,[r2,0x68]')]
    for x in exacts:exact(*x)
    exact(0x1013e10,'jne.d','[blink]');assert word(0x1013d64)==0x104126c
    assert word(0x10048ac)==word(0x1004ba8)==0x200601
    rows=defaultdict(list);operations=defaultdict(dict);checks=[];counts=Counter();total_table_loads=0;contexts=[]
    for c in d['cases']:
        assert c['exit_code']==0 and c['fault'] is None and c['original_calls_completed'] and c['runtime_global_restored']
        if not c['observer_enabled']:continue
        tp=src/(c['name']+'.trace');inputs[str(tp)]=sha(tp)
        assert tp.read_bytes()==(src/(c['name'].replace('_observed','_reference')+'.trace')).read_bytes()
        stem=c['name'].removesuffix('_observed');elf=src/(stem+'.elf');asm=(src/(stem+'.s')).read_text()
        b,sections,symbols=elf_symbols(elf);ctx,si=symbols['context'];task,ti=symbols['task'];nest,ni=symbols['nesting']
        section=sections[si];depth=c['nesting_depth'];assert depth in [1,2,7] and si==ti==ni and task==ctx+32 and nest==task+104
        off=section[4]+ctx-section[3];expected_ctx=bytes(24)+struct.pack('<HHI',1,0,task)+bytes(104)+struct.pack('<I',depth)
        assert section[1]==1 and b[off:off+len(expected_ctx)]==expected_ctx
        contexts.append(dict(case=c['name'],context=hex(ctx),task=hex(task),nesting=hex(nest),depth=depth,global_pointer='0x104126c',restored_to=0))
        chunks=[];global_stores=[];initial_global=[]
        for line in tp.read_text().splitlines():
            m=re.match(r'0x([0-9a-f]+)\s+(\S+)\s+(.*)',line)
            if not m:continue
            pc=int(m[1],16);op=m[2];operand=m[3]
            assert op not in ['lr','sr','flag']
            value=re.search(r'<- (0x[0-9a-f]+)',line);value=int(value[1],16) if value else None
            if pc in [0x1004744,0x10047c8]:chunks.append([])
            if chunks:chunks[-1].append((pc,op,value))
            if base<=pc<base+len(body):
                ins=decode(pc)
                if op.startswith('st'):
                    assert pc in [0x10047a8,0x10048f4,0x10049b6,0x1013d52,0x1013e14,0x103e0e0,0x103e0e4,0x103e0e8],hex(pc)
            elif op=='st':
                assert 'r0,[0x0104126c,0]' in operand;global_stores.append(value)
            elif op=='ld' and '[0x0104126c,0]' in operand:initial_global.append(value)
        assert global_stores==[ctx,0] and initial_global==[0] and len(chunks)==len(c['original_calls'])==114
        state={int(k,0):struct.unpack_from('<H',bytes.fromhex(v['before']),int(k,0)%8)[0] for k,v in c['fixtures'].items()}
        expected=[];seen=Counter();invalid=[];table_count=0
        for ordinal,(call,chunk) in enumerate(zip(c['original_calls'],chunks)):
            entry=call['entry'];key=call['arguments'][0];r=by_key.get(key);loads=[];ev=[];ret=0 if r else 0x200601
            if entry==0x1004744:
                limit=r['table_index'] if r else 3
                for j,t in enumerate(tables[:limit+1]):
                    n=r['index']+1 if r and j==limit else t['count']+1
                    for i in range(n):
                        loads.extend([(0x1004756,0x1043480),(0x100475a,t['pointer']),(0x100475c,t['count'])])
                        if i<t['count']:loads.append((0x1004768,t['records'][i]['key']))
                if r:
                    t=tables[r['table_index']];a=t['ack'];v=2**r['ack_bit']
                    loads.extend([(0x1004794,t['pointer']),(0x1004796,a),(0x100479c,r['ack_bit'])]);ev=[(0x10047a8,'write',a,v)]
            else:
                assert entry==0x10047c8 and call['arguments'][1]==c['flag']
                cat=key&0xff00;t=next((t for t in tables if t['records'][0]['key']&0xff00==cat),None)
                if t:
                    loads.append((mask_pools[cat],t['pointer']))
                    n=r['index']+1 if r else t['count']+1
                    for i in range(n):
                        loads.append((0x10048c4,t['count']))
                        if i<t['count']:loads.append((0x10048d2,t['records'][i]['key']))
                if r:
                    a=t['mask'];old=state[a];on=c['flag']!=0
                    v=sum((int(on) if i==r['mask_bit'] else ((old>>i)&1))<<i for i in range(16))
                    pc=0x10048ec if on else 0x10049ae
                    loads.extend([(0x10048e0,a),(0x10048e4,r['mask_bit'])]);ev=[(pc,'read',a,old),(pc+8,'write',a,v)]
            assert call['return0']==ret and ev==[tuple(x) for x in call['events']]
            marker=f'mov r12,{entry:#x}\njl [r12]\n'
            # Every call has exactly the expected immediate return check.
            assert asm.count(marker)==57
            tablepcs={0x1004756,0x100475a,0x100475c,0x1004768,0x1004794,0x1004796,0x100479c,0x10048c4,0x10048d2,0x10048e0,0x10048e4,*mask_pools.values()}
            actual_loads=[(p,v) for p,o,v in chunk if p in tablepcs]
            assert actual_loads==loads,(c['name'],ordinal,actual_loads,loads)
            table_count+=len(loads)
            service=[(p,v) for p,o,v in chunk if p in [0x1013d40,0x1013d4e,0x1013d52,0x1013d54,0x1013e06,0x1013e14]]
            expected_service=[(0x1013d40,depth),(0x1013d4e,depth),(0x1013d52,depth+1),(0x1013d54,1),(0x1013e06,depth+1),(0x1013e14,depth)] if r else []
            assert service==expected_service
            actual_mmio=[(p,'read' if o=='ldw.di' else 'write',v&65535) for p,o,v in chunk if p in [0x10047a8,0x10048ec,0x10048f4,0x10049ae,0x10049b6]]
            assert actual_mmio==[(p,o,v) for p,o,a,v in ev],(c['name'],ordinal,actual_mmio,ev)
            if r:
                assert call['table']==r['table'] and call['record_index']==r['index'];seen[key]+=1
                descriptor=dict(entry=hex(entry),selector=hex(key),original_table=hex(r['table']),record_index=r['index'],
                                bit=r['ack_bit'] if entry==0x1004744 else r['mask_bit'],software_operation=call['kind'],physical_meaning='unknown')
                for pc,op,a,v in ev:
                    if op=='write':state[a]=v
                    rows[a].append(dict(case=c['name'],call_ordinal=ordinal,entry=hex(entry),selector=hex(key),pc=pc,operation=op,address=a,value=v));counts[op]+=1
                    operations[a][entry,key]=descriptor
            else:invalid.append((entry,key))
            expected.extend(ev)
        assert set(seen)==set(by_key) and set(seen.values())=={2}
        assert invalid==[(e,k) for k in [0,0x411,0x504,0x908,0x909] for e in [0x1004744,0x10047c8]]
        # Independently bind every call's return assertion to the corresponding JL.
        jl_checks=re.findall(r'mov r12,(0x[0-9a-f]+)\njl \[r12\]\ncmp r0,(0x[0-9a-f]+)\nbne fail',asm)
        assert [(int(e,0),int(v,0)) for e,v in jl_checks]==[(x['entry'],x['return0']) for x in c['original_calls']]
        err=src/(c['name']+'.stderr.log');inputs[str(err)]=sha(err)
        raw=[json.loads(x.removeprefix('S33_MEM ')) for x in err.read_text().splitlines() if x.startswith('S33_MEM ')]
        done=[x for x in raw if x['stage']=='result'];assert done==c['completed_memory_events'] and len(raw)==312
        assert [(x['pc'],x['operation'],x['address'],x['value']) for x in done]==expected
        for b,e in zip(raw[::2],raw[1::2]):
            assert b['stage']=='begin' and e['stage']=='result' and b['width_bytes']==e['width_bytes']==2
            assert all(b[k]==e[k] for k in ['id','pc','operation','address'])
        for key,f in c['fixtures'].items():
            a=int(key,0);off=a%8;before=bytes.fromhex(f['before']);after=(src/f['file']).read_bytes()
            assert struct.unpack_from('<H',before,off)[0]==(c['seed']^(a>>2))&65535
            assert struct.unpack_from('<H',after,off)[0]==state[a] and all(before[j]==after[j] for j in range(8) if j not in [off,off+1])
        total_table_loads+=table_count
        checks.append(dict(case=c['name'],original_calls=114,table_selector_matches=104,invalid_returns=10,table_loads=table_count,
                           nested_services_completed=104,mmio_events=len(expected),runtime_global_restored=True))
    assert len(checks)==12 and dict(counts)==dict(write=1248,read=624) and len(rows)==8
    known={r['number'] for r in load(parent/'register_map.json')['records'] if r['space']=='soc_mmio'}
    assert len(set(rows)-known)==6 and set(rows)&known=={0xfef0050,0xfef0328}
    audit=dict(status='PASS_TBIB_SELECTOR_TABLES_AUDIT',date='2026-10-25',checks=checks,operation_counts=dict(counts),tables=tables,
        context_fixtures=contexts,table_load_checks=total_table_loads,instructions={hex(k):v for k,v in decoded.items()},input_sha256=inputs,
        hardware_access=False,limits=d['limits'])
    save(src/'tbib_selector_tables_audit.json',audit)
    publish(parent=parent,source=src,copy_files=[(src/'verified_evidence.json','tbib_selector_tables_cpu.json'),(src/'tbib_selector_tables_audit.json','tbib_selector_tables_audit.json')],
        rows=rows,operations={a:list(v.values()) for a,v in operations.items()},input_hashes=inputs,scripts=[Path(__file__),Path(__file__).with_name('s33_verify_tbib_selector_tables.py')],
        validation=dict(status='PASS_TBIB_SELECTOR_TABLES_NO_COVERAGE_REGRESSION',new_scalar_mmio_addresses=6,enriched_scalar_mmio_addresses=2,
                        selected_scenarios=12,trace_identical_pairs=12,original_table_records=52,original_calls_per_scenario=114,guest_MMIO_events=1872,
                        operation_counts=dict(counts),table_load_checks=total_table_loads,nested_services_completed=1248,limits=d['limits']),
        next_work=['Trace other originalselector category delegates1014BCC..1015E50 andinitializer100559C;non-nested FLAG/IRQpaths remainunproved.',
                   'FullTBIBcensusOOBgap,AUXindirect/overlay,BCR/SoC/DSPphysicalmap remainopen.'])

if __name__=='__main__':main()
