#!/usr/bin/env python3
"""Bind original BL/table, audit repeated table loads/RMW, publish scalar evidence."""
import argparse,json,re,struct
from collections import Counter,defaultdict
from pathlib import Path
from s33_integrate_ffc7000_table_tail import ROOT,load,save,sha
from s33_verify_sensor_mmio_dialog import aligned_window
from s33_verify_custom_aux_cfg import call_at
from s33_publish_mmio_accessor_evidence import publish


def main():
    ap=argparse.ArgumentParser(description=__doc__);ap.add_argument('source',type=Path);src=ap.parse_args().source.resolve()
    d=load(src/'verified_evidence.json');assert d['status']=='PASS_ORIGINAL_TBIB_MASKED_TABLE'
    parent=Path(d['parent_atlas']);info=d['payload'];body=Path(info['path']).read_bytes();base=info['base'];fw=ROOT/'OriginalSoftware_NikonS33_V1.1/firmware.bin'
    assert body==fw.read_bytes()[0x7c:0x7c+info['size']] and sha(Path(info['path']))==info['sha256']
    inputs={**d['input_hashes'],str(src/'verified_evidence.json'):sha(src/'verified_evidence.json'),str(Path(__file__)):sha(Path(__file__))}
    assert all(sha(Path(k))==v for k,v in inputs.items()) and all(sha(src/k)==v for k,v in d['files'].items())
    for p in [ROOT/'work/build-arc/binutils/objdump',ROOT/'work/build-arc/binutils/objcopy',Path(__file__).with_name('s33_verify_sensor_mmio_dialog.py'),Path(__file__).with_name('s33_verify_custom_aux_cfg.py')]:inputs[str(p)]=sha(p)
    decoded={}
    def decode(pc):
        if pc not in decoded:
            text=aligned_window(body,base,pc,pc+12);line=next(x for x in text.splitlines() if re.match(r'\s*'+f'{pc:x}:',x))
            m=re.match(r'\s*[0-9a-f]+:\s+((?:[0-9a-f]{4}\s+)+)\t(\S+)\s*(.*)',line)
            raw=b''.join(bytes.fromhex(w)[::-1] for w in m[1].split());assert raw==body[pc-base:pc-base+len(raw)]
            decoded[pc]=dict(opcode=m[2],operands=m[3].strip(),bytes_hex=raw.hex())
        return decoded[pc]
    def exact(pc,op,args):assert (decode(pc)['opcode'],decode(pc)['operands'])==(op,args),(hex(pc),decode(pc))
    for pc,op,args in [(0x1004440,'push_s','blink'),(0x1004442,'bl.d','40\t;0x1004468'),(0x1004446,'ld_s','r0,[pcl,0x14]\t;0x1004458'),
        (0x1004476,'mov_s','r15,r0'),(0x1004478,'mov_s','r14,0'),(0x1004488,'and','r0,r0,-1024'),(0x100448c,'or','r0,r0,682'),
        (0x1004496,'add3','r13,r15,r14'),(0x100449a,'ld_s','r0,[r13,0]'),(0x100449c,'cmp_s','r0,0'),(0x100449e,'beq','34\t;0x10044be'),
        (0x10044a2,'ldh.di','r0,[r0]'),(0x10044a6,'ldw_s','r1,[r13,0x4]'),(0x10044a8,'ldw_s','r2,[r13,0x6]'),
        (0x10044aa,'bic_s','r0,r0,r1'),(0x10044ac,'and_s','r1,r1,r2'),(0x10044ae,'or_s','r0,r0,r1'),
        (0x10044b0,'ld_s','r1,[r13,0]'),(0x10044b4,'sth.di','r0,[r1]'),(0x10044b8,'add_s','r14,r14,0x1'),(0x10044ba,'b','-34\t;0x1004496')]:exact(pc,op,args)
    assert call_at(body,0x1004442-base,base)['target']==0x1004468
    table=struct.unpack_from('<I',body,0x1004458-base)[0];assert table==0x1043258
    table_rows=[]
    for i in range(256):
        address,mask,value=struct.unpack_from('<IHH',body,table-base+8*i)
        if address==0:break
        table_rows.append(dict(index=i,table_address=hex(table+8*i),firmware_offset=hex(0x7c+table-base+8*i),address=address,mask=mask,value=value))
    assert i==68 and len(table_rows)==68 and len({r['address'] for r in table_rows})==44
    for pc,op,args in [(0x10045cc,'bclr','r10,r10,r0'),(0x10045e8,'bset','r10,r10,r0'),(0x1004604,'lsr_s','r0,r0'),
        (0x1004606,'bxor','r0,r0,0'),(0x100460a,'bmsk_s','r0,r0,0'),(0x1004624,'lsr_s','r0,r0,0x8'),
        (0x1004626,'bxor','r0,r0,0'),(0x100462a,'bmsk_s','r0,r0,0'),(0x1004640,'lsr_s','r0,r0,0x5'),(0x1004642,'bmsk_s','r0,r0,0'),
        (0x100465a,'cmp_s','r0,0x1'),(0x1004660,'cmp_s','r13,0x4'),(0x1004674,'bset','r10,r10,r0'),(0x1004690,'bclr','r10,r10,r0'),
        (0x100469a,'mov_s','r14,0x1'),(0x10046be,'cmp_s','r0,0x1'),(0x10046c2,'cmp_s','r13,0x2'),
        (0x10046d8,'bset','r10,r10,r14'),(0x10046f0,'bclr','r10,r10,r14'),(0x10046fa,'mov_s','r14,0x1')]:exact(pc,op,args)
    entries=[0x1004568,0x1004580,0x10045f4,0x10045bc,0x10045f4,0x10045d8,0x10045f4,0x1004614,0x1004630,0x1004648,0x10046ac,
        0x1004468,0x10045f4,0x1004614,0x1004568,0x1004580]
    rows=defaultdict(list);operations=defaultdict(dict);checks=[];counts=Counter();table_checks=[];pools=[];initial_final=[]
    for c in d['cases']:
        assert c['exit_code']==0 and c['fault'] is None and c['original_calls_completed']
        if not c['observer_enabled']:continue
        trace_path=src/(c['name']+'.trace');inputs[str(trace_path)]=sha(trace_path);trace=trace_path.read_text()
        assert trace_path.read_bytes()==(src/(c['name'].replace('_observed','_reference')+'.trace')).read_bytes()
        assembly=(src/(c['name'].removesuffix('_observed')+'.s')).read_text()
        state={int(k,0):struct.unpack_from('<H',bytes.fromhex(f['before']),int(k,0)%8)[0] for k,f in c['fixtures'].items()}
        assert len(state)==44 and [x['entry'] for x in c['original_calls']]==entries
        expected=[];expected_loads=[];observed_by_call=[];v=c['value'];initial_0144=state[0xfef0144]
        for ordinal,call in enumerate(c['original_calls']):
            e=call['entry'];ret=None;ev=[];desc=[]
            if e==0x1004468:
                assert call['arguments']==[table] and call['table_record_count']==68
                assert call['original_table_records']==[[r[k] for k in ['address','mask','value']] for r in table_rows]
                old=state[0xfef0144];initial_field=(old//1024)*1024+682
                ev.extend([(0x1004484,'read',0xfef0144,old),(0x1004492,'write',0xfef0144,initial_field)]);state[0xfef0144]=initial_field
                desc.append((0xfef0144,-1,dict(entry=hex(e),phase='pre_table_force_low10',mask='0x3ff',value='0x2aa',physical_meaning='unknown')))
                for record in table_rows:
                    a,mask,value=record['address'],record['mask'],record['value'];old=state[a]
                    new=sum(((((value if mask&(1<<bit) else old)>>bit)&1)<<bit) for bit in range(16))
                    ev.extend([(0x10044a2,'read',a,old),(0x10044b4,'write',a,new)]);state[a]=new
                    expected_loads.extend([(0x100449a,a),(0x10044a6,mask),(0x10044a8,value),(0x10044b0,a)])
                    desc.append((a,record['index'],dict(entry=hex(e),phase='original_table_record',record_index=record['index'],table_address=record['table_address'],
                        mask=hex(mask),value=hex(value),physical_meaning='unknown')))
                expected_loads.append((0x100449a,0));initial_final.append(dict(case=c['name'],initial_read=initial_0144,pre_table_write=initial_field,final_value=state[0xfef0144]))
            else:
                assert call['arguments']==[v]
                if e in [0x1004568,0x1004580,0x10045f4,0x1004614,0x1004630]:
                    a,bit,inverse={0x1004568:(0xff04020,15,False),0x1004580:(0xff04024,0,False),0x10045f4:(0xfef00d8,1,True),
                        0x1004614:(0xff04000,8,True),0x1004630:(0xff04000,5,False)}[e]
                    old=state[a];ret=int(bool(old&(1<<bit)))^int(inverse);ev=[(e+12,'read',a,old)]
                elif e in [0x10045bc,0x10045d8]:
                    a=0xfef00d8;old=state[a];new=(old|2) if e==0x10045d8 else old-(old&2)
                    ev=[(e+12,'read',a,old),(e+20,'write',a,new)]
                elif e==0x1004648:
                    ret=int(v not in [1,4]);a=0xff04004
                    if not ret:
                        old=state[a];on=v==4;new=sum((int(on) if i==9 else ((old>>i)&1))<<i for i in range(16));pc=0x1004670 if on else 0x100468c
                        ev=[(pc,'read',a,old),(pc+8,'write',a,new)]
                elif e==0x10046ac:
                    ret=int(v not in [1,2]);a=0xfef00d8
                    if not ret:
                        old=state[a];on=v==1;new=sum((int(on) if i==0 else ((old>>i)&1))<<i for i in range(16));pc=0x10046d4 if on else 0x10046ec
                        ev=[(pc,'read',a,old),(pc+8,'write',a,new)]
                else:raise AssertionError(hex(e))
                if ev:desc.append((a,e,dict(entry=hex(e),software_operation=call['kind'],physical_meaning='unknown')))
            assert ret==call['return0'] and ev==[tuple(x) for x in call['events']]
            # Repeated getter calls: every occurrence is protected by a return check.
            if ret is not None:assert f'cmp r0,{ret:#x}\nbne fail\n' in assembly.split(f'mov r12,{e:#x}\njl [r12]\n',1)[1]
            for pc,op,a,val in ev:
                assert decode(pc)['opcode']==('ldh.di' if op=='read' else 'sth.di')
                if op=='write':state[a]=val
                rows[a].append(dict(case=c['name'],call_ordinal=ordinal,entry=hex(e),pc=pc,operation=op,address=a,value=val));counts[op]+=1
            for a,key,fields in desc:operations[a][e,key]=fields
            expected.extend(ev)
        actual_entries=[];actual_mmio=[];actual_loads=[];poolloads=[]
        for line in trace.splitlines():
            m=re.match(r'0x([0-9a-f]+)\s+(\S+)\s+(.*)',line)
            if not m:continue
            pc=int(m[1],16);op=m[2];assert op not in ['lr','sr']
            if pc in entries:actual_entries.append(pc)
            if op in ['ldw.di','stw.di']:actual_mmio.append((pc,'read' if op=='ldw.di' else 'write',int(re.search(r'<- (0x[0-9a-f]+)',line)[1],16)&65535))
            if pc in [0x100449a,0x10044a6,0x10044a8,0x10044b0]:
                assert op in ['ld_s','ldw_s'];actual_loads.append((pc,int(re.search(r'<- (0x[0-9a-f]+)',line)[1],16)))
            if 0x1004468<=pc<0x1004704 and op=='ld_s' and '[pcl,' in decode(pc)['operands']:
                p=int(re.search(r';(?:0x)?([0-9a-f]+)',decode(pc)['operands'])[1],16);word=struct.unpack_from('<I',body,p-base)[0]
                assert int(re.search(r'<- (0x[0-9a-f]+)',line)[1],16)==word and word in state;poolloads.append(dict(pc=hex(pc),pool=hex(p),value=hex(word)))
        assert actual_entries==entries and actual_mmio==[(p,o,v) for p,o,a,v in expected] and actual_loads==expected_loads and len(actual_loads)==273
        table_checks.append(dict(case=c['name'],word_and_halfword_loads=actual_loads,records=68,sentinel_address=hex(table+68*8),sentinel_value=0))
        err=src/(c['name']+'.stderr.log');inputs[str(err)]=sha(err)
        raw_events=[json.loads(line.removeprefix('S33_MEM ')) for line in err.read_text().splitlines() if line.startswith('S33_MEM ')]
        done=[e for e in raw_events if e['stage']=='result'];assert done==c['completed_memory_events'] and len(raw_events)==2*len(expected)
        assert [(e['pc'],e['operation'],e['address'],e['value']) for e in done]==expected
        for b,e in zip(raw_events[::2],raw_events[1::2]):
            assert b['stage']=='begin' and e['stage']=='result' and b['width_bytes']==e['width_bytes']==2
            assert all(b[k]==e[k] for k in ['id','pc','operation','address'])
        for key,f in c['fixtures'].items():
            a=int(key,0);off=a%8;before=bytes.fromhex(f['before']);after=(src/f['file']).read_bytes()
            assert struct.unpack_from('<H',before,off)[0]==(c['seed']^(a>>2))&65535
            assert struct.unpack_from('<H',after,off)[0]==state[a] and all(before[j]==after[j] for j in range(8) if j not in [off,off+1])
        checks.append(dict(case=c['name'],events=len(expected),pool_loads=len(poolloads),original_table_loads=273,original_calls=16));pools.extend(poolloads)
    assert len(checks)==18 and sum(counts.values())==2778 and len(rows)==44 and len(pools)==264
    known={r['number'] for r in load(parent/'register_map.json')['records'] if r['space']=='soc_mmio'}
    assert len(set(rows)-known)==42 and set(rows)&known=={0xff04020,0xff04024}
    for x in initial_final:assert x['pre_table_write']&0x3ff==0x2aa and x['final_value']&0x3ff==0x155
    audit=dict(status='PASS_ORIGINAL_TBIB_MASKED_TABLE_AUDIT',date='2026-10-25',checks=checks,operation_counts=dict(counts),
        original_table_rows=table_rows,table_sentinel_address=hex(table+68*8),table_load_checks=table_checks,pool_load_checks=pools,initial_final_0144=initial_final,
        original_caller=dict(pc='0x1004442',target='0x1004468',delay_slot='0x1004446',pointer_pool='0x1004458',table=hex(table),caller_executed=False),
        independently_redecoded_instructions={hex(k):v for k,v in decoded.items()},input_sha256=inputs,hardware_access=False,whole_physical_map_complete=False,limits=d['limits'])
    save(src/'tbib_mask_table_audit.json',audit)
    out=publish(parent=parent,source=src,copy_files=[(src/'verified_evidence.json','tbib_mask_table_cpu.json'),(src/'tbib_mask_table_audit.json','tbib_mask_table_audit.json')],
        rows=rows,operations={a:list(v.values()) for a,v in operations.items()},input_hashes=inputs,
        validation=dict(status='PASS_TBIB_ORIGINAL_MASK_TABLE_NO_COVERAGE_REGRESSION',new_scalar_mmio_addresses=42,enriched_scalar_mmio_addresses=2,
            original_routines=10,original_calls_per_scenario=16,original_table_rows=68,table_unique_addresses=44,selected_scenarios=18,trace_identical_pairs=18,
            guest_MMIO_events=2778,operation_counts=dict(counts),original_table_load_checks=4914,original_pool_load_checks=264,original_caller_executed=False,
            full_TBIB_boot_proven=False,limits=d['limits']),scripts=[Path(__file__),Path(__file__).with_name('s33_verify_tbib_mask_table.py')],
        next_work=['Continue originalTBIBgroups beyond1004704 and10053B0;seek further originaltablebindings,retainwholecensusOOBgap',
            'AUXindirect/overlay/code-data andBCR/SoC/DSPphysicalimplementation remainopen'])
    atlas=load(out/'register_map.json');assert len(atlas['records'])==1245 and atlas['counts']==dict(core=64,aux=200,soc_mmio=981)


if __name__=='__main__':main()
