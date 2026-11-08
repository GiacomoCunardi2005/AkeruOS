#!/usr/bin/env python3
"""Independently audit original byte-table wrappers, loads and MMIO stores."""
import argparse,json,re,struct
from collections import defaultdict
from pathlib import Path
from s33_integrate_ffc7000_table_tail import ROOT,load,save,sha
from s33_verify_sensor_mmio_dialog import aligned_window
from s33_publish_mmio_accessor_evidence import publish

def main():
    ap=argparse.ArgumentParser(description=__doc__);ap.add_argument('source',type=Path);src=ap.parse_args().source.resolve()
    d=load(src/'verified_evidence.json');assert d['status']=='PASS_ORIGINAL_TBIB_BYTE_CONFIG'
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
    def word(p):return int.from_bytes(body[p-base:p-base+4],'little')
    entries=[0x10056c4,0x10056cc]
    for pc,pool in [(0x10056c4,0x10056ec),(0x10056cc,0x10056f4)]:
        exact(pc,'ld_s',f'r0,[pcl,0x28]\t;{hex(pool)}')
        exact(pc+2,'b.d',f'{0x10053a8-((pc+2)&~3)}\t;0x10053a8')
    exact(0x10056ca,'ld_s','r1,[pcl,0x28]\t;0x10056f0')
    exact(0x10056d2,'ld_s','r1,[pcl,0x20]\t;0x10056f0')
    exact(0x10053a8,'push_s','blink');exact(0x10053aa,'bl','232764\t;0x103e0e4')
    exact(0x10053ae,'mov_s','r14,r1');exact(0x10053b2,'mov_s','r13,r0')
    exact(0x10054a4,'b','232620\t;0x103e150')
    stores=[0x10053c4+20*i for i in range(10)]+[0x100548c,0x10054a0]
    # Store9 is separated by the same 20-byte pattern; store10 changes source register.
    assert stores[9]==0x1005478
    poolloads=[0x10053b6]+[p-12 for p in stores[1:]]
    bytepcs=[(0x10053b0,0x10053b4)]+[(p-16,p-14) for p in stores[1:]]
    addresses=[word(p-4) for p in stores]
    assert addresses==[0xfee0004+4*i for i in range(9)]+[0xfee054c,0xfee05c4,0xfe10004]
    for i,(pc,ld,(hi,lo),a) in enumerate(zip(stores,poolloads,bytepcs,addresses)):
        reg='r2' if i<10 else 'r0';src_reg='r0' if i<10 else 'r1'
        exact(pc,'sth.di',f'{src_reg},[{reg}]')
        pool=pc-4;inst=decode(ld);assert inst['opcode']=='ld_s' and inst['operands'].startswith(reg+',[pcl,') and inst['operands'].endswith(';'+hex(pool))
        highreg='r1' if i in [0,10] else 'r2' if i==11 else 'r0'
        lowreg='r0' if i==0 else 'r2' if i==10 else 'r1'
        pointerreg='r0' if i==0 else 'r14' if i==11 else 'r13'
        off=0 if i==11 else 2*i
        exact(hi,'ldb_s',f'{highreg},[{pointerreg},{hex(off+1)}]')
        exact(lo,'ldb_s',f'{lowreg},[{pointerreg},{hex(off) if off else "0"}]')
        padding=2 if i==0 else 0
        exact(pc-10-padding,'asl_s',f'{highreg},{highreg},0x8')
        exact(pc-8-padding,'or_s',f'{src_reg},{src_reg},{highreg if src_reg==lowreg else lowreg}')
        exact(pc-6-padding,'b_s',f'{8 if i else 8}\t;{hex(pc)}')
    rows=defaultdict(list);operations=defaultdict(list);checks=[];tables=[]
    for c in d['cases']:
        assert c['exit_code']==0 and c['fault'] is None and c['original_calls_completed']
        if not c['observer_enabled']:continue
        tp=src/(c['name']+'.trace');inputs[str(tp)]=sha(tp)
        assert tp.read_bytes()==(src/(c['name'].replace('_observed','_reference')+'.trace')).read_bytes()
        assert [x['entry'] for x in c['original_calls']]==entries
        expected=[];byte_reads=[];pcl=[];final={}
        for n,(entry,pool) in enumerate(zip(entries,[0x10056ec,0x10056f4])):
            ptr=word(pool);common=word(0x10056f0);call=c['original_calls'][n]
            assert call['arguments']==[] and call['original_data_pointer']==ptr and call['original_common_pointer']==common
            assert ptr in [0x1042874,0x104288c] and common==0x104120a
            pcl.extend([(entry,ptr),(entry+6,common)])
            ev=[]
            for i,(pc,ld,(hi,lo),a) in enumerate(zip(stores,poolloads,bytepcs,addresses)):
                q=ptr+2*i if i<11 else common;low,high=body[q-base:q-base+2]
                value=high*256+low;ev.append((pc,'write',a,value));final[a]=value
                byte_reads.extend([(hi,high),(lo,low)]);pcl.append((ld,a))
                rows[a].append(dict(case=c['name'],entry=hex(entry),pc=pc,operation='write',address=a,value=value))
                if c['seed']==0:
                    operations[a].append(dict(entry=hex(entry),writer='0x10053a8',software_operation='assemble_two_bytes_low_plus_256_times_high',
                                              input_address=hex(q),firmware_offset=hex(0x7c+q-base),input_bytes=bytes([low,high]).hex(),value=hex(value),physical_meaning='unknown'))
            assert ev==[tuple(x) for x in call['events']];expected.extend(ev)
            if c['seed']==0:tables.append(dict(wrapper=hex(entry),data_pointer=hex(ptr),common_pointer=hex(common),values=[x[3] for x in ev]))
        actual_entries=[];actual_bytes=[];actual_pcl=[];actual_mmio=[];writer_entries=0;returns=0
        for line in tp.read_text().splitlines():
            m=re.match(r'0x([0-9a-f]+)\s+(\S+)\s+(.*)',line)
            if not m:continue
            pc=int(m[1],16);op=m[2];assert op not in ['lr','sr']
            if pc in entries:actual_entries.append(pc)
            if pc==0x10053a8:writer_entries+=1
            if pc==0x10054a4:returns+=1
            if 0x10053a8<=pc<=0x10054a4 or pc in [x+o for x in entries for o in [0,2,6]]:
                inst=decode(pc)
                value=re.search(r'<- (0x[0-9a-f]+)',line)
                if op=='ldb_s':actual_bytes.append((pc,int(value[1],16)))
                if op=='ld_s' and '[pcl,' in inst['operands']:actual_pcl.append((pc,int(value[1],16)))
            if op in ['ldw.di','stw.di']:
                assert op=='stw.di';actual_mmio.append((pc,int(re.search(r'<- (0x[0-9a-f]+)',line)[1],16)))
        assert actual_entries==entries and writer_entries==returns==2
        assert actual_bytes==byte_reads and len(actual_bytes)==48 and actual_pcl==pcl and len(pcl)==28
        assert actual_mmio==[(p,v) for p,op,a,v in expected]
        err=src/(c['name']+'.stderr.log');inputs[str(err)]=sha(err)
        raw=[json.loads(x.removeprefix('S33_MEM ')) for x in err.read_text().splitlines() if x.startswith('S33_MEM ')]
        done=[x for x in raw if x['stage']=='result'];assert done==c['completed_memory_events'] and len(raw)==48
        assert [(x['pc'],x['operation'],x['address'],x['value']) for x in done]==expected
        for begin,end in zip(raw[::2],raw[1::2]):
            assert begin['stage']=='begin' and end['stage']=='result' and begin['width_bytes']==end['width_bytes']==2
            assert all(begin[k]==end[k] for k in ['id','pc','operation','address'])
        for key,f in c['fixtures'].items():
            a=int(key,0);off=a%8;before=bytes.fromhex(f['before']);after=(src/f['file']).read_bytes()
            assert struct.unpack_from('<H',before,off)[0]==(c['seed']^(a>>2))&65535
            assert struct.unpack_from('<H',after,off)[0]==final[a] and all(before[j]==after[j] for j in range(8) if j not in [off,off+1])
        checks.append(dict(case=c['name'],mmio_writes=24,original_byte_reads=48,pcl_loads=28,original_wrappers_completed=2))
    assert len(checks)==3 and len(rows)==12
    known={r['number'] for r in load(parent/'register_map.json')['records'] if r['space']=='soc_mmio'}
    assert len(set(rows)-known)==11 and set(rows)&known=={0xfe10004}
    save(src/'tbib_byte_config_audit.json',dict(status='PASS_TBIB_BYTE_CONFIG_AUDIT',date='2026-10-25',checks=checks,tables=tables,
        instructions={hex(k):v for k,v in decoded.items()},input_sha256=inputs,hardware_access=False,limits=d['limits']))
    publish(parent=parent,source=src,copy_files=[(src/'verified_evidence.json','tbib_byte_config_cpu.json'),(src/'tbib_byte_config_audit.json','tbib_byte_config_audit.json')],
            rows=rows,operations=operations,input_hashes=inputs,scripts=[Path(__file__),Path(__file__).with_name('s33_verify_tbib_byte_config.py')],
            validation=dict(status='PASS_TBIB_BYTE_CONFIG_NO_COVERAGE_REGRESSION',new_scalar_mmio_addresses=11,enriched_scalar_mmio_addresses=1,
                            original_wrappers=2,original_writer='0x10053a8',selected_scenarios=3,trace_identical_pairs=3,guest_MMIO_events=72,
                            operation_counts=dict(read=0,write=72),original_byte_load_checks=144,original_pool_load_checks=84,limits=d['limits']),
            next_work=['Follow original selector/tablegroups1004744/10047C8 andinitializer100559C without replacing services or inventingMMIOtargets.',
                       'Retain fullTBIBcensusOOBgap;AUXindirect/overlay/BCR/SoC/DSPphysicalmap incomplete.'])

if __name__=='__main__':main()
