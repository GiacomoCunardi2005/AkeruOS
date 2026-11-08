#!/usr/bin/env python3
"""Audit TBIB bit-index semantics, byte masks and pulse stores; publish evidence."""
import argparse,json,re,struct
from collections import Counter,defaultdict
from pathlib import Path
from s33_integrate_ffc7000_table_tail import ROOT,load,save,sha
from s33_verify_sensor_mmio_dialog import aligned_window
from s33_publish_mmio_accessor_evidence import publish


def main():
    ap=argparse.ArgumentParser(description=__doc__);ap.add_argument('source',type=Path);src=ap.parse_args().source.resolve()
    d=load(src/'verified_evidence.json');assert d['status']=='PASS_ORIGINAL_TBIB_FED20_TAIL'
    parent=Path(d['parent_atlas']);inputs={**d['input_hashes'],str(src/'verified_evidence.json'):sha(src/'verified_evidence.json'),str(Path(__file__)):sha(Path(__file__))}
    assert all(sha(Path(k))==v for k,v in inputs.items()) and all(sha(src/k)==v for k,v in d['files'].items())
    info=d['payload'];body=Path(info['path']).read_bytes();base=info['base'];fw=ROOT/'OriginalSoftware_NikonS33_V1.1/firmware.bin'
    assert body==fw.read_bytes()[0x7c:0x7c+info['size']] and sha(Path(info['path']))==info['sha256']
    assert sum(x[0] for x in struct.iter_unpack('<I',body))&0xffffffff==info['checksum']
    for q in [ROOT/'work/build-arc/binutils/objdump',ROOT/'work/build-arc/binutils/objcopy',Path(__file__).with_name('s33_verify_sensor_mmio_dialog.py')]:inputs[str(q)]=sha(q)
    manual=ROOT/'outputs/gnu_arc700_aux/sources/ARCompact_5115-029.txt';inputs[str(manual)]=sha(manual)
    assert 'dest = src1 OR (1 << (src2 & 31))' in manual.read_text() and 'dest = src1 AND NOT(1 << (src2 & 31))' in manual.read_text()
    decoded={}
    def decode(pc):
        if pc not in decoded:
            text=aligned_window(body,base,pc,pc+12);line=next(x for x in text.splitlines() if re.match(r'\s*'+f'{pc:x}:',x))
            m=re.match(r'\s*[0-9a-f]+:\s+((?:[0-9a-f]{4}\s+)+)\t(\S+)\s*(.*)',line)
            raw=b''.join(bytes.fromhex(w)[::-1] for w in m[1].split());assert raw==body[pc-base:pc-base+len(raw)]
            decoded[pc]=dict(opcode=m[2],operands=m[3].strip(),bytes_hex=raw.hex())
        return decoded[pc]
    def exact(pc,op,args):assert (decode(pc)['opcode'],decode(pc)['operands'])==(op,args),(hex(pc),decode(pc))
    for pc,op,args in [(0x100377c,'bset','r10,r10,r0'),(0x1003798,'bclr','r10,r10,r0'),
        (0x10037b8,'extb_s','r0,r0'),(0x10037d0,'add_s','r13,r13,0x8'),(0x10037d2,'mov_s','r1,0'),
        (0x10037d4,'bset','r1,r1,r13'),(0x10037d8,'and_s','r0,r0,r1'),(0x10037da,'asr_s','r0,r0,0x8'),
        (0x10037e0,'extb_s','r0,r0'),(0x10037f4,'and','r0,r0,0xff00'),(0x1003800,'asr_s','r0,r0,0x8'),
        (0x100380a,'mov_s','r0,0'),(0x1003818,'mov_s','r0,0x1'),(0x1003838,'and','r0,r0,-4'),
        (0x100383c,'bmsk_s','r14,r14,0x1'),(0x100383e,'or_s','r0,r0,r14'),(0x1003860,'bmsk_s','r0,r0,0x1'),
        (0x1003874,'and','r0,r0,0xc'),(0x100387c,'asr_s','r0,r0,0x2')]:exact(pc,op,args)
    for e,bit in [(0x10036a4,2),(0x10036d8,4),(0x100370c,6)]:
        exact(e+16,'lsr_s',f'r0,r0,{hex(bit)}');exact(e+22,'bmsk_s','r0,r0,0')
    for e,bit in [(0x10036bc,3),(0x10036f0,5)]:exact(e+4,'mov_s',f'r0,{hex(bit)}');exact(e+16,'bset','r10,r10,r0')
    exact(0x1003728,'cmp_s','r0,0');exact(0x100372a,'beq.d','32\t;0x1003748');exact(0x100372e,'mov_s','r1,0x7')
    exact(0x100373c,'bset','r10,r10,r1');exact(0x100374c,'bclr','r10,r10,r1')
    entries=[0x10036a4,0x10036bc,0x10036d8,0x10036f0,0x100370c,0x1003724,0x1003758,0x100376c,
        0x1003788,0x10037a4,0x10037bc,0x10037e4,0x1003804,0x1003824,0x100384c,0x1003864]
    rows=defaultdict(list);operations=defaultdict(dict);checks=[];counts=Counter();bitmaps=[];pools=[]
    for case in d['cases']:
        assert case['exit_code']==0 and case['fault'] is None and case['original_calls_completed']
        if not case['observer_enabled']:continue
        trace_path=src/(case['name']+'.trace');inputs[str(trace_path)]=sha(trace_path);trace=trace_path.read_text()
        assert trace_path.read_bytes()==(src/(case['name'].replace('_observed','_reference')+'.trace')).read_bytes()
        assembly=(src/(case['name'].removesuffix('_observed')+'.s')).read_text()
        state={int(k,0):struct.unpack_from('<H',bytes.fromhex(f['before']),int(k,0)%8)[0] for k,f in case['fixtures'].items()}
        expected=[];rets=[];v=case['value'];idx=v%32
        assert [c['entry'] for c in case['original_calls']]==entries
        for c in case['original_calls']:
            e=c['entry'];a=0xfed2038 if e<=0x1003724 else 0xfed2054 if e<=0x10037e4 else 0xfed2058 if e==0x1003804 else 0xfed205c
            old=state[a];ret=None;ev=[]
            if e in [0x10036a4,0x10036d8,0x100370c]:
                bit={0x10036a4:2,0x10036d8:4,0x100370c:6}[e];ev=[(e+12,'read',a,old)];ret=int(bool(old&(2**bit)))
            elif e in [0x10036bc,0x10036f0]:
                bit=3 if e==0x10036bc else 5;new=old if old&(2**bit) else old+2**bit;ev=[(e+12,'read',a,old),(e+20,'write',a,new)]
            elif e==0x1003724:
                new=sum((int(v!=0) if i==7 else ((old>>i)&1))<<i for i in range(16));off=20 if v else 36
                ev=[(e+off,'read',a,old),(e+off+8,'write',a,new)]
            elif e==0x1003758:
                word=(case['seed']^(v*0x1357))%65536;assert c['arguments']==[word];ev=[(e+12,'write',a,word)]
            elif e in [0x100376c,0x1003788]:
                new=sum((int(e==0x100376c) if i==idx else ((old>>i)&1))<<i for i in range(16))
                ev=[(e+12,'read',a,old),(e+20,'write',a,new)]
            elif e in [0x10037a4,0x10037bc,0x10037e4]:
                ev=[((e+16) if e==0x10037bc else e+12,'read',a,old)]
                if e==0x10037a4:ret=old%256
                elif e==0x10037e4:ret=old//256
                else:
                    ret=sum((((old>>(8+i))&1)<<i) for i in range(8) if (v+8)%32==8+i)
                    bitmaps.append(dict(case=case['name'],argument=v,effective_bit=(v+8)%32,read16=old,returned_byte_bitmap=ret))
            elif e==0x1003804:ev=[(e+16,'write',a,0),(e+22,'write',a,1)]
            elif e==0x1003824:
                new=sum((((v if i<2 else old)>>i)&1)<<i for i in range(16));ev=[(e+16,'read',a,old),(e+30,'write',a,new)]
            elif e in [0x100384c,0x1003864]:ev=[(e+12,'read',a,old)];ret=old%4 if e==0x100384c else (old//4)%4
            else:raise AssertionError(hex(e))
            if e!=0x1003758:assert c['arguments']==[v]
            assert ev==[tuple(x) for x in c['events']] and ret==c['return0']
            if ret is not None:
                assert assembly.split(f'mov r12,{e:#x}\njl [r12]\n',1)[1].startswith(f'cmp r0,{ret:#x}\nbne fail\n');rets.append(ret)
            for pc,op,aa,val in ev:
                assert decode(pc)['opcode']==('ldh.di' if op=='read' else 'sth.di')
                if op=='write':state[aa]=val
                rows[aa].append(dict(case=case['name'],entry=hex(e),kind=c['kind'],pc=pc,operation=op,address=aa,value=val));counts[op]+=1
            descriptor=dict(entry=hex(e),software_operation=c['kind'],namespace='original_TBIB',physical_meaning='unknown')
            if e==0x10037bc:descriptor['software_return_formula']='((read16 & (1<<((arg0+8)&31)))>>8)&255;bytebitmap,notboolean'
            if e in [0x100376c,0x1003788]:descriptor['software_bit_index']='arg0&31,documentedARCompactrule;16bitstorediscardsbits16..31'
            operations[a][e]=descriptor;expected.extend(ev)
        actual_entries=[];actual_mmio=[];poolloads=[]
        for line in trace.splitlines():
            m=re.match(r'0x([0-9a-f]+)\s+(\S+)\s+(.*)',line)
            if not m:continue
            pc=int(m[1],16);op=m[2];assert op not in ['lr','sr']
            if pc in entries:actual_entries.append(pc)
            if op in ['ldw.di','stw.di']:actual_mmio.append((pc,'read' if op=='ldw.di' else 'write',int(re.search(r'<- (0x[0-9a-f]+)',line)[1],16)&65535))
            if 0x10036a4<=pc<0x1003880 and op=='ld_s' and '[pcl,' in decode(pc)['operands']:
                p=int(re.search(r';(?:0x)?([0-9a-f]+)',decode(pc)['operands'])[1],16);word=struct.unpack_from('<I',body,p-base)[0]
                assert int(re.search(r'<- (0x[0-9a-f]+)',line)[1],16)==word and word in rows
                poolloads.append(dict(pc=hex(pc),pool=hex(p),value=hex(word)))
        assert actual_entries==entries and actual_mmio==[(p,o,v) for p,o,a,v in expected] and len(poolloads)==16
        err=src/(case['name']+'.stderr.log');inputs[str(err)]=sha(err)
        raw=[json.loads(line.removeprefix('S33_MEM ')) for line in err.read_text().splitlines() if line.startswith('S33_MEM ')]
        done=[e for e in raw if e['stage']=='result'];assert done==case['completed_memory_events'] and len(raw)==46
        assert [(e['pc'],e['operation'],e['address'],e['value']) for e in done]==expected
        for b,e in zip(raw[::2],raw[1::2]):
            assert b['stage']=='begin' and e['stage']=='result' and b['width_bytes']==e['width_bytes']==2
            assert all(b[k]==e[k] for k in ['id','pc','operation','address'])
        for key,f in case['fixtures'].items():
            aa=int(key,0);off=aa%8;before=bytes.fromhex(f['before']);after=(src/f['file']).read_bytes()
            assert struct.unpack_from('<H',before,off)[0]==(case['seed']^(aa>>2))&65535
            assert struct.unpack_from('<H',after,off)[0]==state[aa] and all(before[j]==after[j] for j in range(8) if j not in [off,off+1])
        checks.append(dict(case=case['name'],events=23,return_checks=len(rets),pool_loads=16));pools.extend(poolloads)
    assert len(checks)==39 and sum(counts.values())==897 and len(rows)==4 and len(pools)==624 and max(x['returned_byte_bitmap'] for x in bitmaps)==128
    audit=dict(status='PASS_ORIGINAL_TBIB_FED20_TAIL_AUDIT',date='2026-10-25',checks=checks,operation_counts=dict(counts),pool_load_checks=pools,
        bitmap_checks=bitmaps,manual_reference=dict(path=str(manual),BSET_printed_page=225,BCLR_printed_page=213,scope='Documentedlow5indexrule;notNikonphysicalregisteridentification'),
        independently_redecoded_instructions={hex(k):v for k,v in decoded.items()},input_sha256=inputs,hardware_access=False,whole_physical_map_complete=False,limits=d['limits'])
    save(src/'tbib_fed20_tail_audit.json',audit)
    out=publish(parent=parent,source=src,copy_files=[(src/'verified_evidence.json','tbib_fed20_tail_cpu.json'),(src/'tbib_fed20_tail_audit.json','tbib_fed20_tail_audit.json')],
        rows=rows,operations={a:list(v.values()) for a,v in operations.items()},input_hashes=inputs,
        validation=dict(status='PASS_TBIB_FED20_TAIL_NO_COVERAGE_REGRESSION',new_scalar_mmio_addresses=3,enriched_scalar_mmio_addresses=1,
            original_routines=16,selected_scenarios=39,trace_identical_pairs=39,guest_MMIO_events=897,operation_counts=dict(counts),original_pool_load_checks=624,
            nonboolean_bitmap_return_observed=128,full_TBIB_boot_proven=False,limits=d['limits']),
        scripts=[Path(__file__),Path(__file__).with_name('s33_verify_tbib_fed20_tail.py'),Path(__file__).with_name('s33_tbib_accessor_harness.py')],
        next_work=['Continue originalTBIBgroups andindirectcallerconstraints beyond1003880;no fullboot orphysicalmap claim',
            'AUX/BCR/SoCphysicalimplementation andremainingoverlay/code-data candidates'])
    a=load(out/'register_map.json');assert a['counts']==dict(core=64,aux=200,soc_mmio=939) and len(a['records'])==1203


if __name__=='__main__':main()
