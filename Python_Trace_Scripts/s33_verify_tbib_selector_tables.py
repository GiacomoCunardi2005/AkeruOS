#!/usr/bin/env python3
"""Execute full original TBIB selector services with explicit nested kernel context."""
import json,struct,shutil
from pathlib import Path
from types import SimpleNamespace
from s33_run_gnu_arc700 import ROOT,LEGACY,TOOLCHAIN,sha
from s33_verify_gnu_defined_memory import LAB,BUILD,known_sections
from s33_verify_ff7_transfer_windows import SeparatedRunner
from s33_verify_gnu_dsp_lab import compile_probe
from s33_integrate_ffc7000_table_tail import load
from s33_tbib_accessor_harness import REUSED

PARENT=ROOT/'Risultati/Processor_Registers/20261025T210001Z'
FW=ROOT/'OriginalSoftware_NikonS33_V1.1/firmware.bin'
raw=FW.read_bytes();BASE,SIZE,CHECKSUM,ENTRY=struct.unpack_from('<4I',raw,0x6c);BODY=raw[0x7c:0x7c+SIZE]
TABLES=[]
for pointer in struct.unpack_from('<4I',BODY,0x1043480-BASE):
    ack,mask,count=struct.unpack_from('<IIH',BODY,pointer-BASE)
    records=[struct.unpack_from('<HBBI',BODY,pointer-BASE+12+8*i) for i in range(count)]
    TABLES.append(dict(pointer=pointer,ack=ack,mask=mask,count=count,records=records))
assert [x['count'] for x in TABLES]==[16,6,16,14]
INVALID=[0,0x411,0x504,0x908,0x909]

def plan(seed,flag):
    initial={a:(seed^(a>>2))&65535 for t in TABLES for a in [t['ack'],t['mask']]};state=dict(initial);calls=[]
    for table in TABLES:
        for ordinal,(key,ackbit,maskbit,callback) in enumerate(table['records']):
            assert ackbit==maskbit and callback==0
            a=table['ack'];v=1<<ackbit;assert v<=65535
            calls.append(dict(entry=0x1004744,arguments=[key],return0=0,events=[(0x10047a8,'write',a,v)],
                              table=table['pointer'],record_index=ordinal,kind='one_hot_store'))
            state[a]=v;a=table['mask'];old=state[a];v=old|(1<<maskbit) if flag else old&~(1<<maskbit)
            pc=0x10048ec if flag else 0x10049ae
            calls.append(dict(entry=0x10047c8,arguments=[key,flag],return0=0,
                              events=[(pc,'read',a,old),(pc+8,'write',a,v)],table=table['pointer'],record_index=ordinal,kind='nonzero_set_zero_clear'))
            state[a]=v
    for key in INVALID:
        for entry,args in [(0x1004744,[key]),(0x10047c8,[key,flag])]:
            calls.append(dict(entry=entry,arguments=args,return0=0x200601,events=[],kind='invalid_selector'))
    assert len(calls)==114
    return dict(initial=initial,final=state,calls=calls)

def main():
    ledger=load(PARENT/'sha256.json');assert all(sha(PARENT/k)==v for k,v in ledger.items())
    assert BASE==ENTRY==0x1000000 and sum(x[0] for x in struct.iter_unpack('<I',BODY))&0xffffffff==CHECKSUM
    assert struct.unpack_from('<I',BODY,0x104126c-BASE)[0]==0
    r=SeparatedRunner(SimpleNamespace(legacy_root=LEGACY,toolchain=TOOLCHAIN,output=None,action='original-tbib-selector-tables'))
    print('Evidence:',r.out,flush=True)
    try:
        r.prepare();r.known_ranges='';r.experimental_engine=LAB
        assert sha(LAB/'install/bin/arc-elf32-run')==load(BUILD)['engine_sha256']
        assert sha(REUSED/'observer')==load(REUSED/'verified_evidence.json')['files']['observer']
        shutil.copy2(REUSED/'observer',r.out/'observer')
        for p in [Path(__file__),PARENT/'sha256.json',FW,BUILD,LAB/'install/bin/arc-elf32-run',REUSED/'observer',REUSED/'verified_evidence.json']:
            r.input_hashes[str(p)]=sha(p)
        for n in ['s33_run_gnu_arc700','s33_verify_gnu_defined_memory','s33_verify_ff7_transfer_windows','s33_verify_gnu_dsp_lab','s33_integrate_ffc7000_table_tail','s33_tbib_accessor_harness']:
            p=Path(__file__).with_name(n+'.py');r.input_hashes[str(p)]=sha(p)
        shutil.copy2(Path(__file__),r.out/Path(__file__).name)
        payload=r.out/'tbib_runtime_mmap.bin';payload.write_bytes(BODY);pairs=[]
        for pattern,(seed,depth) in enumerate([(0,1),(65535,2),(0xa55a,7)]):
            for flag in [0,1,2,0xffffffff]:
                name=f'select_{pattern}_{flag:x}';p=plan(seed,flag);calls=p['calls'];events=[e for c in calls for e in c['events']]
                asm='mov r20,sp\n'+''.join(f'mov r{i},{i*0x01100110:#x}\n' for i in range(13,20))
                asm+='ld r0,[0x104126c]\ncmp r0,0\nbne fail\nmov r0,context\nst r0,[0x104126c]\n'
                for c in calls:
                    asm+=''.join(f'mov r{i},{v:#x}\n' for i,v in enumerate(c['arguments']))+f'mov r12,{c["entry"]:#x}\njl [r12]\ncmp r0,{c["return0"]:#x}\nbne fail\n'
                    asm+='cmp sp,r20\nbne fail\n'+''.join(f'cmp r{i},{i*0x01100110:#x}\nbne fail\n' for i in range(13,20))
                    asm+=f'ld r0,[nesting]\ncmp r0,{depth}\nbne fail\n'
                asm+='mov r0,0\nst r0,[0x104126c]\nb finish\nfail:\nmov r0,7\nfinish:\nmov r8,1\ntrap_s 1\n'
                # Explicit file-backed context: gate+24=1, current task at+28,
                # task nesting at+104. No instruction or descriptor is patched.
                asm+=f'.section .data,"aw",@progbits\n.align 4\ncontext:\n.zero 24\n.hword 1\n.hword 0\n.word task\ntask:\n.zero 104\nnesting:\n.word {depth}\n'
                elf=compile_probe(r,name,asm);traces=[]
                for observed in [False,True]:
                    case_name=name+('_observed' if observed else '_reference');r.observe=observed;fixtures={}
                    options=['--memory-mapfile','/result/'+payload.name,'--memory-region',f'{BASE:#x},{SIZE:#x}']
                    for a,v in sorted(p['initial'].items()):
                        before=bytearray(b'\xa5'*8);struct.pack_into('<H',before,a%8,v);f=r.out/f'{case_name}_{a:x}.bin';f.write_bytes(before)
                        fixtures[hex(a)]=dict(file=f.name,before=before.hex());options+=['--memory-mapfile','/result/'+f.name,'--memory-region',f'{a:#x},2']
                    r.range_override=known_sections(elf,False)+f',{BASE:#x}:{SIZE:#x}'
                    case,log=r.run(case_name,'/result/'+elf.name,options,trace=True,extract=True)
                    assert case['exit_code']==0 and case['fault'] is None,(case_name,log[-5000:])
                    assert not any(x in log for x in ['S33_UNDEFINED','S33_AUX_UNKNOWN','S33_DSP_LAB','runtime error:'])
                    raw_events=[json.loads(x.removeprefix('S33_MEM ')) for x in (r.out/(case_name+'.stderr.log')).read_text().splitlines() if x.startswith('S33_MEM ')]
                    done=[x for x in raw_events if x['stage']=='result'];assert len(raw_events)==2*len(done) and all(x['width_bytes']==2 for x in raw_events)
                    assert [(x['pc'],x['operation'],x['address'],x['value']) for x in done]==(events if observed else [])
                    for key,f in fixtures.items():
                        a=int(key,0);off=a%8;before=bytes.fromhex(f['before']);after=(r.out/f['file']).read_bytes()
                        assert struct.unpack_from('<H',after,off)[0]==p['final'][a] and all(before[j]==after[j] for j in range(8) if j not in [off,off+1]);f['after']=after.hex()
                    assert payload.read_bytes()==BODY
                    case.update(seed=seed,flag=flag,nesting_depth=depth,observer_enabled=observed,original_calls=calls,fixtures=fixtures,
                                completed_memory_events=done,original_calls_completed=True,runtime_global_pointer_address='0x104126c',runtime_global_restored=True)
                    traces.append((r.out/(case_name+'.trace')).read_bytes());print(case_name,'PASS',len(done),'MMIO',flush=True)
                assert traces[0]==traces[1];pairs.append(dict(name=name,events=len(events),trace_identical=True))
        assert all(sha(PARENT/k)==v for k,v in ledger.items())
        r.results.update(status='PASS_ORIGINAL_TBIB_SELECTOR_TABLES',parent_atlas=str(PARENT),pairs=pairs,original_tables=TABLES,
            payload=dict(base=BASE,size=SIZE,checksum=CHECKSUM,path=str(payload),sha256=sha(payload),firmware_offset=0x7c),
            hardware_access=False,gnu_modified=False,limits=['Runtime context is a fixture: global104126C temporarily points to harness.data and is restored;no code/table/selector byte changes.',
                'Only nested service paths with depth1/2/7 andgate+24=1 execute;FLAG/IRQeffects andnon-nested kernel paths notproven.',
                'All52original table selectors and5invalid selectors tested forflag0/1/2/FFFFFFFF;othercategorydelegates andruntimecallerreachability unproven.',
                'MMIO backing andseeds arefixtures;onehotstores do notprove W1C/reset/IRQphysicalsemantics;noTBIBboot orhardware.'])
        r.finish()
    except Exception as exc:r.results.update(status='FAIL',error=repr(exc));raise
    finally:r.save()
    print(r.out/'verified_evidence.json',flush=True)

if __name__=='__main__':main()
