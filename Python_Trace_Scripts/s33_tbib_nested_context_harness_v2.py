#!/usr/bin/env python3
"""Versioned nested TBIB runner with audited fixture setup/teardown hooks."""
import json,struct,shutil
from pathlib import Path
from types import SimpleNamespace
from s33_run_gnu_arc700 import ROOT,LEGACY,TOOLCHAIN,sha
from s33_verify_gnu_defined_memory import LAB,BUILD,known_sections
from s33_verify_ff7_transfer_windows import SeparatedRunner
from s33_verify_gnu_dsp_lab import compile_probe
from s33_integrate_ffc7000_table_tail import load
from s33_tbib_accessor_harness import REUSED

def execute(*,source,parent,action,status,builder,limits,extra,values=(0,1,2,0xffffffff)):
    ledger=load(parent/'sha256.json');assert all(sha(parent/k)==v for k,v in ledger.items())
    fw=ROOT/'OriginalSoftware_NikonS33_V1.1/firmware.bin';raw=fw.read_bytes();base,size,checksum,entry=struct.unpack_from('<4I',raw,0x6c);body=raw[0x7c:0x7c+size]
    assert base==entry==0x1000000 and sum(x[0] for x in struct.iter_unpack('<I',body))&0xffffffff==checksum
    assert struct.unpack_from('<I',body,0x104126c-base)[0]==0
    r=SeparatedRunner(SimpleNamespace(legacy_root=LEGACY,toolchain=TOOLCHAIN,output=None,action=action));print('Evidence:',r.out,flush=True)
    try:
        r.prepare();r.known_ranges='';r.experimental_engine=LAB
        assert sha(LAB/'install/bin/arc-elf32-run')==load(BUILD)['engine_sha256']
        assert sha(REUSED/'observer')==load(REUSED/'verified_evidence.json')['files']['observer'];shutil.copy2(REUSED/'observer',r.out/'observer')
        for p in [source,Path(__file__),parent/'sha256.json',fw,BUILD,LAB/'install/bin/arc-elf32-run',REUSED/'observer',REUSED/'verified_evidence.json']:r.input_hashes[str(p)]=sha(p)
        for n in ['s33_run_gnu_arc700','s33_verify_gnu_defined_memory','s33_verify_ff7_transfer_windows','s33_verify_gnu_dsp_lab','s33_integrate_ffc7000_table_tail','s33_tbib_accessor_harness']:
            p=Path(__file__).with_name(n+'.py');r.input_hashes[str(p)]=sha(p)
        for p in [source,Path(__file__)]:shutil.copy2(p,r.out/p.name)
        payload=r.out/'tbib_runtime_mmap.bin';payload.write_bytes(body);pairs=[]
        for pattern,(seed,depth) in enumerate([(0,1),(65535,2),(0xa55a,7)]):
            for flag in values:
                name=f'nested_{pattern}_{flag:x}';p=builder(seed,flag,depth);calls=p['calls'];events=[e for c in calls for e in c['events']]
                asm='mov r20,sp\n'+''.join(f'mov r{i},{i*0x01100110:#x}\n' for i in range(13,20))
                asm+='ld r0,[0x104126c]\ncmp r0,0\nbne fail\nmov r0,context\nst r0,[0x104126c]\n'
                asm+=p.get('setup_asm','')
                for c in calls:
                    asm+=''.join(f'mov r{i},{v:#x}\n' for i,v in enumerate(c['arguments']))+f'mov r12,{c["entry"]:#x}\njl [r12]\ncmp r0,{c["return0"]:#x}\nbne fail\n'
                    asm+='cmp sp,r20\nbne fail\n'+''.join(f'cmp r{i},{i*0x01100110:#x}\nbne fail\n' for i in range(13,20))
                    asm+=f'ld r0,[nesting]\ncmp r0,{depth}\nbne fail\n'
                asm+=p.get('teardown_asm','')
                asm+='mov r0,0\nst r0,[0x104126c]\nb finish\nfail:\nmov r0,7\nfinish:\nmov r8,1\ntrap_s 1\n'
                asm+=f'.section .data,"aw",@progbits\n.align 4\ncontext:\n.zero 24\n.hword 1\n.hword 0\n.word task\ntask:\n.zero 104\nnesting:\n.word {depth}\n'
                elf=compile_probe(r,name,asm);traces=[]
                for observed in [False,True]:
                    cn=name+('_observed' if observed else '_reference');r.observe=observed;fixtures={}
                    options=['--memory-mapfile','/result/'+payload.name,'--memory-region',f'{base:#x},{size:#x}']
                    for a,v in sorted(p['initial'].items()):
                        before=bytearray(b'\xa5'*8);struct.pack_into('<H',before,a%8,v);f=r.out/f'{cn}_{a:x}.bin';f.write_bytes(before)
                        fixtures[hex(a)]=dict(file=f.name,before=before.hex());options+=['--memory-mapfile','/result/'+f.name,'--memory-region',f'{a:#x},2']
                    r.range_override=known_sections(elf,False)+f',{base:#x}:{size:#x}'
                    c,log=r.run(cn,'/result/'+elf.name,options,trace=True,extract=True)
                    assert c['exit_code']==0 and c['fault'] is None,(cn,log[-5000:])
                    assert not any(x in log for x in ['S33_UNDEFINED','S33_AUX_UNKNOWN','S33_DSP_LAB','runtime error:'])
                    raw_events=[json.loads(x.removeprefix('S33_MEM ')) for x in (r.out/(cn+'.stderr.log')).read_text().splitlines() if x.startswith('S33_MEM ')]
                    done=[x for x in raw_events if x['stage']=='result'];assert len(raw_events)==2*len(done) and all(x['width_bytes']==2 for x in raw_events)
                    assert [(x['pc'],x['operation'],x['address'],x['value']) for x in done]==(events if observed else [])
                    for key,f in fixtures.items():
                        a=int(key,0);off=a%8;before=bytes.fromhex(f['before']);after=(r.out/f['file']).read_bytes()
                        assert struct.unpack_from('<H',after,off)[0]==p['final'][a] and all(before[j]==after[j] for j in range(8) if j not in [off,off+1]);f['after']=after.hex()
                    assert payload.read_bytes()==body
                    c.update(seed=seed,flag=flag,nesting_depth=depth,observer_enabled=observed,original_calls=calls,fixtures=fixtures,
                             completed_memory_events=done,original_calls_completed=True,runtime_global_pointer_address='0x104126c',runtime_global_restored=True)
                    traces.append((r.out/(cn+'.trace')).read_bytes());print(cn,'PASS',len(done),'MMIO',flush=True)
                assert traces[0]==traces[1];pairs.append(dict(name=name,events=len(events),trace_identical=True))
        assert all(sha(parent/k)==v for k,v in ledger.items())
        r.results.update(status=status,parent_atlas=str(parent),pairs=pairs,payload=dict(base=base,size=size,checksum=checksum,path=str(payload),sha256=sha(payload),firmware_offset=0x7c),
                         hardware_access=False,gnu_modified=False,limits=limits,**extra);r.finish()
    except Exception as exc:r.results.update(status='FAIL',error=repr(exc));raise
    finally:r.save()
    print(r.out/'verified_evidence.json',flush=True)
