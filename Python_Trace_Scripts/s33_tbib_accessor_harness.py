#!/usr/bin/env python3
"""Reusable original-TBIB accessor probe runner; caller supplies the oracle."""
import json,struct,shutil
from pathlib import Path
from types import SimpleNamespace
from s33_run_gnu_arc700 import ROOT,LEGACY,TOOLCHAIN,sha
from s33_verify_gnu_defined_memory import LAB,BUILD,known_sections
from s33_verify_ff7_transfer_windows import SeparatedRunner
from s33_verify_gnu_dsp_lab import compile_probe
from s33_integrate_ffc7000_table_tail import load

REUSED=ROOT/'outputs/gnu_arc700/20261025T203639Z_c493e826'


def execute(*,source,parent,action,status,values,seeds,builder,limits):
    ledger=load(parent/'sha256.json');assert all(sha(parent/k)==v for k,v in ledger.items())
    fw=ROOT/'OriginalSoftware_NikonS33_V1.1/firmware.bin';raw=fw.read_bytes();base,size,checksum,entry=struct.unpack_from('<4I',raw,0x6c)
    body=raw[0x7c:0x7c+size];assert len(body)==size and sum(x[0] for x in struct.iter_unpack('<I',body))&0xffffffff==checksum and base==entry==0x1000000
    r=SeparatedRunner(SimpleNamespace(legacy_root=LEGACY,toolchain=TOOLCHAIN,output=None,action=action));print('Evidence:',r.out,flush=True)
    try:
        r.prepare();r.known_ranges='';r.experimental_engine=LAB
        assert sha(LAB/'install/bin/arc-elf32-run')==load(BUILD)['engine_sha256']
        assert sha(REUSED/'observer')==load(REUSED/'verified_evidence.json')['files']['observer']
        shutil.copy2(REUSED/'observer',r.out/'observer')
        for p in [source,Path(__file__),parent/'sha256.json',fw,BUILD,LAB/'install/bin/arc-elf32-run',REUSED/'observer',REUSED/'verified_evidence.json']:
            r.input_hashes[str(p)]=sha(p)
        for n in ['s33_run_gnu_arc700','s33_verify_gnu_defined_memory','s33_verify_ff7_transfer_windows','s33_verify_gnu_dsp_lab','s33_integrate_ffc7000_table_tail']:
            p=Path(__file__).with_name(n+'.py');r.input_hashes[str(p)]=sha(p)
        for p in [source,Path(__file__)]:shutil.copy2(p,r.out/p.name)
        code=r.out/'tbib_original_mmap.bin';code.write_bytes(body);pairs=[]
        for pattern,seed in enumerate(seeds):
            for value in values:
                scenario=f'access_{pattern}_{value:x}';plan=builder(seed,value);calls=plan['calls'];events=[e for c in calls for e in c['events']]
                asm='mov r20,sp\n'+''.join(f'mov r{i},{i*0x01100110:#x}\n' for i in range(13,20))
                for c in calls:
                    asm+=''.join(f'mov r{i},{v:#x}\n' for i,v in enumerate(c['arguments']))+f'mov r12,{c["entry"]:#x}\njl [r12]\n'
                    if c.get('return0') is not None:asm+=f'cmp r0,{c["return0"]:#x}\nbne fail\n'
                    if c.get('return1') is not None:asm+=f'cmp r1,{c["return1"]:#x}\nbne fail\n'
                    asm+='cmp sp,r20\nbne fail\n'+''.join(f'cmp r{i},{i*0x01100110:#x}\nbne fail\n' for i in range(13,20))
                asm+='mov r0,0\nb finish\nfail:\nmov r0,7\nfinish:\nmov r8,1\ntrap_s 1\n';elf=compile_probe(r,scenario,asm);traces=[]
                for observed in [False,True]:
                    name=scenario+('_observed' if observed else '_reference');r.observe=observed;fixtures={}
                    options=['--memory-mapfile','/result/'+code.name,'--memory-region',f'{base:#x},{size:#x}']
                    for a,v in sorted(plan['initial'].items()):
                        before=bytearray(b'\xa5'*8);struct.pack_into('<H',before,a%8,v);p=r.out/f'{name}_{a:x}.bin';p.write_bytes(before)
                        fixtures[hex(a)]=dict(file=p.name,before=before.hex());options+=['--memory-mapfile','/result/'+p.name,'--memory-region',f'{a:#x},2']
                    r.range_override=known_sections(elf,False)+f',{base:#x}:{size:#x}'
                    case,log=r.run(name,'/result/'+elf.name,options,trace=True,extract=True)
                    assert case['exit_code']==0 and case['fault'] is None,(name,log[-4000:])
                    assert not any(s in log for s in ['S33_UNDEFINED','S33_AUX_UNKNOWN','S33_DSP_LAB','runtime error:'])
                    raw_events=[json.loads(line.removeprefix('S33_MEM ')) for line in (r.out/(name+'.stderr.log')).read_text().splitlines() if line.startswith('S33_MEM ')]
                    done=[e for e in raw_events if e['stage']=='result'];assert len(raw_events)==2*len(done) and all(e['width_bytes']==2 for e in raw_events)
                    assert [(e['pc'],e['operation'],e['address'],e['value']) for e in done]==(events if observed else [])
                    for key,f in fixtures.items():
                        a=int(key,0);off=a%8;before=bytes.fromhex(f['before']);after=(r.out/f['file']).read_bytes()
                        assert struct.unpack_from('<H',after,off)[0]==plan['final'][a] and all(before[j]==after[j] for j in range(8) if j not in [off,off+1]);f['after']=after.hex()
                    assert code.read_bytes()==body
                    case.update(pattern=pattern,seed=seed,value=value,observer_enabled=observed,original_calls=calls,
                        fixtures=fixtures,completed_memory_events=done,original_calls_completed=True)
                    traces.append((r.out/(name+'.trace')).read_bytes());print(name,'PASS',len(done),'events',flush=True)
                assert traces[0]==traces[1];pairs.append(dict(name=scenario,events=len(events),trace_identical=True))
        assert all(sha(parent/k)==v for k,v in ledger.items())
        r.results.update(status=status,parent_atlas=str(parent),pairs=pairs,seeds=seeds,values=values,
            payload=dict(base=base,size=size,path=str(code),sha256=sha(code),firmware_offset=0x7c,checksum=checksum),
            hardware_access=False,gnu_modified=False,full_TBIB_boot_proven=False,limits=limits)
        r.finish()
    except Exception as exc:r.results.update(status='FAIL',error=repr(exc));raise
    finally:r.save()
    print(r.out/'verified_evidence.json',flush=True)

