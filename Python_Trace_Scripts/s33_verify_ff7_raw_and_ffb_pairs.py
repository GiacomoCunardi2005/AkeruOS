#!/usr/bin/env python3
"""Execute original FF7 raw tables and FFB split-argument setters/getters offline."""
import json,re,shutil,struct
from pathlib import Path
from types import SimpleNamespace
from s33_run_gnu_arc700 import ROOT,LEGACY,TOOLCHAIN,sha
from s33_verify_gnu_defined_memory import LAB,BUILD,known_sections
from s33_verify_gnu_dsp_lab import compile_probe
from s33_verify_ff7_transfer_windows import SeparatedRunner
from s33_trace_state_dispatch import verified_payloads
from s33_verify_sensor_mmio_dialog import aligned_window

REUSED=ROOT/'outputs/gnu_arc700/20261025T104108Z_2704fcf9'
TABLES=[dict(name='raw12',entry=0x2e0bd0,end=0x2e0c30,base=0xff7600c,count=12,store_pc=0x2e0c04,tails=[0xff7603c,0xff76040],tail_pcs=[0x2e0c18,0x2e0c28],aux_pcs=[0x2e0be4,0x2e0bea]),dict(name='raw17',entry=0x2e0c30,end=0x2e0c70,base=0xff76044,count=17,store_pc=0x2e0c60,tails=[],tail_pcs=[],aux_pcs=[0x2e0c40,0x2e0c46]),dict(name='raw33_a',entry=0x2e0f30,end=0x2e0f70,base=0xff741dc,count=33,store_pc=0x2e0f60,tails=[],tail_pcs=[],aux_pcs=[0x2e0f40,0x2e0f46]),dict(name='raw33_overlap',entry=0x2e0f70,end=0x2e0fb0,base=0xff74044,count=33,store_pc=0x2e0fa0,tails=[],tail_pcs=[],aux_pcs=[0x2e0f80,0x2e0f86]),dict(name='raw9_a',entry=0x2e0fb0,end=0x2e0ff0,base=0xff74260,count=9,store_pc=0x2e0fe0,tails=[],tail_pcs=[],aux_pcs=[0x2e0fc0,0x2e0fc6]),dict(name='raw9_b',entry=0x2e0ff0,end=0x2e1030,base=0xff74284,count=9,store_pc=0x2e1020,tails=[],tail_pcs=[],aux_pcs=[0x2e1000,0x2e1006])]
SINGLES=[(0x2e14bc,0x2e14e4,0xffb8000),(0x2e14d0,0x2e14f8,0xffb8004),(0x2e1560,0x2e1574,0xffb8028),(0x2e1684,0x2e1698,0xffb8048),(0x2e17a8,0x2e17bc,0xffb8068)]
PAIRS=[(0x2e150c,0xffb8020),(0x2e1588,0xffb802c),(0x2e15dc,0xffb8034),(0x2e1630,0xffb8040),(0x2e16ac,0xffb804c),(0x2e1700,0xffb8054),(0x2e1754,0xffb8060),(0x2e17d0,0xffb806c),(0x2e1824,0xffb8074)]

def main():
 r=SeparatedRunner(SimpleNamespace(legacy_root=LEGACY,toolchain=TOOLCHAIN,output=None,action='ff7-raw-overlap-ffb-pairs'));print('Evidence:',r.out,flush=True)
 try:
  r.prepare();r.known_ranges='';build=json.loads(BUILD.read_text());assert sha(LAB/'install/bin/arc-elf32-run')==build['engine_sha256'];r.experimental_engine=LAB;prior=json.loads((REUSED/'verified_evidence.json').read_text());assert sha(REUSED/'observer')==prior['files']['observer'];shutil.copy2(REUSED/'observer',r.out/'observer')
  for p in[Path(__file__),Path(__file__).with_name('s33_verify_ff7_transfer_windows.py'),BUILD,LAB/'install/bin/arc-elf32-run',REUSED/'observer',REUSED/'verified_evidence.json']:r.input_hashes[str(p)]=sha(p)
  shutil.copy2(Path(__file__),r.out/Path(__file__).name);bs,ps,bd=verified_payloads(ROOT);info=bs[0];body=ps[0];base=info['load_address_candidate'];main_file=r.out/'payload0_mmap.bin';main_file.write_bytes(body);r.input_hashes[str(bd/info['file'])]=sha(bd/info['file']);(r.out/'original_windows_candidates.txt').write_text('\n\n'.join(aligned_window(body,base,a,b)for a,b in[(0x2e0bd0,0x2e0c70),(0x2e0f30,0x2e1030),(0x2e14bc,0x2e1878)]))
  values=[0,1,0x1fff0000,0x20000000,0x80008000,0xffffffff,0x12345678,0xa55a5aa5];scenarios=[(s,p)for s in TABLES for p in range(4)]+[(None,p)for p in range(len(values))];pairs=[]
  for spec,pattern in scenarios:
   scenario=(spec['name']if spec else'ffb')+f'_{pattern}';state={};initial={};buffers={};sequence=[];calls=[];asm='mov r20,sp\nmov r13,0x13371337\nmov r14,0x14471447\nmov r15,0x15571557\nmov r16,0x16671667\n'
   def call(entry,args,events,ret=None):
    nonlocal asm
    asm+=''.join(f'mov r{i},{v&0xffffffff:#x}\n'for i,v in enumerate(args))+f'mov r12,{entry:#x}\njl [r12]\n'
    if ret is not None:asm+=f'cmp r0,{ret:#x}\nbne fail\n'
    asm+='cmp sp,r20\nbne fail\n'+''.join(f'cmp r{i},{v:#x}\nbne fail\n'for i,v in[(13,0x13371337),(14,0x14471447),(15,0x15571557),(16,0x16671667)]);sequence.extend(events);calls.append(dict(entry=entry,arguments=args,expected_return=ret))
    for _,op,a,v in events:
     if op=='write':state[a]=v
   if spec:
    vals=[(0 if pattern==0 else 65535 if pattern==1 else((109*i+0x55aa)^(65535 if pattern==3 else 0))&65535)for i in range(spec['count'])];raw=struct.pack('<'+'H'*len(vals),*vals);p=r.out/(scenario+'_input.bin');p.write_bytes(raw);buffers[0x700000]=dict(file=p.name,bytes=raw.hex());initial={spec['base']+4*i:0xa5a5 for i in range(spec['count'])};args=[0x700000,0xdead1234,0xbeef8001];ev=[(spec['store_pc'],'write',spec['base']+4*i,v)for i,v in enumerate(vals)]
    for pc,a,v in zip(spec['tail_pcs'],spec['tails'],args[1:]):initial[a]=0xa55a;ev.append((pc,'write',a,v&65535))
    state=dict(initial);call(spec['entry'],args,ev)
   else:
    seed=65535 if pattern%2 else 0xa55a;initial={a:seed for _,_,a in SINGLES};initial.update({a+off:seed for _,a in PAIRS for off in[0,4]});state=dict(initial);v=values[pattern]
    for _,getter,a in SINGLES:call(getter,[],[(getter+12,'read',a,seed)],seed)
    for setter,a in PAIRS:
     for off,getter in[(0,setter+44),(4,setter+64)]:call(getter,[],[(getter+12,'read',a+off,seed)],seed)
    for setter,getter,a in SINGLES:
     call(setter,[v],[(setter+12,'write',a,v&65535)]);call(getter,[],[(getter+12,'read',a,v&65535)],v&65535)
    for setter,a in PAIRS:
     hi=(v>>16)&8191;lo=v&65535;call(setter,[v],[(setter+20,'write',a+4,hi),(setter+36,'write',a,lo)]);call(setter+44,[],[(setter+56,'read',a,lo)],lo);call(setter+64,[],[(setter+76,'read',a+4,hi)],hi)
   asm+='mov r0,0\nb finish\nfail:\nmov r0,7\nfinish:\nmov r8,1\ntrap_s 1\n';elf=compile_probe(r,scenario,asm);traces=[]
   for enabled in[False,True]:
    name=scenario+('_observed'if enabled else'_reference');r.observe=enabled;options=['--memory-mapfile','/result/'+main_file.name,'--memory-region',f'{base:#x},{len(body):#x}'];fixtures={}
    for a,b in buffers.items():options+=['--memory-mapfile','/result/'+b['file'],'--memory-region',f'{a:#x},{len(bytes.fromhex(b["bytes"])):#x}']
    for a,v in sorted(initial.items()):
     data=bytearray(b'\xa5'*8);struct.pack_into('<H',data,a%8,v);p=r.out/f'{name}_{a:x}.bin';p.write_bytes(data);fixtures[hex(a)]=dict(file=p.name,before=data.hex());options+=['--memory-mapfile','/result/'+p.name,'--memory-region',f'{a:#x},2']
    r.range_override=known_sections(elf,False)+f',{base:#x}:{len(body):#x}'+''.join(f',{a:#x}:{len(bytes.fromhex(b["bytes"])):#x}'for a,b in buffers.items());case,log=r.run(name,'/result/'+elf.name,options,trace=True,extract=True);assert case['exit_code']==0 and case['fault']is None,log[-4000:];assert all(s not in log for s in['S33_UNDEFINED','S33_AUX_UNKNOWN','runtime error:'])
    events=[json.loads(s.removeprefix('S33_MEM '))for s in(r.out/(name+'.stderr.log')).read_text().splitlines()if s.startswith('S33_MEM ')];done=[e for e in events if e['stage']=='result'];assert len(events)==2*len(done)and all(e['width_bytes']==2 for e in done);assert[(e['pc'],e['operation'],e['address'],e['value'])for e in done]==(sequence if enabled else[]),(name,done,sequence)
    for key,f in fixtures.items():
     a=int(key,0);after=(r.out/f['file']).read_bytes();before=bytes.fromhex(f['before']);assert struct.unpack_from('<H',after,a%8)[0]==state[a]and all(after[j]==before[j]for j in range(8)if j not in[a%8,a%8+1]);f['after']=after.hex()
    assert main_file.read_bytes()==body and all((r.out/b['file']).read_bytes()==bytes.fromhex(b['bytes'])for b in buffers.values());case.update(scenario=scenario,spec_name=spec['name']if spec else None,pattern=pattern,observer_enabled=enabled,fixtures=fixtures,input_buffers=buffers,original_calls=calls,completed_memory_events=done,full_original_calls_completed=True);traces.append((r.out/(name+'.trace')).read_bytes());print(name,'PASS',len(done),'events',flush=True)
   assert traces[0]==traces[1];pairs.append(dict(scenario=scenario,events=len(sequence),trace_identical=True))
  assert len(pairs)==32 and sum(p['events']for p in pairs)==1012;fw=(ROOT/'OriginalSoftware_NikonS33_V1.1/firmware.bin').read_bytes();offset=fw.find(body);assert offset>=0 and fw.find(body,offset+1)<0
  r.results.update(status='PASS_FF7_RAW_AND_FFB_PAIRS',tables=TABLES,ffb_singles=SINGLES,ffb_pairs=PAIRS,ffb_input_values=values,pairs=pairs,payload=dict(base=base,size=len(body),firmware_offset=offset,sha256=sha(main_file),path=str(main_file)),capture_streams_separate=True,hardware_access=False,gnu_modified=False,limits=['Six raw apertures can overlap earlier windows and scalar parameter roles; same software address does not establish physical aliasing.','FFB write splits one argument into high13/low16 halfwords; reads are full16 in seeded storage, not physical register readback.','Input, MMIO backing/seeds and caller stack are laboratory fixtures; no physical function/reset/timing/permissions inferred.','Synthetic callers complete selected routines; original Nikon caller ranges and global reachability remain unproven.']);r.finish()
 except Exception as exc:r.results.update(status='FAIL',error=repr(exc));raise
 finally:r.save()
 print(r.out/'verified_evidence.json',flush=True)
if __name__=='__main__':main()
