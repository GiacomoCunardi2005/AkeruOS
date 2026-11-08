#!/usr/bin/env python3
"""Original FFC3000 accessors plus FFB9F computed writer, without replacing DSP helpers."""
import json,re,shutil,struct
from pathlib import Path
from types import SimpleNamespace
from s33_run_gnu_arc700 import ROOT,LEGACY,TOOLCHAIN,sha
from s33_verify_gnu_defined_memory import LAB,BUILD,known_sections
from s33_verify_gnu_dsp_lab import compile_probe
from s33_verify_ff7_transfer_windows import SeparatedRunner,REUSED
from s33_trace_state_dispatch import verified_payloads
from s33_verify_sensor_mmio_dialog import aligned_window

BRANCH_BITS=[(0x2e3bac,0xffc3000,5,'zero'),(0x2e3be0,0xffc3000,0,'one'),(0x2e3c14,0xffc3000,1,'one'),(0x2e3c48,0xffc3000,3,'nonzero'),(0x2e3c7c,0xffc3000,4,'nonzero'),(0x2e3cb0,0xffc3000,8,'one'),(0x2e3ce4,0xffc3000,9,'one'),(0x2e3d18,0xffc3130,0,'one')]
SPLITS=[(0x2e3dc4,0xffc3070),(0x2e3e38,0xffc30c0),(0x2e3eac,0xffc30dc),(0x2e3ed4,0xffc3100),(0x2e3f48,0xffc311c),(0x2e3f70,0xffc3044)]
QUADS=[(0x2e3dec,0xffc3078),(0x2e3e60,0xffc30c8),(0x2e3efc,0xffc3108)]
VALUES=[0,1,2,3,0x80000000,0xffffffff,0x12345678,0xa55a5aa5]
INPUTS=[([640,480,320,240,128,64],[8]*9),([320,240,640,480,1024,768],list(range(1,10))),([1,2,3,4,5,6],[1]*9),([1024,768,256,192,64,48],[16,8,4,2,1,3,5,7,9])]

def stack_values(path):
 values={}
 for line in path.read_text().splitlines():
  m=re.match(r'0x([0-9a-f]+)\s+ldw\s+.*? - .*?<- (0x[0-9a-f]+)',line)
  if m and int(m[1],16)in range(0x2e2a24,0x2e2c75,16):values[int(m[1],16)]=int(m[2],16)&65535
 return values

def main():
 r=SeparatedRunner(SimpleNamespace(legacy_root=LEGACY,toolchain=TOOLCHAIN,output=None,action='ffc3000-ffb9f-original-computation'));print('Evidence:',r.out,flush=True)
 try:
  r.prepare();r.known_ranges='';assert sha(LAB/'install/bin/arc-elf32-run')==json.loads(BUILD.read_text())['engine_sha256'];r.experimental_engine=LAB;assert sha(REUSED/'observer')==json.loads((REUSED/'verified_evidence.json').read_text())['files']['observer'];shutil.copy2(REUSED/'observer',r.out/'observer')
  for p in[Path(__file__),BUILD,LAB/'install/bin/arc-elf32-run',REUSED/'observer',REUSED/'verified_evidence.json']+[Path(__file__).with_name(x+'.py')for x in['s33_run_gnu_arc700','s33_verify_gnu_defined_memory','s33_verify_gnu_dsp_lab','s33_verify_ff7_transfer_windows','s33_trace_state_dispatch','s33_verify_sensor_mmio_dialog']]:r.input_hashes[str(p)]=sha(p)
  shutil.copy2(Path(__file__),r.out/Path(__file__).name);bs,ps,bd=verified_payloads(ROOT);body=ps[0];base=bs[0]['load_address_candidate'];mf=r.out/'payload0_mmap.bin';mf.write_bytes(body);r.input_hashes[str(bd/bs[0]['file'])]=sha(bd/bs[0]['file']);(r.out/'linear_navigation_only.txt').write_text('\n'.join(aligned_window(body,base,a,b)for a,b in[(0x2e3bac,0x2e3f98),(0x2e2918,0x2e2988),(0x2e29b4,0x2e2cc0),(0x303a40,0x303c40)]));pairs=[]
  for group,pattern in[('ffc',p)for p in range(8)]+[('ffb',p)for p in range(4)]:
   v=VALUES[pattern];scenario=f'{group}_{pattern}';buffers={};sequence=[];calls=[];computed_slots=[];asm='mov r20,sp\nmov r13,0x13371337\nmov r14,0x14471447\nmov r15,0x15571557\nmov r16,0x16671667\n'
   addresses=({0xffc3000,0xffc3130,0xffc3008,0xffc300c}|{a+off for _,a in SPLITS for off in[0,4]}|{a+off for _,a in QUADS for off in[0,4,8,12]})if group=='ffc'else(set(range(0xffb9f10,0xffb9f28,4))|set(range(0xffb9f2c,0xffb9fc4,4))|{0xffb9fc4});assert len(addresses)==(28 if group=='ffc'else 45);initial={a:(0 if pattern==0 else 65535 if pattern==1 else((pattern*0x2345)^a)&65535)for a in addresses};state=dict(initial)
   def call(entry,args,events,ret=None):
    nonlocal asm
    asm+=''.join(f'mov r{i},{x&0xffffffff:#x}\n'for i,x in enumerate(args))+f'mov r12,{entry:#x}\njl [r12]\n'
    if ret is not None:asm+=f'cmp r0,{ret:#x}\nbne fail\n'
    asm+='cmp sp,r20\nbne fail\n'+''.join(f'cmp r{i},{x:#x}\nbne fail\n'for i,x in[(13,0x13371337),(14,0x14471447),(15,0x15571557),(16,0x16671667)]);calls.append(dict(entry=entry,arguments=args,expected_return=ret));sequence.extend(events)
    for _,op,a,x in events:
     if op=='write':state[a]=x
   if group=='ffc':
    for entry,a,bit,rule in BRANCH_BITS:
     for flag in[0,1,2,3,0x80000000,0xffffffff]:
      is_set=(flag==0 if rule=='zero'else flag==1 if rule=='one'else flag!=0);off=20 if is_set else 36;new=state[a]|(1<<bit)if is_set else state[a]&~(1<<bit);call(entry,[flag],[(entry+off,'read',a,state[a]),(entry+off+8,'write',a,new)])
    a=0xffc3008;call(0x2e3d4c,[],[(0x2e3d58,'read',a,state[a])],state[a]);call(0x2e3d60,[v],[(0x2e3d6c,'write',a,v&65535)]);call(0x2e3d4c,[],[(0x2e3d58,'read',a,state[a])],state[a])
    a=0xffc300c;mask=VALUES[(pattern+4)%8]
    for flag in[0,1,2,0xffffffff]:
     rd=24 if flag==1 else 42;wr=34 if flag==1 else 50;new=((state[a]|mask)if flag==1 else(state[a]&~mask))&65535;call(0x2e3d74,[flag,mask],[(0x2e3d74+rd,'read',a,state[a]),(0x2e3d74+wr,'write',a,new)]);call(0x2e3db0,[],[(0x2e3dbc,'read',a,state[a])],state[a])
    for entry,a in SPLITS:call(entry,[v],[(entry+16,'write',a,v&65535),(entry+32,'write',a+4,v>>16)])
    for entry,a in QUADS:
     q=VALUES[(pattern+2)%8];call(entry,[v,q],[(entry+20,'write',a,v&65535),(entry+36,'write',a+4,v>>16),(entry+52,'write',a+8,q&65535),(entry+68,'write',a+12,q>>16)])
   else:
    argv=[VALUES[(pattern+i+4)%8]for i in range(3)];call(0x2e2918,argv,[(0x2e2930+16*i,'write',0xffb9f10+4*i,(argv[i//2]>>(16*(i%2)))&65535)for i in range(6)])
    for flag in[0,1,2,0xffffffff]:
     a=0xffb9fc4;off=20 if flag else 36;new=state[a]|1 if flag else state[a]&~1;call(0x2e2c8c,[flag],[(0x2e2c8c+off,'read',a,state[a]),(0x2e2c8c+off+8,'write',a,new)])
    halves,bytes_=INPUTS[pattern];raw=struct.pack('<6H9B',*halves,*bytes_);p=r.out/(scenario+'_input.bin');p.write_bytes(raw);buffers[0x700000]=dict(file=p.name,before=raw.hex());events=[]
    for i in range(38):
     pc=0x2e2a30+16*i;a=struct.unpack_from('<I',body,pc-4-base)[0];assert a in addresses;computed_slots.append(dict(source_pc=pc-12,store_pc=pc,address=a));events.append((pc,'write',a,None))
    call(0x2e29b4,[0x700000],events)
   asm+='mov r0,0\nb finish\nfail:\nmov r0,7\nfinish:\nmov r8,1\ntrap_s 1\n';elf=compile_probe(r,scenario,asm);traces=[];reference_values=None
   for enabled in[False,True]:
    name=scenario+('_observed'if enabled else'_reference');r.observe=enabled;options=['--memory-mapfile','/result/'+mf.name,'--memory-region',f'{base:#x},{len(body):#x}'];fixtures={}
    for a,b in buffers.items():options+=['--memory-mapfile','/result/'+b['file'],'--memory-region',f'{a:#x},{len(bytes.fromhex(b["before"])):#x}']
    for a,x in sorted(initial.items()):
     raw=bytearray(b'\xa5'*8);struct.pack_into('<H',raw,a%8,x);p=r.out/f'{name}_{a:x}.bin';p.write_bytes(raw);fixtures[hex(a)]=dict(file=p.name,before=raw.hex());options+=['--memory-mapfile','/result/'+p.name,'--memory-region',f'{a:#x},2']
    r.range_override=known_sections(elf,False)+f',{base:#x}:{len(body):#x}'+''.join(f',{a:#x}:{len(bytes.fromhex(b["before"])):#x}'for a,b in buffers.items());case,log=r.run(name,'/result/'+elf.name,options,trace=True,extract=True);assert case['exit_code']==0 and case['fault']is None,(name,log[-5000:]);assert all(s not in log for s in['S33_UNDEFINED','S33_AUX_UNKNOWN','runtime error:']);trace=r.out/(name+'.trace')
    if group=='ffb':
     values=stack_values(trace);assert len(values)==38
     if not enabled:reference_values=values
     assert values==reference_values;completed=[(pc,op,a,values[pc-12]if x is None else x)for pc,op,a,x in sequence]
    else:completed=sequence
    final=dict(initial)
    for _,op,a,x in completed:
     if op=='write':final[a]=x
    events=[json.loads(s.removeprefix('S33_MEM '))for s in(r.out/(name+'.stderr.log')).read_text().splitlines()if s.startswith('S33_MEM ')];done=[e for e in events if e['stage']=='result'];assert len(events)==2*len(done)and all(e['width_bytes']==2 for e in done);assert[(e['pc'],e['operation'],e['address'],e['value'])for e in done]==(completed if enabled else[]),(name,done,completed)
    for key,f in fixtures.items():
     a=int(key,0);after=(r.out/f['file']).read_bytes();before=bytes.fromhex(f['before']);assert struct.unpack_from('<H',after,a%8)[0]==final[a]and all(after[j]==before[j]for j in range(8)if j not in[a%8,a%8+1]);f['after']=after.hex()
    assert mf.read_bytes()==body and all((r.out/b['file']).read_bytes()==bytes.fromhex(b['before'])for b in buffers.values());case.update(scenario=scenario,group=group,pattern=pattern,observer_enabled=enabled,fixtures=fixtures,input_buffers=buffers,original_calls=calls,completed_memory_events=done,computed_slots=computed_slots,computed_value_oracle='original_CPU_stack_loads_not_independent_math'if group=='ffb'else None,full_original_calls_completed=True);traces.append(trace.read_bytes());print(name,'PASS',len(done),'events',flush=True)
   assert traces[0]==traces[1];pairs.append(dict(scenario=scenario,events=len(sequence),trace_identical=True))
  fw=(ROOT/'OriginalSoftware_NikonS33_V1.1/firmware.bin').read_bytes();offset=fw.find(body);assert offset>=0 and fw.find(body,offset+1)<0;r.results.update(status='PASS_FFC3000_FFB_COMPUTED',pairs=pairs,payload=dict(base=base,size=len(body),firmware_offset=offset,sha256=sha(mf),path=str(mf)),capture_streams_separate=True,hardware_access=False,gnu_modified=False,limits=['FFC and direct FFB formulas independently reconstructed; computed FFB outputs traced from original303A40 stack results,not independently mathematically validated.','Original DSP/software-floating helpers execute unchanged in provisional GNU model; no hardware or physical coefficient meaning verified.','Synthetic callers,input buffer,stack and MMIO seeds are fixtures;real Nikon parameter domains remain unproven.','No physical reset,permission,atomicity,latch,IRQ or timing inference.']);r.finish()
 except Exception as exc:r.results.update(status='FAIL',error=repr(exc));raise
 finally:r.save()
 print(r.out/'verified_evidence.json',flush=True)
if __name__=='__main__':main()
