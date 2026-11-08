#!/usr/bin/env python3
"""Execute residual FF7 scalar operations with original code and unchanged GNU."""
import json,struct,shutil
from pathlib import Path
from types import SimpleNamespace
from s33_run_gnu_arc700 import ROOT,LEGACY,TOOLCHAIN,sha
from s33_verify_gnu_defined_memory import LAB,BUILD,known_sections
from s33_verify_ff7_transfer_windows import SeparatedRunner
from s33_verify_gnu_dsp_lab import compile_probe
from s33_trace_state_dispatch import verified_payloads
from s33_verify_sensor_mmio_dialog import aligned_window
REUSED=ROOT/'outputs/gnu_arc700/20261025T104108Z_2704fcf9'
BRANCHES=[(0x2e050c,0xff74000,0,'one'),(0x2e0b9c,0xff76008,2,'one'),(0x2e0c70,0xff76098,0,'one'),(0x2e0db4,0xff7000c,5,'nonzero'),(0x2e0e2c,0xff70400,5,'nonzero'),(0x2e0e60,0xff70400,6,'one'),(0x2e0e94,0xff74000,7,'nonzero'),(0x2e0ec8,0xff74000,8,'nonzero'),(0x2e0efc,0xff74000,9,'one')]
SINGLES=[(0x2e0d64+20*i,0xff76088+4*i)for i in range(4)]
SPLITS=[(0x2e11d0+40*i,0xff76100+8*i,0xff76104+8*i)for i in range(5)]
VALUES=[0,1,2,3,0x80000000,0xffffffff,0x12345678,0xa55a5aa5]
SEEDS=[0,65535,0xa55a,0x5aa5,0x8001,0x7ffe,0x20,0xffdf]
def main():
 r=SeparatedRunner(SimpleNamespace(legacy_root=LEGACY,toolchain=TOOLCHAIN,output=None,action='ff7-residual-scalar-controls'));print('Evidence:',r.out,flush=True)
 try:
  r.prepare();r.known_ranges='';assert sha(LAB/'install/bin/arc-elf32-run')==json.loads(BUILD.read_text())['engine_sha256'];r.experimental_engine=LAB;assert sha(REUSED/'observer')==json.loads((REUSED/'verified_evidence.json').read_text())['files']['observer'];shutil.copy2(REUSED/'observer',r.out/'observer')
  for p in[Path(__file__),BUILD,LAB/'install/bin/arc-elf32-run',REUSED/'observer',REUSED/'verified_evidence.json',Path(__file__).with_name('s33_verify_ff7_transfer_windows.py')]:r.input_hashes[str(p)]=sha(p)
  shutil.copy2(Path(__file__),r.out/Path(__file__).name);bs,ps,bd=verified_payloads(ROOT);body=ps[0];base=bs[0]['load_address_candidate'];mf=r.out/'payload0_mmap.bin';mf.write_bytes(body);r.input_hashes[str(bd/bs[0]['file'])]=sha(bd/bs[0]['file']);addresses=sorted({a for _,a,_,_ in BRANCHES}|{a for _,a in SINGLES}|{a for _,lo,hi in SPLITS for a in[lo,hi]}|{0xff70008,0xff741d4,0xff741d8,0xff760fc});assert len(addresses)==23
  windows=[(0x2e050c,0x2e0540),(0x2e0b9c,0x2e0bd0),(0x2e0c70,0x2e0ca4),(0x2e0d64,0x2e0f30),(0x2e1030,0x2e1054),(0x2e1150,0x2e1298)];(r.out/'linear_navigation_only.txt').write_text('\n\n'.join(aligned_window(body,base,a,b)for a,b in windows));pairs=[]
  for pattern,(v,seed)in enumerate(zip(VALUES,SEEDS)):
   scenario='controls_'+str(pattern);state={a:seed for a in addresses};calls=[];sequence=[];asm='mov r20,sp\nmov r13,0x13371337\nmov r14,0x14471447\nmov r15,0x15571557\nmov r16,0x16671667\n'
   def call(entry,argv,events,ret=None):
    nonlocal asm
    asm+=''.join(f'mov r{i},{x:#x}\n'for i,x in enumerate(argv))+f'mov r12,{entry:#x}\njl [r12]\n'
    if ret is not None:asm+=f'cmp r0,{ret:#x}\nbne fail\n'
    asm+='cmp sp,r20\nbne fail\n'+''.join(f'cmp r{i},{x:#x}\nbne fail\n'for i,x in[(13,0x13371337),(14,0x14471447),(15,0x15571557),(16,0x16671667)]);calls.append(dict(entry=hex(entry),arguments=list(map(hex,argv)),expected_return=hex(ret)if ret is not None else None));sequence.extend(events)
    for _,op,a,x in events:
     if op=='write':state[a]=x
   call(0x2e0de8,[],[(0x2e0df4,'read',0xff7000c,state[0xff7000c])],(state[0xff7000c]>>5)&1)
   for entry,a,bit,rule in BRANCHES:
    assert struct.unpack_from('<I',body,entry+16-base)[0]==a
    for flag in[0,1,2,3,0x80000000,0xffffffff]:
     flagset=flag==1 if rule=='one'else flag!=0;off=20 if flagset else 36;result=state[a]|1<<bit if flagset else state[a]&~(1<<bit);call(entry,[flag],[(entry+off,'read',a,state[a]),(entry+off+8,'write',a,result)])
     if entry==0x2e0db4:call(0x2e0de8,[],[(0x2e0df4,'read',a,state[a])],(state[a]>>5)&1)
   call(0x2e0e00,[],[(0x2e0e0c,'read',0xff70008,state[0xff70008])],state[0xff70008]&0x20);call(0x2e0e18,[v],[(0x2e0e24,'write',0xff70008,0x20)]);call(0x2e0e00,[],[(0x2e0e0c,'read',0xff70008,state[0xff70008])],0x20)
   for entry,a in SINGLES:call(entry,[v],[(entry+12,'write',a,v&65535)])
   other=VALUES[(pattern+3)%8];call(0x2e1030,[v,other],[(0x2e1040,'write',0xff741d4,v&65535),(0x2e104c,'write',0xff741d8,other&65535)])
   for entry,a,op,bit in[(0x2e1150,0xff760fc,'set',0),(0x2e116c,0xff760fc,'clear',0),(0x2e1188,0xff760fc,'set',1)]:
    result=state[a]|1<<bit if op=='set'else state[a]&~(1<<bit);call(entry,[v],[(entry+12,'read',a,state[a]),(entry+20,'write',a,result)])
   for value in[0,3,0xfc,0x100,0xffffffff,v]:
    a=0xff760fc;result=(state[a]&0xff03)|(value&0xfc);call(0x2e11a4,[value],[(0x2e11b4,'read',a,state[a]),(0x2e11c6,'write',a,result)])
   for entry,lo,hi in SPLITS:call(entry,[v],[(entry+16,'write',lo,v&65535),(entry+32,'write',hi,v>>16)])
   assert len(calls)==83 and len(sequence)==152;asm+='mov r0,0\nb finish\nfail:\nmov r0,7\nfinish:\nmov r8,1\ntrap_s 1\n';elf=compile_probe(r,scenario,asm);traces=[]
   for enabled in[False,True]:
    name=scenario+('_observed'if enabled else'_reference');r.observe=enabled;options=['--memory-mapfile','/result/'+mf.name,'--memory-region',f'{base:#x},{len(body):#x}'];fixtures={}
    for a in addresses:
     raw=bytearray(b'\xa5'*8);struct.pack_into('<H',raw,a%8,seed);p=r.out/f'{name}_{a:x}.bin';p.write_bytes(raw);fixtures[hex(a)]=dict(file=p.name,before=raw.hex());options+=['--memory-mapfile','/result/'+p.name,'--memory-region',f'{a:#x},2']
    r.range_override=known_sections(elf,False)+f',{base:#x}:{len(body):#x}';case,log=r.run(name,'/result/'+elf.name,options,trace=True,extract=True);assert case['exit_code']==0 and case['fault']is None,log[-5000:];assert all(s not in log for s in['S33_UNDEFINED','S33_AUX_UNKNOWN','runtime error:']);raw_events=[json.loads(s.removeprefix('S33_MEM '))for s in(r.out/(name+'.stderr.log')).read_text().splitlines()if s.startswith('S33_MEM ')];done=[e for e in raw_events if e['stage']=='result'];assert len(raw_events)==2*len(done)and all(e['width_bytes']==2 for e in raw_events);assert[(e['pc'],e['operation'],e['address'],e['value'])for e in done]==(sequence if enabled else[])
    for key,f in fixtures.items():
     a=int(key,0);after=(r.out/f['file']).read_bytes();before=bytes.fromhex(f['before']);assert struct.unpack_from('<H',after,a%8)[0]==state[a]and all(before[j]==after[j]for j in range(8)if j not in[a%8,a%8+1]);f['after']=after.hex()
    assert mf.read_bytes()==body;case.update(scenario=scenario,pattern=pattern,observer_enabled=enabled,original_calls=calls,fixtures=fixtures,completed_memory_events=done,full_original_calls_completed=True);traces.append((r.out/(name+'.trace')).read_bytes());print(name,'PASS',len(calls),'calls',len(done),'events',flush=True)
   assert traces[0]==traces[1];pairs.append(dict(scenario=scenario,events=len(sequence),calls=len(calls),trace_identical=True))
  fw=(ROOT/'OriginalSoftware_NikonS33_V1.1/firmware.bin').read_bytes();offset=fw.find(body);assert offset>=0 and fw.find(body,offset+1)<0;r.results.update(status='PASS_FF7_RESIDUAL_SCALAR_CONTROLS',pairs=pairs,scalar_addresses=list(map(hex,addresses)),selected_original_entries=26,payload=dict(base=base,size=len(body),firmware_offset=offset,sha256=sha(mf),path=str(mf)),capture_streams_separate=True,hardware_access=False,gnu_modified=False,limits=['FF70008 getter returns mask0x20,not normalized boolean;write0x20 does not prove acknowledgment orW1C.','FF760FC field replaces bits2..7 from rawargument&FC,preservinglow2 andhigh8;unconditionalbitset/clear ignoresargument.','Caller stack,MMIO seeds and backing are synthetic fixtures,not physical reset/configuration orfreeRAM.','Split argument means ordered halfwordstores,not atomicphysical32bit register;real caller domains andhardware semantics unknown.']);r.finish()
 except Exception as exc:r.results.update(status='FAIL',error=repr(exc));raise
 finally:r.save()
 print(r.out/'verified_evidence.json',flush=True)
if __name__=='__main__':main()
