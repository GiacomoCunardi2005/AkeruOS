#!/usr/bin/env python3
"""Original FFC2000 control tail and complete FFC4000 accessor group, offline GNU."""
import json,shutil,struct
from pathlib import Path
from types import SimpleNamespace
from s33_run_gnu_arc700 import ROOT,LEGACY,TOOLCHAIN,sha
from s33_verify_gnu_defined_memory import LAB,BUILD,known_sections
from s33_verify_gnu_dsp_lab import compile_probe
from s33_verify_ff7_transfer_windows import SeparatedRunner,REUSED
from s33_trace_state_dispatch import verified_payloads
from s33_verify_sensor_mmio_dialog import aligned_window

# Fixed source-derived entries; these describe software operations, not peripheral names.
RMW_BITS=[(0x2e3610,0xffc20b8,0,True),(0x2e362c,0xffc20b8,0,False),(0x2e3648,0xffc20b8,1,True),(0x2e3664,0xffc20b8,1,False),(0x2e3680,0xffc20bc,0,True),(0x2e369c,0xffc20bc,0,False),(0x2e36b8,0xffc20bc,1,False),(0x2e36d4,0xffc20bc,1,True),(0x2e36f0,0xffc20bc,2,True),(0x2e3754,0xffc20bc,5,True),(0x2e37b8,0xffc20bc,8,True),(0x2e37d4,0xffc20bc,8,False),(0x2e3820,0xffc2098,12,True),(0x2e383c,0xffc2098,12,False)]
SET_MASKS=[(0x2e370c,12),(0x2e3730,28),(0x2e3770,96),(0x2e3794,224)]
EQ1=[(0x2e38a0,0xffc4000,0),(0x2e38d4,0xffc4000,1),(0x2e3960,0xffc4000,8),(0x2e3994,0xffc4000,9),(0x2e39c8,0xffc4100,0)]
LSB=[(0x2e3908,3),(0x2e3934,4)]
SPLITS=[(0x2e3a74,0xffc4070),(0x2e3ae8,0xffc40c0),(0x2e3b5c,0xffc40dc),(0x2e3b84,0xffc4044)]
QUADS=[(0x2e3a9c,0xffc4078),(0x2e3b10,0xffc40c8)]
VALUES=[0,1,2,3,0x80000000,0xffffffff,0x12345678,0xa55a5aa5]
SEEDS=[0,65535,0x40,0x80,0x100,0x1c0,0x55aa,0xa55a]

def main():
 r=SeparatedRunner(SimpleNamespace(legacy_root=LEGACY,toolchain=TOOLCHAIN,output=None,action='ffc2000-control-tail-ffc4000'));print('Evidence:',r.out,flush=True)
 try:
  r.prepare();r.known_ranges='';assert sha(LAB/'install/bin/arc-elf32-run')==json.loads(BUILD.read_text())['engine_sha256'];r.experimental_engine=LAB;assert sha(REUSED/'observer')==json.loads((REUSED/'verified_evidence.json').read_text())['files']['observer'];shutil.copy2(REUSED/'observer',r.out/'observer')
  deps=[Path(__file__),BUILD,LAB/'install/bin/arc-elf32-run',REUSED/'observer',REUSED/'verified_evidence.json']+[Path(__file__).with_name(x+'.py')for x in['s33_run_gnu_arc700','s33_verify_gnu_defined_memory','s33_verify_gnu_dsp_lab','s33_verify_ff7_transfer_windows','s33_trace_state_dispatch','s33_verify_sensor_mmio_dialog']]
  for p in deps:r.input_hashes[str(p)]=sha(p)
  shutil.copy2(Path(__file__),r.out/Path(__file__).name);bs,ps,bd=verified_payloads(ROOT);body=ps[0];base=bs[0]['load_address_candidate'];mf=r.out/'payload0_mmap.bin';mf.write_bytes(body);r.input_hashes[str(bd/bs[0]['file'])]=sha(bd/bs[0]['file']);(r.out/'linear_navigation_only.txt').write_text(aligned_window(body,base,0x2e3548,0x2e3bac));pairs=[]
  addresses={0xffc20b4,0xffc20b8,0xffc20bc,0xffc20c0,0xffc20c4,0xffc2098,0xffc20a0,0xffc4000,0xffc4100,0xffc4008,0xffc400c}|{a+off for _,a in SPLITS for off in[0,4]}|{a+off for _,a in QUADS for off in[0,4,8,12]};assert len(addresses)==27
  for pattern,v in enumerate(VALUES):
   scenario=f'controls_{pattern}';initial={a:SEEDS[pattern]for a in addresses};state=dict(initial);sequence=[];calls=[];asm='mov r20,sp\nmov r13,0x13371337\nmov r14,0x14471447\nmov r15,0x15571557\nmov r16,0x16671667\n'
   def call(entry,args,events,ret=None):
    nonlocal asm
    asm+=''.join(f'mov r{i},{x&0xffffffff:#x}\n'for i,x in enumerate(args))+f'mov r12,{entry:#x}\njl [r12]\n'
    if ret is not None:asm+=f'cmp r0,{ret:#x}\nbne fail\n'
    asm+='cmp sp,r20\nbne fail\n'+''.join(f'cmp r{i},{x:#x}\nbne fail\n'for i,x in[(13,0x13371337),(14,0x14471447),(15,0x15571557),(16,0x16671667)]);calls.append(dict(entry=entry,arguments=args,expected_return=ret));sequence.extend(events)
    for _,op,a,x in events:
     if op=='write':state[a]=x
   def status():
    for entry,a,bit in[(0x2e355c,0xffc20b4,0),(0x2e358c,0xffc20b4,1),(0x2e3858,0xffc20a0,6),(0x2e3870,0xffc20a0,7),(0x2e3888,0xffc20a0,8)]:call(entry,[],[(entry+12,'read',a,state[a])],(state[a]>>bit)&1)
   status();call(0x2e3548,[v],[(0x2e3554,'write',0xffc20b4,v&65535)]);status()
   for entry,value in[(0x2e3578,1),(0x2e35a8,2)]:call(entry,[],[(entry+12,'write',0xffc20b4,value)]);status()
   call(0x2e35bc,[],[(0x2e35c8,'read',0xffc20b8,state[0xffc20b8])],state[0xffc20b8]);call(0x2e35d0,[v],[(0x2e35dc,'write',0xffc20b8,v&65535)]);call(0x2e35e4,[v],[(0x2e35f4,'read',0xffc20b8,state[0xffc20b8]),(0x2e3608,'write',0xffc20b8,(~v)&65535)]);call(0x2e35bc,[],[(0x2e35c8,'read',0xffc20b8,state[0xffc20b8])],state[0xffc20b8])
   for entry,a,bit,set_ in RMW_BITS:
    new=state[a]|1<<bit if set_ else state[a]&~(1<<bit);call(entry,[],[(entry+12,'read',a,state[a]),(entry+20,'write',a,new)])
   for entry,mask in SET_MASKS:
    a=0xffc20bc;call(entry,[],[(entry+12,'read',a,state[a]),(entry+26,'write',a,state[a]|mask)])
   for entry,a in[(0x2e37f0,0xffc20c0),(0x2e3808,0xffc20c4)]:args=[v,VALUES[(pattern+3)%8]];call(entry,args,[(entry+16,'write',a,(args[0]|args[1]<<8)&65535)])
   for entry,a,bit in EQ1:
    for flag in[0,1,2,0xffffffff]:
     off=20 if flag==1 else 36;new=state[a]|1<<bit if flag==1 else state[a]&~(1<<bit);call(entry,[flag],[(entry+off,'read',a,state[a]),(entry+off+8,'write',a,new)])
   for entry,bit in LSB:
    a=0xffc4000;call(entry,[v],[(entry+16,'read',a,state[a]),(entry+34,'write',a,(state[a]&~(1<<bit))|((v&1)<<bit))])
   a=0xffc4008;call(0x2e39fc,[],[(0x2e3a08,'read',a,state[a])],state[a]);call(0x2e3a10,[v],[(0x2e3a1c,'write',a,v&65535)]);call(0x2e39fc,[],[(0x2e3a08,'read',a,state[a])],state[a])
   a=0xffc400c;mask=VALUES[(pattern+4)%8]
   for flag in[0,1,2,0xffffffff]:
    off=24 if flag==1 else 42;store_off=34 if flag==1 else 50;new=((state[a]|mask)if flag==1 else(state[a]&~mask))&65535;call(0x2e3a24,[flag,mask],[(0x2e3a24+off,'read',a,state[a]),(0x2e3a24+store_off,'write',a,new)]);call(0x2e3a60,[],[(0x2e3a6c,'read',a,state[a])],state[a])
   for entry,a in SPLITS:call(entry,[v],[(entry+16,'write',a,v&65535),(entry+32,'write',a+4,v>>16)])
   for entry,a in QUADS:
    other=VALUES[(pattern+2)%8];call(entry,[v,other],[(entry+20,'write',a,v&65535),(entry+36,'write',a+4,v>>16),(entry+52,'write',a+8,other&65535),(entry+68,'write',a+12,other>>16)])
   asm+='mov r0,0\nb finish\nfail:\nmov r0,7\nfinish:\nmov r8,1\ntrap_s 1\n';elf=compile_probe(r,scenario,asm);traces=[]
   for enabled in[False,True]:
    name=scenario+('_observed'if enabled else'_reference');r.observe=enabled;options=['--memory-mapfile','/result/'+mf.name,'--memory-region',f'{base:#x},{len(body):#x}'];fixtures={}
    for a,x in sorted(initial.items()):
     raw=bytearray(b'\xa5'*8);struct.pack_into('<H',raw,a%8,x);p=r.out/f'{name}_{a:x}.bin';p.write_bytes(raw);fixtures[hex(a)]=dict(file=p.name,before=raw.hex());options+=['--memory-mapfile','/result/'+p.name,'--memory-region',f'{a:#x},2']
    r.range_override=known_sections(elf,False)+f',{base:#x}:{len(body):#x}';case,log=r.run(name,'/result/'+elf.name,options,trace=True,extract=True);assert case['exit_code']==0 and case['fault']is None,(name,log[-4000:]);assert all(s not in log for s in['S33_UNDEFINED','S33_AUX_UNKNOWN','runtime error:']);events=[json.loads(s.removeprefix('S33_MEM '))for s in(r.out/(name+'.stderr.log')).read_text().splitlines()if s.startswith('S33_MEM ')];done=[e for e in events if e['stage']=='result'];assert len(events)==2*len(done)and all(e['width_bytes']==2 for e in done);assert[(e['pc'],e['operation'],e['address'],e['value'])for e in done]==(sequence if enabled else[]),(name,done,sequence)
    for key,f in fixtures.items():
     a=int(key,0);after=(r.out/f['file']).read_bytes();before=bytes.fromhex(f['before']);assert struct.unpack_from('<H',after,a%8)[0]==state[a]and all(after[j]==before[j]for j in range(8)if j not in[a%8,a%8+1]);f['after']=after.hex()
    assert mf.read_bytes()==body;case.update(scenario=scenario,pattern=pattern,observer_enabled=enabled,fixtures=fixtures,original_calls=calls,completed_memory_events=done,full_original_calls_completed=True);traces.append((r.out/(name+'.trace')).read_bytes());print(name,'PASS',len(done),'events',flush=True)
   assert traces[0]==traces[1];pairs.append(dict(scenario=scenario,events=len(sequence),trace_identical=True))
  fw=(ROOT/'OriginalSoftware_NikonS33_V1.1/firmware.bin').read_bytes();offset=fw.find(body);assert offset>=0 and fw.find(body,offset+1)<0;assert len(pairs)==8;r.results.update(status='PASS_FFC_CONTROL_TAIL_4000',pairs=pairs,payload=dict(base=base,size=len(body),firmware_offset=offset,sha256=sha(mf),path=str(mf)),capture_streams_separate=True,hardware_access=False,gnu_modified=False,limits=['Synthetic callers, seeds and halfword storage are model fixtures, not Nikon hardware.','Write1/write2 are full halfword stores, not software RMW; physical acknowledgment/W1C semantics unknown.','Complement accessor reads MMIO then writes low16 of NOT argument; its read is not elided despite result independence.','Equality1 controls differ from argument LSB controls; domains of real Nikon callers remain open.','Sequential low/high stores do not prove atomic32bit transfer, latch, physical fields, reset, permissions or timing.']);r.finish()
 except Exception as exc:r.results.update(status='FAIL',error=repr(exc));raise
 finally:r.save()
 print(r.out/'verified_evidence.json',flush=True)
if __name__=='__main__':main()
