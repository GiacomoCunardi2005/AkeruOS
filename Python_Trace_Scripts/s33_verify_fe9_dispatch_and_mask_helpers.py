#!/usr/bin/env python3
"""Original bounded FE9 selectors and unbound mask-helper contracts on GNU CPU."""
import json,struct,shutil
from pathlib import Path
from types import SimpleNamespace
from s33_run_gnu_arc700 import ROOT,LEGACY,TOOLCHAIN,sha
from s33_verify_gnu_defined_memory import LAB,BUILD,known_sections
from s33_verify_ff7_transfer_windows import SeparatedRunner
from s33_verify_gnu_dsp_lab import compile_probe
from s33_trace_state_dispatch import verified_payloads
from s33_verify_sensor_mmio_dialog import aligned_window
from s33_verify_custom_aux_cfg import call_at
REUSED=ROOT/'outputs/gnu_arc700/20261025T104108Z_2704fcf9'
LAB_CELL=0xffb8000
FAMILIES=[dict(first=0x30989c,masked=[0x3098b8,0x309918,0x309944,0x309970,0x30999c,0x3099e4],flag=0x3098e4,split=0x3099c8,get=0x309a10),dict(first=0x309ab4,masked=[0x309ad0,0x309b30,0x309b5c,0x309b88,0x309bb4,0x309be0],flag=0x309afc,split=0x309c0c,get=0x309c28)]
DISPATCH=[(0x309a2c,0xfe9013c,10),(0x309c44,0xfe9813c,11)]
MASKS=[0]+[1<<i for i in range(16)]+[0xa55a,0x8001,0xff00,0xffff,0x10000,0x80000000,0xffffffff]
def first16(value):
 value&=65535
 return (value&-value).bit_length()-1 if value else 15

def main():
 r=SeparatedRunner(SimpleNamespace(legacy_root=LEGACY,toolchain=TOOLCHAIN,output=None,action='fe9-selectors-mask-contracts'));print('Evidence:',r.out,flush=True)
 try:
  r.prepare();r.known_ranges='';assert sha(LAB/'install/bin/arc-elf32-run')==json.loads(BUILD.read_text())['engine_sha256'];r.experimental_engine=LAB;assert sha(REUSED/'observer')==json.loads((REUSED/'verified_evidence.json').read_text())['files']['observer'];shutil.copy2(REUSED/'observer',r.out/'observer')
  for p in[Path(__file__),BUILD,LAB/'install/bin/arc-elf32-run',REUSED/'observer',REUSED/'verified_evidence.json']+[Path(__file__).with_name(x+'.py')for x in['s33_verify_ff7_transfer_windows','s33_verify_sensor_mmio_dialog','s33_run_gnu_arc700','s33_trace_state_dispatch','s33_verify_gnu_defined_memory','s33_verify_gnu_dsp_lab','s33_verify_custom_aux_cfg']]:r.input_hashes[str(p)]=sha(p)
  shutil.copy2(Path(__file__),r.out/Path(__file__).name);bs,ps,bd=verified_payloads(ROOT);body=ps[0];base=bs[0]['load_address_candidate'];mf=r.out/'payload0_mmap.bin';mf.write_bytes(body);targets={0x309884,*[x for f in FAMILIES for x in[f['first'],*f['masked'],f['flag'],f['split'],f['get']]],*[e for e,_,_ in DISPATCH]};calls=[];pointers=[]
  for info in bs:
   blob=ps[info['index']];loadbase=info['load_address_candidate'];r.input_hashes[str(bd/info['file'])]=sha(bd/info['file'])
   for off in range(0,len(blob)-7,2):
    c=call_at(blob,off,loadbase)
    if c and c['target']in targets:calls.append(dict(payload=info['index'],**c))
   for target in sorted(targets):
    for kind,needle in[('LE',struct.pack('<I',target)),('ME',struct.pack('<HH',target>>16,target&65535))]:
     off=blob.find(needle)
     while off>=0:pointers.append(dict(payload=info['index'],address=hex(loadbase+off),target=hex(target),kind=kind));off=blob.find(needle,off+1)
  census=dict(classification='static_candidates_not_executed_caller_domains',targets=list(map(hex,sorted(targets))),call_candidates=calls,pointer_candidates=pointers,payload_sha256={str(bd/i['file']):sha(bd/i['file'])for i in bs},limits=['Halfword BL andexactLE/ME references only;data can decode ascode,indirect/computed/tail callers remain open.','No register admission orNikon argument domain inferred fromraw candidates.']);(r.out/'caller_census.json').write_text(json.dumps(census,indent=2)+'\n');print('Census:',len(calls),'BL candidates,',len(pointers),'word references',flush=True)
  (r.out/'linear_navigation_only.txt').write_text(aligned_window(body,base,0x309884,0x309cd0));pairs=[];sentinels={13:0x13371337,14:0x14471447,15:0x15571557,16:0x16671667,17:0x17771777,18:0x18871887,19:0x19971997}
  for group,pattern in[('fixed',p)for p in range(8)]+[('generic',p)for p in range(4)]:
   scenario=f'{group}_{pattern}';seed=[0,65535,0xa55a,0x5aa5,0xfc00,0xf800,0x8001,0x7ffe][pattern];value=[0,1,0x3ff,0x400,0x7ff,0x800,0x80018000,0xffffffff][pattern]if group=='fixed'else[0,0xffffffff,0x12345678,0x800180ff][pattern];addresses=([a+off for _,a,_ in DISPATCH for off in[0,4]]+[0xffc7070])if group=='fixed'else[LAB_CELL,LAB_CELL+4];initial={a:seed for a in addresses};state=dict(initial);sequence=[];original_calls=[];asm='mov r20,sp\n'+''.join(f'mov r{i},{x:#x}\n'for i,x in sentinels.items())
   def call(entry,argv,events,ret=None):
    nonlocal asm
    asm+=''.join(f'mov r{i},{x&0xffffffff:#x}\n'for i,x in enumerate(argv))+f'mov r12,{entry:#x}\njl [r12]\n'
    if ret is not None:asm+=f'cmp r0,{ret:#x}\nbne fail\n'
    asm+='cmp sp,r20\nbne fail\n'+''.join(f'cmp r{i},{x:#x}\nbne fail\n'for i,x in sentinels.items());original_calls.append(dict(entry=hex(entry),arguments=list(map(hex,argv)),expected_return=ret));sequence.extend(events)
    for _,op,a,x in events:
     if op=='write':state[a]=x
   if group=='fixed':
    call(0x309884,[],[(0x309890,'read',0xffc7070,state[0xffc7070])],state[0xffc7070])
    for entry,a,width in DISPATCH:
     delta=entry-0x309a2c;lowmask=(1<<width)-1
     for selector in[1,0,1,2,3,4,255,0x7fffffff,0x80000000,0xffffffff]:
      if selector==0:new=(state[a]&~lowmask)|(value&lowmask);ev=[(0x309a58+delta,'read',a,state[a]),(0x309a66+delta,'write',a,new)];ret=0
      elif selector==1:ev=[(0x309aa4+delta,'read',a,state[a])];ret=state[a]
      elif selector==2:new=(state[a+4]&~lowmask)|(value&lowmask);ev=[(0x309a78+delta,'read',a+4,state[a+4]),(0x309a66+delta,'write',a+4,new)];ret=0
      elif selector==3:new=state[a+4]&~value&65535;ev=[(0x309a90+delta,'read',a+4,state[a+4]),(0x309a66+delta,'write',a+4,new)];ret=0
      else:ev=[];ret=0x55aa
      call(entry,[value,selector],ev,ret)
   else:
    assert len(MASKS)==24
    for f in FAMILIES:
     for mask in MASKS:
      shift=first16(mask);call(f['first'],[mask],[],shift)
      for entry in f['masked']:
       new=((state[LAB_CELL]&~mask)|((value<<shift)&mask))&65535;call(entry,[LAB_CELL,value,mask],[(entry+12,'read',LAB_CELL,state[LAB_CELL]),(entry+34,'write',LAB_CELL,new)])
      ret=((state[LAB_CELL]&mask)>>shift)&65535;call(f['get'],[LAB_CELL,mask],[(f['get']+6,'read',LAB_CELL,state[LAB_CELL])],ret)
      for flag in[0,1,2,0xffffffff]:
       off=16 if flag==0 else 36;wr=24 if flag==0 else 44;new=state[LAB_CELL]|(1<<shift)if flag else state[LAB_CELL]&~(1<<shift);call(f['flag'],[LAB_CELL,flag,mask],[(f['flag']+off,'read',LAB_CELL,state[LAB_CELL]),(f['flag']+wr,'write',LAB_CELL,new)])
     call(f['split'],[LAB_CELL,value],[(f['split']+12,'write',LAB_CELL,value&65535),(f['split']+20,'write',LAB_CELL+4,value>>16)])
   assert len(sequence)==(17 if group=='fixed'else 1012);asm+='mov r0,0\nb finish\nfail:\nmov r0,7\nfinish:\nmov r8,1\ntrap_s 1\n';elf=compile_probe(r,scenario,asm);traces=[]
   for enabled in[False,True]:
    name=scenario+('_observed'if enabled else'_reference');r.observe=enabled;options=['--memory-mapfile','/result/'+mf.name,'--memory-region',f'{base:#x},{len(body):#x}'];fixtures={}
    for a in addresses:
     before=bytearray(b'\xa5'*8);struct.pack_into('<H',before,a%8,seed);q=r.out/f'{name}_{a:x}.bin';q.write_bytes(before);fixtures[hex(a)]=dict(file=q.name,before=before.hex());options+=['--memory-mapfile','/result/'+q.name,'--memory-region',f'{a:#x},2']
    r.range_override=known_sections(elf,False)+f',{base:#x}:{len(body):#x}';case,log=r.run(name,'/result/'+elf.name,options,trace=True,extract=True);assert case['exit_code']==0 and case['fault']is None,log[-5000:];assert all(x not in log for x in['S33_UNDEFINED','S33_AUX_UNKNOWN','runtime error:']);captured=[json.loads(line.removeprefix('S33_MEM '))for line in(r.out/(name+'.stderr.log')).read_text().splitlines()if line.startswith('S33_MEM ')];events=[e for e in captured if e['stage']=='result'];assert len(captured)==2*len(events)and all(e['width_bytes']==2 for e in captured);assert[(e['pc'],e['operation'],e['address'],e['value'])for e in events]==(sequence if enabled else[])
    for key,q in fixtures.items():
     a=int(key,0);before=bytes.fromhex(q['before']);after=(r.out/q['file']).read_bytes();off=a%8;assert struct.unpack_from('<H',after,off)[0]==state[a]and all(before[j]==after[j]for j in range(8)if j not in[off,off+1]);q['after']=after.hex()
    assert mf.read_bytes()==body;case.update(scenario=scenario,group=group,pattern=pattern,observer_enabled=enabled,original_calls=original_calls,fixtures=fixtures,completed_memory_events=events,full_original_calls_completed=True,address_binding='original_fixed_pool'if group=='fixed'else'unbound_synthetic_lab_address_no_catalog_admission');traces.append((r.out/(name+'.trace')).read_bytes());print(name,'PASS',len(events),'events',flush=True)
   assert traces[0]==traces[1];pairs.append(dict(scenario=scenario,events=len(sequence),trace_identical=True))
  fw=(ROOT/'OriginalSoftware_NikonS33_V1.1/firmware.bin').read_bytes();offset=fw.find(body);assert offset>=0 and fw.find(body,offset+1)<0;assert len(pairs)==12 and sum(x['events']for x in pairs)==4184;r.results.update(status='PASS_FE9_SELECTORS_UNBOUND_MASK_HELPERS',pairs=pairs,generic_helper_families=FAMILIES,generic_masks=list(map(hex,MASKS)),generic_sample_addresses_not_admitted=[hex(LAB_CELL),hex(LAB_CELL+4)],caller_census_file='caller_census.json',payload=dict(base=base,size=len(body),firmware_offset=offset,sha256=sha(mf),path=str(mf)),capture_streams_separate=True,hardware_access=False,gnu_modified=False,limits=['Only fixed FE9dispatcher pool addresses andFFC7070read are admitted;generichelper r0destinations remain unbound andlab samples do not proveNikon caller domains.','First-set-bit helper searches low16 andreturns15 whennone:zero/high-only masks can selectbit15 inflaghelper,not a physicalhardware defect.','Two selector tables bind0..3;invalidunsigned selectors return55AA withno MMIO,not a universalerror convention.','Seed/backing andcallers are fixtures;no physicalreset/permission/W1C/IRQ/timing oratomicity established.']);r.finish()
 except Exception as exc:r.results.update(status='FAIL',error=repr(exc));raise
 finally:r.save()
 print(r.out/'verified_evidence.json',flush=True)
if __name__=='__main__':main()
