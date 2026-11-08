#!/usr/bin/env python3
"""Run original FF7 packed-table writers with separate observer/reference traces."""
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
SPECS=[
 dict(name='masked7_a',entry=0x2e06f0,end=0x2e0774,mode='masked7',base=0xff74044,store_pc=0x2e074c,tails=[0xff74088],tail_pcs=[0x2e0768],aux_pcs=[0x2e072e,0x2e0734]),
 dict(name='masked7_b',entry=0x2e0774,end=0x2e07f8,mode='masked7',base=0xff7408c,store_pc=0x2e07d0,tails=[0xff740d0],tail_pcs=[0x2e07ec],aux_pcs=[0x2e07b2,0x2e07b8]),
 dict(name='strided_a',entry=0x2e0884,end=0x2e0908,mode='strided_bytes',base=0xff740f0,store_pc=0x2e08dc,tails=[0xff74138,0xff74134],tail_pcs=[0x2e08f0,0x2e08fc],aux_pcs=[0x2e08bc,0x2e08c2]),
 dict(name='contiguous_a',entry=0x2e0908,end=0x2e098c,mode='contiguous_bytes',base=0xff740f0,store_pc=0x2e0960,tails=[0xff74138,0xff74134],tail_pcs=[0x2e0974,0x2e0980],aux_pcs=[0x2e0940,0x2e0946]),
 dict(name='strided_b',entry=0x2e098c,end=0x2e0a10,mode='strided_bytes',base=0xff7413c,store_pc=0x2e09e4,tails=[0xff74184,0xff74180],tail_pcs=[0x2e09f8,0x2e0a04],aux_pcs=[0x2e09c4,0x2e09ca]),
 dict(name='contiguous_b',entry=0x2e0a10,end=0x2e0a94,mode='contiguous_bytes',base=0xff7413c,store_pc=0x2e0a68,tails=[0xff74184,0xff74180],tail_pcs=[0x2e0a7c,0x2e0a88],aux_pcs=[0x2e0a48,0x2e0a4e]),
 dict(name='strided_c',entry=0x2e0a94,end=0x2e0b18,mode='strided_bytes',base=0xff74188,store_pc=0x2e0aec,tails=[0xff741d0,0xff741cc],tail_pcs=[0x2e0b00,0x2e0b0c],aux_pcs=[0x2e0acc,0x2e0ad2]),
 dict(name='contiguous_c',entry=0x2e0b18,end=0x2e0b9c,mode='contiguous_bytes',base=0xff74188,store_pc=0x2e0b70,tails=[0xff741d0,0xff741cc],tail_pcs=[0x2e0b84,0x2e0b90],aux_pcs=[0x2e0b50,0x2e0b56])]

def main():
 r=SeparatedRunner(SimpleNamespace(legacy_root=LEGACY,toolchain=TOOLCHAIN,output=None,action='ff7-packed-tables'));print('Evidence:',r.out,flush=True)
 try:
  r.prepare();r.known_ranges='';build=json.loads(BUILD.read_text());assert sha(LAB/'install/bin/arc-elf32-run')==build['engine_sha256'];r.experimental_engine=LAB
  prior=json.loads((REUSED/'verified_evidence.json').read_text());assert sha(REUSED/'observer')==prior['files']['observer'];shutil.copy2(REUSED/'observer',r.out/'observer')
  for p in[Path(__file__),Path(__file__).with_name('s33_verify_ff7_transfer_windows.py'),BUILD,LAB/'install/bin/arc-elf32-run',REUSED/'observer',REUSED/'verified_evidence.json']:r.input_hashes[str(p)]=sha(p)
  shutil.copy2(Path(__file__),r.out/Path(__file__).name);bs,ps,bd=verified_payloads(ROOT);info=next(b for b in bs if b['index']==0);body=ps[0];base=info['load_address_candidate'];main_file=r.out/'payload0_mmap.bin';main_file.write_bytes(body);r.input_hashes[str(bd/info['file'])]=sha(bd/info['file'])
  windows=[(0x2e0600,0x2e0b9c)];(r.out/'original_windows_candidates.txt').write_text(aligned_window(body,base,*windows[0]));pairs=[];previous={}
  scenarios=[(s,p)for s in SPECS for p in range(4)]+[(None,p)for p in range(2)]
  for spec,pattern in scenarios:
   name=(spec['name']if spec else'scalars')+f'_{pattern}';sequence=[];calls=[];buffers={};initial={};expected={};asm='mov r20,sp\nmov r13,0x13371337\nmov r14,0x14471447\nmov r15,0x15571557\nmov r16,0x16671667\n'
   def call(entry,args,events):
    nonlocal asm
    asm+=''.join(f'mov r{i},{v&0xffffffff:#x}\n'for i,v in enumerate(args))+f'mov r12,{entry:#x}\njl [r12]\ncmp sp,r20\nbne fail\n'
    asm+=''.join(f'cmp r{i},{v:#x}\nbne fail\n'for i,v in [(13,0x13371337),(14,0x14471447),(15,0x15571557),(16,0x16671667)])
    sequence.extend(events);calls.append(dict(entry=entry,arguments=args,events=events))
   def scalar(address,value=0xa55a):initial.setdefault(address,value);expected.setdefault(address,value)
   if spec:
    mode=spec['mode'];n=33 if mode=='contiguous_bytes'else 66;raw=bytearray([0 if pattern==0 else 255 if pattern==1 else(37*i+0x80)&255 for i in range(n)])
    if pattern==3:
     for i in range(32 if n==33 else 64):
      if mode=='masked7':raw[i]^=0x80 if i%2==0 else 255
      elif mode=='strided_bytes':raw[i]^=255 if i%2 else 0
      else:raw[i]^=128
    if n==33:raw[32]=[0,255,128,127][pattern]
    else:struct.pack_into('<H',raw,64,[0,65535,0x80ff,0xff80][pattern])
    vals=[(((struct.unpack_from('<H',raw,4*i)[0]&127)|((struct.unpack_from('<H',raw,4*i+2)[0]&127)<<8))if mode=='masked7'else(raw[4*i]|raw[4*i+2]<<8)if mode=='strided_bytes'else(raw[2*i]|raw[2*i+1]<<8))for i in range(16)]
    vals.append(raw[32]if n==33 else struct.unpack_from('<H',raw,64)[0]);args=[(0,0),(0xffffffff,0xffffffff),(0x12345678,0x9abcdef0),(0x10001,0xfeed8000)][pattern]
    tails=[(args[1]|args[0]<<10)&65535]if mode=='masked7'else[args[1]&65535,args[0]&65535]
    if pattern==2:previous[spec['name']]=vals[:16]
    if pattern==3 and mode!='contiguous_bytes':assert previous[spec['name']]==vals[:16]
    inp=r.out/(name+'_input.bin');inp.write_bytes(raw);buffers[0x700000]=dict(file=inp.name,bytes=bytes(raw).hex());initial.update({spec['base']+4*i:0xa5a5 for i in range(17)});expected.update(dict(zip([spec['base']+4*i for i in range(17)],vals)))
    for a,v in zip(spec['tails'],tails):scalar(a);expected[a]=v
    call(spec['entry'],[0x700000]+list(args),[(spec['store_pc'],'write',spec['base']+4*i,v)for i,v in enumerate(vals)]+[(pc,'write',a,v)for pc,a,v in zip(spec['tail_pcs'],spec['tails'],tails)])
   else:
    seed=0 if pattern==0 else 65535;scalar(0xff74000,seed)
    for entry,bit in[(0x2e0600,5),(0x2e0634,6)]:
     for arg in[1,0,2,0xffffffff]:
      old=expected[0xff74000];value=(old|1<<bit)if arg==1 else old&~(1<<bit);pc=entry+(0x14 if arg==1 else 0x24);call(entry,[arg],[(pc,'read',0xff74000,old),(pc+8,'write',0xff74000,value)]);expected[0xff74000]=value
    vals=[0x12345678,0x9abcdef0,0x80010001,0xffffffff]if pattern else[0,1,0x8000,65535]
    ev=[]
    for a,pc,v in zip(range(0xff74004,0xff74014,4),[0x2e067c,0x2e0688,0x2e0694,0x2e06a0],vals):scalar(a,seed);expected[a]=v&65535;ev.append((pc,'write',a,v&65535))
    call(0x2e0668,vals,ev)
    for entry,a in[(0x2e06a8,0xff74014),(0x2e06c0,0xff74018),(0x2e06d8,0xff7401c)]:
     scalar(a,seed)
     for x,y in[(0,0),(1,2),(65535,65535),(0x12345678,0x9abcdef0)]:
      value=(x|y<<4)&65535;call(entry,[x,y],[(entry+16,'write',a,value)]);expected[a]=value
    for i,entry in enumerate(range(0x2e07f8,0x2e0884,20)):
     a=0xff740d4+4*i;v=(0x8000+i*0x12345)if pattern else i;scalar(a,seed);call(entry,[v],[(entry+12,'write',a,v&65535)]);expected[a]=v&65535
   asm+='mov r0,0\nb finish\nfail:\nmov r0,7\nfinish:\nmov r8,1\ntrap_s 1\n';elf=compile_probe(r,name,asm);traces=[]
   for enabled in[False,True]:
    case_name=name+('_observed'if enabled else'_reference');r.observe=enabled;options=['--memory-mapfile','/result/'+main_file.name,'--memory-region',f'{base:#x},{len(body):#x}'];fixtures={}
    for address,b in buffers.items():options+=['--memory-mapfile','/result/'+b['file'],'--memory-region',f'{address:#x},{len(bytes.fromhex(b["bytes"])):#x}']
    for address in sorted(initial):
     data=bytearray(b'\xa5'*8);struct.pack_into('<H',data,address%8,initial[address]);p=r.out/f'{case_name}_{address:x}.bin';p.write_bytes(data);fixtures[hex(address)]=dict(file=p.name,before=data.hex());options+=['--memory-mapfile','/result/'+p.name,'--memory-region',f'{address:#x},2']
    r.range_override=known_sections(elf,False)+f',{base:#x}:{len(body):#x}'+''.join(f',{a:#x}:{len(bytes.fromhex(b["bytes"])):#x}'for a,b in buffers.items());case,log=r.run(case_name,'/result/'+elf.name,options,trace=True,extract=True)
    assert case['exit_code']==0 and case['fault']is None,log[-4000:];assert all(s not in log for s in['S33_UNDEFINED','S33_AUX_UNKNOWN','runtime error:'])
    events=[json.loads(line.removeprefix('S33_MEM '))for line in(r.out/(case_name+'.stderr.log')).read_text().splitlines()if line.startswith('S33_MEM ')];done=[e for e in events if e['stage']=='result'];assert len(events)==2*len(done)and all(e['width_bytes']==2 for e in done)
    assert[(e['pc'],e['operation'],e['address'],e['value'])for e in done]==(sequence if enabled else[]),(case_name,done,sequence)
    for key,f in fixtures.items():
     a=int(key,0);after=(r.out/f['file']).read_bytes();before=bytes.fromhex(f['before']);assert struct.unpack_from('<H',after,a%8)[0]==expected[a];assert all(after[j]==before[j]for j in range(8)if j not in[a%8,a%8+1]);f['after']=after.hex()
    assert main_file.read_bytes()==body and all((r.out/b['file']).read_bytes()==bytes.fromhex(b['bytes'])for b in buffers.values());traces.append((r.out/(case_name+'.trace')).read_bytes());case.update(scenario=name,spec_name=spec['name']if spec else None,pattern=pattern,observer_enabled=enabled,fixtures=fixtures,input_buffers=buffers,original_calls=calls,completed_memory_events=done,full_original_calls_completed=True);print(case_name,'PASS',len(done),'events',flush=True)
   assert traces[0]==traces[1];pairs.append(dict(scenario=name,trace_identical=True,events=len(sequence)))
  fw=(ROOT/'OriginalSoftware_NikonS33_V1.1/firmware.bin').read_bytes();offset=fw.find(body);assert offset>=0 and fw.find(body,offset+1)<0
  assert len(pairs)==34 and sum(p['events']for p in pairs)==678
  r.results.update(status='PASS_FF7_PACKED_TABLES',pairs=pairs,specs=SPECS,payload=dict(base=base,size=len(body),firmware_offset=offset,sha256=sha(main_file),path=str(main_file)),capture_streams_separate=True,hardware_access=False,gnu_modified=False,limits=['Five17cell apertures are separate from independent scalar controls; no physical width/reset/permission/function inferred.','Buffers, backing storage and initial seeds are explicit fixtures, not Nikon state or free RAM.','Caller arguments exceed nominal field widths deliberately; whole-halfword OR/truncation is software behavior, not a safe hardware API.','Synthetic callers complete routines but do not establish reachability from Nikon boot or real caller argument domains.']);r.finish()
 except Exception as exc:r.results.update(status='FAIL',error=repr(exc));raise
 finally:r.save()
 print(r.out/'verified_evidence.json',flush=True)
if __name__=='__main__':main()
