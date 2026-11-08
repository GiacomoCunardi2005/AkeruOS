#!/usr/bin/env python3
"""Original scalar FFC7000 tail: repeated field RMWs and argument equality controls."""
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
# (address,read,write,mask,destination_shift,argument_or_input_byte)
FIELDS=[(0x309504,[(0xffc7718,0x309520,0x30952e,127,0,0),(0xffc7718,0x309532,0x30954e,0x7f00,8,1)],False),(0x309558,[(0xffc771c,0x30956c,0x30957a,255,0,0),(0xffc771c,0x30957e,0x30959c,0xff00,8,1),(0xffc7720,0x3095a8,0x3095b6,255,0,2),(0xffc7720,0x3095ba,0x3095d4,0xff00,8,3)],True),(0x3095dc,[(0xffc7724,0x3095f0,0x3095fe,7,0,0),(0xffc7724,0x309602,0x309616,0x700,8,1)],False),(0x309620,[(0xffc7204,0x309630,0x309642,15,0,4),(0xffc7208,0x309650,0x30965e,15,0,5),(0xffc720c,0x30966c,0x30967a,15,0,6)],True)]
for entry,a,mask in[(0x3096b8,0xffc7228,3),(0x3096e0,0xffc722c,1),(0x309738,0xffc7228,3),(0x309760,0xffc7238,1),(0x3097b8,0xffc721c,3),(0x3097e0,0xffc7220,1)]:FIELDS.append((entry,[(a,entry+16,entry+30 if mask==3 else entry+28,mask,0,0)],False))
FLAGS=[(0x309684,0xffc7224,0),(0x309704,0xffc7230,0),(0x309784,0xffc7218,0),(0x309804,0xffc7200,0),(0x309850,0xffc7064,1)]
VALUES=[0,1,3,7,127,128,0x800180ff,0xffffffff]
def main():
 r=SeparatedRunner(SimpleNamespace(legacy_root=LEGACY,toolchain=TOOLCHAIN,output=None,action='ffc7000-scalar-tail'));print('Evidence:',r.out,flush=True)
 try:
  r.prepare();r.known_ranges='';assert sha(LAB/'install/bin/arc-elf32-run')==json.loads(BUILD.read_text())['engine_sha256'];r.experimental_engine=LAB;assert sha(REUSED/'observer')==json.loads((REUSED/'verified_evidence.json').read_text())['files']['observer'];shutil.copy2(REUSED/'observer',r.out/'observer')
  for p in[Path(__file__),BUILD,LAB/'install/bin/arc-elf32-run',REUSED/'observer',REUSED/'verified_evidence.json']+[Path(__file__).with_name(x+'.py')for x in['s33_verify_ff7_transfer_windows','s33_verify_sensor_mmio_dialog','s33_run_gnu_arc700','s33_trace_state_dispatch','s33_verify_gnu_defined_memory','s33_verify_gnu_dsp_lab']]:r.input_hashes[str(p)]=sha(p)
  shutil.copy2(Path(__file__),r.out/Path(__file__).name);bs,ps,bd=verified_payloads(ROOT);body=ps[0];base=bs[0]['load_address_candidate'];mf=r.out/'payload0_mmap.bin';mf.write_bytes(body);r.input_hashes[str(bd/bs[0]['file'])]=sha(bd/bs[0]['file']);(r.out/'linear_navigation_only.txt').write_text(aligned_window(body,base,0x309504,0x309884));addresses=sorted({f[0]for _,fields,_ in FIELDS for f in fields}|{a for _,a,_ in FLAGS}|{0xffc7080});assert len(addresses)==18;pairs=[];outputs={};sentinels={i:v for i,v in[(13,0x13371337),(14,0x14471447),(15,0x15571557),(16,0x16671667),(17,0x17771777),(18,0x18871887),(19,0x19971997)]}
  for pattern in range(9):
   p=6 if pattern==8 else pattern;args=[VALUES[p],VALUES[(p+3)%8]]
   if pattern==8:args=[x^0xffff0000 for x in args]
   seed=[0,65535,0xa55a,0x5aa5,0x8080,0x0101,0x8001,0x7ffe][p];raw=bytes(7)if p==0 else bytes([255]*7)if p==1 else bytes(((x+p*19)&255)for x in[0,255,128,127,1,254,85]);scenario='scalar_tail_'+str(pattern);inp=r.out/(scenario+'_input.bin');inp.write_bytes(raw);state={a:seed for a in addresses};calls=[];sequence=[];asm='mov r20,sp\n'+''.join(f'mov r{i},{x:#x}\n'for i,x in sentinels.items())
   def call(entry,argv,events,ret=None):
    nonlocal asm
    asm+=''.join(f'mov r{i},{x:#x}\n'for i,x in enumerate(argv))+f'mov r12,{entry:#x}\njl [r12]\n'
    if ret is not None:asm+=f'cmp r0,{ret:#x}\nbne fail\n'
    asm+='cmp sp,r20\nbne fail\n'+''.join(f'cmp r{i},{x:#x}\nbne fail\n'for i,x in sentinels.items());calls.append(dict(entry=hex(entry),arguments=list(map(hex,argv)),expected_return=ret));sequence.extend(events)
    for _,op,a,x in events:
     if op=='write':state[a]=x
   for entry,fields,buffer in FIELDS:
    temp=dict(state);ev=[]
    for a,rd,wr,mask,shift,index in fields:
     value=raw[index]if buffer else args[index];new=(temp[a]&~mask)|((value<<shift)&mask);ev.extend([(rd,'read',a,temp[a]),(wr,'write',a,new)]);temp[a]=new
    argv=([0x700000,0x700002]if entry==0x309558 else[0x700004])if buffer else args;call(entry,argv,ev)
   for entry,a,bit in FLAGS:
    for flag in[0,1,2,0xffffffff]:
     off=20 if flag==1 else 36;new=state[a]|(1<<bit)if flag==1 else state[a]&~(1<<bit);call(entry,[flag],[(entry+off,'read',a,state[a]),(entry+off+8,'write',a,new)])
   call(0x309838,[],[(0x309844,'read',0xffc7080,state[0xffc7080])],state[0xffc7080]&1);assert len(sequence)==75;outputs[pattern]=sequence;asm+='mov r0,0\nb finish\nfail:\nmov r0,7\nfinish:\nmov r8,1\ntrap_s 1\n';elf=compile_probe(r,scenario,asm);traces=[]
   for enabled in[False,True]:
    name=scenario+('_observed'if enabled else'_reference');r.observe=enabled;options=['--memory-mapfile','/result/'+mf.name,'--memory-region',f'{base:#x},{len(body):#x}','--memory-mapfile','/result/'+inp.name,'--memory-region','0x700000,7'];fixtures={}
    for a in addresses:
     before=bytearray(b'\xa5'*8);struct.pack_into('<H',before,a%8,seed);f=r.out/f'{name}_{a:x}.bin';f.write_bytes(before);fixtures[hex(a)]=dict(file=f.name,before=before.hex());options+=['--memory-mapfile','/result/'+f.name,'--memory-region',f'{a:#x},2']
    r.range_override=known_sections(elf,False)+f',{base:#x}:{len(body):#x},0x700000:7';case,log=r.run(name,'/result/'+elf.name,options,trace=True,extract=True);assert case['exit_code']==0 and case['fault']is None,log[-5000:];assert all(x not in log for x in['S33_UNDEFINED','S33_AUX_UNKNOWN','runtime error:']);captured=[json.loads(line.removeprefix('S33_MEM '))for line in(r.out/(name+'.stderr.log')).read_text().splitlines()if line.startswith('S33_MEM ')];events=[e for e in captured if e['stage']=='result'];assert len(captured)==2*len(events)and all(e['width_bytes']==2 for e in captured);assert[(e['pc'],e['operation'],e['address'],e['value'])for e in events]==(sequence if enabled else[])
    for key,f in fixtures.items():
     a=int(key,0);before=bytes.fromhex(f['before']);after=(r.out/f['file']).read_bytes();off=a%8;assert struct.unpack_from('<H',after,off)[0]==state[a]and all(before[j]==after[j]for j in range(8)if j not in[off,off+1]);f['after']=after.hex()
    assert inp.read_bytes()==raw and mf.read_bytes()==body;case.update(scenario=scenario,pattern=pattern,observer_enabled=enabled,input_file=inp.name,input_bytes_hex=raw.hex(),original_calls=calls,fixtures=fixtures,completed_memory_events=events,full_original_calls_completed=True);traces.append((r.out/(name+'.trace')).read_bytes());print(name,'PASS',len(events),'events',flush=True)
   assert traces[0]==traces[1];pairs.append(dict(scenario=scenario,events=len(sequence),trace_identical=True))
  assert outputs[6]==outputs[8]and len(pairs)==9;fw=(ROOT/'OriginalSoftware_NikonS33_V1.1/firmware.bin').read_bytes();offset=fw.find(body);assert offset>=0 and fw.find(body,offset+1)<0;r.results.update(status='PASS_FFC7000_SCALAR_TAIL',pairs=pairs,metamorphic_equivalences=1,payload=dict(base=base,size=len(body),firmware_offset=offset,sha256=sha(mf),path=str(mf)),capture_streams_separate=True,hardware_access=False,gnu_modified=False,limits=['Original fixed scalar fields;separateRMW updates are not atomic andpreserved bits come from seededmodel storage.','Argument equality1 flags differ fromLSB fields;actualNikon caller domains andphysical roles remain unknown.','Input RAM,stack andMMIO backing are fixtures;no reset/permission/IRQ/timing/W1C inference.']);r.finish()
 except Exception as exc:r.results.update(status='FAIL',error=repr(exc));raise
 finally:r.save()
 print(r.out/'verified_evidence.json',flush=True)
if __name__=='__main__':main()
