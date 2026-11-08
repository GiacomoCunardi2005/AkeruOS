#!/usr/bin/env python3
"""Run fixed-caller FFC7000 transfer loops and two fixed nibble accumulators unchanged."""
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
RAW_WRAPPERS=[(0x308f7c,0xffc7314,0xffc7348),(0x308f98,0xffc737c,0xffc73b0),(0x308fb4,0xffc73e4,0xffc7418),(0x308fd0,0xffc744c,0xffc7480)]
LOW9_BASES=[0xffc74bc,0xffc74cc,0xffc74dc,0xffc74ec]
def data(group,pattern):
 if group=='byte9':
  raw=bytes([0,255,128,127,1,254,85,170,129]);return[bytes(9)if pattern==0 else bytes([255]*9)if pattern==1 else bytes(x^255 for x in raw)if pattern==3 else raw]
 if group=='nibble_pair':
  aa=bytes([0,15,16,255]);bb=bytes([0,7,8,255])
  if pattern==0:return[bytes(4),bytes(4)]
  if pattern==1:return[bytes([255]*4),bytes([255]*4)]
  if pattern==3:return[bytes(x^0xf0 for x in aa),bytes(x^0xf8 for x in bb)]
  return[aa,bb]
 n=16 if group=='low9_four'else 26;values=[(i*1237+0x3412)&65535 for i in range(n)];values[:6]=[0,65535,0x8000,0x1ff,0x200,0x1234]
 if pattern==0:values=[0]*n
 elif pattern==1:values=[65535]*n
 elif pattern==3:values=[x^(0xfe00 if group=='low9_four'else 65535)for x in values]
 return[struct.pack('<'+'H'*n,*values)]

def main():
 r=SeparatedRunner(SimpleNamespace(legacy_root=LEGACY,toolchain=TOOLCHAIN,output=None,action='ffc7000-fixed-caller-loop-writers'));print('Evidence:',r.out,flush=True)
 try:
  r.prepare();r.known_ranges='';assert sha(LAB/'install/bin/arc-elf32-run')==json.loads(BUILD.read_text())['engine_sha256'];r.experimental_engine=LAB;assert sha(REUSED/'observer')==json.loads((REUSED/'verified_evidence.json').read_text())['files']['observer'];shutil.copy2(REUSED/'observer',r.out/'observer')
  for p in[Path(__file__),BUILD,LAB/'install/bin/arc-elf32-run',REUSED/'observer',REUSED/'verified_evidence.json',Path(__file__).with_name('s33_verify_ff7_transfer_windows.py')]:r.input_hashes[str(p)]=sha(p)
  shutil.copy2(Path(__file__),r.out/Path(__file__).name);bs,ps,bd=verified_payloads(ROOT);body=ps[0];base=bs[0]['load_address_candidate'];mf=r.out/'payload0_mmap.bin';mf.write_bytes(body);r.input_hashes[str(bd/bs[0]['file'])]=sha(bd/bs[0]['file']);table=body[0x354e50-base:0x354e56-base];assert struct.unpack('<2H2B',table)==(255,65280,0,8);assert[struct.unpack_from('<I',body,0x309010+4*i-base)[0]for i in range(8)]==[a for _,lo,hi in RAW_WRAPPERS for a in[lo,hi]];assert struct.unpack_from('<I',body,0x309134-base)[0]==0x309090 and[struct.unpack_from('<I',body,0x309138+4*i-base)[0]for i in range(4)]==LOW9_BASES
  (r.out/'linear_navigation_only.txt').write_text(aligned_window(body,base,0x308ed4,0x3090fc));pairs=[];outputs={};sentinels={13:0x13371337,14:0x14471447,15:0x15571557,16:0x16671667,17:0x17771777,18:0x18871887,19:0x19971997};specs=[('byte9',0x308ed4,None)]+[('raw13_'+str(i),entry,i)for i,(entry,lo,hi)in enumerate(RAW_WRAPPERS)]+[('nibble_pair',0x308fec,None),('low9_four',0x3090d0,None)]
  for group,entry,index in specs:
   for pattern in range(4):
    scenario=group+'_'+str(pattern);buffers=data(group,pattern);seed=0 if pattern==0 else 65535 if pattern==1 else 0xa55a;addresses=sorted(set(range(0xffc7300,0xffc7314,4))if group=='byte9'else{0xffc74b4,0xffc74b8}if group=='nibble_pair'else{a+4*i for a in LOW9_BASES for i in range(4)}if group=='low9_four'else{a+4*i for a in RAW_WRAPPERS[index][1:]for i in range(13)});state={a:seed for a in addresses};sequence=[];input_files=[]
    for j,raw in enumerate(buffers):
     p=r.out/(scenario+f'_input{j}.bin');p.write_bytes(raw);input_files.append(dict(file=p.name,address=hex(0x700000+0x100*j),bytes=raw.hex()))
    def rw(pc,write,a,value):sequence.extend([(pc,'read',a,state[a]),(write,'write',a,value)]);state[a]=value
    if group=='byte9':
     for i,x in enumerate(buffers[0]):
      a=0xffc7300+4*(i//2);mask=[255,65280][i%2];shift=[0,8][i%2];rw(0x308f18,0x308f38,a,(state[a]&~mask)|((x<<shift)&mask))
    elif group=='nibble_pair':
     for i in range(4):
      shift=4*i
      for address,values,mask,rd,wr in[(0xffc74b4,buffers[0],15,0x30903c,0x309058),(0xffc74b8,buffers[1],7,0x309064,0x309080)]:rw(rd,wr,address,(state[address]&~(mask<<shift))|((values[i]&mask)<<shift))
    elif group=='low9_four':
     values=struct.unpack('<16H',buffers[0])
     for j,a in enumerate(LOW9_BASES):
      for i in range(4):address=a+4*i;rw(0x3090b4,0x3090c4,address,(state[address]&0xfe00)|(values[4*j+i]&0x1ff))
    else:
     values=struct.unpack('<26H',buffers[0])
     for j,a in enumerate(RAW_WRAPPERS[index][1:]):
      for i in range(13):address=a+4*i;value=values[13*j+i];sequence.append((0x308f70,'write',address,value));state[address]=value
    outputs[(group,pattern)]=[(a,v)for pc,op,a,v in sequence if op=='write'];asm='mov r20,sp\n'+''.join(f'mov r{i},{x:#x}\n'for i,x in sentinels.items())+'mov r0,0x700000\n'+('mov r1,0x700100\n'if group=='nibble_pair'else'')+f'mov r12,{entry:#x}\njl [r12]\ncmp sp,r20\nbne fail\n'+''.join(f'cmp r{i},{x:#x}\nbne fail\n'for i,x in sentinels.items())+'mov r0,0\nb finish\nfail:\nmov r0,7\nfinish:\nmov r8,1\ntrap_s 1\n';elf=compile_probe(r,scenario,asm);traces=[]
    for enabled in[False,True]:
     name=scenario+('_observed'if enabled else'_reference');r.observe=enabled;options=['--memory-mapfile','/result/'+mf.name,'--memory-region',f'{base:#x},{len(body):#x}'];fixtures={}
     for item in input_files:options+=['--memory-mapfile','/result/'+item['file'],'--memory-region',f'{item["address"]},{len(bytes.fromhex(item["bytes"])):#x}']
     for address in addresses:
      raw=bytearray(b'\xa5'*8);struct.pack_into('<H',raw,address%8,seed);p=r.out/f'{name}_{address:x}.bin';p.write_bytes(raw);fixtures[hex(address)]=dict(file=p.name,before=raw.hex());options+=['--memory-mapfile','/result/'+p.name,'--memory-region',f'{address:#x},2']
     r.range_override=known_sections(elf,False)+f',{base:#x}:{len(body):#x}'+''.join(f',{item["address"]}:{len(bytes.fromhex(item["bytes"])):#x}'for item in input_files);case,log=r.run(name,'/result/'+elf.name,options,trace=True,extract=True);assert case['exit_code']==0 and case['fault']is None,log[-5000:];assert all(x not in log for x in['S33_UNDEFINED','S33_AUX_UNKNOWN','runtime error:']);captured=[json.loads(line.removeprefix('S33_MEM '))for line in(r.out/(name+'.stderr.log')).read_text().splitlines()if line.startswith('S33_MEM ')];events=[e for e in captured if e['stage']=='result'];assert len(captured)==2*len(events)and all(e['width_bytes']==2 for e in captured);assert[(e['pc'],e['operation'],e['address'],e['value'])for e in events]==(sequence if enabled else[])
     for key,f in fixtures.items():
      address=int(key,0);before=bytes.fromhex(f['before']);after=(r.out/f['file']).read_bytes();off=address%8;assert struct.unpack_from('<H',after,off)[0]==state[address]and all(before[i]==after[i]for i in range(8)if i not in[off,off+1]);f['after']=after.hex()
     assert mf.read_bytes()==body and all((r.out/item['file']).read_bytes()==bytes.fromhex(item['bytes'])for item in input_files);case.update(scenario=scenario,group=group,pattern=pattern,selected_entry=hex(entry),observer_enabled=enabled,input_files=input_files,fixtures=fixtures,completed_memory_events=events,full_original_calls_completed=True);traces.append((r.out/(name+'.trace')).read_bytes());print(name,'PASS',len(events),'events',flush=True)
    assert traces[0]==traces[1];pairs.append(dict(scenario=scenario,events=len(sequence),trace_identical=True))
  assert outputs[('nibble_pair',2)]==outputs[('nibble_pair',3)]and outputs[('low9_four',2)]==outputs[('low9_four',3)];assert len(pairs)==28 and sum(p['events']for p in pairs)==680;fw=(ROOT/'OriginalSoftware_NikonS33_V1.1/firmware.bin').read_bytes();offset=fw.find(body);assert offset>=0 and fw.find(body,offset+1)<0;r.results.update(status='PASS_FFC7000_BOUND_LOOP_WRITERS',pairs=pairs,raw_wrappers=[dict(entry=hex(e),destinations=list(map(hex,[lo,hi])))for e,lo,hi in RAW_WRAPPERS],low9_wrapper=dict(entry='0x3090d0',helper='0x309090',destinations=list(map(hex,LOW9_BASES))),byte_table=dict(address='0x354e50',bytes_hex=table.hex(),values=list(struct.unpack('<2H2B',table)),source='original_Main_read_only'),metamorphic_equivalences=2,payload=dict(base=base,size=len(body),firmware_offset=offset,sha256=sha(mf),path=str(mf)),capture_streams_separate=True,hardware_access=False,gnu_modified=False,limits=['Only original fixed wrappers bind13word andlow9helper destinations;unresolved other callers and arbitrary destination arguments are not cataloged.','Byte9last output preserves prior high8;other paired outputs accumulate through separate halfwordRMW operations.','Two nibble addresses are fixed fields:maskF or7 shifted0/4/8/12;second register preserves bit3 ofeach nibble.','RAM input,stack andMMIO seeds/backing are fixtures;reset/physical role/permissions/IRQ/timing and actual caller domains unknown.']);r.finish()
 except Exception as exc:r.results.update(status='FAIL',error=repr(exc));raise
 finally:r.save()
 print(r.out/'verified_evidence.json',flush=True)
if __name__=='__main__':main()
